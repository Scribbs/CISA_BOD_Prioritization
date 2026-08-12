"""
BOD 26-04 Inspired Risk-Based Vulnerability Prioritization Agent
A simple agentic pipeline to help organizations build priority-based
security assessment and remediation plans based on CISA BOD 26-04 principles.

Features:
- Controlled access (login)
- Secure local storage of proprietary asset configs & controls
- Automated KEV enrichment
- 4-factor risk scoring (Exposure, KEV, Automatable, Technical Impact)
- Priority tiers and remediation timelines
- Guided plan generation
- Clear, user-friendly Streamlit UI
"""

import streamlit as st
import pandas as pd
import sqlite3
import hashlib
import json
import os
import requests
from datetime import datetime, timedelta
from pathlib import Path
import plotly.express as px
import plotly.graph_objects as go
from typing import Dict, List, Optional, Tuple
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# =============================================================================
# Configuration & Security
# =============================================================================

DB_PATH = Path(__file__).parent / "secure_data" / "bod_agent.db"
KEY_FILE = Path(__file__).parent / "secure_data" / ".key"
os.makedirs(DB_PATH.parent, exist_ok=True)

# Default admin (change in production)
DEFAULT_ADMIN = {"username": "admin", "password": "ChangeMe123!", "role": "admin"}

# Priority definitions inspired by BOD 26-04 Table 1 logic
# (Simplified decision tree based on public descriptions of the 4 factors)
PRIORITY_TIERS = {
    "Critical": {
        "timeline_days": 3,
        "color": "#d32f2f",
        "forensic_triage": True,
        "description": "Highest risk: Immediate action + forensic triage required. Publicly exposed + known exploited + high impact.",
        "actions": [
            "Initiate forensic triage within 2 hours of identification",
            "Preserve volatile evidence before patching",
            "Remediate (patch/isolate/decommission) within 3 calendar days",
            "Document all actions and escalate if compromise indicators found",
            "Notify leadership and relevant stakeholders immediately"
        ]
    },
    "High": {
        "timeline_days": 14,
        "color": "#f57c00",
        "forensic_triage": False,
        "description": "High risk: Rapid remediation. Significant combination of exposure, exploitation evidence, or control impact.",
        "actions": [
            "Schedule remediation within 14 calendar days",
            "Assess compensating controls if immediate patch not possible",
            "Increase monitoring on affected assets",
            "Update change management tickets with priority justification"
        ]
    },
    "Medium": {
        "timeline_days": 60,
        "color": "#fbc02d",
        "forensic_triage": False,
        "description": "Moderate risk: Planned remediation. Lower exposure or limited exploitability.",
        "actions": [
            "Include in next monthly/quarterly patch cycle (within 60 days)",
            "Apply compensating controls (network segmentation, WAF rules, etc.)",
            "Track in vulnerability management system",
            "Re-evaluate if asset exposure or KEV status changes"
        ]
    },
    "Low": {
        "timeline_days": None,  # Next upgrade
        "color": "#388e3c",
        "forensic_triage": False,
        "description": "Lower risk: Defer to next system upgrade or major maintenance window.",
        "actions": [
            "Defer to next scheduled system upgrade or major release",
            "Document risk acceptance with business owner",
            "Monitor for changes in KEV status or exposure",
            "Apply temporary mitigations if practical (e.g., configuration hardening)"
        ]
    }
}


def get_or_create_key() -> bytes:
    """Generate or load encryption key for sensitive fields."""
    if KEY_FILE.exists():
        return KEY_FILE.read_bytes()
    key = Fernet.generate_key()
    KEY_FILE.write_bytes(key)
    KEY_FILE.chmod(0o600)
    return key


def get_fernet() -> Fernet:
    return Fernet(get_or_create_key())


def encrypt_text(text: str) -> str:
    if not text:
        return ""
    return get_fernet().encrypt(text.encode()).decode()


def decrypt_text(token: str) -> str:
    if not token:
        return ""
    try:
        return get_fernet().decrypt(token.encode()).decode()
    except Exception:
        return "[decryption error]"


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


# =============================================================================
# Database
# =============================================================================

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'analyst',
            created_at TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_name TEXT NOT NULL,
            asset_type TEXT,
            environment TEXT,
            is_publicly_exposed INTEGER DEFAULT 0,
            criticality TEXT DEFAULT 'Medium',
            owner TEXT,
            ip_or_hostname TEXT,
            notes_encrypted TEXT,
            security_controls_encrypted TEXT,
            created_at TEXT,
            updated_at TEXT,
            created_by TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER,
            cve_id TEXT NOT NULL,
            title TEXT,
            description TEXT,
            is_kev INTEGER DEFAULT 0,
            kev_date_added TEXT,
            automatable TEXT DEFAULT 'Unknown',  -- Yes / No / Unknown
            technical_impact TEXT DEFAULT 'Unknown',  -- Total / Partial / Unknown
            cvss_score REAL,
            status TEXT DEFAULT 'Open',
            identified_date TEXT,
            remediation_due TEXT,
            priority_tier TEXT,
            notes TEXT,
            created_at TEXT,
            updated_at TEXT,
            FOREIGN KEY (asset_id) REFERENCES assets(id)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS assessment_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_name TEXT,
            run_date TEXT,
            summary_json TEXT,
            created_by TEXT
        )
    """)

    # Seed default admin if none
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        c.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (DEFAULT_ADMIN["username"], hash_password(DEFAULT_ADMIN["password"]), "admin", datetime.utcnow().isoformat())
        )

    conn.commit()
    conn.close()


def get_conn():
    return sqlite3.connect(DB_PATH)


# =============================================================================
# KEV Enrichment
# =============================================================================

@st.cache_data(ttl=3600)
def fetch_kev_catalog() -> Dict[str, dict]:
    """Fetch and cache CISA KEV catalog."""
    try:
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        kev_map = {}
        for v in data.get("vulnerabilities", []):
            cve = v.get("cveID", "").upper()
            if cve:
                kev_map[cve] = v
        return kev_map
    except Exception as e:
        st.warning(f"Could not refresh KEV catalog: {e}. Using empty cache.")
        return {}


def is_kev(cve_id: str, kev_map: Dict) -> Tuple[bool, Optional[str]]:
    cve = cve_id.upper().strip()
    if cve in kev_map:
        return True, kev_map[cve].get("dateAdded")
    return False, None


# =============================================================================
# Core Prioritization Logic (Agent Decision Tree)
# Inspired by BOD 26-04 four-factor model + public timeline descriptions
# =============================================================================

def determine_priority(
    is_publicly_exposed: bool,
    is_kev: bool,
    automatable: str,          # "Yes", "No", "Unknown"
    technical_impact: str      # "Total", "Partial", "Unknown"
) -> str:
    """
    Decision tree approximating BOD 26-04 Table 1.
    Conservative when Unknown (treat as higher risk).
    """
    auto_yes = automatable in ("Yes", "Unknown")
    total_impact = technical_impact in ("Total", "Unknown")
    partial_or_higher = technical_impact in ("Total", "Partial", "Unknown")

    # Critical: 3-day + triage cases
    if is_publicly_exposed and is_kev:
        if total_impact:
            return "Critical"  # Total control on exposed KEV → 3d + triage
        if auto_yes and partial_or_higher:
            return "Critical"  # Automatable + at least partial on exposed KEV

    if is_publicly_exposed and total_impact and auto_yes:
        # Even non-KEV but fully automatable total-control exposed is high urgency
        return "Critical"

    # High: 14-day
    if is_publicly_exposed and is_kev:
        return "High"  # Remaining exposed KEVs (e.g. partial, non-auto)

    if is_kev and total_impact:
        return "High"  # Internal KEV with total control

    if is_publicly_exposed and auto_yes and partial_or_higher:
        return "High"

    # Medium: 60-day
    if is_kev or (is_publicly_exposed and partial_or_higher):
        return "Medium"

    if auto_yes or total_impact:
        return "Medium"

    # Low: next upgrade
    return "Low"


def compute_due_date(priority: str, identified: datetime = None) -> Optional[str]:
    if identified is None:
        identified = datetime.utcnow()
    tier = PRIORITY_TIERS[priority]
    days = tier["timeline_days"]
    if days is None:
        return "Next system upgrade"
    due = identified + timedelta(days=days)
    return due.strftime("%Y-%m-%d")


# =============================================================================
# Streamlit UI Helpers
# =============================================================================

def require_login():
    if "authenticated" not in st.session_state or not st.session_state.authenticated:
        st.warning("Please log in to access the Priority Assessment Agent.")
        st.stop()


def login_page():
    st.title("🔐 BOD Priority Agent — Secure Access")
    st.markdown("""
    **Controlled Access Portal** for risk-based vulnerability prioritization  
    inspired by CISA Binding Operational Directive 26-04.
    
    Proprietary system configurations and security controls are stored encrypted 
    and accessible only to authenticated users.
    """)

    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Log In")

        if submitted:
            conn = get_conn()
            c = conn.cursor()
            c.execute("SELECT password_hash, role FROM users WHERE username = ?", (username,))
            row = c.fetchone()
            conn.close()
            if row and row[0] == hash_password(password):
                st.session_state.authenticated = True
                st.session_state.username = username
                st.session_state.role = row[1]
                st.success("Login successful")
                st.rerun()
            else:
                st.error("Invalid credentials")

    with st.expander("First-time setup / Default credentials"):
        st.info(f"Default admin: `{DEFAULT_ADMIN['username']}` / `{DEFAULT_ADMIN['password']}`  \n**Change this password immediately after first login.**")


def sidebar_nav():
    st.sidebar.title("🧭 Navigation")
    st.sidebar.markdown(f"**User:** {st.session_state.username} ({st.session_state.role})")
    page = st.sidebar.radio(
        "Go to",
        [
            "🏠 Dashboard",
            "📦 Asset Inventory",
            "🔍 Vulnerability Intake",
            "🤖 Run Assessment Pipeline",
            "📋 Remediation Plans",
            "⚙️ Settings & Security"
        ]
    )
    if st.sidebar.button("Log Out"):
        for k in list(st.session_state.keys()):
            del st.session_state[k]
        st.rerun()
    return page


# =============================================================================
# Pages
# =============================================================================

def page_dashboard():
    st.header("🏠 Priority Assessment Dashboard")
    st.caption("Risk-based view of your systems aligned with BOD 26-04 principles (Exposure • KEV • Automatable • Technical Impact)")

    conn = get_conn()
    assets = pd.read_sql("SELECT * FROM assets", conn)
    vulns = pd.read_sql("SELECT * FROM vulnerabilities", conn)
    conn.close()

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Assets Tracked", len(assets))
    col2.metric("Open Vulnerabilities", len(vulns[vulns["status"] == "Open"]) if not vulns.empty else 0)
    critical = len(vulns[vulns["priority_tier"] == "Critical"]) if not vulns.empty else 0
    col3.metric("Critical (≤3 days)", critical, delta_color="inverse")
    high = len(vulns[vulns["priority_tier"] == "High"]) if not vulns.empty else 0
    col4.metric("High (≤14 days)", high, delta_color="inverse")

    if not vulns.empty:
        st.subheader("Priority Distribution")
        tier_counts = vulns["priority_tier"].value_counts().reindex(["Critical", "High", "Medium", "Low"]).fillna(0)
        fig = px.bar(
            x=tier_counts.index,
            y=tier_counts.values,
            color=tier_counts.index,
            color_discrete_map={k: v["color"] for k, v in PRIORITY_TIERS.items()},
            labels={"x": "Priority Tier", "y": "Count"},
            title="Vulnerabilities by Priority Tier"
        )
        st.plotly_chart(fig, use_container_width=True)

        st.subheader("Upcoming Due Dates (Open Items)")
        open_v = vulns[vulns["status"] == "Open"].copy()
        if not open_v.empty:
            open_v = open_v.sort_values("remediation_due")
            display_cols = ["cve_id", "priority_tier", "remediation_due", "status", "asset_id"]
            st.dataframe(open_v[display_cols].head(20), use_container_width=True)
    else:
        st.info("No vulnerability assessments yet. Go to **Vulnerability Intake** or **Run Assessment Pipeline** to begin.")


def page_assets():
    st.header("📦 Asset Inventory")
    st.markdown("""
    Maintain an inventory of systems. **Public exposure** is a key BOD 26-04 factor.  
    Proprietary configuration notes and implemented security controls are **encrypted at rest**.
    """)

    conn = get_conn()
    assets = pd.read_sql("SELECT id, asset_name, asset_type, environment, is_publicly_exposed, criticality, owner, ip_or_hostname, created_at FROM assets", conn)
    conn.close()

    tab1, tab2 = st.tabs(["View / Edit Assets", "Add New Asset"])

    with tab1:
        if assets.empty:
            st.info("No assets recorded yet.")
        else:
            st.dataframe(assets, use_container_width=True)

            selected = st.selectbox("Select asset to view/edit sensitive details", options=assets["id"].tolist(),
                                    format_func=lambda x: f"{x} — {assets[assets.id==x]['asset_name'].values[0]}")
            if selected:
                conn = get_conn()
                c = conn.cursor()
                c.execute("SELECT notes_encrypted, security_controls_encrypted, is_publicly_exposed, criticality, owner FROM assets WHERE id=?", (selected,))
                row = c.fetchone()
                conn.close()
                if row:
                    notes = decrypt_text(row[0])
                    controls = decrypt_text(row[1])
                    st.subheader("Encrypted Proprietary Data (decrypted for authorized view)")
                    with st.form(f"edit_asset_{selected}"):
                        new_notes = st.text_area("Configuration / System Notes (proprietary)", value=notes, height=120)
                        new_controls = st.text_area("Security Controls Implemented", value=controls, height=120)
                        new_exposed = st.checkbox("Publicly Exposed (Internet-reachable)", value=bool(row[2]))
                        new_crit = st.selectbox("Business Criticality", ["Critical", "High", "Medium", "Low"], index=["Critical","High","Medium","Low"].index(row[3] or "Medium"))
                        new_owner = st.text_input("Owner / Team", value=row[4] or "")
                        if st.form_submit_button("Update Asset"):
                            conn = get_conn()
                            c = conn.cursor()
                            c.execute("""
                                UPDATE assets SET notes_encrypted=?, security_controls_encrypted=?,
                                is_publicly_exposed=?, criticality=?, owner=?, updated_at=?
                                WHERE id=?
                            """, (encrypt_text(new_notes), encrypt_text(new_controls),
                                  int(new_exposed), new_crit, new_owner, datetime.utcnow().isoformat(), selected))
                            conn.commit()
                            conn.close()
                            st.success("Asset updated. Sensitive fields re-encrypted.")
                            st.rerun()

    with tab2:
        with st.form("add_asset"):
            name = st.text_input("Asset Name *", placeholder="e.g. prod-web-01, ERP-DB, laptop-fleet")
            atype = st.selectbox("Asset Type", ["Server", "Workstation", "Network Device", "Cloud Instance", "Container/K8s", "Application", "Other"])
            env = st.selectbox("Environment", ["Production", "Staging", "Development", "Lab", "OT/ICS", "Other"])
            exposed = st.checkbox("Is this asset publicly exposed / internet-reachable?", help="Key BOD 26-04 factor. When in doubt, mark Yes.")
            crit = st.selectbox("Business Criticality", ["Critical", "High", "Medium", "Low"])
            owner = st.text_input("Owner / Responsible Team")
            iphost = st.text_input("IP / Hostname / Identifier")
            notes = st.text_area("Proprietary Configuration Notes (will be encrypted)")
            controls = st.text_area("Current Security Controls (will be encrypted)")
            if st.form_submit_button("Add Asset"):
                if not name:
                    st.error("Asset name is required")
                else:
                    conn = get_conn()
                    c = conn.cursor()
                    now = datetime.utcnow().isoformat()
                    c.execute("""
                        INSERT INTO assets (asset_name, asset_type, environment, is_publicly_exposed,
                        criticality, owner, ip_or_hostname, notes_encrypted, security_controls_encrypted,
                        created_at, updated_at, created_by)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (name, atype, env, int(exposed), crit, owner, iphost,
                          encrypt_text(notes), encrypt_text(controls), now, now, st.session_state.username))
                    conn.commit()
                    conn.close()
                    st.success(f"Asset '{name}' added with encrypted proprietary data.")
                    st.rerun()


def page_vuln_intake():
    st.header("🔍 Vulnerability Intake & Enrichment")
    st.markdown("Add vulnerabilities linked to assets. The agent will automatically check CISA KEV status.")

    conn = get_conn()
    assets = pd.read_sql("SELECT id, asset_name, is_publicly_exposed FROM assets", conn)
    conn.close()

    if assets.empty:
        st.warning("Add at least one asset first.")
        return

    kev_map = fetch_kev_catalog()
    st.caption(f"KEV Catalog loaded: {len(kev_map)} entries (refreshed hourly)")

    with st.form("add_vuln"):
        asset_id = st.selectbox("Affected Asset", options=assets["id"].tolist(),
                                format_func=lambda x: f"{x} — {assets[assets.id==x]['asset_name'].values[0]}")
        cve = st.text_input("CVE ID *", placeholder="CVE-2024-XXXXX").upper().strip()
        title = st.text_input("Short Title / Name")
        desc = st.text_area("Description / Notes from scanner")
        auto = st.selectbox("Exploit Automatable? (BOD factor)", ["Unknown", "Yes", "No"],
                            help="Can an adversary fully automate exploitation? Check Vulnrichment / PoC availability.")
        impact = st.selectbox("Technical Impact (BOD factor)", ["Unknown", "Total", "Partial"],
                              help="Total = full control / arbitrary code / high privileges. Partial = limited (e.g. DoS, info leak).")
        cvss = st.number_input("CVSS Score (optional, informational only — BOD 26-04 does not use CVSS for prioritization)", 0.0, 10.0, 0.0, 0.1)
        if st.form_submit_button("Add & Enrich Vulnerability"):
            if not cve or not cve.startswith("CVE-"):
                st.error("Valid CVE ID required")
            else:
                is_k, date_added = is_kev(cve, kev_map)
                # Get exposure from asset
                exposed = bool(assets[assets.id == asset_id]["is_publicly_exposed"].values[0])
                priority = determine_priority(exposed, is_k, auto, impact)
                due = compute_due_date(priority)

                conn = get_conn()
                c = conn.cursor()
                now = datetime.utcnow().isoformat()
                c.execute("""
                    INSERT INTO vulnerabilities
                    (asset_id, cve_id, title, description, is_kev, kev_date_added,
                     automatable, technical_impact, cvss_score, status, identified_date,
                     remediation_due, priority_tier, notes, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Open', ?, ?, ?, ?, ?, ?)
                """, (asset_id, cve, title, desc, int(is_k), date_added, auto, impact, cvss,
                      now, due, priority, "", now, now))
                conn.commit()
                conn.close()

                st.success(f"Added {cve} → Priority **{priority}** | Due: {due} | KEV: {'Yes' if is_k else 'No'}")
                if is_k:
                    st.warning("This is a Known Exploited Vulnerability. Prioritize accordingly.")
                st.rerun()

    st.divider()
    st.subheader("Current Vulnerabilities")
    conn = get_conn()
    vulns = pd.read_sql("""
        SELECT v.id, v.cve_id, a.asset_name, v.priority_tier, v.is_kev, v.automatable,
               v.technical_impact, v.remediation_due, v.status, v.identified_date
        FROM vulnerabilities v JOIN assets a ON v.asset_id = a.id
        ORDER BY CASE v.priority_tier
            WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END
    """, conn)
    conn.close()
    if not vulns.empty:
        st.dataframe(vulns, use_container_width=True)
    else:
        st.info("No vulnerabilities recorded.")


def page_pipeline():
    st.header("🤖 Agentic Assessment Pipeline")
    st.markdown("""
    **Guided multi-step pipeline** that applies BOD 26-04 risk factors to produce a prioritized remediation plan.
    
    Steps:
    1. **Ingest** — Review current assets & open vulnerabilities
    2. **Enrich** — Refresh KEV status for all CVEs
    3. **Score** — Re-evaluate the 4 factors and assign priority tiers
    4. **Plan** — Generate actionable grouped remediation plan
    5. **Report** — Export summary for leadership / change management
    """)

    if st.button("▶️ Run Full Pipeline Now", type="primary"):
        kev_map = fetch_kev_catalog()
        conn = get_conn()
        c = conn.cursor()

        # Step 1-2: Enrich all open vulns
        c.execute("SELECT id, cve_id, asset_id, automatable, technical_impact FROM vulnerabilities WHERE status='Open'")
        rows = c.fetchall()
        updated = 0
        for vid, cve, asset_id, auto, impact in rows:
            is_k, date_added = is_kev(cve, kev_map)
            c.execute("SELECT is_publicly_exposed FROM assets WHERE id=?", (asset_id,))
            exposed = bool(c.fetchone()[0])
            priority = determine_priority(exposed, is_k, auto or "Unknown", impact or "Unknown")
            due = compute_due_date(priority)
            c.execute("""
                UPDATE vulnerabilities SET is_kev=?, kev_date_added=?, priority_tier=?,
                remediation_due=?, updated_at=? WHERE id=?
            """, (int(is_k), date_added, priority, due, datetime.utcnow().isoformat(), vid))
            updated += 1

        conn.commit()

        # Summary
        c.execute("""
            SELECT priority_tier, COUNT(*) FROM vulnerabilities WHERE status='Open' GROUP BY priority_tier
        """)
        summary = dict(c.fetchall())
        summary_json = json.dumps({
            "run_date": datetime.utcnow().isoformat(),
            "vulns_updated": updated,
            "by_tier": summary,
            "kev_count": len(kev_map)
        })
        c.execute("INSERT INTO assessment_runs (run_name, run_date, summary_json, created_by) VALUES (?, ?, ?, ?)",
                  (f"Pipeline run {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}", datetime.utcnow().isoformat(),
                   summary_json, st.session_state.username))
        conn.commit()
        conn.close()

        st.success(f"Pipeline complete. Re-scored {updated} open vulnerabilities.")
        st.json(json.loads(summary_json))

        # Show resulting priorities
        conn = get_conn()
        result = pd.read_sql("""
            SELECT v.cve_id, a.asset_name, a.is_publicly_exposed as exposed,
                   v.is_kev, v.automatable, v.technical_impact, v.priority_tier, v.remediation_due
            FROM vulnerabilities v JOIN assets a ON v.asset_id = a.id
            WHERE v.status = 'Open'
            ORDER BY CASE v.priority_tier WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END
        """, conn)
        conn.close()
        st.subheader("Updated Priority View")
        st.dataframe(result, use_container_width=True)


def page_plans():
    st.header("📋 Remediation Plans & Actions")
    st.markdown("Actionable plans grouped by priority tier, ready for assignment and tracking.")

    conn = get_conn()
    vulns = pd.read_sql("""
        SELECT v.*, a.asset_name, a.owner, a.criticality as asset_crit, a.is_publicly_exposed
        FROM vulnerabilities v JOIN assets a ON v.asset_id = a.id
        WHERE v.status = 'Open'
        ORDER BY CASE v.priority_tier WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END
    """, conn)
    conn.close()

    if vulns.empty:
        st.info("No open vulnerabilities. Run the assessment pipeline first.")
        return

    for tier in ["Critical", "High", "Medium", "Low"]:
        subset = vulns[vulns["priority_tier"] == tier]
        if subset.empty:
            continue
        info = PRIORITY_TIERS[tier]
        with st.expander(f"**{tier}** — {len(subset)} item(s)  |  Timeline: {info['timeline_days'] or 'Next upgrade'} days  |  {info['description']}", expanded=(tier == "Critical")):
            st.markdown(f"**Recommended Actions:**")
            for a in info["actions"]:
                st.markdown(f"- {a}")
            if info["forensic_triage"]:
                st.error("⚠️ Forensic triage required for these items (preserve evidence before remediation).")

            st.dataframe(subset[["cve_id", "asset_name", "owner", "is_kev", "automatable", "technical_impact", "remediation_due"]], use_container_width=True)

            # Simple export
            csv = subset.to_csv(index=False)
            st.download_button(f"Download {tier} list (CSV)", csv, file_name=f"remediation_{tier.lower()}.csv", mime="text/csv")

    st.divider()
    st.subheader("Full Plan Export")
    full_csv = vulns.to_csv(index=False)
    st.download_button("Download Complete Open Items Plan (CSV)", full_csv, file_name="bod_priority_remediation_plan.csv", mime="text/csv")

    # Generate narrative summary
    if st.button("Generate Executive Summary"):
        critical_n = len(vulns[vulns.priority_tier == "Critical"])
        high_n = len(vulns[vulns.priority_tier == "High"])
        summary = f"""
## Executive Summary — Risk-Based Remediation Plan
**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}  
**Framework:** CISA BOD 26-04 inspired (Asset Exposure • KEV Status • Exploit Automation • Technical Impact)

### Snapshot
- **Critical (≤3 days + forensic triage):** {critical_n}
- **High (≤14 days):** {high_n}
- **Medium (≤60 days):** {len(vulns[vulns.priority_tier == "Medium"])}
- **Low (next upgrade):** {len(vulns[vulns.priority_tier == "Low"])}

### Immediate Attention Required
{"Focus resources on the Critical tier. These represent publicly exposed, known-exploited (or highly automatable) vulnerabilities that can grant significant control. Forensic triage must precede patching where indicated." if critical_n else "No Critical items currently. Maintain vigilance on High tier."}

### Recommendations
1. Assign owners and open change tickets for all Critical and High items today.
2. Validate public exposure flags — when uncertain, treat as exposed.
3. Re-run the Assessment Pipeline after any major scan or KEV catalog update.
4. Document risk acceptances for Low-tier deferrals with business owners.
5. Review contracts/SLAs for third-party and cloud systems to ensure remediation support.

*This plan protects proprietary system configurations by keeping detailed notes encrypted and access-controlled.*
"""
        st.markdown(summary)
        st.download_button("Download Executive Summary (Markdown)", summary, file_name="executive_summary.md")


def page_settings():
    st.header("⚙️ Settings & Security Controls")
    st.markdown("""
    ### Data Protection
    - All proprietary **configuration notes** and **security controls** are encrypted at rest using Fernet (AES).
    - Access is gated by username/password (SHA-256 hashed).
    - Database file lives in a restricted local directory on this host.
    - No data is sent to external services except the public CISA KEV catalog (read-only).
    
    ### Changing the Admin Password
    """)
    if st.session_state.role == "admin":
        with st.form("change_pw"):
            new_pw = st.text_input("New password for current user", type="password")
            confirm = st.text_input("Confirm", type="password")
            if st.form_submit_button("Update Password"):
                if new_pw and new_pw == confirm and len(new_pw) >= 8:
                    conn = get_conn()
                    c = conn.cursor()
                    c.execute("UPDATE users SET password_hash=? WHERE username=?",
                              (hash_password(new_pw), st.session_state.username))
                    conn.commit()
                    conn.close()
                    st.success("Password updated.")
                else:
                    st.error("Passwords must match and be at least 8 characters.")

        st.subheader("Add Analyst User")
        with st.form("add_user"):
            uname = st.text_input("New username")
            upw = st.text_input("Temporary password", type="password")
            if st.form_submit_button("Create User"):
                if uname and upw:
                    try:
                        conn = get_conn()
                        c = conn.cursor()
                        c.execute("INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, 'analyst', ?)",
                                  (uname, hash_password(upw), datetime.utcnow().isoformat()))
                        conn.commit()
                        conn.close()
                        st.success(f"User {uname} created.")
                    except sqlite3.IntegrityError:
                        st.error("Username already exists.")
    else:
        st.info("Only admin can manage users and passwords.")

    st.subheader("About the Model")
    st.markdown("""
    This tool implements a practical, company-friendly adaptation of **CISA BOD 26-04: Prioritizing Security Updates Based on Risk** (issued June 10, 2026).

    **Four risk factors used for prioritization:**
    1. **Asset Exposure** — Is the asset publicly reachable from the internet?
    2. **KEV Status** — Is the CVE listed in CISA’s Known Exploited Vulnerabilities Catalog?
    3. **Exploit Automation** — Can an adversary fully automate the exploit path?
    4. **Technical Impact** — Does successful exploitation yield *Total* or *Partial* control?

    Timelines (Critical ≤3 days + triage, High ≤14 days, Medium ≤60 days, Low = next upgrade) are derived from the spirit and publicly described bands of the directive’s Table 1.  
    **Note:** Federal agencies must follow the official directive and Table 1 exactly. This tool is designed for broader organizational use as best-practice guidance.
    """)


# =============================================================================
# Main
# =============================================================================

def main():
    st.set_page_config(
        page_title="BOD Priority Agent",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    init_db()

    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False

    if not st.session_state.authenticated:
        login_page()
        return

    page = sidebar_nav()

    if page == "🏠 Dashboard":
        page_dashboard()
    elif page == "📦 Asset Inventory":
        page_assets()
    elif page == "🔍 Vulnerability Intake":
        page_vuln_intake()
    elif page == "🤖 Run Assessment Pipeline":
        page_pipeline()
    elif page == "📋 Remediation Plans":
        page_plans()
    elif page == "⚙️ Settings & Security":
        page_settings()


if __name__ == "__main__":
    main()
