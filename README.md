# BOD Priority Agent

**Risk-based vulnerability prioritization pipeline inspired by CISA BOD 26-04**

A simple, secure, user-friendly Streamlit application that helps organizations build priority-based security assessments and remediation plans. It adapts the four-factor model from CISA’s Binding Operational Directive 26-04 (*Prioritizing Security Updates Based on Risk*, June 10, 2026) for practical company use.

## Key Features

- **Controlled access** – Username/password authentication
- **Secure data storage** – Proprietary system configurations and security controls are encrypted at rest (Fernet / AES)
- **Automated KEV enrichment** – Pulls the live CISA Known Exploited Vulnerabilities Catalog
- **Four-factor risk scoring**:
  1. Asset Exposure (publicly reachable?)
  2. KEV Status
  3. Exploit Automation
  4. Technical Impact (Total vs Partial control)
- **Clear priority tiers & timelines**:
  - Critical → ≤ 3 calendar days + forensic triage
  - High → ≤ 14 days
  - Medium → ≤ 60 days
  - Low → next system upgrade
- **Agentic pipeline** – One-click re-score of all open items and plan generation
- **User-friendly interface** – Dashboard, asset inventory, vulnerability intake, remediation plans, and exports (CSV + executive summary)

## Quick Start

```bash
# Clone or unpack the repository
cd bod-priority-agent

# Install dependencies
pip install -r requirements.txt

# Run the application
streamlit run app.py
```

Open the URL shown in the terminal (usually http://localhost:8501).

**Default credentials** (change immediately after first login):

| Username | Password     |
|----------|--------------|
| `admin`  | `ChangeMe123!` |

## Project Structure

```
bod-priority-agent/
├── app.py              # Main Streamlit application
├── requirements.txt    # Python dependencies
├── README.md           # This file
├── .gitignore          # Git ignore rules
└── secure_data/        # Created at runtime (encrypted DB + key)
    ├── bod_agent.db
    └── .key
```

## Security Notes

- All proprietary **configuration notes** and **security controls** are encrypted at rest.
- Access is gated by hashed passwords.
- The only external network call is a read-only fetch of the public CISA KEV JSON feed.
- Designed for internal / single-host deployment. For production use, add proper identity provider (SSO), TLS termination, and regular backups of the `secure_data/` directory.
- Never commit the `secure_data/` folder or the encryption key to version control.

## How Prioritization Works

The decision logic approximates the publicly described bands of BOD 26-04 Table 1:

| Scenario (simplified)                                      | Tier     | Timeline              |
|------------------------------------------------------------|----------|-----------------------|
| Exposed + KEV + (Total impact **or** Automatable)          | Critical | 3 days + forensic triage |
| Exposed + KEV (remaining cases)                            | High     | 14 days               |
| Other high-impact / KEV combinations                       | High/Med | 14–60 days            |
| Low exposure + weak exploit signals                        | Low      | Next system upgrade   |

When a factor is marked “Unknown”, the agent treats it conservatively (higher urgency).

**Note:** Federal Civilian Executive Branch agencies must follow the official directive and Table 1 exactly. This tool is intended as organizational best-practice guidance.

## Recommended Workflow

1. Log in and immediately change the admin password.
2. Add assets and carefully mark public exposure status.
3. Ingest vulnerabilities (link CVEs to assets; supply Automatable / Technical Impact when known).
4. Run the **Assessment Pipeline** to enrich with live KEV data and assign priorities.
5. Review **Remediation Plans**, download tiered CSVs or the executive summary, and assign owners.
6. Re-run the pipeline after new vulnerability scans or major KEV catalog updates.

## Disclaimer

This project is an independent, open implementation inspired by publicly available CISA guidance. It is **not** an official CISA product. Always validate critical remediation decisions against the current official BOD 26-04 text, Implementation Guidance, and your organization’s risk management framework.

## License

MIT License – feel free to adapt for internal use or further development.

## Future Extension Ideas

- Full automated Vulnrichment / SSVC parsing from CVE records
- Direct integration with vulnerability scanners or CMDB APIs
- SSO / multi-tenant support
- Export to GRC / eMASS platforms
- Scheduled pipeline runs
