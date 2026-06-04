# Project Athena: Modern Detection-as-Code & Validation Lab

🛡️ **Project Athena** is a complete, enterprise-grade **Detection-as-Code (DaC) & Validation Framework** built specifically to address the modern challenges of engineering and operationalizing threat detection rules across on-premises and cloud infrastructures.

This repository serves as a technical showcase for an enterprise threat detection engineering environment, demonstrating proficiency in platform-independent detection design (Sigma schema), translation compilers (Splunk SPL and Sentinel KQL), automated purple-team validation testing, log stream telemetry auditing, and rapid incident scoping query generation.

---

## ✨ Features

1. **Rule Registry & DaC Pipeline**:
   - Parses platform-agnostic detection rules written in structured YAML.
   - Enforces metadata compliance (validates UUIDs, severity ratings, MITRE ATT&CK tags, and log sources).
   - Programmatically compiles detections into **Splunk SPL** and **Microsoft Sentinel KQL** queries.
   - Generates production-ready configurations: Splunk `savedsearches.conf` files and Sentinel ARM template definitions.

2. **Simulation & Validation Lab (Purple Teaming)**:
   - Contains high-fidelity simulated telemetry datasets in JSON (containing both malicious adversarial events and benign developer/system noise).
   - Simulates query execution by evaluating rule logic against log records.
   - Calculates key detection performance indicators (KPIs): **Precision**, **Recall**, and **F1-Score**.
   - Generates interactive Confusion Matrices and lists logging adjustments needed to tune out false positives.

3. **Telemetry & Log Quality Audit**:
   - Analyzes log records for completeness and schema sanity.
   - Rates telemetry quality using a health score indicator (0-100%).
   - Flags missing critical fields (e.g. Sysmon `CallTrace` or Active Directory `TicketEncryptionType`).
   - Recommends explicit Group Policy Objects (GPOs), Sysmon configs, and cloud diagnostic policies to resolve telemetry gaps.

4. **Incident Response Scoper**:
   - Instantly generates index-optimized, time-bounded scoping queries based on active indicators of compromise (Hostnames, IPs, Usernames, File Hashes) to accelerate incident triaging.

5. **Stunning Web Dashboard**:
   - A highly polished Streamlit application providing a glassmorphic dark-mode web user interface to interact with and present all features.

---

## 📂 Repository Structure

```text
├── README.md                      # Project introduction and operational guide
├── requirements.txt               # Python package dependencies
├── app.py                         # Streamlit web dashboard application
├── core/
│   ├── rule_parser.py             # Schema validator and rule registry parser
│   ├── translator.py              # Sigma-to-SPL and KQL translation engine
│   ├── validator.py               # Rule simulation and validation metrics calculator
│   └── gap_analyzer.py            # Log schema auditor and GPO recommendations engine
├── rules/                         # Detection rules registry (YAML format)
│   ├── endpoint_lsass_dump.yaml       # Credential Dumping (MITRE ATT&CK T1003.001)
│   ├── identity_kerberoasting.yaml    # AD Kerberoasting (MITRE ATT&CK T1558.003)
│   ├── cloud_entra_malicious_app.yaml # OAuth App Consent Phishing (MITRE ATT&CK T1528)
│   ├── cloud_aws_privesc.yaml         # AWS IAM Credential Persistence (MITRE ATT&CK T1098)
│   └── network_dns_tunneling.yaml     # DNS Tunneling & Exfiltration (MITRE ATT&CK T1048.003)
└── telemetry/                     # Simulated logs containing attack and baseline events
    ├── sysmon_lsass_dump.json
    ├── security_kerberoasting.json
    ├── entra_consent_grant.json
    ├── aws_cloudtrail_privesc.json
    └── dns_query_logs.json
```

---

## 🚀 Quick Start & Operations

### Prerequisites
- Python 3.8 or higher
- pip package manager

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Launch the Streamlit Dashboard
```bash
streamlit run app.py
```
*The dashboard will run locally at `http://localhost:8501`. A public HTTPS tunnel is currently active at [https://inherited-genetic-flu-disposal.trycloudflare.com](https://inherited-genetic-flu-disposal.trycloudflare.com).*

---

## 🛡️ Showcased Threat Scenarios

- **Sysmon LSASS dump**: Evaluates Sysmon Event ID 10 process access logs targeting LSASS with dumping access rights (like `0x1010` and `0x1F1F`), filtering out SVCHost and Windows Defender.
- **Active Directory Kerberoasting**: Examines Kerberos Ticket requests (Event ID 4769) requesting weak RC4 (`0x17`) service tickets, filtering out machine accounts (`*$`) and domain controllers (`krbtgt`).
- **Entra ID Malicious App Consent**: Identifies Azure AD administrative consent grants to multi-tenant applications requesting high-privilege scopes like `Mail.ReadWrite` and `Directory.AccessAsUser.All`.
- **AWS Key Persistence**: Tracks programmatically generated static AWS Access Keys (`CreateAccessKey`) from untrusted roles, filtering out Okta SSO sessions and Terraform deployments.
- **DNS Tunneling**: Highlights DNS query telemetry where record requests exceed `80` characters, filtering out common CDNs like Cloudflare and Akamai.
