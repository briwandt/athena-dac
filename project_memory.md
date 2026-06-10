# Project Athena & MITRE ATT&CK Integration: Technical Memory

This document acts as a persistent memory and blueprint for the **Athena Detection-as-Code (DaC) & MITRE ATT&CK Integration** platform. It consolidates the architecture, data structures, deployment steps, and environmental configurations.

---

## 🚀 Key URLs & Repositories

- **Deployed URL**: [https://athena-dac.vercel.app/](https://athena-dac.vercel.app/)
- **GitHub Repository**: [https://github.com/briwandt/athena-dac.git](https://github.com/briwandt/athena-dac)
- **Local Workspace**: `c:\Users\user\Documents\AntiGravity\detection engineering`

---

## 🏗️ Architecture & Core Components

```
c:\Users\user\Documents\AntiGravity\detection engineering\
├── app/
│   ├── layout.tsx            # Next.js Root Layout
│   └── page.tsx              # Sidebar Tab Router, Matrix Renderer, and DaC Playground
├── src/
│   └── data/
│       ├── campaigns.ts      # Campaigns (APT29, LockBit, Cloud Abuse, AD Escalation, DNS Tunneling)
│       ├── athena_data.ts    # YAML parser, SIEM query compilers, evaluation engines, audit rules, threat intel datasets
│       ├── elastic_detections.json # Ingestion database of static rules
│       └── telemetry_inventory.json # Ingestion status tracking of SIEM feeds
```

---

## 🛠️ Feature Matrix & Logic Flows

### 1. MITRE ATT&CK Matrix Triage
- **Tactic Matrix**: Renders a dynamic 12-column tactic header mapped to specific attack IDs and techniques.
- **Heatmap Coverage**: Highlights logs dynamically using colour coding:
  - `emerald-500` (Fully Covered)
  - `amber-500` (Telemetry Gap)
  - `rose-500` (Blind Spot)
  - `slate-950` (Unmonitored)

### 2. Live SIEM Compiler
- Maps rules from the dynamic active rules registry (`registeredRules` state, initialized with static `RULES`) or live inputs.
- Appends appropriate index headers based on mapping types:
  - `endpoint:windows:sysmon` -> `index=ep_sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"` / `SysmonEventLogs`
  - `identity:active_directory:security` -> `index=ad_security sourcetype="WinEventLog:Security"` / `SecurityEvent`
  - `cloud:azure_entra:auditlogs` -> `index=cloud_entra sourcetype="azure:aad:audit"` / `AuditLogs`
  - `cloud:aws:cloudtrail` -> `index=aws_cloudtrail sourcetype="aws:cloudtrail"` / `AWSCloudTrail`
  - `network:dns:queries` -> `index=net_dns sourcetype="infoblox:dns"` / `DnsEvents`

### 3. Emulation & Validation Lab
- Evaluates detection rules against mock logs.
- Features an **Interactive Test Suite Editor** (`datasetJsonText` state) allowing users to modify or expand the list of benign/malicious logs dynamically.
- Measures and calculates:
  - **Precision**: $TP / (TP + FP)$
  - **Recall**: $TP / (TP + FN)$
  - **F1-Score**: $2 \times \frac{Precision \times Recall}{Precision + Recall}$
  - **Confusion Matrix**: Visual 2x2 grid (TP, FP, FN, TN).

### 4. Telemetry Health Auditor
- Compares user-supplied JSON payloads against structural logging requirements (`TELEMETRY_REQUIREMENTS`).
- Validates the presence of crucial auditing components (e.g. `CallTrace` for LSASS access or `TicketEncryptionType` for AD Kerberoasting) and computes a health percentage.

### 5. IR Fast Scoper
- Converts comma-separated lists of hostnames, IPs, user accounts, and SHA-256 file hashes into index-optimized, time-bounded query templates.

### 6. Interactive DaC Playground
- **Client-Side YAML Parser**: Custom stack-based line parser (`parseYamlRule`) built directly in TS to map indentation-heavy Sigma YAML formats to rule objects without external packages.
- **Log Simulator**: Evaluates real-time custom YAML rules against custom JSON log payloads in the browser.
- **Rules Deployment Registration**: Deploys the rules directly to the active components via React state handlers.

### 7. Palantir ADS Integration
- **Alerting & Detection Strategy (ADS) Spec**: Renders comprehensive documentation mapping including Goal, Categorization, Known False Positives, Incident Response steps, and Assumptions directly in the Rules Database tab.

### 8. Heuristic Resilience Auditor & Operational Axioms Workspace
- **Pyramid of Pain Rule Auditor**: Classifies Sigma rule resilience into *Fragile* (Scores 1-3: Hash, IP, Domain Name), *Moderate* (Scores 4-5: Host/Network Artifact, Tools), and *Resilient* (Score 6: TTPs / Behaviors) with actionable optimization advice.
- **3D Pyramid visual stack**: A tilted 3D CSS container that highlights the audited rule's layer (e.g. glowing green for TTP, glowing red for Hash).
- **Operational Axioms Feed**: A card carousel slide showing 10 personal hot-takes/axioms from the core document (e.g. Intent Understanding, Feedback Loop, Breaks Inevitability, Simplicity Wins) for engineering interview prep.
- **Rules Database Resilience Badge**: Dynamic badges mapped to rule records in the active registry.

### 10. MITRE ATLAS Integration (AI/ML TTP Matrix)
- **ATLAS Schema Mappings**: Maps `AML.TA####` tactic IDs and `AML.T####` technique IDs to enable high-fidelity security coverage tracking for LLM API and deployment environments.
- **Dynamic Matrix Layout**: Adjusts responsive grid columns (`grid-cols-9` vs `grid-cols-12`) and minimum widths depending on the active matrix selection (`enterprise` vs `atlas`).
- **AI Rule Profiler**: Automatically assesses LLM prompt injection and application filters, generating specific remediation guidance and profiling rules on David Bianco's Pyramid of Pain under the `Network Artifact` category.

---

## 💻 Environment & Shell Scripting Cheat Sheet

To run local builds and tests, Node.js must be explicitly appended to the powershell session PATH:

### 1. Build Verification
```powershell
# Append Node binary directory and project binaries to path
$env:PATH += ";C:\Program Files\nodejs;c:\Users\user\Documents\AntiGravity\detection engineering\node_modules\.bin"

# Trigger compilation
npm run build
```

### 2. Git Synchronization
```powershell
git commit -am "Commit message here"
git push origin main
```
Vercel listens to pushes on the `main` branch to trigger builds automatically. If type mismatches occur, the build will fail or Vercel will fall back to serving the last successful static deployment. Always verify builds locally first.
