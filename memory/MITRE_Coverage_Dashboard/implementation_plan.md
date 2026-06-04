# MITRE ATT&CK Coverage & Log Mapping Dashboard Implementation Plan

This plan outlines the design and building of a highly interactive, premium-grade single-page dashboard designed for a cybersecurity portfolio. It showcases how security teams can map raw logs to MITRE ATT&CK tactics, detect coverage gaps, highlight blind spots, and run gap analysis using realistic synthetic threat campaigns.

## User Review Required

> [!IMPORTANT]
> **Directory Setup:** The application will be created in a new subdirectory: `C:\Users\user\.gemini\antigravity\scratch\attack-coverage-dashboard`. 
> You should open this folder as your active workspace in your editor once approved.

> [!IMPORTANT]
> **Simulated Gaps, Blind Spots, and Remediation:**
> To showcase your skills to hiring managers, the dashboard will explicitly display **what the gaps/blind spots are** and **how to fix them** directly on the web page.
> *   **Simulated Blind Spot:** Lateral Movement (T1021.006) using WinRM. The UI will show a warning: *"Zero telemetry captured for Remote Management execution on target host CORP-DC-01."*
> *   **Simulated Gap:** Command Execution (T1059.001) via PowerShell. The UI will show: *"Command execution captured, but Script Block Logging (Event 4104) is disabled, obscuring obfuscated commands."*
> *   **Actionable Remediation (How to Fix):** Each gap and blind spot will feature a click-to-expand card showing the exact GPO setting, registry keys, or command to run to resolve the telemetry issue.

## Proposed Changes

We will create a structured project inside the scratch directory:
- `attack-coverage-dashboard/`
  - `index.html` (markup)
  - `styles.css` (design system, dark mode, animations)
  - `app.js` (logic, matrix rendering, log parsing, gap calculator)
  - `campaigns.js` (multiple preloaded, highly realistic threat campaigns)

---

### UI/UX Design System (CSS)
*   **Theme:** Deep Cyberpunk / Slate Dark mode (Deep Slate background, glassmorphism card interfaces, and neon glow accents).
*   **Harmonious Color Palette:**
    *   Background: `#0A0D16` (Deep Navy-Slate)
    *   Card Surface: `rgba(16, 20, 35, 0.65)` with `backdrop-filter: blur(12px)` and a subtle `border: 1px solid rgba(255, 255, 255, 0.08)`
    *   Active/Alert: `#10B981` (Emerald Green)
    *   Partial Coverage/Warning: `#F59E0B` (Amber)
    *   Blind Spot/Gap: `#EF4444` (Vibrant Rose-Red)
    *   Text: High-contrast Off-White (`#F3F4F6`) and Muted Grey (`#9CA3AF`)
*   **Typography:** Google Fonts **Outfit** for sleek headers and **JetBrains Mono** for log readouts.
*   **Animations:** Smooth hover scaling, glowing button accents, and transition fades when expanding log entries.

---

### Dashboard Features (JavaScript)

#### 1. Dynamic MITRE ATT&CK Matrix
*   Renders a modular grid representing core ATT&CK tactics (Initial Access, Execution, Persistence, Privilege Escalation, Credential Access, Lateral Movement, Exfiltration).
*   Each cell dynamically updates its styling (Fully Covered / Partial / Blind Spot / Inactive) based on the currently selected log dataset.
*   Clicking a technique cell filters the log timeline to highlight events mapping to that specific technique.

#### 2. Interactive Log Timeline Viewer
*   Displays a chronological list of log entries in the threat campaign.
*   Shows a summary header for each log: timestamp, host, event type, and action.
*   Includes collapsible log panels: Clicking a log expands it into a fully formatted JSON viewer with syntax highlighting.
*   Incorporates **MITRE Technique Badges** containing links that connect the log file to the matrix.

#### 3. Gap & Blind Spot Remediation Panel (New)
*   Displays real-time metric counters: **Total Techniques Evaluated**, **Detections Configured**, **Identified Gaps**, and **Unmonitored Blind Spots**.
*   **Remediation Diagnostics Card:** For every gap or blind spot identified in the active log set, it renders a detailed alert card with:
    1.  **Detection Gap:** Description of the missing telemetry or visibility issue.
    2.  **Impact:** Which MITRE ATT&CK technique is unmonitored because of this.
    3.  **Remediation (How to Fix):** Code snippets, command lines, or specific GPO policies to enable (e.g., `AuditProcessCreation`, `ScriptBlockLogging` enable command).

#### 4. Campaigns & Custom Log Uploader
*   Allows the user to toggle between pre-loaded scenarios:
    1.  **APT29 Spearphishing Campaign** (Active logs showcasing initial entry to exfiltration).
    2.  **Ransomware Simulation** (Shadow copy deletion, local discovery, encryption).
    3.  **Cloud Access Violation** (M365/AWS credential theft and data exfiltration).
*   Includes a **Log Upload / Paste** feature where a user can paste their own JSON logs to parse and map them in real-time.

---

### [NEW] [index.html](file:///C:/Users/user/.gemini/antigravity/scratch/attack-coverage-dashboard/index.html)
Main application frame, structured layout including Sidebar Navigation, MITRE Matrix Grid, Log Timeline panel, and Gap Recommendation console.

### [NEW] [styles.css](file:///C:/Users/user/.gemini/antigravity/scratch/attack-coverage-dashboard/styles.css)
The design system, custom scrollbars, animations, responsive media queries, and glassmorphic card stylings.

### [NEW] [campaigns.js](file:///C:/Users/user/.gemini/antigravity/scratch/attack-coverage-dashboard/campaigns.js)
Multiple raw synthetic datasets (including our APT29 and Ransomware log campaigns) formatted in standard ECS.

### [NEW] [app.js](file:///C:/Users/user/.gemini/antigravity/scratch/attack-coverage-dashboard/app.js)
State management, UI rendering code, interactive events, click handlers, JSON parser, and gap analysis algorithms.

---

## Verification Plan

### Manual Verification
1.  Verify the application page runs correctly by launching a local dev server (using Python or Node) or opening the file directly.
2.  Test all interactive states:
    *   Toggling between different Threat Campaigns updates both the MITRE matrix and the timeline.
    *   Clicking a log expands the detailed JSON view with clean indentation.
    *   Clicking a MITRE badge in a log highlights the respective matrix cell.
    *   Clicking a technique in the MITRE matrix highlights the associated log entry in the timeline.
    *   Testing log upload with customized JSON inputs.
