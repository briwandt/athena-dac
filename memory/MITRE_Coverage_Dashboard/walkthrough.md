# Next.js Integration Walkthrough: MITRE ATT&CK Coverage Dashboard

We have successfully integrated all design and functional improvements directly into your Next.js application repository located at `C:\Users\user\attack-coverage-agent`.

Hiring managers viewing your personal portfolio will now see a fully interactive, stateful SIEM coverage dashboard.

---

## Codebase Modifications

1.  **[campaigns.ts](file:///C:/Users/user/attack-coverage-agent/src/data/campaigns.ts) [NEW]:**
    Created a TypeScript file containing 3 high-fidelity synthetic threat scenarios (APT29 Spearphishing, LockBit Ransomware, and Entra ID Cloud Access Abuse) with schema-aligned event logs, custom visibility gap reasons, and step-by-step GPO/PowerShell remediation guidelines.
2.  **[page.tsx](file:///C:/Users/user/attack-coverage-agent/app/page.tsx) [MODIFY]:**
    *   Overwrote the main routing entrypoint with a stateful client-side React page (`"use client"`).
    *   Designed a multi-tabbed layout:
        *   **Coverage Sandbox:** Displays the 12-column scrollable MITRE Heatmap, log timeline, and gap advisor.
        *   **Rules Database:** Integrates your original ingested rule parser (`elastic_detections.json`).
        *   **Telemetry Inventory:** Integrates your original active/missing telemetry inventory list (`telemetry_inventory.json`).
    *   Coded **bi-directional click events** (Badge-to-Matrix cell scroll, and Matrix-to-Timeline log expand & scroll).
    *   Created a JSON color-coded syntax highlighter inside React.
    *   Engineered a **Log Upload Modal** that dynamically parses uploaded/pasted JSON log arrays and updates metrics, heatmap cells, and remediations.

---

## Local Verification & Deployment

Since Vercel builds your Next.js site directly in the cloud, you can deploy these changes instantly to your live URL.

### 1. Verification (Check Git changes)
Verify that the files have been modified correctly by running `git status` in the repository root `C:\Users\user\attack-coverage-agent`:
*   `modified:   app/page.tsx`
*   `untracked:  src/data/campaigns.ts`

### 2. Live Deployment (Vercel)
To update your website (`https://attack-coverage-agent-git-main-brianna-wandt-s-projects.vercel.app/`), open a terminal in `C:\Users\user\attack-coverage-agent` and push your changes to your Git remote (which triggers Vercel's automatic deploy pipeline):

```powershell
# Stage all changes
git add .

# Commit changes
git commit -m "feat: integrate premium interactive MITRE matrix, log timeline, and gap remediation diagnostics"

# Push to your main branch (triggers Vercel cloud build automatically)
git push origin main
```

Once pushed, Vercel will build the Next.js bundle and deploy the new interactive dashboard to your live URL.
