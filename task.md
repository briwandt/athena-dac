# Task List: Next.js Athena + MITRE Merge

- `[x]` **Phase 1: Create Rules & Port Engines to TypeScript**
  - `[x]` Create `src/data/athena_data.ts` containing the YAML rules, simulated logs, query compiler, validation evaluator, and telemetry gap analyzer.
- `[x]` **Phase 2: Integrate Tabs in Next.js UI**
  - `[x]` Modify `app/page.tsx` to add sidebar tabs (Compiler, Validation Lab, Telemetry Auditor, IR Scoper).
  - `[x]` Implement React components for each tab (rendered dynamically based on `activeTab`).
- `[x]` **Phase 3: Deploy & Verify**
  - `[x]` Stage, commit, and push the merged React project to GitHub.
  - `[x]` Verify that the app builds and deploys successfully on Vercel.

- `[x]` **Phase 4: Implement Detection-as-Code (DaC) Playground**
  - `[x]` Implement client-side Sigma YAML parser `parseYamlRule` in `src/data/athena_data.ts`.
  - `[x]` Add "DaC Playground" workspace tab as default in `app/page.tsx`.
  - `[x]` Integrate dynamic editor to compile SPL and KQL on-the-fly.
  - `[x]` Add JSON log simulator with interactive logic matching evaluation.
  - `[x]` Test and verify zero-warning Next.js local build.
  - `[x]` Push updates to GitHub to trigger Vercel deployment.
