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

- `[x]` **Phase 5: Integrate Palantir ADS Framework Specs**
  - `[x]` Populated Rules Database tab with interactive Project Athena rules registry.
  - `[x]` Implemented Palantir Alerting and Detection Strategy (ADS) Spec panels mapping Goal, Categorization, False Positives, Playbooks, and Assumptions.
  - `[x]` Tested Next.js production compilation and pushed to GitHub for automated Vercel deployment.

- `[x]` **Phase 6: Heuristic Resilience Analyzer & Axioms Workspace**
  - `[x]` Implement `analyzeRuleResilience` logic engine in `src/data/athena_data.ts`.
  - `[x]` Add `📐 Resilience & Axioms` tab button in the sidebar of `app/page.tsx`.
  - `[x]` Add custom Sigma rule editor and pre-built rule selector in the new workspace.
  - `[x]` Implement the visual 3D-styled Pyramid of Pain stack layout in CSS.
  - `[x]` Implement the 10 operational axioms carousel cards feed.
  - `[x]` Add Resilience Score columns and badges to the main Rules Database table.
  - `[x]` Compile local Next.js build and verify zero warnings.
  - `[x]` Deploy updates to GitHub to sync Vercel.

- `[x]` **Phase 7: Threat Intel to Detection Lab (KQL, YARA, SPL)**
  - `[x]` Define Threat Intel Advisories dataset and simulation engines in `src/data/athena_data.ts`.
  - `[x]` Import new structures and declare report selection states in `app/page.tsx`.
  - `[x]` Add `📝 Threat Intel to Detection Lab` sidebar button.
  - `[x]` Implement report text renderer, YARA/KQL/SPL rule views, and construction guides in `app/page.tsx`.
  - `[x]` Implement interactive evaluation simulators (YARA scanner, KQL log runner, SPL search filters) in `app/page.tsx`.
  - `[x]` Test local Next.js build and verify zero warnings.
  - `[x]` Commit changes and push to GitHub to sync Vercel.

- `[x]` **Phase 8: Write, Add & Evaluate Custom Detections**
  - `[x]` Initialize dynamic component states for rules registry and telemetry datasets in `app/page.tsx`.
  - `[x]` Add "Write New Detection" button in the Rules Database registry header linking to the playground editor.
  - `[x]` Add "Register & Deploy to Active Rules Registry" button in the DaC Playground to parse, validate, and append custom rules.
  - `[x]` Add log simulation capture to automatically build matching mock logs for custom rules.
  - `[x]` Implement the interactive "Edit Test Dataset" JSON editor inside the Simulation & Validation Lab.
  - `[x]` Test local Next.js build and verify successful compilation.
  - `[x]` Push code updates to Vercel to deploy the new features.

- `[x]` **Phase 9: MITRE ATLAS Framework Integration**
  - `[x]` Implement AI/ML TTP Matrix representing the core tactics (AML.TA) and techniques (AML.T) defined in the ATLAS framework.
  - `[x]` Support toggling between Enterprise ATT&CK and AI ATLAS matrices in the Campaign Heatmap tab.
  - `[x]` Register simulated LLM Prompt Injection and Model Extraction attack campaign.
  - `[x]` Deploy a functional prompt injection Sigma rule that compiles to SPL/KQL and passes validation with simulated datasets.
  - `[x]` Add customized heuristic resilience evaluations for ATLAS and LLM security rules.
  - `[x]` Test local Next.js build and verify zero errors.
  - `[x]` Push updates to main to synchronize Vercel.
