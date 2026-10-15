# PatchProof UI overhaul

Implemented on `feature/ui-overhaul`, starting from `main` at `940a8db` (the full-pipeline merge). All application changes are in the frontend. Authentication, shared contracts, database migrations, detection, AI providers, repository ingestion, patch generation, and Docker verification are unchanged.

## Source inspection

`apps/web/src/components/code/DiffViewer.tsx` and `MonacoWorkspace.tsx` provide the reusable comparison for both portals. The vocabulary is **Current source** and **Proposed revision**. Source snapshots come directly from `Patch.files[].original` and `.proposed`; the optional unified view preserves `Patch.unifiedDiff` exactly.

The editor includes synchronized comparison, change alignment, resizable columns, collapsed unchanged regions, line numbers, syntax highlighting, horizontal scrolling, fullscreen, copy controls, recorded patch export, a multi-file selector, and generated security-test source. Empty file snapshots remain empty. Unsupported source types fall back to plain text; unavailable snapshots offer the recorded diff. At widths below 850px, source tabs replace the split editor. Code is read only at 14px with 23px line height.

Monaco and its editor/JSON workers are bundled locally. No source code is sent to an editor CDN. Monaco is loaded only when a comparison is opened; chart code is also lazy loaded. The editor chunk is larger than Vite's default size threshold, so the production build reports a size warning. Its initial compressed size is approximately 730 KB, separate from the normal application entry; JSON language support is another on-demand chunk.

`components/patches/PatchWorkspace.tsx` combines repository and finding context, recorded commit, patch attempt, file statistics, rationale, and a six-stage evidence summary. Review state is displayed independently of automated checks. Evidence is matched by both run and patch IDs, with the latest record selected for each stage.

## Intelligence and review workflow

- `features/intelligence/` supplies the repository/run-scoped overview and the repository detail dashboard. Recharts renders actual category counts and shares, severity counts, finding lifecycle counts, and elapsed run history when at least two settled runs exist. Legends and chart selections link to filtered findings.
- `lib/security-data.ts` holds normalization, distinct-ID counting, recorded metadata extraction, Git-hunk line statistics, and conservative evidence-derived statuses. A reviewer approval cannot turn missing execution evidence into a passing result. Empty/all-skipped suites are never counted as verified.
- `pages/Artifacts.tsx` connects scoped findings, Patch Studio, and Evidence Rail. Finding filters include search, category, severity, and workflow state. Patch and finding IDs are retained in navigation.
- `pages/Reviews.tsx` adds queue search, category/severity/repository/verification filters, date/severity sorting, contextual inspection, inline logs, rationale validation, explicit decision confirmation, and searchable decision history. Approval requires complete passing evidence in the interface and remains subject to the existing backend guard. Rejection remains available with incomplete execution evidence once the run context loads.
- `components/artifacts.tsx` exposes expandable chronological evidence with commands, logs, exit codes, durations, test totals, individual outcomes, trace references, and available artifact downloads. Reproduction explains why the security test is expected to fail against the current source. Skipped tests have an explicit skipped state.
- `styles/workspace.css` contains workspace-specific typography, chart, comparison, evidence, review, and responsive styles. Secondary text uses `#A4A4AA`. The original public two-portal homepage composition is preserved.

## Data provenance and contract gaps

The production interface contains no seeded findings, patches, chart percentages, model metrics, or test results. A run with unavailable execution is identified as missing analysis evidence, never as a clean assessment.

The current API does not provide the following structured fields:

- Reviewer-visible repository names/URLs or reviewer assignments. Reviewers see stable repository ID references; the frontend does not call the developer-only repository endpoint.
- A dedicated review-submission timestamp. The queue labels and sorts the actual patch `updatedAt` as **Last updated**, with its creation timestamp available on the date tooltip.
- A structured analyzed commit SHA, source-search file count, or complete mapping result on a run. Where available, these are extracted only from the existing orchestrator messages `Cloned at commit …`, `Search funnel: … source files`, and `Mapped: … · test command …`. Otherwise they are shown as not recorded. Structured fields would remove this dependency on message formats.
- Language byte counts or comparable weights. Detected language/framework names are displayed without invented shares.
- Dedicated analysis completion timestamps/durations. The history chart explicitly uses creation-to-last-settled-update elapsed time, including failed attempts. It does not claim CPU time or reconstruct an unavailable historical finding trend. The latest completed-analysis metric uses runs ready for review or verified.
- A separate finding title, structured standalone reviewer comments, or a request-changes API action. The queue uses recorded CWE/category and source path; the decision rationale is the supported review note. Only existing approval/rejection actions are offered.

Older execution records may lack parsed test summaries or a final verification decision. Their recorded stages remain inspectable, but the stricter overview does not label the patch checks verified. Verification remains a bounded claim about available evidence, separate from human approval.

## Validation

- Full workspace build, including the unchanged API and shared package.
- Full Vitest suite, including frontend evidence-state, metadata, normalization, distinct-ID, and Git-diff edge-case tests in `tests/ui/security-data.test.ts`.
- Browser verification of the existing local reviewer demo sign-in and honest empty states.
- Populated desktop (1366×768) and mobile (390×844) checks using a separate, clearly labeled in-memory QA database and a separate loopback hostname. No synthetic records were inserted into the user's database. Checks cover chart-to-finding filtering, review queue filters, comparison modes, multiple files, empty/unsupported source, copy, fullscreen, source tabs, evidence disclosures, skipped-test presentation, confirmation/cancellation, and recorded test-only review history.
- Production output checked for local demo credential leakage; candidate/staged project files scanned for secrets before committing.

The local real pipeline currently reports no configured AI provider/sandbox. UI fixtures exercise presentation and interaction only; they do not demonstrate live security analysis or execute repository tests. Existing pipeline integration tests use their isolated test adapters.
