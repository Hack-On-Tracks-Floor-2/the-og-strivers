# Isolated Vulnerability / Risk Analytics dashboard

This branch, `feature/vulnerability-risk-dashboard`, starts at the latest fetched `origin/main`, `b592323`. It selectively applies the six dashboard files introduced by `f602b7b07fc69116086bd89535b8aff49fdeb102`, then removes dependencies on unpublished repair-planning work. The original `feature/ml-repair-intelligence` branch remains at that exact original commit.

Only dashboard UI, read-only frontend aggregation, tests and this documentation are added. No backend, shared contract, model, artifact, dataset, dependency, configuration, scanner, patch generator or regression engine changes are included. Earlier unpublished feature commits are not ancestors of this branch.

## Existing data sources

The existing ML Intelligence page keeps its repository/run selector, original prediction cards/provenance, existing model metrics and Model Playground. It reads the current main branch's authenticated APIs:

- `GET /api/runs` and `/api/repositories` populate the existing selector.
- `GET /api/runs/:id` provides analysis status and repository association.
- `GET /api/runs/:id/ml-findings` provides saved findings and existing Java/Python CWE predictions.
- `GET /api/runs/:id/patches` provides persisted patch candidates and attempt numbers.
- `GET /api/runs/:id/verification` provides proof stages, exit codes, logs/artifact references and executed test summaries.

No new endpoint, database migration, inference call or repair-guidance integration is introduced. Existing reviewer and repository authorization continues to apply. Selecting or refreshing the dashboard performs reads only.

## Dashboard behavior

Six run-scoped cards summarize distinct findings, critical/high severity, verified resolutions, unresolved findings and pending verification. Native SVG/CSS charts show real scanner severity counts and integer CWE rankings. Existing saved classifier output is displayed separately from scanner CWE, with uncalibrated scores and comparison only when both actual CWE predictions exist. JavaScript and TypeScript show No trained CWE model. Valid bounded CWE identifiers link to official MITRE documentation; no CVE identity is inferred.

Patch analytics show eligible verified candidates, failed verification attempts, pending candidates, recorded patch retries and a success rate only when a conclusive denominator exists. The patch-evidence cards link to the existing reviewer inspection and logs.

- Findings are deduplicated by finding ID and filtered to the selected run. Patches must belong to that run and an included finding.
- Verification uses the unchanged main-branch `verificationState()` and shared `stageHasProof()`: every required stage and the final decision need the expected exits, completed logs/artifacts and nonempty executed test summaries. Reproduction correctly fails on the vulnerable source. A status flag, approval or proposal alone is insufficient.
- A verified resolution requires the latest patch attempt for that finding, an eligible non-proposed/non-rejected status and full passing proof. It denotes a tested candidate, not a merge or production deployment.
- Failed verification attempts count distinct patch IDs with a failed latest stage, not failing stages or distinct vulnerabilities. Success rate is eligible verified patches divided by eligible verified plus failed patch attempts. Proposals, pending/incomplete or ineligible records and generation failures are excluded.
- **Recorded patch retries** count unique stored `(findingId, attempt)` pairs beyond attempt one. Missing attempt numbers are not filled in. Generation failures without a patch record are not available on the base APIs and are not counted or inferred.
- Missing auxiliary responses are distinct from successful empty arrays. Dependent metrics show unknown rather than zero, while the original finding and prediction cards remain usable. Zero conclusive attempts yield no percentage.

The original dashboard commit also referenced an unpublished planning schema and endpoint. This isolated version omits that fetch, schema/type dependency, strategy/advice counters and planning-insight section. It shows existing patch verification evidence instead. No missing experimental feature is copied in to make the dashboard compile.

## Included files

1. `apps/web/src/components/ml/RepositoryMLReview.tsx`: extends the existing read-only evidence loader and prediction cards.
2. `apps/web/src/components/ml/MLAnalyticsDashboard.tsx`: overview, charts, patch metrics and proof-evidence cards.
3. `apps/web/src/lib/ml-analytics.ts`: scoped and deduplicated evidence calculations.
4. `apps/web/src/styles/ml-analytics.css`: existing dark/lime theme and responsive layout, without new dependencies.
5. `tests/ui/ml-analytics.test.ts`: ten focused aggregation, proof, language/model, scoping, retry and CWE-link tests.
6. This report.

## Delivery

Validation passed: **43 focused tests** (10 dashboard, 20 existing proof-state, 13 shared contracts), `npm run typecheck`, and `npm run build`. The existing Vite bundle-size warning is nonblocking. The changed-file secret scan found no credentials. The production build rebuilt shared types from main before validation; no stale unpublished schema export is required.

Only `feature/vulnerability-risk-dashboard` is published with a normal single-branch push. Its history contains one dashboard-only commit above `b5923235b67f5354d97bb54e5aacf26e21a8d8a3`; all six changed files are listed above. The original feature branch remains at `f602b7b07fc69116086bd89535b8aff49fdeb102`. No merge, force push or deployment is part of this work. Updating the checked-out local branch does not update the public Vercel site; that requires a separately authorized release.
