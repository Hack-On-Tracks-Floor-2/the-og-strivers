# Automatic repository finding classification

## Scope and actual integration point

This branch builds on `feature/multilang-ml` / `653c6c264d452e877fbe9ad2e86c1d6fe5025b24`. Neither classifier is retrained or modified. The Java/Python model artifacts, preprocessing/training code, scanner implementations, patch generation and regression implementation remain unchanged.

The developer submits a repository through `apps/api/src/routes/index.ts` (`POST /api/repositories`). That creates an analysis run and starts `createPipeline()` when the existing AI/sandbox capability is available. `githubIngestion().ingest()` in `apps/api/src/repositories/clone.ts` clones and audits the repository, records the actual Git commit and removes `.git`. The original workspace is kept separate from patched copies.

In `apps/api/src/pipeline/orchestrator.ts`, immediately after each normalized finding is saved by `saveFinding()`, the pipeline now calls `recordFindingML()` with the original workspace, repository, run and finding. It runs only for recorded findings (currently at most three), not every source file. This occurs after the existing Bandit/sink-search/AI-confirmation stages and before patch generation. ML does not alter detection, supply approval evidence, replace an existing scanner/locator or feed a new signal to Groq.

The hook awaits a bounded classification attempt. Missing models, unsupported language, unknown category, invalid source coordinates, extraction failure, runtime failure, inference timeout or a failed ML-sidecar write leave the original finding available and do not reject the patch/regression workflow. ML availability is deliberately not a verification or approval condition.

## Source selection and inference

`apps/api/src/services/finding-ml.ts::recordFindingML()`:

1. Checks repository/run/owner/workspace association and a real-format commit SHA supplied by ingestion.
2. Determines language from the normalized finding's source-file extension. Only Python and Java invoke a classifier. Unsupported languages get a saved unsupported status without scanning/reading every file.
3. Resolves only the finding's plain source file inside the audited workspace. Absolute paths, traversal, `.git`, symlinks, missing files and source files above 1 MiB are rejected. Reads are bounded and source is never executed by ML.
4. Reuses `enrichScannerFinding()` with bounded source selection: at most 80 lines / 20,000 characters. A complete small file is used when it fits; otherwise the scanner-provided source span is used. A finding that exceeds the bound is not silently truncated to obtain a score. Complete indented Python spans are dedented without changing their original line numbers. Incomplete/poor context may correctly return unknown.
5. Calls the existing `classifySource()` worker/router with the snippet, language and metadata-only file path. The classifier still verifies trusted artifact hashes, chooses only registered models, returns model versions and marks probabilities uncalibrated. No training runs.
6. Bounds the automatic enrichment wait to 15 seconds. The shared worker retains its existing bounded process lifecycle; an attempt already in progress can finish within its existing worker timeout after the automatic caller records unavailable. A busy worker can also cause a nonblocking unavailable sidecar. There is no silent retry or fake prediction.
7. Stores a separate ML sidecar. The original finding object, CWE, severity, scanner confidence and evidence are preserved.

Both models are experimental benchmark classifiers. `BENCHMARK_NEGATIVE` does not clear a scanner finding or prove general safety. The stored scanner CWE is the existing normalized finding's CWE, which this pipeline produces after its existing AI-confirmation step; raw scanner and AI categorization are not reinterpreted by this change.

## Persistence and retrieval

Migration 3 adds `finding_ml`, keyed by the existing finding ID with run/repository/owner foreign keys and a JSON document. It is additive and does not rewrite existing findings or verification data.

`packages/shared/src/intelligence.ts::FindingMLSchema` records:

- Finding/run/repository/owner IDs, canonical submitted repository URL and ingested source commit.
- Source path/language and original finding line range.
- Actual source-file SHA-256 and classified snippet range/hash/character count/transformation when extracted.
- Prediction/status, original normalized CWE, agreement/disagreement, reason and timestamp.
- Real model version, predicted category and uncalibrated probability when the existing classifier returns them.

Source code is not duplicated in the ML table. An existing sidecar is never overwritten on a repeated call. Hashes link the prediction to the captured text; they are provenance fingerprints, not cryptographic execution attestations. The source commit is the ingested original revision, never the repository's later HEAD.

`GET /api/runs/:id/ml-findings` requires an authenticated reviewer. It returns original finding records left-joined with their ML sidecars for that run. Developers and anonymous callers cannot read repository predictions. Older findings without ML return `ml: null`; opening the page never fabricates or lazily computes a result. Because old workspace clones are cleaned up, a new analysis is required to obtain new source-bound predictions for those findings.

## Reviewer interface

`apps/web/src/components/ml/RepositoryMLReview.tsx` is mounted only for reviewers. It reuses the existing repository/run picker, loads stored records and refreshes active analysis runs. It displays source file/lines/language, original CWE/severity, separate ML category/probability/status/model version, source commit and expandable provenance. Disagreement and unsupported/unknown/unavailable states are explicit.

The existing `MLIntelligence.tsx` retains real per-model metrics, model selection, source/version/license information and scope limitations. Manual classification is collapsed under **Model Playground**. Normal repository review needs no manual code paste. The developer's existing model exploration view remains available, without fetching reviewer-only repository findings. `Dashboard.tsx` places **ML Intelligence** immediately above **Patch Inspection** in the reviewer navigation.

## Semgrep and deployment boundaries

Read-only inspection found the available teammate branch `feature/multilanguage-semgrep` at `ff190a0cea67892224e0e62e25d53612da765d90`. It was not merged, checked out over this work, pushed or deployed. Its normalized `Finding`/`DetectedIssue` contract remains compatible with this service, but it adds a separate detection-only path as well as the proof-capable path.

Automatic enrichment is genuinely connected to this branch's existing normalized Python pipeline. Java inference/source association is implemented and tested through the same service, but this base pipeline only ingests through its existing Python+pytest execution path; this change does not expand scanner/runtime support. After a reviewed combination with the teammate branch, call the same `recordFindingML()` helper immediately after `saveFinding()` in **both** its detection-only and proof-capable finding loops. Preserve each branch's scanner limits, test runner and proof gates. Do not claim the unmerged Semgrep/Java runtime path is connected or deployed today.

No production deployment is performed. On the existing Azure backend, a later reviewed ref needs the additive database migration, API/service/router code and the already-trained Java/Python artifacts. The existing Python runtime and pinned requirements remain sufficient; no new language model, service, port or dependency is introduced. Preserve `.data` and production configuration. Deploy the same reviewed frontend ref to Vercel separately for the repository view and navigation. A fresh submitted analysis on the deployed ref is required to populate records. Existing records are not backfilled from a different commit.

## Changed files

- `apps/api/src/database/migrations.ts`: additive `finding_ml` table/index.
- `packages/shared/src/intelligence.ts`: validated stored prediction/provenance contract.
- `apps/api/src/services/ml-enrichment.ts`: exported language inference and optional complete bounded source-span selection/dedenting; default adapter behavior retained.
- `apps/api/src/services/finding-ml.ts`: safe source extraction, genuine inference, provenance and nonblocking persistence.
- `apps/api/src/pipeline/orchestrator.ts`: finding-save hook and classification-status event before patch generation; no proof/regression changes.
- `apps/api/src/routes/index.ts`: reviewer-only stored ML-findings retrieval.
- `apps/web/src/components/ml/RepositoryMLReview.tsx`: repository/run-oriented reviewer display.
- `apps/web/src/pages/MLIntelligence.tsx`: reviewer repository view and secondary Model Playground; evaluation retained.
- `apps/web/src/layouts/Dashboard.tsx`: requested reviewer navigation order.
- `tests/finding-ml.test.ts`: real local Git ingestion, genuine Java/Python predictions, source hashes/commit, dedenting, unsupported/OOD/missing runtime/timeouts, persistence/reopen, legacy and role isolation.
- `tests/pipeline/pipeline.test.ts`: automatic-hook assertions and model-outage continuation, using the existing explicitly simulated AI/sandbox orchestration fixtures. The original regression engine tests remain unchanged.
- `docs/AUTOMATIC_ML_INTEGRATION.md`: this implementation/status/runbook report.

## Validation

Integration tests use actual attributed held-out source and trained classifier inference. Normalized findings and the existing pipeline AI/sandbox doubles are explicitly test fixtures, not production scanner evidence or fabricated model predictions. No evaluation metrics were recomputed or changed.

- `npm test`: **129/129 tests passed across eight files** (191.74 seconds), including 18 new source-bound finding/persistence tests, 21 pipeline tests, the existing real red/green regression test, authentication/role checks, nine ML API tests, 28 existing adapter tests and shared/UI data tests.
- The actual ingested local Git clone's Python source produced CWE-22 using the saved Python model. A bounded Java crypto source region produced CWE-327 using the unchanged Java model. Source commit, file SHA-256, actual snippet SHA-256/range and model version were checked. The attributed source comes from existing held-out benchmark examples; no new training samples or evaluation claims were created.
- Unsupported JavaScript never invokes a classifier. Tests retain original findings on real missing executable errors, unknown/OOD source, oversized/missing/unsafe source, invalid ranges, inference deadlines and simulated sidecar storage outage.
- Tests verify genuine predictions survive reopening the database, legacy records stay explicitly empty, unrelated runs do not acquire those predictions, anonymous callers receive 401 and developer callers receive 403. The existing orchestration reaches its original proof/review state with the ML runtime missing.
- `npm run typecheck --workspaces --if-present` passed. `npm run build` passed for shared/API/frontend. After the final UI guard against stale run selection, `npm run build -w @proofpatch/web` passed again. Vite retains its existing large Monaco chunk warning.
- An isolated loopback QA server used an explicit temporary database and actual saved-model inference. The reviewer browser showed stored Python CWE-22 (90.39% uncalibrated), Java CWE-327 (97.34% on the bounded region), unsupported JavaScript, original file/line/CWE/severity, source commit and model version without pasting code. The sidebar order and collapsed/expandable Model Playground were checked. The page carried an explicit normalized-fixture/real-inference banner; no production scan or proof was claimed.
- `git diff --check` passed. Git confirms both complete classifier directories, scanner implementations, patching modules and verification modules are unchanged from `653c6c2`. The only orchestrator behavior added is the pre-patch finding-enrichment hook/status event.
- Secret scan checked all 12 changed/new project files. No exposed secrets were found. One inherited unit-test password and one new ephemeral `example.test` account password were identified as test-only fixtures in isolated test databases. QA launchers/screenshots, temporary repositories/databases, build output and local configuration are excluded from the commit.

These results describe the automatic-ML checkpoint before combining any newer teammate branch. No push, merge or deployment was part of that checkpoint.
