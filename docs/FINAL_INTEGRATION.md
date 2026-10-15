# Final ML and regression integration

## Available application routes

Both Developer and Security Reviewer dashboards expose **ML Intelligence** (`/:role/app/ml`) and **Regression Verification** (`/:role/app/regression`). Aditya's developer/reviewer access split is preserved: developers submit repositories and can inspect the classifier and recorded reference scenario; repository findings, patches, private evidence and Merge remain reviewer-only. Existing Patch Inspection remains intact and links a selected patch to its scoped regression evidence and corresponding finding. The recorded regression reference fixture also opens its actual source snapshots in the same comparison editor at `/reviewer/app/patches?reference=regression`.

The comparison vocabulary remains **Current source / Proposed revision**. No model was retrained during integration. No detector, patch generator, verification algorithm, or existing review capability was removed or replaced.

## Actual inference

- Authenticated `GET /api/ml/model-info` reads the saved evaluation, metadata, and artifact hashes. Statistics are not hardcoded into the frontend.
- Authenticated `POST /api/ml/classify` accepts `{ "code": "Java source text", "language": "java" }`. It returns the saved classifier's genuine category and uncalibrated probability, with a model version derived from the model hash.
- Authenticated `GET /api/ml/example` provides the actual, attributed held-out Java example for the demonstration button.
- A persistent Python subprocess loads the trusted committed model/vectorizer once. Submitted code is JSON input to TF-IDF; it is never executed. No caller-supplied model path, executable, or command is accepted. Artifact hashes are checked before loading. Input, concurrency, request rate, startup time, and inference duration are bounded.
- Unsupported declared languages return `status: unsupported`. Insufficient context and low-probability predictions return unknown; missing runtime/dependencies/artifacts return an explicit service error.

The model/vectorizer are approximately 90 KB together and are included in Git for deployment. Downloaded data and local Python dependencies stay ignored. The original dataset license, held-out example notice, pinned dataset revision, real evaluation, and split manifest are retained under `ml/mini_classifier/`.

## Genuine regression evidence

The existing authenticated `/api/regression-demo/evidence` endpoint supplies the executed reference scenario. This integration only adds actual recorded source snapshots when they are available; it does not rerun or alter the regression engine. The page displays baseline, expected failing reproduction, recorded patch application, post-patch security tests, unchanged functional-suite results, raw execution logs, and the backend verdict.

Reference-fixture evidence is explicitly separate from user repository verification and ML predictions. Repository/patch selections use the original run-scoped evidence API. Missing records are shown as **Not executed** or incomplete; skipped suites are not passing proof.

## Runtime and deployment

The owner identified the existing backend as Azure VM **proofpatch-api**, resource group **proofpatch-rg**, subscription **Azure for Students**, region **malaysiawest**, Ubuntu 24.04, size Standard_DS2_v2_Promo. Its IP is **85.211.253.253**, and its HTTPS API origin is **https://85-211-253-253.sslip.io**. Caddy forwards `/api/*` to `127.0.0.1:3001`. The existing systemd service is **proofpatch-api**, running as user **proofpatch** from `/opt/proofpatch`; persistent data/work files are `/opt/proofpatch/.data`.

The integration is based on **fd456bb** from `claude/trained-locator`, which the owner identifies as the live role split, public demo login, Merge feature and deployment script revision. Those features and the existing optional `DETECTOR_*` locator hook are preserved. The Java classifier is an independently invoked, experimental classification API; it does not introduce another code-search locator or alter patch generation, application, merge proofs or regression execution.

The existing runbook is `deploy/aws/push.sh` plus `deploy/aws/setup.sh`; the historical directory name does not identify the cloud provider. `deploy/vercel.json` records the same-origin rewrite to the Azure HTTPS origin. No second backend or proxy change is required.

The required SSH key `~/.ssh/id_rsa` exists only on Aditya's laptop, according to the owner. It is absent from this workspace, and no authenticated Azure session is available here. The combined branch can therefore be pushed for Aditya to deploy, but this workspace cannot honestly claim a completed Azure rollout.

From Aditya's existing repository and production `.env`, fetch and check out the combined branch, then deploy that exact ref:

```sh
git fetch origin
git switch --track origin/codex/ml-azure-integration
PUBLIC_DEMO=true bash deploy/aws/push.sh 85.211.253.253 ~/.ssh/id_rsa https://proofpatch-r2.vercel.app HEAD
```

Do not deploy the earlier main/ML-only ref over this VM: deployment replaces the application code. Keep Aditya's half-finished JavaScript work local and use a clean checkout if needed. Use Aditya's existing server configuration, not another developer's local `.env`. The updated runbook takes both application archive and setup script from the requested ref, preserves the existing `.data` behavior, installs Python 3.12 dependencies in `ml/mini_classifier/.venv`, sets `MINI_ML_PYTHON`, checks trusted artifact hashes, and performs a genuine held-out inference before restarting the existing service. No new listening port or service is introduced.

Redeploy the existing Vercel **proofpatch-r2** project from the same combined ref with the existing `deploy/vercel.json` configuration and demo environment settings. API deployment alone does not update frontend navigation. Existing authentication cookies remain same-origin, with no new CORS or cross-site cookie policy. The Docker pipeline remains an independent existing requirement; the classifier does not provide sandbox proof.

An online integration claim requires an authenticated real classification after backend deployment, plus verification of the frontend deployment revision. A public health response or unauthenticated 401 is insufficient. Following explicit user approval, one integration-test developer account was created; its credentials stay in ignored local QA storage. The latest authenticated deployed checks returned **404 for `/api/ml/model-info`**, and **200 with genuine executed regression evidence** for `/api/regression-demo/evidence`: baseline 5/5, expected reproduction 0/3, patched security 3/3, regression 5/5, verdict VERIFIED. The live backend still needs this combined ref deployed. Production frontend builds emit `/deployment-info.json` with source commit/build timestamp, so the frontend rollout can be verified directly.

## Validation commands

```sh
npm run build
# Windows: set PYTHON_BIN to the installed Python executable before running the suite.
npm test
python ml/mini_classifier/test_classifier.py
python ml/mini_classifier/predict.py --file ml/mini_classifier/artifacts/heldout-example.java --language java
```

`tests/ml-api.test.ts` performs real Python inference on the saved held-out example and verifies authentication, recorded metrics, unsupported languages, and rejection of caller-supplied model/command fields. It requires the Python dependencies and trusted model artifacts. Browser checks cover both dashboard links, actual classification, reference source comparison, and recorded regression outcomes.

Completed combined-branch results: **78/78 workspace tests passed**, including all 20 existing pipeline/locator/Merge tests, 19 authentication/role API tests, five genuine ML API checks, the executed regression integration test, 20 UI data tests and 13 contract tests. The **full shared/API/frontend production build passed**; Vite retains its existing Monaco chunk-size warning. The Windows test process used the installed Python 3.12 runtime through `PYTHON_BIN`; no scanner or pipeline algorithm was changed to make tests pass. All six saved-classifier tests passed. CLI inference reproduced **CWE-327**, probability **0.9856365584438977**, from the actual held-out example without retraining. Both roles' ML/regression navigation was checked in the browser; developers retained submission-only repository access, and the reviewer demo login still worked. The regression page displayed baseline 5/5, expected reproduction 0/3, patched security 3/3, and unchanged regression 5/5 from the genuine retained record. Azure deployment script syntax passed `bash -n`; an actual Azure rollout remains dependent on the SSH-key holder.
