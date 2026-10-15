# Final ML and regression integration

## Available application routes

Both Developer and Security Reviewer dashboards expose **ML Intelligence** (`/:role/app/ml`) and **Regression Verification** (`/:role/app/regression`). Existing Patch Studio remains intact and links a selected patch to its scoped regression evidence and corresponding finding. The recorded regression reference fixture also opens its actual source snapshots in the same comparison editor at `/:role/app/patches?reference=regression`.

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

The owner confirms the existing backend is on **Microsoft Azure**. The checked-out repository and related local regression worktrees contain no Azure resource ID/name, deployment workflow, API-origin hostname, Bicep/Terraform/ARM definition, publish profile, or SSH deployment runbook. No Azure CLI, Azure credential session, or SSH host configuration is available here. Caddy's response header does not identify whether the Azure resource is a VM, App Service, or Container Apps; the exact resource cannot responsibly be inferred. Updating the existing backend requires its resource/SSH hostname and current deployment process. Do not create another backend or change the functioning proxy/regression service to guess these details.

The frontend uses existing same-origin `/api` calls and the existing Vite development proxy. The supplied Vercel website responds to `/api/health`, and `/api/ml/model-info` returns an authentication challenge; this alone does **not** prove that the deployed backend has the new inference route or saved model. Responses include `Via: Caddy`, consistent with an existing proxy/backend arrangement, but its target is not recorded in this checkout. No tracked Vercel configuration or project linkage was found. The existing online proxy configuration is preserved.

Vercel serving the frontend does not automatically install or run the local Python worker. Run the Node API and Python together on a persistent backend host with Python **3.12**, Node **22.12+**, the complete repository, and the committed artifacts. For that host:

```sh
npm ci
python3 -m pip install --target ml/mini_classifier/.deps --only-binary=:all: -r ml/mini_classifier/requirements.txt
npm run build
# Set MINI_ML_PYTHON to the trusted absolute python3 executable.
# Preserve the backend's existing APP_ORIGIN, database, session, and pipeline settings.
npm run start
```

Keep Vercel's existing `/api/:path*` proxy directed to this backend. If setting up a separate backend, configure that same-origin rewrite in the Vercel project to its real HTTPS origin; do not insert a guessed origin. Existing authentication cookies remain same-origin, with no new CORS or cross-site cookie policy. A configured Docker verification pipeline remains a separate existing requirement; the ML worker does not provide a Docker sandbox.

An online integration claim requires an authenticated real classification after backend deployment, plus verification of the frontend deployment revision. A public health response or unauthenticated 401 is insufficient. GitHub deployment metadata was unavailable without authenticated access during initial checks. Following explicit user approval, one integration-test developer account was created; its credentials stay in ignored local QA storage. Authenticated deployed checks returned **404 for `/api/ml/model-info`**, and **200 with genuine executed regression evidence** for `/api/regression-demo/evidence`. The deployed backend therefore still needs this ML integration deployed. Production frontend builds now emit `/deployment-info.json` with the source commit and build timestamp, so a later deployment can be checked directly rather than assumed.

## Validation commands

```sh
npm run build
npm test
python ml/mini_classifier/test_classifier.py
python ml/mini_classifier/predict.py --file ml/mini_classifier/artifacts/heldout-example.java --language java
```

`tests/ml-api.test.ts` performs real Python inference on the saved held-out example and verifies authentication, recorded metrics, unsupported languages, and rejection of caller-supplied model/command fields. It requires the Python dependencies and trusted model artifacts. Browser checks cover both dashboard links, actual classification, reference source comparison, and recorded regression outcomes.

Completed results: the full workspace build passed. The full suite had 71 passing tests and one existing pipeline retry case hit its 30-second timeout while the build was running concurrently. That unchanged case passed in isolation in 9.3 seconds with a 90-second test timeout. All five genuine ML API checks and the executed regression integration test passed. The reviewer UI returned CWE-327 with the saved model's actual 98.56% uncalibrated probability for its held-out example; the regression page displayed baseline 5/5, expected reproduction 0/3, patched security 3/3, and unchanged regression 5/5 from the genuine retained record.
