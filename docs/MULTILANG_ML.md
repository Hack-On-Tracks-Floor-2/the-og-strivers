# Multi-language classifier implementation report

## Implemented scope

This upgrade preserves the existing Java classifier and adds an independently trained **Python** classifier. Both are TF-IDF + balanced Logistic Regression baselines. Classification is experimental and never confirms a vulnerability. JavaScript and TypeScript are unsupported; no training samples, labels or performance claims were invented for them.

The existing scanners, optional UniXcoder locator, AI patch generation, Docker regression pipeline, Merge implementation and review permissions are unchanged. Automatic scanner enrichment is **not connected**. A standalone optional adapter is ready for a later explicit integration after the teammate's Semgrep branch is merged.

## Actual datasets and measured results

Java uses official [OWASP Benchmark Java v1.2](https://github.com/OWASP-Benchmark/BenchmarkJava/tree/0a3113b7054a56a072e694ab65a2f8cd7405aeb7), revision `0a3113b7054a56a072e694ab65a2f8cd7405aeb7`, GPL-2.0-only. Its saved weights/vectorizer/evaluation were not changed: 1,501 training / 375 held-out examples; CWEs 22, 327, 328, 330, 78, 79, 89 plus benchmark negative; macro precision 75.28%, recall 94.02%, F1 80.57%. Negative recall is 52.17%, equivalent to 47.83% false positives among benchmark-negative examples. The existing experimental workflow is preserved with that limitation visible.

Python uses official [OWASP Benchmark Python v0.1](https://github.com/OWASP-Benchmark/BenchmarkPython/tree/f1291485808b66e20ddb6b01b10dc71b3df8c8ba), revision `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`, **GPL-3.0-only**. Source notices and the original license are retained. The official `expectedresults-0.1.csv` supplies each source ID, target CWE and true/false vulnerability label; scanner output is never used as ground truth. Positive examples retain their official CWE; negative examples are grouped as `BENCHMARK_NEGATIVE`, meaning absence of the targeted benchmark weakness only.

The official Python corpus has 1,230 cases. Five CWEs satisfy the predeclared post-validation minimum of 30 vulnerable and 30 negative samples plus at least five control-flow groups: **22, 328, 330, 643, 79**. Those categories supply 920 examples. Other categories are excluded with counts recorded in the actual evaluation report.

Python fitting uses `LogisticRegression(C=4, class_weight='balanced', solver='lbfgs', max_iter=400, random_state=42)` and training-only TF-IDF 1–2 token grams. Parsing removes comments/docstrings, benchmark route decorators, test identities and GET bootstrap; it never imports or executes source. Broad grouping omits API names, identifiers, literals and straight-line statement counts while retaining control-flow families. This is deliberately more conservative than grouping near-identical source strings alone.

The first eligible seeded group fold produced **738 training / 182 held-out examples**, **173 training / 47 test groups**, zero shared groups and zero shared normalized source hashes. Actual held-out macro precision is **0.7407672**, recall **0.9586777**, F1 **0.8131393**. There were **30 false positives among 121 negative examples**, FPR **0.2479339**. Exact values, per-class precision/recall/F1 and confusion matrix are in `ml/multilang_classifier/artifacts/python/evaluation.json`.

The Python model passed the predeclared gate of macro-F1 >= 0.65 and negative FPR <= 0.30. It is enabled for experimental manual inference only. Both languages come from synthetic benchmark repositories; neither report establishes independent-production-repository accuracy. Grouping reduces leakage but cannot eliminate benchmark-family correlations. Neither classifier supplies execution proof or generates patches.

Actual saved Python inference: `BenchmarkTest00001` expected/predicted CWE-22, probability **0.9038790767**. The first held-out negative, `BenchmarkTest00004`, was incorrectly predicted CWE-22 with probability **0.6829798656**. It is retained honestly rather than replaced with an easier example. Probabilities are uncalibrated.

The Python training command was reproduced with unchanged data, split, features and hyperparameters after integrity-file serialization was finalized; both model/vectorizer digests and metrics were identical. No test-score-based tuning occurred. The manifest records language, dataset revision, source repository/path/ID, label, CWE, license, source hash, group and split for every sample.

## Why JavaScript and TypeScript remain unsupported

- [OpenSSF CVE Benchmark](https://github.com/ossf-cve-benchmark/ossf-cve-benchmark/tree/91c59fd54b2b768c0f310bb0027d2ac59cdf74d4), revision `91c59fd54b2b768c0f310bb0027d2ac59cdf74d4`: MIT metadata/tooling, 222 cases with vulnerable/fixed revision metadata and localized weaknesses. Only 12 records identify TypeScript locations. Source-level pair extraction, individual upstream licenses, multi-CWE handling and repository-aware grouping remain necessary before training.
- [Cisco Foundation AI vulnerability-localization benchmark](https://github.com/cisco-foundation-ai/vulnerability-localization-benchmark/tree/fa50b671aa0b954d73691d6ef8d592d42a2ac1e0): Apache-2.0 tooling with individual upstream license records; 75 cases identify JavaScript files and 19 TypeScript files, including mixed cases. Largest TypeScript CWE group is four cases, insufficient at this upgrade's minima.
- [JsVul](https://github.com/jsvul/jsvul/tree/036c7f77749c524c51984419a37f666685796ef6): GPL-3.0 curation code, but packaged dataset DOI `10.5281/zenodo.18195838` returned 410 from the authoritative API during research. Available curation code alone is not a verified training corpus.
- SecJS packaging/license metadata is incomplete; SecBench.js has no recognized repository license. Neither was used. No license was inferred from public availability.

These are researched candidates, not installed datasets or supported models. Fixed source associated with a CVE would be negative only for that recorded weakness, not universally safe.

## API and model-loading behavior

Existing authentication and default Java compatibility are retained:

- `GET /api/ml/model-info` defaults to Java; `?language=python` returns Python's actual report. Unsupported model metadata returns a structured 404.
- `GET /api/ml/models` lists trained model info and explicit unsupported/unavailable/disabled status without fabricating counts or metrics.
- `GET /api/ml/example?language=python` supplies the actual attributed held-out example; omission still means Java.
- `POST /api/ml/classify` accepts `{language, code, filePath?}`. The 20,000-character source and 500-character metadata path are bounded. The path is never read and cannot choose artifacts or commands. Extra model/command/override fields are rejected.

The Node service starts a fixed persistent JSON-lines worker with bounded output, one active classification, startup/request timeouts, no shell and one numerical thread per library. Registered language paths are fixed by the server. Python verifies serialized model/vectorizer digests before loading verified bytes and caches by those digests, preventing old predictions from being labeled with a replacement model's version. Missing/disabled/invalid models return unknown without a category/probability; unsupported languages never fall back to Java. Source parsing/TF-IDF never executes submitted code. Readiness metadata is not a substitute for actual inference if Python dependencies are missing.

The frontend defaults to Java, offers only models with actual training metadata, displays measured language-specific metrics/activation reasons, shows JavaScript/TypeScript as unsupported, and clears stale prediction state on language changes. Developer/Reviewer permissions and existing styling/navigation remain intact.

## Optional finding enrichment: prepared, not wired

`apps/api/src/services/ml-enrichment.ts::enrichScannerFinding()` accepts the original scanner finding and caller-supplied source text. It extracts bounded context (at most 80 lines / 20,000 characters), infers or validates language metadata, and returns `{finding, ml}` while preserving the exact original finding object and its severity/CWE/confidence. It exposes agreement, disagreement and benchmark-negative disagreement. Missing models and prediction failures are nonblocking and do not suppress or modify scanner findings.

After the Semgrep branch is merged, an authorized caller can supply a genuine finding plus its source snapshot and store/display the returned sidecar separately. No current scanner, orchestrator, finding schema or database write calls this adapter. No automatic enrichment or Groq consumption is claimed.

## Azure deployment requirements

No deployment is performed by this upgrade. Use the existing Azure VM/systemd/Caddy backend; no second service or port is needed. Preserve the production environment and `.data`. Include both committed artifact folders and the new router/features/worker files. Use Python 3.12 and the existing pinned `ml/mini_classifier/requirements.txt` in the current classifier virtual environment; `MINI_ML_PYTHON` remains the executable setting. No additional dependencies were introduced. The existing setup script now preflights both Java and Python held-out inference. Vercel needs a separate frontend build/redeployment of the same reviewed ref to show the new selector/catalog.

This branch must not replace newer teammate commits during a later deployment. Merge/review coordination is required first. GitHub push, merge and deployment are not part of this request.

## Validation actually executed

- Actual Python training ran against the pinned official checkout and was reproduced with identical split, model/vectorizer hashes and metrics. Evaluation was performed on held-out data, never on training accuracy.
- `npm test`: **110/110 tests passed across seven files**, including the existing pipeline (20), regression (1), API/auth/roles (19), ML API (9), UI data (20), optional enrichment (28) and shared contracts (13). Authenticated ML API checks execute the real saved Java and Python classifiers.
- `ml/mini_classifier/run.ps1 predict --file ml/mini_classifier/artifacts/heldout-example.java --language java`: genuine CWE-327 prediction, probability **0.9856365584438977**, identical to the preserved evidence. Original `run.ps1 test`: **6/6 passed**.
- `python ml/multilang_classifier/test_python.py`: **8/8 passed**, including real positive/negative inference, source provenance, group/hash separation, activation calculation, malformed and out-of-distribution input.
- `python ml/multilang_classifier/test_router.py`: **7/7 passed**, including preserved Java probability, real Python probability, unsupported languages, missing/disabled/corrupt artifacts and digest-based cache invalidation.
- Actual Python CLI positive: CWE-22, probability **0.9038790767131254**. Actual negative CLI: false-positive CWE-22, probability **0.6829798656105392**, as recorded before UI testing.
- `npm run build`: shared package, API and frontend production builds passed. Vite reports the existing large Monaco bundle warning.
- After the final model-version precedence correction, authenticated ML API tests were rerun (**9/9 passed**) and the API was rebuilt successfully. Predictions retain the worker's version for the exact verified weights, even if preflight metadata changes concurrently.
- `bash -n deploy/aws/setup.sh` and whitespace checks for application changes passed. The staged check flags trailing/extra blank-line whitespace already present in the two verbatim upstream held-out Python examples; these attributed source examples are intentionally preserved. Git also reports normal LF-to-CRLF conversion notices.
- Browser verification on local port 5173: reviewer login, default Java report, Python selection, genuine held-out source loading, authenticated classification and returned CWE-22 / 90.39% uncalibrated probability / matching model version were verified. JavaScript/TypeScript unsupported reasons and existing reviewer navigation are visible. No online deployment or production inference is claimed.
- The complete `ml/mini_classifier` directory, scanners, pipeline, verification engine and dashboard navigation are byte-for-byte unchanged from the integration base according to Git.

## Exact project files changed

Existing files modified:

- `packages/shared/src/intelligence.ts`: compatible language/path/prediction contracts and real model catalog.
- `apps/api/src/services/mini-ml.ts`: fixed trusted language registry, language-specific metadata/examples, bounded shared worker and graceful unavailable results.
- `apps/api/src/routes/index.ts`: authenticated catalog and optional language query on existing metadata/example routes.
- `apps/web/src/pages/MLIntelligence.tsx`: real model selector, metrics/status, supported categories, optional source-path metadata and actual inference.
- `tests/ml-api.test.ts`: authenticated Python/Java compatibility, unsupported/malformed inputs and real model-catalog checks.
- `deploy/aws/setup.sh`: additional Python held-out preflight in the existing deployment process; no deployment executed.

New files:

- `apps/api/src/services/ml-enrichment.ts`: optional bounded sidecar adapter, deliberately not called by scanner/orchestrator.
- `tests/ml-enrichment.test.ts`: 28 adapter behavior and failure checks.
- `docs/MULTILANG_ML.md`: this implementation, dataset, validation and deployment report.
- `ml/multilang_classifier/.gitignore`: local corpus/dependency/cache exclusions.
- `ml/multilang_classifier/README.md`: prediction and pinned-data reproduction commands.
- `ml/multilang_classifier/features.py`: Python AST cleaning, template grouping and guarded text-only inference.
- `ml/multilang_classifier/train_python.py`: pinned official labels/source collection, group split, training, held-out evaluation and artifact generation.
- `ml/multilang_classifier/router.py`: fixed language-to-artifact routing, verified-byte loading and digest-aware cache.
- `ml/multilang_classifier/worker.py`: bounded JSON-lines inference bridge.
- `ml/multilang_classifier/predict.py`: local command-line inference.
- `ml/multilang_classifier/test_python.py`: eight real artifact/provenance/leakage/OOD checks.
- `ml/multilang_classifier/test_router.py`: seven routing, compatibility and artifact-lifecycle checks.
- `ml/multilang_classifier/artifacts/python/DATASET_LICENSE.txt`: original dataset license.
- `ml/multilang_classifier/artifacts/python/evaluation.json`: measured class metrics, confusion matrix, source/training provenance and activation result.
- `ml/multilang_classifier/artifacts/python/heldout-example.py`: attributed real positive test example.
- `ml/multilang_classifier/artifacts/python/heldout-negative.py`: attributed real negative test example.
- `ml/multilang_classifier/artifacts/python/heldout-inference.json`: actual inference evidence for both examples, including the false positive.
- `ml/multilang_classifier/artifacts/python/integrity.json`: serialized artifact SHA-256 digests.
- `ml/multilang_classifier/artifacts/python/metadata.json`: labels, language, threshold, model version and activation gate.
- `ml/multilang_classifier/artifacts/python/model.joblib`: actual trained Logistic Regression weights.
- `ml/multilang_classifier/artifacts/python/vectorizer.joblib`: training-only vocabulary and IDF values.
- `ml/multilang_classifier/artifacts/python/split-manifest.json`: all 920 example source identities, labels, licenses, groups and split assignments.

Downloaded source corpus, installed dependencies, build output, local QA screenshots and credentials are excluded from the commit.

The pre-commit scan checked all 28 changed/new project files for private keys, common cloud/provider tokens, sensitive file names and assigned secret literals. It found no exposed secrets. One pre-existing test-only password literal for an ephemeral `example.test` account was identified and verified unchanged from the integration base; it is not a deployed account credential.
