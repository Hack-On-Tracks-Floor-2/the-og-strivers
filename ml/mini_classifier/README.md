# Mini Java CWE classifier

An isolated, genuinely trained **TF-IDF + Logistic Regression** baseline. The existing `ml/` UniXcoder/Python locator is unfinished and is not modified. The classifier is now available through authenticated `/api/ml/model-info` and `/api/ml/classify` endpoints and the ML Intelligence dashboard. The existing detection, patch-generation, and regression algorithms remain unchanged. See `docs/FINAL_INTEGRATION.md` for deployment requirements.

Completed validation: **1,501 training / 375 held-out examples**, seven CWEs plus the benchmark-negative class. Actual macro precision **0.752810**, macro recall **0.940217**, macro-F1 **0.805701**. Supported CWEs: 22, 78, 79, 89, 327, 328, 330. Negative-example recall is only **0.521739**: this baseline still flags many benchmark-negative examples as CWE categories. The saved-model CLI correctly classified held-out `BenchmarkTest00005` as `CWE-327` (uncalibrated model probability 0.985637). All **six artifact/contract tests passed**. These are measured results from `artifacts/evaluation.json`, not production accuracy claims.

## Run now on this Windows workspace

```powershell
.\ml\mini_classifier\run.ps1 predict --file ml/mini_classifier/artifacts/heldout-example.java --language java
.\ml\mini_classifier\run.ps1 test
```

The wrapper uses the installed Codex Python runtime when available; elsewhere it uses `python`. Direct portable commands are `python ml/mini_classifier/predict.py --file path/to/Snippet.java --language java` or pipe source to its standard input. `--cwe CWE-...` optionally declares a required category and returns unknown if that category was not trained.

Predictions are JSON containing `status`, `predicted_category`, `cwe`, `probability`, and supported categories. `BENCHMARK_NEGATIVE` means the official example is negative for its benchmark weakness; it **does not establish that arbitrary code is safe**. Untrained declared languages/CWEs, insufficient Java context/vocabulary, and probabilities below the fixed 0.35 threshold return `unknown`. This threshold was declared before evaluation, not optimized on test results. It does not guarantee rejection of every unknown CWE. Probabilities are not calibrated.

## Reproduce training

Requires Python 3.12 and Git. Local `.deps` and `.data` folders are isolated and ignored.

```powershell
python -m pip install --target ml/mini_classifier/.deps --only-binary=:all: -r ml/mini_classifier/requirements.txt
git clone --depth 1 --filter=blob:none --sparse https://github.com/OWASP-Benchmark/BenchmarkJava.git ml/mini_classifier/.data/BenchmarkJava
git -C ml/mini_classifier/.data/BenchmarkJava sparse-checkout set src/main/java/org/owasp/benchmark/testcode
git -C ml/mini_classifier/.data/BenchmarkJava fetch --depth 1 origin 0a3113b7054a56a072e694ab65a2f8cd7405aeb7
git -C ml/mini_classifier/.data/BenchmarkJava checkout --detach 0a3113b7054a56a072e694ab65a2f8cd7405aeb7
python ml/mini_classifier/train.py
python ml/mini_classifier/test_classifier.py
```

Source: [official OWASP BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava), version **1.2**, pinned revision **0a3113b7054a56a072e694ab65a2f8cd7405aeb7**. Labels come exclusively from `expectedresults-1.2.csv`: true examples receive their supplied CWE, false examples receive `BENCHMARK_NEGATIVE`. No examples or labels are invented. This official test suite itself contains deliberately generated benchmark vulnerabilities; it is not a corpus of independent production projects.

Only categories retaining at least 30 vulnerable and 30 negative distinct sources and five template groups are admitted. Exact normalized duplicate sources are removed; conflicting duplicates are excluded. Comments, benchmark identities, route category hints, and servlet registration boilerplate are removed from features; actual sink APIs and data flow remain. Related templates are grouped by abstracted identifiers, string/numeric/boolean literals, and control-flow structure, across CWE categories. A deterministic grouped 80/20-style split uses the first seeded fold with adequate per-class support. TF-IDF is fitted only on training data. Template grouping reduces leakage but cannot establish independent-project generalization.

## Saved evidence

- `artifacts/model.joblib` and `vectorizer.joblib`: actual trained weights/features, committed for backend deployment. `integrity.json` pins their SHA-256 digests. Load only these trusted joblib files.
- `artifacts/evaluation.json`: real macro precision/recall/F1, per-class metrics, confusion matrix, counts, versions, dataset commit/CSV digest, excluded categories, split details, and CLI rejection coverage. Closed-set metrics include the negative class; they are not an official OWASP scanner score.
- `artifacts/split-manifest.json`: traceable official example IDs, ground truth, cleaned-source hashes, template groups, and train/test memberships.
- `artifacts/heldout-example.java` and `heldout-inference.json`: first eligible vulnerable held-out example, selected irrespective of whether the model predicts correctly. CLI inference reloads saved artifacts.
- `artifacts/metadata.json`: supported CWEs and inference contract.

The benchmark is **GPL-2.0-only**. Downloaded original sources retain their notices; `artifacts/DATASET_LICENSE.txt` reproduces the upstream license, and the held-out source retains its original GPL notice. The pinned source and metadata are available through the official repository above. This small research/demo classifier claims neither cross-language accuracy nor production-wide vulnerability detection.
