# Language-specific experimental classification

Java is preserved under `../mini_classifier`, including its original artifacts and CLI. This folder adds a separately trained Python baseline and a fixed language router. JavaScript and TypeScript have no trained model and remain explicitly unsupported.

See [the full implementation and dataset report](../../docs/MULTILANG_ML.md).

The saved models share the pinned dependencies in `../mini_classifier/requirements.txt`. Local scripts reuse `../mini_classifier/.deps` when present; Azure uses the existing classifier virtual environment. No source code submitted for classification is executed.

```sh
python ml/multilang_classifier/predict.py --language java --file ml/mini_classifier/artifacts/heldout-example.java
python ml/multilang_classifier/predict.py --language python --file ml/multilang_classifier/artifacts/python/heldout-example.py
python ml/multilang_classifier/predict.py --language python --file ml/multilang_classifier/artifacts/python/heldout-negative.py
python ml/multilang_classifier/test_python.py
python ml/multilang_classifier/test_router.py
```

The first saved Python negative example is an actual false positive. Its expected label and real prediction remain in `artifacts/python/heldout-inference.json`. Never interpret `BENCHMARK_NEGATIVE` as proof of global safety.

To reproduce Python training, download only the official labeled benchmark and check out the recorded revision. Do not run the benchmark application:

```sh
git clone https://github.com/OWASP-Benchmark/BenchmarkPython.git ml/multilang_classifier/.data/BenchmarkPython
git -C ml/multilang_classifier/.data/BenchmarkPython checkout --detach f1291485808b66e20ddb6b01b10dc71b3df8c8ba
python ml/multilang_classifier/train_python.py
```

Training rejects another dataset revision, selects the first group-disjoint split with adequate class support, fits TF-IDF only on training data and records class metrics/confusion matrix, negative false positives, source/license provenance and reproducibility hashes. The activation gate was declared before training: macro-F1 at least 0.65 and negative false-positive rate at most 0.30. This is a benchmark demonstration gate, not production validation.

`router.py` accepts only registered language names and trusted fixed artifact directories. It verifies both serialized artifact hashes before loading verified bytes, caches by artifact digests, and returns unknown for missing, invalid or disabled artifacts. `worker.py` provides bounded JSON-lines inference to Node. `--allow-disabled-experiment` is a deliberately explicit offline inspection option; the HTTP API never accepts it.
