"""Train a pinned OWASP Python benchmark baseline with a predeclared activation gate."""

import argparse
import csv
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "mini_classifier" / ".deps"))
for variable in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "NUMEXPR_NUM_THREADS"):
    os.environ[variable] = "1"

from features import NEGATIVE, clean_python, predict_python, template_group
import joblib
import numpy as np
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import StratifiedGroupKFold
from threadpoolctl import threadpool_limits

PINNED_REVISION = "f1291485808b66e20ddb6b01b10dc71b3df8c8ba"
ACTIVATION_GATE = {"minimum_macro_f1": 0.65, "maximum_negative_false_positive_rate": 0.30}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=ROOT / ".data" / "BenchmarkPython")
    parser.add_argument("--out", type=Path, default=ROOT / "artifacts" / "python")
    args = parser.parse_args()
    started = time.monotonic()
    dataset, output = args.dataset.resolve(), args.out.resolve()
    commit = subprocess.check_output(["git", "-C", str(dataset), "rev-parse", "HEAD"], text=True).strip()
    if commit != PINNED_REVISION:
        raise RuntimeError("Dataset checkout is not the reviewed pinned official revision.")
    labels_file = dataset / "expectedresults-0.1.csv"
    print(json.dumps({"dataset_commit": commit, "predeclared_activation_gate": ACTIVATION_GATE}), flush=True)
    rows, skipped, seen, contradictions = [], Counter(), {}, set()
    for entry in csv.reader(labels_file.read_text(encoding="utf-8-sig").splitlines()):
        if not entry or entry[0].lstrip().startswith("#"):
            continue
        if len(entry) != 4:
            skipped["invalid_metadata"] += 1
            continue
        name, category, truth, cwe = [value.strip() for value in entry]
        if not name.startswith("BenchmarkTest") or not name[13:].isdigit() or truth not in ("true", "false") or not cwe.isdigit():
            skipped["invalid_metadata"] += 1
            continue
        path = dataset / "testcode" / f"{name}.py"
        if not path.is_file():
            skipped["missing_source"] += 1
            continue
        code = clean_python(path.read_text(encoding="utf-8"))
        if len(code) < 25:
            skipped["unparseable_or_empty_source"] += 1
            continue
        label = f"CWE-{cwe}" if truth == "true" else NEGATIVE
        digest = hashlib.sha256(code.encode()).hexdigest()
        if digest in seen:
            skipped["duplicate_normalized_source"] += 1
            if seen[digest] != label:
                contradictions.add(digest)
            continue
        seen[digest] = label
        rows.append({"id": name, "category": category, "cwe": f"CWE-{cwe}",
                     "vulnerable": truth == "true", "label": label, "code": code,
                     "sha256": digest, "group": template_group(code),
                     "language": "python", "dataset": "OWASP Benchmark Python v0.1",
                     "dataset_revision": commit, "license": "GPL-3.0-only",
                     "source_repository": "https://github.com/OWASP-Benchmark/BenchmarkPython",
                     "source": str(path.relative_to(dataset)).replace("\\", "/")})
    rows = [row for row in rows if row["sha256"] not in contradictions]
    counts, groups = defaultdict(Counter), defaultdict(set)
    for row in rows:
        counts[row["cwe"]][str(row["vulnerable"])] += 1
        groups[row["cwe"]].add(row["group"])
    eligible = sorted(cwe for cwe, count in counts.items()
                      if count["True"] >= 30 and count["False"] >= 30 and len(groups[cwe]) >= 5)
    excluded = {cwe: {**dict(count), "groups": len(groups[cwe])}
                for cwe, count in counts.items() if cwe not in eligible}
    rows = [row for row in rows if row["cwe"] in eligible]
    group_sizes = Counter(row["group"] for row in rows)
    print(json.dumps({"eligible_cwes": eligible, "samples": len(rows), "families": len(group_sizes),
                      "largest_family_samples": max(group_sizes.values(), default=0),
                      "excluded_cwes": excluded}), flush=True)
    if len(eligible) < 2:
        raise RuntimeError("Insufficient valid labeled categories with five conservative groups.")
    labels = np.array([row["label"] for row in rows])
    group_ids = np.array([row["group"] for row in rows])
    all_labels = sorted(set(labels))
    selection = None
    # Labels/group sizes alone select the FIRST eligible fold. Scores never influence selection.
    splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)
    for fold, (train, test) in enumerate(splitter.split(np.zeros(len(rows)), labels, group_ids)):
        train_counts, test_counts = Counter(labels[train]), Counter(labels[test])
        if all(train_counts[label] >= 10 and test_counts[label] >= 5 for label in all_labels):
            selection = (fold, train, test)
            break
    if selection is None:
        raise RuntimeError("No first-seed group-disjoint fold supplies ten train/five test examples per class; no model trained.")
    fold, train, test = selection
    assert not set(group_ids[train]) & set(group_ids[test])
    assert not {rows[i]["sha256"] for i in train} & {rows[i]["sha256"] for i in test}
    vectorizer = TfidfVectorizer(token_pattern=r"(?u)[A-Za-z_][\w]*|\d+|==|!=|<=|>=|:=|[-+*/%]",
                                 lowercase=False, ngram_range=(1, 2), min_df=2,
                                 max_features=25000, sublinear_tf=True)
    train_features = vectorizer.fit_transform([rows[i]["code"] for i in train])
    model = LogisticRegression(max_iter=400, C=4.0, class_weight="balanced", solver="lbfgs", random_state=42)
    with threadpool_limits(limits=1):
        model.fit(train_features, labels[train])
    predicted = model.predict(vectorizer.transform([rows[i]["code"] for i in test]))
    precision, recall, f1, _ = precision_recall_fscore_support(labels[test], predicted, average="macro", zero_division=0)
    negative_mask = labels[test] == NEGATIVE
    false_positives = int(np.sum(predicted[negative_mask] != NEGATIVE))
    negative_samples = int(np.sum(negative_mask))
    negative_fpr = false_positives / negative_samples
    enabled = bool(f1 >= ACTIVATION_GATE["minimum_macro_f1"] and negative_fpr <= ACTIVATION_GATE["maximum_negative_false_positive_rate"])
    activation_reason = ("Passed the predeclared benchmark activation gate; remains experimental." if enabled else
                         "Disabled by the predeclared benchmark gate: require macro-F1 >= 0.65 and negative false-positive rate <= 0.30.")
    metadata = {"supported_cwes": eligible, "negative_label": NEGATIVE, "language": "python",
                "rejection_threshold": 0.35, "dataset_commit": commit,
                "enabled": enabled, "activation_reason": activation_reason,
                "activation_gate": ACTIVATION_GATE, "experimental": True}
    selective = [predict_python(rows[i]["code"], model, vectorizer, metadata) for i in test]
    accepted = [index for index, result in enumerate(selective) if result["status"] == "predicted"]
    report = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "model": "TF-IDF Python code tokens (1–2 grams) + balanced LogisticRegression",
        "dataset": {"repository": "https://github.com/OWASP-Benchmark/BenchmarkPython", "version": "0.1",
                    "language": "python", "commit": commit, "license": "GPL-3.0-only",
                    "labels_file": labels_file.name, "labels_sha256": hashlib.sha256(labels_file.read_bytes()).hexdigest(),
                    "eligible_cwes": eligible, "excluded_cwes": excluded,
                    "counts_before_filter": {key: dict(value) for key, value in counts.items()},
                    "groups_before_filter": {key: len(value) for key, value in groups.items()},
                    "skipped": dict(skipped), "conflicting_duplicates_excluded": len(contradictions)},
        "split": {"method": "StratifiedGroupKFold; broad sink-independent control-flow families; every identifier, literal, API and straight-line statement count omitted from grouping",
                  "seed": 42, "fold": fold, "selection": "First fold meeting class support, using labels only; no score-based tuning",
                  "train_samples": len(train), "test_samples": len(test),
                  "train_groups": len(set(group_ids[train])), "test_groups": len(set(group_ids[test])),
                  "shared_groups": 0, "shared_normalized_sources": 0, "largest_family_samples": max(group_sizes.values()),
                  "train_counts": dict(Counter(labels[train])), "test_counts": dict(Counter(labels[test]))},
        "evaluation": {"scope": "Untouched grouped split from one synthetic benchmark repository; not independent real-world evaluation or an official OWASP detector score.",
                       "precision_macro": float(precision), "recall_macro": float(recall), "f1_macro": float(f1),
                       "per_class": classification_report(labels[test], predicted, output_dict=True, zero_division=0),
                       "confusion_labels": all_labels, "confusion_matrix": confusion_matrix(labels[test], predicted, labels=all_labels).tolist(),
                       "negative_samples": negative_samples, "negative_false_positives": false_positives,
                       "negative_false_positive_rate": negative_fpr,
                       "cli_rejection_threshold": 0.35, "cli_accepted_test_samples": len(accepted),
                       "cli_coverage": len(accepted) / len(test),
                       "cli_accepted_accuracy": float(np.mean([selective[k]["predicted_category"] == labels[test[k]] for k in accepted])) if accepted else None},
        "activation": {"enabled": enabled, "reason": activation_reason, "gate": ACTIVATION_GATE},
        "environment": {"python": platform.python_version(), "scikit_learn": sklearn.__version__, "numpy": np.__version__, "joblib": joblib.__version__},
        "reproducibility": {"seed": 42, "model_parameters": model.get_params(), "preprocessor_sha256": hashlib.sha256((ROOT / "features.py").read_bytes()).hexdigest(),
                            "training_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
        "limitations": ["Single synthetic OWASP Python benchmark only; no independent repository evaluation.",
                        "Broad template/control-flow grouping reduces but cannot eliminate benchmark-family leakage.",
                        "Negative means the target benchmark weakness is absent, not that the program is globally secure.",
                        "CWE probabilities are uncalibrated and classification never confirms a vulnerability.",
                        "Low-confidence/context rejection cannot guarantee out-of-distribution recognition.",
                        "Java artifacts and existing scanning/patching/regression pipelines are unchanged."],
        "training_seconds": time.monotonic() - started,
    }
    output.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, output / "model.joblib", compress=3)
    joblib.dump(vectorizer, output / "vectorizer.joblib", compress=3)
    metadata["model_version"] = "owasp-python-0.1-" + hashlib.sha256((output / "model.joblib").read_bytes()).hexdigest()[:12]
    for name, value in (("metadata.json", metadata), ("evaluation.json", report)):
        (output / name).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    split_names = {int(i): "train" for i in train}
    split_names.update({int(i): "test" for i in test})
    manifest = [{**{key: value for key, value in row.items() if key != "code"}, "split": split_names[index]} for index, row in enumerate(rows)]
    (output / "split-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    inference = None
    for vulnerable, filename in ((True, "heldout-example.py"), (False, "heldout-negative.py")):
        example_index = next(int(i) for i in test if rows[i]["vulnerable"] == vulnerable)
        example = rows[example_index]
        shutil.copyfile(dataset / example["source"], output / filename)
        result = {"example_id": example["id"], "split": "test", "expected_label": example["label"],
                  "source_sha256": example["sha256"], "prediction": predict_python(example["code"], model, vectorizer, metadata)}
        if vulnerable:
            inference = result
        else:
            inference["negative_example"] = result
    (output / "heldout-inference.json").write_text(json.dumps(inference, indent=2) + "\n", encoding="utf-8")
    shutil.copyfile(dataset / "LICENSE", output / "DATASET_LICENSE.txt")
    hashes = {name: hashlib.sha256((output / name).read_bytes()).hexdigest() for name in ("model.joblib", "vectorizer.joblib")}
    (output / "integrity.json").write_text(json.dumps(hashes, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"trained": True, "enabled": enabled, "model_version": metadata["model_version"],
                      "train_samples": len(train), "test_samples": len(test), "supported_cwes": eligible,
                      "precision_macro": float(precision), "recall_macro": float(recall), "f1_macro": float(f1),
                      "negative_false_positive_rate": negative_fpr, "training_seconds": report["training_seconds"],
                      "heldout_inference": inference}, indent=2), flush=True)


if __name__ == "__main__":
    main()
