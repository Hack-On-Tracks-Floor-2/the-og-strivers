"""Check real trained Python artifacts, held-out provenance and safety contracts."""

import hashlib
import json
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "mini_classifier" / ".deps"))
for name in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "NUMEXPR_NUM_THREADS"):
    os.environ[name] = "1"

from features import NEGATIVE, clean_python, predict_python, template_group
import joblib


class PythonClassifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = ROOT / "artifacts" / "python"
        integrity = json.loads((cls.folder / "integrity.json").read_text(encoding="utf-8"))
        hashes = integrity.get("files", integrity)
        for filename in ("model.joblib", "vectorizer.joblib"):
            if hashlib.sha256((cls.folder / filename).read_bytes()).hexdigest() != hashes[filename]:
                raise ValueError("Trusted artifact integrity failed before loading.")
        cls.model = joblib.load(cls.folder / "model.joblib")
        cls.vectorizer = joblib.load(cls.folder / "vectorizer.joblib")
        cls.metadata = json.loads((cls.folder / "metadata.json").read_text(encoding="utf-8"))
        cls.report = json.loads((cls.folder / "evaluation.json").read_text(encoding="utf-8"))
        cls.manifest = json.loads((cls.folder / "split-manifest.json").read_text(encoding="utf-8"))
        cls.evidence = json.loads((cls.folder / "heldout-inference.json").read_text(encoding="utf-8"))

    def test_actual_split_is_group_and_duplicate_disjoint(self):
        for field in ("group", "sha256"):
            train = {row[field] for row in self.manifest if row["split"] == "train"}
            test = {row[field] for row in self.manifest if row["split"] == "test"}
            self.assertTrue(train)
            self.assertTrue(test)
            self.assertFalse(train & test)
        self.assertEqual(sum(row["split"] == "train" for row in self.manifest), self.report["split"]["train_samples"])
        self.assertEqual(sum(row["split"] == "test" for row in self.manifest), self.report["split"]["test_samples"])

    def test_pinned_official_provenance_and_sample_support(self):
        self.assertEqual(self.metadata["dataset_commit"], "f1291485808b66e20ddb6b01b10dc71b3df8c8ba")
        self.assertEqual(self.report["dataset"]["license"], "GPL-3.0-only")
        for cwe in self.metadata["supported_cwes"]:
            examples = [row for row in self.manifest if row["cwe"] == cwe]
            self.assertGreaterEqual(sum(row["vulnerable"] for row in examples), 30)
            self.assertGreaterEqual(sum(not row["vulnerable"] for row in examples), 30)
            self.assertGreaterEqual(len({row["group"] for row in examples}), 5)

    def test_saved_model_reproduces_genuine_heldout_positive(self):
        self._check_heldout(self.evidence, "heldout-example.py", True)

    def test_saved_model_reproduces_genuine_heldout_negative(self):
        evidence = self.evidence["negative_example"]
        self.assertEqual(evidence["expected_label"], NEGATIVE)
        self._check_heldout(evidence, "heldout-negative.py", False)

    def _check_heldout(self, evidence, filename, vulnerable):
        row = next(row for row in self.manifest if row["id"] == evidence["example_id"])
        self.assertEqual(row["split"], "test")
        self.assertEqual(row["vulnerable"], vulnerable)
        self.assertEqual(row["label"], evidence["expected_label"])
        code = (self.folder / filename).read_text(encoding="utf-8")
        self.assertEqual(hashlib.sha256(clean_python(code).encode()).hexdigest(), evidence["source_sha256"])
        actual = predict_python(code, self.model, self.vectorizer, self.metadata)
        self.assertEqual(actual["predicted_category"], evidence["prediction"]["predicted_category"])
        if actual["probability"] is not None:
            self.assertAlmostEqual(actual["probability"], evidence["prediction"]["probability"])

    def test_predeclared_gate_uses_heldout_f1_and_negative_fpr(self):
        evaluation = self.report["evaluation"]
        gate = self.metadata["activation_gate"]
        self.assertEqual(gate, {"minimum_macro_f1": 0.65, "maximum_negative_false_positive_rate": 0.30})
        expected = evaluation["f1_macro"] >= 0.65 and evaluation["negative_false_positive_rate"] <= 0.30
        self.assertEqual(self.metadata["enabled"], expected)
        self.assertEqual(self.report["activation"]["enabled"], expected)
        index = evaluation["confusion_labels"].index(NEGATIVE)
        row = evaluation["confusion_matrix"][index]
        self.assertAlmostEqual((sum(row) - row[index]) / sum(row), evaluation["negative_false_positive_rate"])

    def test_metadata_and_obvious_label_identifiers_are_removed(self):
        code = (self.folder / "heldout-example.py").read_text(encoding="utf-8")
        cleaned = clean_python(code)
        self.assertNotIn("OWASP Benchmark", cleaned)
        self.assertNotIn("BenchmarkTest000", cleaned)
        self.assertNotIn("@app.route", cleaned)
        self.assertNotIn("render_template", cleaned.split("def benchmark_handler", 1)[-1])
        self.assertEqual(clean_python(cleaned), cleaned)

    def test_control_flow_families_ignore_sinks_names_literals_and_statement_counts(self):
        left = "def sample(value):\n if value > 3:\n  os.system(value)\n return value\n"
        right = "def other(text):\n untouched = 19\n if text > 900:\n  hashlib.md5(text)\n  result = text\n return result\n"
        self.assertEqual(template_group(left), template_group(right))
        self.assertNotEqual(template_group(left), template_group("def other(text):\n while text:\n  print(text)\n"))

    def test_empty_malformed_and_out_of_distribution_source_are_unknown(self):
        for code in ("", "this is not valid source ???", "public class Main { public static void main(String[] x) {} }", "const answer = () => 42;", "print('hello')"):
            with self.subTest(code=code):
                self.assertEqual(predict_python(code, self.model, self.vectorizer, self.metadata)["status"], "unknown")


if __name__ == "__main__":
    unittest.main()
