"""Tests use actual trained artifacts and official held-out data, not generated training samples."""
import json
import unittest
from common import ROOT, clean_code, template_group, predict
import joblib

class ClassifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder=ROOT/'artifacts'
        cls.model=joblib.load(cls.folder/'model.joblib')
        cls.vectorizer=joblib.load(cls.folder/'vectorizer.joblib')
        cls.metadata=json.loads((cls.folder/'metadata.json').read_text(encoding='utf-8'))
        cls.manifest=json.loads((cls.folder/'split-manifest.json').read_text(encoding='utf-8'))
        cls.code=(cls.folder/'heldout-example.java').read_text(encoding='utf-8')

    def test_actual_split_has_no_shared_templates_or_sources(self):
        for field in ['group','sha256']:
            train={row[field] for row in self.manifest if row['split']=='train'}
            test={row[field] for row in self.manifest if row['split']=='test'}
            self.assertTrue(train); self.assertTrue(test); self.assertFalse(train & test)

    def test_saved_model_reproduces_recorded_heldout_inference(self):
        evidence=json.loads((self.folder/'heldout-inference.json').read_text(encoding='utf-8'))
        self.assertTrue(any(row['id']==evidence['example_id'] and row['split']=='test' for row in self.manifest))
        actual=predict(self.code,self.model,self.vectorizer,self.metadata)
        self.assertEqual(actual['predicted_category'],evidence['prediction']['predicted_category'])
        self.assertAlmostEqual(actual['probability'],evidence['prediction']['probability'])

    def test_unsupported_language_is_unknown(self):
        self.assertEqual(predict(self.code,self.model,self.vectorizer,self.metadata,language='python')['status'],'unknown')

    def test_unsupported_cwe_is_unknown(self):
        self.assertEqual(predict(self.code,self.model,self.vectorizer,self.metadata,expected_cwe='CWE-999999')['status'],'unknown')

    def test_empty_context_is_unknown(self):
        self.assertEqual(predict('',self.model,self.vectorizer,self.metadata)['status'],'unknown')

    def test_identity_and_comments_cannot_reveal_benchmark_labels(self):
        cleaned=clean_code(self.code)
        self.assertNotIn('BenchmarkTest000',cleaned)
        self.assertNotIn('OWASP Benchmark v1.2',cleaned)
        self.assertEqual(template_group('if (true) { foo("one", 1); }'),template_group('if (false) { bar("two", 9); }'))

if __name__=='__main__': unittest.main()
