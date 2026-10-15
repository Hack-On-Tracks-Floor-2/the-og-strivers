"""Real routing/artifact checks; temporary invalid artifacts are isolated from saved models."""
import json
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import router

class RouterTests(unittest.TestCase):
    def test_java_saved_probability_is_preserved(self):
        folder = router.JAVA / 'artifacts'
        saved = json.loads((folder/'heldout-inference.json').read_text())
        result = router.classify('java', (folder/'heldout-example.java').read_text())
        self.assertEqual(result['cwe'], saved['prediction']['cwe'])
        self.assertAlmostEqual(result['probability'], saved['prediction']['probability'])

    def test_python_saved_probability_is_reproduced(self):
        folder = router.ROOT / 'artifacts/python'
        saved = json.loads((folder/'heldout-inference.json').read_text())
        result = router.classify('python', (folder/'heldout-example.py').read_text())
        self.assertEqual(result['cwe'], saved['prediction']['cwe'])
        self.assertAlmostEqual(result['probability'], saved['prediction']['probability'])

    def test_untrained_languages_do_not_fall_back_to_java(self):
        for language in ['javascript','typescript','ruby','../../java']:
            result = router.classify(language, 'public class Example {}')
            self.assertEqual(result['status'],'unsupported')
            self.assertIsNone(result['cwe'])

    def test_missing_models_are_unknown_without_touching_java(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(router.FOLDERS, {'python':Path(directory)}):
                self.assertEqual(router.classify('python','def f(): return 1')['status'],'unknown')

    def test_disabled_model_cannot_predict_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder/'metadata.json').write_text(json.dumps({'supported_cwes':['CWE-22'],'enabled':False}))
            with patch.dict(router.FOLDERS, {'python':folder}):
                result = router.classify('python','def f(): return 1')
                self.assertEqual(result['status'],'unknown')
                self.assertIsNone(result['probability'])

    def test_corrupted_model_is_rejected_before_loading(self):
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory)
            (folder/'metadata.json').write_text(json.dumps({'supported_cwes':['CWE-22'],'enabled':True}))
            (folder/'integrity.json').write_text(json.dumps({'model.joblib':'not-a-real-hash'}))
            (folder/'model.joblib').write_bytes(b'not trusted pickle content')
            (folder/'vectorizer.joblib').write_bytes(b'also not a pickle')
            original=router._loaded.pop('python',None)
            try:
                with patch.dict(router.FOLDERS, {'python':folder}):
                    with patch.object(router.joblib,'load',side_effect=AssertionError('must not load')) as loader:
                        self.assertEqual(router.classify('python','def f(): return 1')['status'],'unknown')
                        loader.assert_not_called()
            finally:
                if original is not None: router._loaded['python']=original

    def test_verified_artifact_refresh_reloads_cached_models_and_version(self):
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory)
            (folder/'metadata.json').write_text(json.dumps({'supported_cwes':['CWE-22'],'enabled':True}))
            def artifacts(model_bytes):
                values={'model.joblib':model_bytes,'vectorizer.joblib':b'test-only-feature-bytes'}
                for name, content in values.items(): (folder/name).write_bytes(content)
                hashes={name:hashlib.sha256(content).hexdigest() for name,content in values.items()}
                (folder/'integrity.json').write_text(json.dumps(hashes))
                return hashes['model.joblib']
            original=router._loaded.pop('python',None)
            try:
                with patch.dict(router.FOLDERS, {'python':folder}):
                    with patch.object(router.joblib,'load',return_value=object()) as loader:
                        with patch('features.predict_python',side_effect=lambda *_: {'status':'unknown','probability':None}):
                            first_hash=artifacts(b'test-only-first-model')
                            first=router.classify('python','def f(): return 1')
                            router.classify('python','def f(): return 1')
                            self.assertEqual(loader.call_count,2)
                            second_hash=artifacts(b'test-only-second-model')
                            second=router.classify('python','def f(): return 1')
                            self.assertEqual(loader.call_count,4)
                            self.assertIn(first_hash[:12],first['modelVersion'])
                            self.assertIn(second_hash[:12],second['modelVersion'])
                            self.assertNotEqual(first['modelVersion'],second['modelVersion'])
            finally:
                router._loaded.pop('python',None)
                if original is not None: router._loaded['python']=original

if __name__ == '__main__': unittest.main()
