"""Fixed, trusted language registry. Source text is never imported or executed."""
import hashlib
import io
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
JAVA = ROOT.parent / 'mini_classifier'
sys.path.insert(0, str(JAVA))
from common import predict as predict_java
import joblib

FOLDERS = {'java': JAVA / 'artifacts', 'python': ROOT / 'artifacts/python'}
_loaded = {}

def classify(language, code, allow_disabled=False):
    language = language.strip().lower()
    result = {'status':'unknown', 'predicted_category':None, 'cwe':None, 'probability':None,
              'language':language, 'supported_cwes':[], 'scope':'Experimental language-specific benchmark classification; not a confirmed vulnerability.'}
    if language not in FOLDERS:
        return {**result, 'status':'unsupported', 'reason':'No evaluated model is registered for this language.'}
    if not isinstance(code, str) or len(code)>20000:
        return {**result, 'reason':'Source must be a string of at most 20,000 characters.'}
    folder = FOLDERS[language]
    try:
        metadata = json.loads((folder / 'metadata.json').read_text(encoding='utf-8'))
        result['supported_cwes'] = metadata['supported_cwes']
        if language != 'java' and not metadata.get('enabled', False) and not allow_disabled:
            return {**result, 'reason':metadata.get('activation_reason', 'The model did not pass the recorded activation quality gate.')}
        integrity = json.loads((folder / 'integrity.json').read_text(encoding='utf-8'))
        blobs = {name:(folder / name).read_bytes() for name in ('model.joblib','vectorizer.joblib')}
        for name, data in blobs.items():
            if hashlib.sha256(data).hexdigest() != integrity[name]:
                raise ValueError('Artifact integrity mismatch')
        fingerprint = (integrity['model.joblib'], integrity['vectorizer.joblib'])
        if language not in _loaded or _loaded[language][0] != fingerprint:
            _loaded[language] = (fingerprint, joblib.load(io.BytesIO(blobs['model.joblib'])), joblib.load(io.BytesIO(blobs['vectorizer.joblib'])))
        _, model, vectorizer = _loaded[language]
        if language == 'java':
            prediction = predict_java(code, model, vectorizer, metadata, language='java')
        else:
            from features import predict_python
            prediction = predict_python(code, model, vectorizer, metadata)
        prediction['modelVersion'] = f"owasp-{language}-{'1.2' if language=='java' else '0.1'}-{integrity['model.joblib'][:12]}"
        prediction['confirmed'] = False
        if prediction.get('probability') is not None: prediction['probabilityKind'] = 'uncalibrated'
        if allow_disabled and language != 'java' and not metadata.get('enabled', False):
            prediction['experimental_override'] = True
        return prediction
    except Exception:
        return {**result, 'reason':'The trusted model artifacts or dependencies are unavailable or invalid.'}
