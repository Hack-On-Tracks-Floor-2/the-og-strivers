"""Trusted local JSON-lines worker. Classifies text; never executes Java source."""
import hashlib
import json
import sys
from common import ROOT, predict
import joblib

folder=ROOT/'artifacts'
integrity=json.loads((folder/'integrity.json').read_text(encoding='utf-8'))
for name in ('model.joblib','vectorizer.joblib'):
    if hashlib.sha256((folder/name).read_bytes()).hexdigest()!=integrity[name]:
        raise RuntimeError('Saved classifier integrity check failed.')
model=joblib.load(folder/'model.joblib')
vectorizer=joblib.load(folder/'vectorizer.joblib')
metadata=json.loads((folder/'metadata.json').read_text(encoding='utf-8'))
print(json.dumps({'ready':True}),flush=True)
for line in sys.stdin:
    try:
        if len(line)>200000: raise ValueError('Input is too large.')
        request=json.loads(line)
        code=request['code']
        if not isinstance(code,str) or len(code)>20000: raise ValueError('Invalid source text.')
        result=predict(code,model,vectorizer,metadata,request.get('language','java'))
        print(json.dumps({'id':request['id'],'result':result}),flush=True)
    except Exception:
        print(json.dumps({'id':request.get('id') if isinstance(locals().get('request'),dict) else None,'error':'Classification failed.'}),flush=True)
