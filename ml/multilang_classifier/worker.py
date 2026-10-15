"""Bounded JSON-lines worker; no caller-supplied commands, modules or model paths."""
import json
import sys
from router import classify

print(json.dumps({'ready':True}), flush=True)
for line in sys.stdin:
    request = None
    try:
        if len(line) > 200000: raise ValueError('Request too large')
        request = json.loads(line)
        if not isinstance(request, dict): raise ValueError('Object required')
        if not isinstance(request.get('language'), str): raise ValueError('Language required')
        if not isinstance(request.get('code'), str) or len(request['code']) > 20000: raise ValueError('Invalid source')
        print(json.dumps({'id':request['id'],'result':classify(request['language'],request['code'])}), flush=True)
    except Exception:
        print(json.dumps({'id':request.get('id') if isinstance(request,dict) else None,'error':'Classification failed.'}), flush=True)
