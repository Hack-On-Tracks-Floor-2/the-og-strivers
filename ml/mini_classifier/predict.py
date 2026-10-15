"""Predict a Java snippet from --file or stdin; JSON output, no server required."""
import argparse
import json
import sys
from pathlib import Path
from common import ROOT, predict
import joblib

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--file',type=Path)
    parser.add_argument('--language',default='java')
    parser.add_argument('--cwe',help='Optional expected category; unsupported CWEs return unknown.')
    parser.add_argument('--artifacts',type=Path,default=ROOT/'artifacts')
    args=parser.parse_args()
    code=args.file.read_text(encoding='utf-8') if args.file else sys.stdin.read(200001)
    if len(code)>200000: raise SystemExit('Input exceeds the 200,000-character limit.')
    if not (args.artifacts/'metadata.json').exists(): raise SystemExit('No trained model found. Run train.py first.')
    metadata=json.loads((args.artifacts/'metadata.json').read_text(encoding='utf-8'))
    # Only load trusted artifacts produced by the local training command.
    model=joblib.load(args.artifacts/'model.joblib'); vectorizer=joblib.load(args.artifacts/'vectorizer.joblib')
    print(json.dumps(predict(code,model,vectorizer,metadata,args.language,args.cwe),indent=2))

if __name__=='__main__': main()
