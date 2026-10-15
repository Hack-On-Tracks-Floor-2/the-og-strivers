"""Evaluates a saved locator on any held-out set; can drop rows that also appear in a training file (leakage).

Usage: python evaluate.py models/locator data/test.jsonl [--exclude data/v1_leaky/train.jsonl]
"""
import argparse
import json
import os
import sys

import torch

_argv = sys.argv
ap = argparse.ArgumentParser()
ap.add_argument('model_dir')
ap.add_argument('test', nargs='+')
ap.add_argument('--exclude', default=None)
args = ap.parse_args(_argv[1:])

from model import LineLocator, collate, load_tokenizer  # noqa: E402
import numpy as np  # noqa: E402
from sklearn.metrics import average_precision_score, f1_score, roc_auc_score  # noqa: E402

device = 'cuda' if torch.cuda.is_available() else 'cpu'
cfg = json.load(open(os.path.join(args.model_dir, 'config.json')))
tok = load_tokenizer(args.model_dir)
model = LineLocator(cfg['base'])
model.load_state_dict(torch.load(os.path.join(args.model_dir, 'locator.pt'), map_location=device))
model.to(device).eval()
key = lambda r: ''.join(''.join(r['lines']).split())
banned = set()
if args.exclude:
    banned = {key(json.loads(l)) for l in open(args.exclude, encoding='utf-8')}

for path in args.test:
    rows = [json.loads(l) for l in open(path, encoding='utf-8')]
    rows = [r for r in rows if key(r) not in banned]
    preds = []
    with torch.no_grad():
        for i in range(0, len(rows), 16):
            ids, att, lids, n, labels = (t.to(device) for t in collate(tok, rows[i:i + 16]))
            with torch.autocast(device_type='cuda', dtype=torch.bfloat16, enabled=device == 'cuda'):
                p = torch.sigmoid(model(ids, att, lids, n).float()).cpu().numpy()
            for b in range(len(n)):
                k = int(n[b])
                preds.append((p[b, :k], labels[b, :k].cpu().numpy()))
    fs = np.array([p.max() for p, _ in preds]); ft = np.array([int((l > 0).any()) for _, l in preds])
    vuln = [(p, l) for p, l in preds if (l > 0).any()]
    th = cfg['threshold']
    print('EVAL', json.dumps({'model': args.model_dir, 'set': path, 'functions': len(rows), 'vulnerable': int(ft.sum()),
        'roc_auc': round(roc_auc_score(ft, fs), 4), 'pr_auc': round(average_precision_score(ft, fs), 4),
        'f1_at_val_threshold': round(f1_score(ft, fs >= th, zero_division=0), 4),
        'top1_line_hit': round(float(np.mean([l[int(np.argmax(p))] > 0 for p, l in vuln])), 4),
        'top3_line_hit': round(float(np.mean([(l[np.argsort(-p)[:3]] > 0).any() for p, l in vuln])), 4)}))
