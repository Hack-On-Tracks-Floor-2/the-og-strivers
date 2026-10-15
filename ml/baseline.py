"""Scores an existing public vulnerability classifier on the same held-out Python test set, for comparison.

Usage: python baseline.py <hf-model-id> [--data data]
Function-level only (these models give one score per function, no line locations).
"""
import argparse
import json
import os

import numpy as np
import torch
from sklearn.metrics import average_precision_score, f1_score, roc_auc_score
from transformers import AutoModelForSequenceClassification, AutoTokenizer

ap = argparse.ArgumentParser()
ap.add_argument('model')
ap.add_argument('--test', default='data/test.jsonl')
args = ap.parse_args()
device = 'cuda' if torch.cuda.is_available() else 'cpu'

tok = AutoTokenizer.from_pretrained(args.model)
model = AutoModelForSequenceClassification.from_pretrained(args.model).to(device).eval()
rows = [json.loads(l) for l in open(args.test, encoding='utf-8')]
truth = np.array([int(any(r['labels'])) for r in rows])
scores = []
with torch.no_grad():
    for i in range(0, len(rows), 16):
        texts = ['\n'.join(r['lines']) for r in rows[i:i + 16]]
        enc = tok(texts, truncation=True, max_length=512, padding=True, return_tensors='pt').to(device)
        logits = model(**enc).logits.float()
        p = torch.softmax(logits, -1)[:, -1] if logits.shape[-1] > 1 else torch.sigmoid(logits[:, 0])
        scores += p.cpu().tolist()
scores = np.array(scores)
best_f1 = max(f1_score(truth, scores >= t, zero_division=0) for t in np.linspace(0.05, 0.95, 91))
out = {'model': args.model, 'function_roc_auc': round(roc_auc_score(truth, scores), 4),
       'function_pr_auc': round(average_precision_score(truth, scores), 4),
       'function_f1_best_threshold_on_test': round(float(best_f1), 4), 'functions': len(rows), 'test': args.test}
os.makedirs('results', exist_ok=True)
json.dump(out, open(f"results/baseline_{args.model.replace('/', '_')}_{os.path.basename(args.test)}.json", 'w'), indent=2)
print('BASELINE', json.dumps(out))
