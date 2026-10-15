"""Fine-tunes the ProofPatch line locator and evaluates it on the held-out DetectVul test set.

Usage: python train.py [--epochs 4] [--batch 8] [--lr 2e-5]
Writes: models/locator/ (weights + tokenizer + config.json) and results/metrics.json
"""
import argparse
import json
import math
import os
import random
import time

import numpy as np
import torch
from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score, roc_auc_score
from torch.utils.data import DataLoader

from model import BASE, LineLocator, collate, load_tokenizer

ap = argparse.ArgumentParser()
ap.add_argument('--epochs', type=int, default=4)
ap.add_argument('--batch', type=int, default=8)
ap.add_argument('--lr', type=float, default=2e-5)
ap.add_argument('--pos-weight', type=float, default=8.0)
ap.add_argument('--out', default='models/locator')
args = ap.parse_args()

random.seed(7)
np.random.seed(7)
torch.manual_seed(7)
device = 'cuda' if torch.cuda.is_available() else 'cpu'


def load(path):
    return [json.loads(l) for l in open(path, encoding='utf-8')]


train, val, test = load('data/train.jsonl'), load('data/val.jsonl'), load('data/test.jsonl')
tok = load_tokenizer()
mk = lambda rows, shuffle: DataLoader(rows, batch_size=args.batch, shuffle=shuffle, collate_fn=lambda b: collate(tok, b))
model = LineLocator(BASE).to(device)
opt = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=0.01)
steps = args.epochs * math.ceil(len(train) / args.batch)
sched = torch.optim.lr_scheduler.LambdaLR(opt, lambda s: min(1.0, s / max(1, 0.06 * steps)) * max(0.0, (steps - s) / steps))
loss_fn = torch.nn.BCEWithLogitsLoss(pos_weight=torch.tensor(args.pos_weight, device=device), reduction='none')


@torch.no_grad()
def predict(rows):
    model.eval()
    out = []
    for batch in mk(rows, False):
        ids, att, lids, n, labels = (t.to(device) for t in batch)
        with torch.autocast(device_type='cuda', dtype=torch.bfloat16, enabled=device == 'cuda'):
            logits = model(ids, att, lids, n)
        probs = torch.sigmoid(logits.float()).cpu().numpy()
        for b in range(len(n)):
            k = int(n[b])
            out.append((probs[b, :k], labels[b, :k].cpu().numpy()))
    return out


def metrics(preds, threshold=None):
    fn_scores = np.array([p.max() if len(p) else 0 for p, _ in preds])
    fn_truth = np.array([int((l > 0).any()) for _, l in preds])
    line_scores = np.concatenate([p for p, _ in preds])
    line_truth = np.concatenate([(l > 0).astype(int) for _, l in preds])
    if threshold is None:  # choose the function-level threshold that maximises F1
        best = max(np.linspace(0.05, 0.95, 91), key=lambda t: f1_score(fn_truth, fn_scores >= t, zero_division=0))
        threshold = float(best)
    pred = fn_scores >= threshold
    vuln = [(p, l) for p, l in preds if (l > 0).any()]
    top1 = np.mean([l[int(np.argmax(p))] > 0 for p, l in vuln]) if vuln else 0.0
    top3 = np.mean([(l[np.argsort(-p)[:3]] > 0).any() for p, l in vuln]) if vuln else 0.0
    return {
        'threshold': round(threshold, 3),
        'function_precision': round(precision_score(fn_truth, pred, zero_division=0), 4),
        'function_recall': round(recall_score(fn_truth, pred, zero_division=0), 4),
        'function_f1': round(f1_score(fn_truth, pred, zero_division=0), 4),
        'function_roc_auc': round(roc_auc_score(fn_truth, fn_scores), 4),
        'function_pr_auc': round(average_precision_score(fn_truth, fn_scores), 4),
        'line_f1': round(f1_score(line_truth, line_scores >= threshold, zero_division=0), 4),
        'line_pr_auc': round(average_precision_score(line_truth, line_scores), 4),
        'top1_line_hit': round(float(top1), 4),
        'top3_line_hit': round(float(top3), 4),
        'functions': int(len(fn_truth)),
        'vulnerable_functions': int(fn_truth.sum()),
    }


best, history, t0 = None, [], time.time()
for epoch in range(1, args.epochs + 1):
    model.train()
    total = 0.0
    for step, batch in enumerate(mk(train, True)):
        ids, att, lids, n, labels = (t.to(device) for t in batch)
        with torch.autocast(device_type='cuda', dtype=torch.bfloat16, enabled=device == 'cuda'):
            logits = model(ids, att, lids, n)
        mask = labels >= 0
        loss = (loss_fn(logits.float(), labels.clamp(min=0)) * mask).sum() / mask.sum().clamp(min=1)
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        opt.step()
        sched.step()
        opt.zero_grad()
        total += loss.item()
        if step % 100 == 0:
            print(f'epoch {epoch} step {step} loss {loss.item():.4f} ({time.time() - t0:.0f}s)', flush=True)
    val_m = metrics(predict(val))
    history.append({'epoch': epoch, 'train_loss': round(total / (step + 1), 4), **{f'val_{k}': v for k, v in val_m.items()}})
    print(f'== epoch {epoch}: val function F1 {val_m["function_f1"]} PR-AUC {val_m["function_pr_auc"]} top-1 line {val_m["top1_line_hit"]}', flush=True)
    if best is None or val_m['function_pr_auc'] > best['function_pr_auc']:
        best = {**val_m, 'epoch': epoch}
        os.makedirs(args.out, exist_ok=True)
        torch.save(model.state_dict(), os.path.join(args.out, 'locator.pt'))
        tok.save_pretrained(args.out)
        json.dump({'base': BASE, 'threshold': val_m['threshold'], 'max_tokens': 512}, open(os.path.join(args.out, 'config.json'), 'w'))

model.load_state_dict(torch.load(os.path.join(args.out, 'locator.pt'), map_location=device))
test_m = metrics(predict(test), threshold=best['threshold'])
os.makedirs('results', exist_ok=True)
report = {'base_model': BASE, 'train_examples': len(train), 'best_epoch': best['epoch'], 'validation': best,
          'test': test_m, 'history': history, 'train_minutes': round((time.time() - t0) / 60, 1),
          'gpu': torch.cuda.get_device_name(0) if device == 'cuda' else 'cpu'}
json.dump(report, open('results/metrics.json', 'w'), indent=2)
print('TEST', json.dumps(test_m), flush=True)
