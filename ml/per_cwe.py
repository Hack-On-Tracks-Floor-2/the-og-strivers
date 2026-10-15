"""Per-CWE breakdown of a locator on a held-out set that carries a 'cwe' field (e.g. data/v5/test_sven.jsonl)."""
import json
import os
import sys
from collections import defaultdict

import numpy as np
import torch
from sklearn.metrics import roc_auc_score

from model import LineLocator, collate, load_tokenizer

model_dir, path = sys.argv[1], sys.argv[2]
device = 'cuda' if torch.cuda.is_available() else 'cpu'
cfg = json.load(open(os.path.join(model_dir, 'config.json')))
tok = load_tokenizer(model_dir)
model = LineLocator(cfg['base'])
model.load_state_dict(torch.load(os.path.join(model_dir, 'locator.pt'), map_location=device))
model.to(device).eval()
rows = [json.loads(l) for l in open(path, encoding='utf-8')]
groups = defaultdict(list)
with torch.no_grad():
    for i in range(0, len(rows), 16):
        batch = rows[i:i + 16]
        ids, att, lids, n, labels = (t.to(device) for t in collate(tok, batch))
        with torch.autocast(device_type='cuda', dtype=torch.bfloat16, enabled=device == 'cuda'):
            p = torch.sigmoid(model(ids, att, lids, n).float()).cpu().numpy()
        for b, r in enumerate(batch):
            k = int(n[b])
            groups[r.get('cwe', '?')].append((p[b, :k], labels[b, :k].cpu().numpy()))
out = {}
for cwe, preds in sorted(groups.items()):
    fs = np.array([q.max() for q, _ in preds]); ft = np.array([int((l > 0).any()) for _, l in preds])
    vuln = [(q, l) for q, l in preds if (l > 0).any()]
    out[cwe] = {'vulnerable': len(vuln), 'roc_auc': round(roc_auc_score(ft, fs), 3) if 0 < ft.sum() < len(ft) else None,
                'top1_line_hit': round(float(np.mean([l[int(np.argmax(q))] > 0 for q, l in vuln])), 3) if vuln else None}
print('PERCWE', json.dumps(out))
