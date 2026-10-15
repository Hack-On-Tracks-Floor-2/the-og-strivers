"""Scores code with the trained ProofPatch line locator.

stdin:  {"functions": [{"id": "...", "source": "def f(...):
 ...", "start": 14}, ...]}  (or "lines": [...] pre-split)
stdout: {"scores": [{"id": "...", "score": 0.93, "lines": [0.01, 0.93, ...], "line_numbers": [14, 16, ...]}], ...}
Raw source is converted to the trained statement format first (normalize.py).
Reads source text only; never imports or executes the scanned code.
"""
import json
import os
import sys

import torch

from model import LineLocator, collate, load_tokenizer
from normalize import statements

MODEL_DIR = os.environ.get('DETECTOR_MODEL', os.path.join(os.path.dirname(__file__), 'models', 'locator'))


def main():
    request = json.load(sys.stdin)
    config = json.load(open(os.path.join(MODEL_DIR, 'config.json')))
    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    tok = load_tokenizer(MODEL_DIR)
    model = LineLocator(config['base'])
    model.load_state_dict(torch.load(os.path.join(MODEL_DIR, 'locator.pt'), map_location=device))
    model.to(device).eval()
    fns = []
    for fn in request.get('functions', []):
        if 'source' in fn:
            st = statements(fn['source'], fn.get('start', 1))
            if not st:
                continue  # does not parse as a function: skip rather than guess
            fns.append({'id': fn['id'], 'lines': [t for t, _ in st], 'line_numbers': [n for _, n in st]})
        else:
            fns.append(fn)
    out = []
    with torch.no_grad():
        for i in range(0, len(fns), 16):
            batch = fns[i : i + 16]
            ids, att, lids, n, _ = (t.to(device) for t in collate(tok, batch))
            with torch.autocast(device_type='cuda', dtype=torch.bfloat16, enabled=device == 'cuda'):
                logits = model(ids, att, lids, n)
            probs = torch.sigmoid(logits.float()).cpu()
            for b, fn in enumerate(batch):
                k = int(n[b])
                lines = [round(float(x), 4) for x in probs[b, :k]]
                row = {'id': fn['id'], 'score': max(lines) if lines else 0.0, 'lines': lines}
                if 'line_numbers' in fn:
                    row['line_numbers'] = fn['line_numbers'][:k]
                out.append(row)
    json.dump({'scores': out, 'threshold': config['threshold'], 'device': device}, sys.stdout)


if __name__ == '__main__':
    main()
