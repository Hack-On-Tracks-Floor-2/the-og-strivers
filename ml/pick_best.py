"""Compares every finished run and copies the best one (by validation PR-AUC, never test) to models/best."""
import glob
import json
import os
import shutil

rows = []
for f in sorted(glob.glob('results/*.json')):
    r = json.load(open(f))
    if 'validation' not in r:
        continue
    name = os.path.splitext(os.path.basename(f))[0]
    rows.append((name, r))

print(f"{'run':16} {'val PR-AUC':>10} {'test PR-AUC':>11} {'test ROC':>8} {'test F1':>7} {'top-1':>6} {'top-3':>6} {'train':>6}")
for name, r in sorted(rows, key=lambda x: -x[1]['validation']['function_pr_auc']):
    v, t = r['validation'], r['test']
    print(f"{name:16} {v['function_pr_auc']:>10} {t['function_pr_auc']:>11} {t['function_roc_auc']:>8} {t['function_f1']:>7} "
          f"{t['top1_line_hit']:>6} {t['top3_line_hit']:>6} {r['train_examples']:>6}")

if rows:
    name, r = max(rows, key=lambda x: x[1]['validation']['function_pr_auc'])
    src = 'models/locator' if name == 'metrics' else f'models/{name}'
    if os.path.exists(os.path.join(src, 'locator.pt')):
        shutil.copytree(src, 'models/best', dirs_exist_ok=True)
        json.dump({'run': name, **r}, open('results/best.json', 'w'), indent=2)
        print(f'best by validation: {name} -> models/best')
