"""Builds the line-level training data for the ProofPatch vulnerability locator.

Sources (all public):
  * DetectVul/CVEFixes (Python, statement-level labels) - train split for training,
    test split kept untouched as the benchmark.
  * hitoshura25/cvefixes (real CVE fix commits) - Python rows only. Lines removed by the
    real fix are labelled vulnerable; the fixed version is added as a clean example.
Output: data/train.jsonl, data/val.jsonl, data/test.jsonl with {"lines": [...], "labels": [...], "source": ...}
"""
import difflib
import glob
import json
import random

import pandas as pd
import pyarrow.parquet as pq

random.seed(7)
MAX_LINES = 60


def clean(lines):
    return [l.rstrip() for l in lines if l.strip()]


def from_detectvul(path):
    out = []
    for _, r in pd.read_parquet(path).iterrows():
        lines = [str(l) for l in r['raw_lines']]
        labels = [int(x) for x in r['label']]
        if not lines:
            continue
        out.append({'lines': lines[:MAX_LINES], 'labels': labels[:MAX_LINES], 'source': 'detectvul'})
    return out


def from_cvefixes():
    out = []
    for f in sorted(glob.glob('data/hit_train-*.parquet')):
        try:
            t = pq.read_table(f, columns=['language', 'cwe_id', 'vulnerable_code', 'fixed_code']).to_pandas()
        except Exception:
            continue
        for _, r in t[t.language == 'Python'].iterrows():
            vuln = clean(str(r['vulnerable_code'] or '').splitlines())
            fixed = clean(str(r['fixed_code'] or '').splitlines())
            if len(vuln) < 3 or len(vuln) > 400:
                continue
            fixed_set = set(l.strip() for l in fixed)
            labels = [0 if l.strip() in fixed_set else 1 for l in vuln]
            if not any(labels) or sum(labels) > 0.6 * len(labels):
                continue  # no removed lines, or a wholesale rewrite: not a precise label
            # cut long hunks into windows around the vulnerable lines
            for start in range(0, len(vuln), MAX_LINES):
                lines, labs = vuln[start:start + MAX_LINES], labels[start:start + MAX_LINES]
                if any(labs):
                    out.append({'lines': lines, 'labels': labs, 'source': 'cvefixes', 'cwe': r['cwe_id']})
            if fixed:
                out.append({'lines': fixed[:MAX_LINES], 'labels': [0] * min(len(fixed), MAX_LINES), 'source': 'cvefixes-fixed'})
    return out


def write(path, rows):
    with open(path, 'w', encoding='utf-8') as fh:
        for r in rows:
            fh.write(json.dumps(r) + '\n')


if __name__ == '__main__':
    dv_train = from_detectvul('data/dv_train.parquet')
    dv_test = from_detectvul('data/dv_test.parquet')
    cve = from_cvefixes()
    random.shuffle(dv_train)
    n_val = len(dv_train) // 10
    val, train = dv_train[:n_val], dv_train[n_val:] + cve
    random.shuffle(train)
    write('data/train.jsonl', train)
    write('data/val.jsonl', val)
    write('data/test.jsonl', dv_test)
    pos = lambda rows: sum(1 for r in rows if any(r['labels']))
    print(f'train {len(train)} ({pos(train)} vulnerable) | val {len(val)} ({pos(val)}) | test {len(dv_test)} ({pos(dv_test)})')
    print(f'cvefixes-derived examples: {len(cve)} ({pos(cve)} vulnerable)')
