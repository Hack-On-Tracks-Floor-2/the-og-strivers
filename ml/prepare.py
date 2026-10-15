"""Builds the line-level training data for the ProofPatch vulnerability locator.

Sources (all public):
  * DetectVul/CVEFixes (Python, statement-level labels) - train split for training,
    test split kept untouched as the benchmark.
  * hitoshura25/cvefixes (real CVE fix commits) - Python rows only. Lines removed by the
    real fix are labelled vulnerable; the fixed version is added as a clean example.
Output: data/train.jsonl, data/val.jsonl, data/test.jsonl with {"lines": [...], "labels": [...], "source": ...}
"""
import argparse
import glob
import json
import os
import random

import pandas as pd
import pyarrow.parquet as pq

from normalize import statements

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


def from_cvefixes(langs):
    out = []
    for f in sorted(glob.glob('data/hit_train-*.parquet')):
        try:
            t = pq.read_table(f, columns=['language', 'cwe_id', 'vulnerable_code', 'fixed_code']).to_pandas()
        except Exception:
            continue
        for _, r in t[t.language.isin(langs)].iterrows():
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
                    out.append({'lines': lines, 'labels': labs, 'source': 'cvefixes', 'lang': r['language'], 'cwe': r['cwe_id']})
            if fixed:
                out.append({'lines': fixed[:MAX_LINES], 'labels': [0] * min(len(fixed), MAX_LINES), 'source': 'cvefixes-fixed', 'lang': r['language']})
    return out


def label_statements(source, deleted_lines):
    """Converts a function to the trained statement format; a statement is vulnerable if a deleted line falls in it."""
    st = statements(source, 1)
    if not st:
        return None
    starts = [n for _, n in st]
    labels = [0] * len(st)
    for d in deleted_lines:
        owner = max((i for i, n in enumerate(starts) if n <= d), default=None)
        if owner is not None:
            labels[owner] = 1
    return [t for t, _ in st], labels


def from_sven():
    """SVEN (eth-sri/sven, MIT): real Python security fixes, CWE-022/078/079/089, line-level diffs.
    SVEN's own train/val split shares commits, so both are pooled and re-split by repository here."""
    out = []
    for f in sorted(glob.glob('data/sven/*-cwe-*.jsonl')):
        for line in open(f, encoding='utf-8'):
            r = json.loads(line)
            if not r['file_name'].endswith('.py'):
                continue
            vuln = label_statements(r['func_src_before'], [d['line_no'] for d in r['line_changes']['deleted']])
            fixed = label_statements(r['func_src_after'], [])
            repo =r['commit_link'].split('/commit/')[0]
            if vuln and any(vuln[1]):
                out.append({'lines': vuln[0], 'labels': vuln[1], 'source': 'sven', 'cwe': r['vul_type'], 'repo': repo})
            if fixed:
                out.append({'lines': fixed[0], 'labels': fixed[1], 'source': 'sven-fixed', 'cwe': r['vul_type'], 'repo': repo})
    return out


def write(path, rows):
    with open(path, 'w', encoding='utf-8') as fh:
        for r in rows:
            fh.write(json.dumps(r) + '\n')


def key(r):
    return ''.join(''.join(r['lines']).split())


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--langs', default='Python', help='comma-separated cvefixes languages')
    ap.add_argument('--out', default='data')
    ap.add_argument('--sven', action='store_true', help='add SVEN train; SVEN val becomes a second test set')
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    dv_train = from_detectvul('data/dv_train.parquet')
    dv_test = from_detectvul('data/dv_test.parquet')
    cve = from_cvefixes(args.langs.split(','))
    held_out = {key(r) for r in dv_test}
    before = len(cve)
    cve = [r for r in cve if key(r) not in held_out]  # never train on a held-out test function
    random.shuffle(dv_train)
    n_val = len(dv_train) // 10
    val, train = dv_train[:n_val], [r for r in dv_train[n_val:] if key(r) not in held_out] + cve
    if args.sven:
        pool = from_sven()
        repos = sorted({r['repo'] for r in pool})
        random.Random(11).shuffle(repos)
        test_repos, n = set(), 0
        for repo in repos:  # hold out whole repositories until ~20% of SVEN functions are test
            if n >= 0.2 * len(pool):
                break
            test_repos.add(repo)
            n += sum(1 for r in pool if r['repo'] == repo)
        sven_test = [r for r in pool if r['repo'] in test_repos]
        sven = [r for r in pool if r['repo'] not in test_repos and key(r) not in held_out]
        sven_keys = {key(r) for r in sven_test}
        train = [r for r in train if key(r) not in sven_keys] + sven
        write(f'{args.out}/test_sven.jsonl', sven_test)
        print(f'sven train {len(sven)} ({sum(1 for r in sven if any(r["labels"]))} vulnerable) | sven test {len(sven_test)} ({sum(1 for r in sven_test if any(r["labels"]))} vulnerable) from {len(test_repos)} held-out repos of {len(repos)}')
    random.shuffle(train)
    write(f'{args.out}/train.jsonl', train)
    write(f'{args.out}/val.jsonl', val)
    write(f'{args.out}/test.jsonl', dv_test)
    pos = lambda rows: sum(1 for r in rows if any(r['labels']))
    print(f'train {len(train)} ({pos(train)} vulnerable) | val {len(val)} ({pos(val)}) | test {len(dv_test)} ({pos(dv_test)})')
    print(f'cvefixes-derived examples: {len(cve)} ({pos(cve)} vulnerable), {before - len(cve)} dropped as test duplicates')
    langs = {}
    for r in cve:
        langs[r.get('lang')] = langs.get(r.get('lang'), 0) + 1
    print('by language', langs)
