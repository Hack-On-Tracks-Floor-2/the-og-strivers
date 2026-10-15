"""Portable language-aware inference. Optional disabled-model override is offline only."""
import argparse
import json
import sys
from pathlib import Path
from router import classify

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--language', required=True)
parser.add_argument('--file', type=Path)
parser.add_argument('--allow-disabled-experiment', action='store_true')
args = parser.parse_args()
code = args.file.read_text(encoding='utf-8') if args.file else sys.stdin.read(20001)
print(json.dumps(classify(args.language, code, args.allow_disabled_experiment), indent=2))
