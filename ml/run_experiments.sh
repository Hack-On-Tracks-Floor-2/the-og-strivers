#!/usr/bin/env bash
# Round 3: SVEN re-split by repository (no project in both train and test). Test sets: DetectVul test + data/v5/test_sven.
cd "$(dirname "$0")"
export HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 HF_HOME=D:/hfcache
PY=./.venv/Scripts/python
run() {
  name=$1; shift
  if [ -f "results/$name.json" ]; then echo "skip $name (done)"; return; fi
  echo "### start $name $*"
  $PY -u train.py --name "$name" --out "models/$name" "$@" > "logs/$name.log" 2>&1
  echo "### end $name exit $? $(grep -E '^(TEST|EXTRA)' logs/$name.log | cut -c1-330 | tr '\n' ' ')"
}
mkdir -p logs results
run v5_sven        --data data/v5 --epochs 5
run v6_sven_multi  --data data/v6 --epochs 5
run v6_then_v5     --data data/v5 --epochs 3 --lr 1e-5 --init models/v6_sven_multi/locator.pt
run v5_sven_e8     --data data/v5 --epochs 8 --lr 3e-5
$PY pick_best.py
