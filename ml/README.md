# ProofPatch trained locator (work in progress)

Fine-tunes `microsoft/unixcoder-base` as a line-level vulnerability locator on real Python CVE fixes
(DetectVul/CVEFixes + hitoshura25/cvefixes). Each line is scored; a function's risk = its riskiest line.

```bash
python prepare.py          # builds data/{train,val,test}.jsonl (datasets downloaded separately into data/)
python train.py --epochs 4 # writes models/locator/ and results/metrics.json
echo '{"functions":[{"id":"f","lines":["os.system(cmd)"]}]}' | python score.py
```

Status: data prepared (train 4,256 / val 458 / test 1,146 functions). Training not yet completed.
The API side (`apps/api/src/scanners/locator.ts`) is ready but not wired into the funnel yet;
it stays off unless `DETECTOR_PYTHON` and `DETECTOR_DIR` are set.
Data, model weights and the venv are not committed.
