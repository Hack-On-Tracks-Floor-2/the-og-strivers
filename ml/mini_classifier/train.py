"""Train a small, isolated TF-IDF + Logistic Regression OWASP Java baseline."""
import argparse
import csv
import hashlib
import json
import platform
import shutil
import subprocess
import time
import faulthandler
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from common import ROOT, NEGATIVE, clean_code, template_group, predict
faulthandler.dump_traceback_later(30)

import joblib
import numpy as np
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import StratifiedGroupKFold
from threadpoolctl import threadpool_limits

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset',type=Path,default=ROOT/'.data/BenchmarkJava')
    parser.add_argument('--out',type=Path,default=ROOT/'artifacts')
    args=parser.parse_args(); started=time.monotonic()
    dataset=args.dataset.resolve(); output=args.out.resolve(); output.mkdir(parents=True,exist_ok=True)
    csv_path=dataset/'expectedresults-1.2.csv'
    commit=subprocess.check_output(['git','-C',str(dataset),'rev-parse','HEAD'],text=True).strip()
    print('Reading official labeled Java sources at '+commit,flush=True)
    rows=[]; skipped=Counter(); seen={}; contradictions=set()
    for entry in csv.reader(csv_path.read_text(encoding='utf-8-sig').splitlines()):
        if not entry or entry[0].lstrip().startswith('#'): continue
        if len(entry)<4 or entry[2].strip() not in ('true','false') or not entry[3].strip().isdigit():
            skipped['invalid_metadata']+=1; continue
        name,category,truth,cwe=[value.strip() for value in entry[:4]]
        if not name.startswith('BenchmarkTest') or not name.replace('BenchmarkTest','',1).isdigit():
            skipped['invalid_test_name']+=1; continue
        path=dataset/'src/main/java/org/owasp/benchmark/testcode'/f'{name}.java'
        if not path.is_file(): skipped['missing_source']+=1; continue
        original=path.read_text(encoding='utf-8'); code=clean_code(original)
        if len(code)<25: skipped['empty_source']+=1; continue
        label=f'CWE-{cwe}' if truth=='true' else NEGATIVE
        digest=hashlib.sha256(code.encode()).hexdigest()
        if digest in seen:
            skipped['duplicate_normalized_source']+=1
            if seen[digest]!=label: contradictions.add(digest)
            continue
        seen[digest]=label
        rows.append({'id':name,'category':category,'cwe':f'CWE-{cwe}','vulnerable':truth=='true','label':label,'code':code,'sha256':digest,'group':template_group(code),'source':str(path.relative_to(dataset))})
    rows=[row for row in rows if row['sha256'] not in contradictions]
    counts=defaultdict(Counter); groups=defaultdict(set)
    for row in rows:
        counts[row['cwe']][str(row['vulnerable'])]+=1; groups[row['cwe']].add(row['group'])
    eligible=sorted(cwe for cwe,count in counts.items() if count['True']>=30 and count['False']>=30 and len(groups[cwe])>=5)
    excluded={cwe:dict(count) for cwe,count in counts.items() if cwe not in eligible}
    rows=[row for row in rows if row['cwe'] in eligible]
    print(f'Prepared {len(rows)} distinct samples, {len(set(row["group"] for row in rows))} template groups, {len(eligible)} CWE categories.',flush=True)
    if len(eligible)<2: raise RuntimeError('Not enough labeled vulnerable/safe categories to train responsibly.')
    labels=np.array([row['label'] for row in rows]); group_ids=np.array([row['group'] for row in rows]); all_labels=sorted(set(labels))
    splitter=StratifiedGroupKFold(n_splits=5,shuffle=True,random_state=42)
    selection=None
    # Choose the FIRST fold with adequate class support using labels only, never scores.
    for fold,(train,test) in enumerate(splitter.split(np.zeros(len(rows)),labels,group_ids)):
        train_counts=Counter(labels[train]); test_counts=Counter(labels[test])
        if all(train_counts[label]>=10 and test_counts[label]>=5 for label in all_labels):
            selection=(fold,train,test); break
    if selection is None: raise RuntimeError('No group-disjoint split has adequate train/test support for every class.')
    fold,train,test=selection
    assert not set(group_ids[train]) & set(group_ids[test])
    assert not {rows[i]['sha256'] for i in train} & {rows[i]['sha256'] for i in test}
    vectorizer=TfidfVectorizer(token_pattern=r'(?u)[A-Za-z_$][\w$]*|\d+|==|!=|&&|\|\|',lowercase=False,ngram_range=(1,2),min_df=2,max_features=25000,sublinear_tf=True)
    features=vectorizer.fit_transform([rows[i]['code'] for i in train])
    print(f'Fitting {len(train)} training samples; holding out {len(test)} samples.',flush=True)
    model=LogisticRegression(max_iter=400,C=4.0,class_weight='balanced',solver='lbfgs',random_state=42)
    with threadpool_limits(limits=1): model.fit(features,labels[train])
    test_features=vectorizer.transform([rows[i]['code'] for i in test]); predicted=model.predict(test_features)
    precision,recall,f1,_=precision_recall_fscore_support(labels[test],predicted,average='macro',zero_division=0)
    metadata={'supported_cwes':eligible,'negative_label':NEGATIVE,'language':'java','rejection_threshold':0.35,'dataset_commit':commit}
    selective=[predict(rows[i]['code'],model,vectorizer,metadata) for i in test]
    accepted=[index for index,result in enumerate(selective) if result['status']=='predicted']
    report={'trained_at':datetime.now(timezone.utc).isoformat(),'model':'TF-IDF word/code tokens (1–2 grams) + balanced LogisticRegression',
      'dataset':{'repository':'https://github.com/OWASP-Benchmark/BenchmarkJava','version':'1.2','commit':commit,'license':'GPL-2.0-only','labels_file':csv_path.name,'labels_sha256':hashlib.sha256(csv_path.read_bytes()).hexdigest(),'eligible_cwes':eligible,'excluded_cwes':excluded,'counts_before_filter':{key:dict(value) for key,value in counts.items()},'skipped':dict(skipped),'conflicting_duplicates_excluded':len(contradictions)},
      'split':{'method':'StratifiedGroupKFold; abstracted doPost control-flow templates; all identifiers/literals/numbers normalized for grouping','seed':42,'fold':fold,'train_samples':len(train),'test_samples':len(test),'train_groups':len(set(group_ids[train])),'test_groups':len(set(group_ids[test])),'shared_groups':0,'shared_normalized_sources':0,'train_counts':dict(Counter(labels[train])),'test_counts':dict(Counter(labels[test]))},
      'evaluation':{'scope':'Closed-set classification on the untouched grouped test split, including BENCHMARK_NEGATIVE. Not an official OWASP score or a general security detector.','precision_macro':float(precision),'recall_macro':float(recall),'f1_macro':float(f1),'per_class':classification_report(labels[test],predicted,output_dict=True,zero_division=0),'confusion_labels':all_labels,'confusion_matrix':confusion_matrix(labels[test],predicted,labels=all_labels).tolist(),'cli_rejection_threshold':0.35,'cli_accepted_test_samples':len(accepted),'cli_coverage':len(accepted)/len(test),'cli_accepted_accuracy':float(np.mean([selective[k]['predicted_category']==labels[test[k]] for k in accepted])) if accepted else None},
      'environment':{'python':platform.python_version(),'scikit_learn':sklearn.__version__,'numpy':np.__version__,'joblib':joblib.__version__},
      'limitations':['Java OWASP Benchmark templates only; synthetic benchmark examples, not independent real-world projects.','Template grouping reduces but cannot eliminate benchmark-family leakage.','Negative labels only assert absence of the benchmark target weakness, not global safety.','Other CWEs/languages are unsupported; confidence rejection cannot guarantee out-of-distribution detection.','No changes to or integration with existing application security pipelines.'], 'training_seconds':time.monotonic()-started}
    joblib.dump(model,output/'model.joblib',compress=3); joblib.dump(vectorizer,output/'vectorizer.joblib',compress=3)
    (output/'metadata.json').write_text(json.dumps(metadata,indent=2)+'\n',encoding='utf-8')
    (output/'evaluation.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    split_names={int(i):'train' for i in train}; split_names.update({int(i):'test' for i in test})
    manifest=[{**{key:value for key,value in row.items() if key!='code'},'split':split_names[index]} for index,row in enumerate(rows)]
    (output/'split-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
    # Preselected first vulnerable test row, irrespective of prediction correctness.
    example_index=next(int(i) for i in test if rows[i]['vulnerable']); example=rows[example_index]
    shutil.copyfile(dataset/example['source'],output/'heldout-example.java')
    inference={'example_id':example['id'],'split':'test','expected_label':example['label'],'source_sha256':example['sha256'],'prediction':predict(example['code'],model,vectorizer,metadata)}
    (output/'heldout-inference.json').write_text(json.dumps(inference,indent=2)+'\n',encoding='utf-8')
    shutil.copyfile(dataset/'LICENSE',output/'DATASET_LICENSE.txt')
    faulthandler.cancel_dump_traceback_later()
    print(json.dumps({'trained':True,'train_samples':len(train),'test_samples':len(test),'supported_cwes':eligible,'precision_macro':float(precision),'recall_macro':float(recall),'f1_macro':float(f1),'training_seconds':report['training_seconds'],'heldout_inference':inference},indent=2))

if __name__=='__main__': main()
