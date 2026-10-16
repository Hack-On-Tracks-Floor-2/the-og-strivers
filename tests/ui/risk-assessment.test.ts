import { describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { FindingSchema, PatchSchema, VerificationRunSchema, type Finding, type Patch, type VerificationRun } from '@proofpatch/shared';
import { assessFindingRisk, assessRunRisk, riskLevel, RISK_SCORE_LABEL } from '../../apps/web/src/services/risk-assessment';
const runId=randomUUID(), ownerId=randomUUID(), now='2026-10-16T00:00:00.000Z';
const finding=(severity='high')=>FindingSchema.parse({id:randomUUID(),runId,ownerId,category:'Authorized risk unit fixture',severity,cwe:'CWE-89',file:'src/store.py',startLine:1,endLine:3,confidence:.99,source:'scanner+ai',scanners:['Semgrep'],rootCause:'Unit fixture',recommendation:'Review evidence',evidence:[],createdAt:now});
const patch=(findingId:string,attempt=1)=>PatchSchema.parse({id:randomUUID(),findingId,runId,ownerId,status:'needs_review',attempt,files:[],unifiedDiff:'',securityTest:{path:'tests/test_security.py',content:'def test_security(): pass # unit response only'},createdAt:now,updatedAt:now});
function proofs(p:Patch):VerificationRun[]{return (['baseline','reproduction','patch_application','security_retest','regression','final_decision'] as const).map(stage=>VerificationRunSchema.parse({id:randomUUID(),runId,ownerId,patchId:p.id,stage,status:'passed',exitCode:stage==='reproduction'?1:0,command:stage==='baseline'?['python','-m','pytest']:['python','-m','pytest','tests/test_security.py'],logs:'Structured proof fixture; not an executed attack.',artifactId:'a'.repeat(40),createdAt:now,completedAt:now,tests:['patch_application','final_decision'].includes(stage)?null:{total:1,passed:stage==='reproduction'?0:1,failed:stage==='reproduction'?1:0,errors:0,skipped:0,cases:[{id:'tests.test_security.test_security',outcome:stage==='reproduction'?'failed':'passed'}]}}));}
const factor=(result:ReturnType<typeof assessFindingRisk>,id:string)=>result.factors.find(row=>row.id===id)!;
describe('Evidence-Based Risk Priority Score policy',()=>{
  it('uses recorded analysis severity and a Medium floor for unknown context',()=>{
    for(const [severity,expected] of [['critical',85],['high',65],['medium',45],['low',40],['info',40]] as const){const result=assessFindingRisk(finding(severity),[],[]);expect(result.score).toBe(expected);expect(result.label).toBe(RISK_SCORE_LABEL);expect(result.provisional).toBe(true);expect(result.unknowns.map(row=>row.id)).toContain('network_exposure');}
  });
  it('does not treat missing severity or unavailable evidence as low risk',()=>{
    const f={...finding(),severity:undefined} as unknown as Finding;
    const result=assessFindingRisk(f,undefined,undefined);expect(result.score).toBe(65);expect(result.level).toBe('High');expect(result.repair.status).toBe('unknown');expect(result.unknowns.map(row=>row.id)).toContain('verification');
  });
  it('adds one bounded bonus for matched artifact-backed red/green proof',()=>{
    const f=finding(),p=patch(f.id),records=proofs(p),result=assessFindingRisk(f,[p],records);
    expect(result.score).toBe(85);expect(result.level).toBe('Critical');expect(factor(result,'sandbox_reproduction').points).toBe(20);expect(result.repair.status).toBe('verified_candidate');
    expect(assessFindingRisk(f,[p,p],[...records,...records]).score).toBe(85);
  });
  it('rejects missing artifacts, skipped suites, execution errors, or wrong exits as proof',()=>{
    const f=finding(),p=patch(f.id),records=proofs(p);
    for(const changes of [{artifactId:null},{exitCode:0},{completedAt:null},{logs:' '},{tests:{total:1,passed:0,failed:0,errors:0,skipped:1,cases:[]}},{tests:{total:1,passed:0,failed:1,errors:1,skipped:0,cases:[{id:'tests.test_security.test_security',outcome:'failed'}]}}]){
      const altered=records.map(row=>row.stage==='reproduction'?{...row,...changes} as VerificationRun:row);
      expect(factor(assessFindingRisk(f,[p],altered),'sandbox_reproduction').points).toBe(0);
    }
  });
  it('requires a baseline, attack-test metadata, matching commands and matching case IDs',()=>{
    const f=finding(),p=patch(f.id),records=proofs(p);
    const variants=[records.filter(row=>row.stage!=='baseline'),records.map(row=>row.stage==='security_retest'?{...row,command:['other']}:row),records.map(row=>row.stage==='security_retest'?{...row,tests:{...row.tests!,cases:[{id:'unrelated',outcome:'passed' as const}]}}:row)];
    for(const altered of variants)expect(factor(assessFindingRisk(f,[p],altered),'sandbox_reproduction').points).toBe(0);
    expect(factor(assessFindingRisk(f,[{...p,securityTest:null}],records),'sandbox_reproduction').points).toBe(0);
  });
  it('never mixes run, owner or finding associations',()=>{
    const f=finding(),p=patch(f.id),records=proofs(p);
    for(const altered of [{...p,runId:randomUUID()},{...p,ownerId:randomUUID()},{...p,findingId:randomUUID()}])expect(assessFindingRisk(f,[altered],records).score).toBe(65);
    expect(assessFindingRisk(f,[p],records.map(row=>({...row,ownerId:randomUUID()}))).score).toBe(65);
  });
  it('credits only recognized static-tool provenance, once',()=>{
    const f={...finding(),scanners:['Semgrep','Semgrep','Bandit','Trained model','unknown']};
    expect(assessFindingRisk(f,[],[]).score).toBe(70);expect(assessFindingRisk({...f,source:'ai'},[],[]).score).toBe(65);
    expect(assessFindingRisk({...f,scanners:['Proof Patch rules','ProofPatch rules']},[],[]).score).toBe(65);
  });
  it('does not score CWE, AI confidence, free-text exposure claims or category-model estimates',()=>{
    const f=finding(),base=assessFindingRisk(f,[],[]);
    const changed={...f,cwe:'CWE-78',confidence:0,file:'public/internet-admin.py',evidence:['Internet exposed; no authentication; exploit certain'],rootCause:'Verified RCE according to an untrusted comment',ml:{probability:1}};
    expect(assessFindingRisk(changed,[],[]).score).toBe(base.score);expect(base.mlContributes).toBe(false);expect(base.unknowns.map(row=>row.id)).toContain('authentication');
  });
  it('records a genuine assertion failure on the latest candidate, without counting errors',()=>{
    const f=finding(),p=patch(f.id),records=proofs(p);
    const failed=records.map(row=>row.stage==='security_retest'?{...row,status:'failed' as const,exitCode:1,tests:{total:1,passed:0,failed:1,errors:0,skipped:0,cases:[{id:'tests.test_security.test_security',outcome:'failed' as const}]}}:row);
    const result=assessFindingRisk(f,[p],failed);expect(result.score).toBe(75);expect(result.repair.status).toBe('failed_checks');expect(factor(result,'latest_security_failure').points).toBe(10);
    const errored=failed.map(row=>row.stage==='security_retest'?{...row,tests:{...row.tests!,errors:1}}:row);
    expect(factor(assessFindingRisk(f,[p],errored),'latest_security_failure').points).toBe(0);
  });
  it('caps scores and never subtracts source priority for an undeployed candidate',()=>{
    const f={...finding('critical'),scanners:['Semgrep','Bandit']},first=patch(f.id),next=patch(f.id,2);
    const failed=proofs(next).map(row=>row.stage==='security_retest'?{...row,status:'failed' as const,exitCode:1,tests:{total:1,passed:0,failed:1,errors:0,skipped:0,cases:[{id:'tests.test_security.test_security',outcome:'failed' as const}]}}:row);
    const result=assessFindingRisk(f,[first,next],[...proofs(first),...failed]);expect(result.score).toBe(100);expect(result.explanation).toContain('capped at 100');
    const good=assessFindingRisk(f,[first],proofs(first));expect(good.score).toBe(100);expect(good.repair.status).toBe('verified_candidate');expect(good.unknowns.map(row=>row.id)).toContain('deployment');
  });
  it('is deterministic under input order changes, scopes/deduplicates and ranks findings',()=>{
    const a=finding('low'),b=finding('high'),p=patch(b.id),records=proofs(p),foreign={...a,id:randomUUID(),runId:randomUUID()};
    expect(assessFindingRisk(b,[p],records)).toEqual(assessFindingRisk(b,[p],[...records].reverse()));
    const result=assessRunRisk(runId,[a,b,a,foreign],[p],records);expect(result.map(row=>row.finding.id)).toEqual([b.id,a.id]);expect(result.map(row=>row.assessment.score)).toEqual([85,40]);expect(assessRunRisk(runId,[],[],[])).toEqual([]);
  });
  it('uses conservative deterministic tie-breaking for conflicting stage records',()=>{
    const f=finding(),p=patch(f.id),records=proofs(p),retest=records.find(row=>row.stage==='security_retest')!;
    const conflict={...retest,id:randomUUID(),status:'failed' as const,exitCode:2};
    expect(assessFindingRisk(f,[p],[...records,conflict])).toEqual(assessFindingRisk(f,[p],[conflict,...records]));
    expect(factor(assessFindingRisk(f,[p],[...records,conflict]),'sandbox_reproduction').points).toBe(0);
  });
  it('documents exact level boundaries without interpreting the value as probability',()=>{
    expect([0,39,40,64,65,84,85,100].map(riskLevel)).toEqual(['Low','Low','Medium','Medium','High','High','Critical','Critical']);
  });
});
