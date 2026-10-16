import { describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { FindingSchema, PatchSchema, VerificationRunSchema, type FindingML } from '@proofpatch/shared';
import { cweModelInsight, cweReference, mlAnalytics } from '../../apps/web/src/lib/ml-analytics';
const runId=randomUUID(), ownerId=randomUUID(), now='2026-10-16T00:00:00Z';
const finding=(severity='high',cwe:string|null='CWE-89')=>FindingSchema.parse({id:randomUUID(),runId,ownerId,category:'Authorized unit fixture',severity,cwe,file:'src/store.py',startLine:1,endLine:2,confidence:.5,rootCause:'Test',recommendation:'Test',evidence:[],createdAt:now});
const patch=(id:string,attempt=1)=>PatchSchema.parse({id:randomUUID(),runId,ownerId,findingId:id,status:'needs_review',files:[],unifiedDiff:'',attempt,createdAt:now,updatedAt:now});
function proofs(patchId:string) {
  return (['baseline','reproduction','patch_application','security_retest','regression','final_decision'] as const).map(stage=>VerificationRunSchema.parse({id:randomUUID(),runId,ownerId,patchId,stage,status:'passed',exitCode:stage==='reproduction'?1:0,command:['test'],logs:'Actual proof fields required by shared gate (unit fixture).',artifactId:'artifact',createdAt:now,completedAt:now,tests:['patch_application','final_decision'].includes(stage)?null:{total:1,passed:stage==='reproduction'?0:1,failed:stage==='reproduction'?1:0,errors:0,skipped:0,cases:[]}}));
}
describe('run-scoped ML dashboard evidence aggregation',()=>{
  it('deduplicates findings, groups scanner severity/CWE, and rejects foreign runs',()=>{
    const a=finding('critical'),b=finding('high','CWE-22'),c=finding('info',null);
    const result=mlAnalytics(runId,[a,a,b,c,{...a,id:randomUUID(),runId:randomUUID()}],[],[]);
    expect(result.total).toBe(3);expect(result.severities.map(row=>row.count)).toEqual([1,1,0,0]);expect(result.informational).toBe(1);
    expect(result.categories.reduce((sum,row)=>sum+row.count,0)).toBe(3);expect(result.unresolved).toBe(3);
  });
  it('requires every proof, counts failed patches once and excludes pending from the rate',()=>{
    const a=finding(),b=finding(),c=finding(),good=patch(a.id),bad=patch(b.id),pending=patch(c.id);
    const failed=proofs(bad.id).map(row=>['security_retest','regression'].includes(row.stage)?{...row,status:'failed' as const,exitCode:1}:row);
    const result=mlAnalytics(runId,[a,b,c],[good,good,bad,pending],[...proofs(good.id),...failed]);
    expect(result.resolved).toBe(1);expect(result.unresolved).toBe(2);expect(result.pendingFindings).toBe(1);
    expect(result.verified).toBe(1);expect(result.failed).toBe(1);expect(result.pending).toBe(1);expect(result.successRate).toBe(.5);expect(result.concluded).toBe(2);
  });
  it('does not call a proposal, approval without proof or incomplete logs a verified fix',()=>{
    const a=finding(),p=patch(a.id);
    expect(mlAnalytics(runId,[a],[{...p,status:'proposed'}],proofs(p.id)).resolved).toBe(0);
    expect(mlAnalytics(runId,[a],[{...p,status:'approved'}],[]).unavailable).toBe(1);
    const missing=proofs(p.id).map(row=>row.stage==='regression'?{...row,artifactId:null}:row);
    expect(mlAnalytics(runId,[a],[p],missing).successRate).toBeNull();
  });
  it('uses the current patch attempt per finding rather than counting retries as fixes',()=>{
    const a=finding(),first=patch(a.id),next=patch(a.id,2);
    const result=mlAnalytics(runId,[a],[first,next],proofs(first.id));
    expect(result.total).toBe(1);expect(result.verified).toBe(1);expect(result.resolved).toBe(0);expect(result.pendingFindings).toBe(1);
  });
  it('deduplicates recorded patch retries without inferring missing generation attempts',()=>{
    const a=finding(),p=patch(a.id,3);
    expect(mlAnalytics(runId,[a],[p,p],[]).retries).toBe(1);
    expect(mlAnalytics(runId,[a],undefined,[]).retries).toBeNull();
  });
  it('distinguishes successful empty responses from unavailable evidence',()=>{
    const empty=mlAnalytics(runId,[],[],[]);expect(empty.total).toBe(0);expect(empty.verified).toBe(0);expect(empty.successRate).toBeNull();
    const missing=mlAnalytics(runId,[finding()],undefined,undefined);expect(missing.total).toBe(1);expect(missing.resolved).toBeNull();expect(missing.verified).toBeNull();
  });
  it('ignores verification belonging to another run or patch',()=>{
    const a=finding(),p=patch(a.id);
    expect(mlAnalytics(runId,[a],[p],proofs(p.id).map(row=>({...row,runId:randomUUID()}))).resolved).toBe(0);
    expect(mlAnalytics(runId,[a],[p],proofs(randomUUID())).resolved).toBe(0);
  });
  it('keeps trained CWE claims language-bound and compares only actual CWE predictions',()=>{
    const a=finding(); const ml={findingId:a.id,runId,language:'python',prediction:{status:'predicted',cwe:'CWE-89'}} as FindingML;
    expect(cweModelInsight(a,ml).agreement).toBe('Agrees');expect(cweModelInsight({...a,cwe:'CWE-22'},ml).agreement).toBe('Disagrees');
    expect(cweModelInsight(a,{...ml,prediction:{...ml.prediction!,cwe:null}}).agreement).toBe('Not comparable');
    for(const file of ['x.js','x.ts']) {const insight=cweModelInsight({...a,file},ml);expect(insight.supported).toBe(false);expect(insight.prediction).toBeUndefined();}
    expect(cweModelInsight(a,{...ml,runId:randomUUID()}).prediction).toBeUndefined();
  });
  it('excludes foreign-run and unknown-finding patches from outcomes and retries',()=>{
    const a=finding(),p=patch(a.id,2),foreign={...p,id:randomUUID(),runId:randomUUID()},unrelated={...p,id:randomUUID(),findingId:randomUUID()};
    const result=mlAnalytics(runId,[a],[foreign,unrelated],proofs(p.id));
    expect(result.patches).toEqual([]);expect(result.retries).toBe(0);expect(result.verified).toBe(0);expect(result.unresolved).toBe(1);
  });
  it('builds official CWE links only from bounded identifiers',()=>{
    expect(cweReference('CWE-89')).toBe('https://cwe.mitre.org/data/definitions/89.html');
    for(const value of [null,'CVE-2026-1','CWE-0','CWE-89/../../evil','https://example.com','CWE-9999999'])expect(cweReference(value)).toBeNull();
  });
});
