import { useState } from 'react';
import type { Finding, Patch, VerificationRun, RunEvent } from '@proofpatch/shared';
import { Eyebrow, Status, date } from './ui';
export function FindingCard({ finding }: { finding: Finding }) {
  return (
    <article className="panel details finding-card">
      <div className="artifact-heading">
        <Eyebrow>{finding.category}</Eyebrow>
        <Status value={finding.severity} />
      </div>
      <h2>
        {finding.file}:{finding.startLine}–{finding.endLine}
      </h2>
      <span className="mono muted">
        {finding.cwe ?? 'CWE N/A'} · CONFIDENCE / {Math.round(finding.confidence * 100)}% · FOUND BY /{' '}
        {finding.source === 'scanner+ai' ? 'SCANNER + AI' : finding.source.toUpperCase()}
      </span>
      <h3>Root cause</h3>
      <p>{finding.rootCause}</p>
      <h3>Supporting evidence</h3>
      <ul>
        {finding.evidence.map((text, i) => (
          <li key={i}>{text}</li>
        ))}
      </ul>
      <h3>Remediation</h3>
      <p>{finding.recommendation}</p>
      <code>
        FINDING / {finding.id} · RUN / {finding.runId}
      </code>
    </article>
  );
}
export function PatchViewer({ patch }: { patch: Patch }) {
  const [tab, setTab] = useState<'diff' | 'original' | 'proposed' | 'security'>('diff');
  const tabs = (['diff', 'original', 'proposed', 'security'] as const).filter(
    (value) => value !== 'security' || !!patch.securityTest,
  );
  return (
    <article className="panel">
      <div className="panel-heading">
        <div>
          <Eyebrow>PATCH / {patch.id.slice(0, 8)}</Eyebrow>
          <h2>Proposed changes</h2>
          <span className="mono muted">ATTEMPT / {patch.attempt}</span>
        </div>
        <Status value={patch.status} />
      </div>
      <div className="code-tabs">
        {tabs.map((value) => (
          <button
            key={value}
            className={tab === value ? 'active' : ''}
            onClick={() => setTab(value)}
          >
            {value === 'diff'
              ? 'Unified diff'
              : value === 'original'
                ? 'Original code'
                : value === 'proposed'
                  ? 'Proposed code'
                  : 'Exploit test'}
          </button>
        ))}
      </div>
      {patch.explanation && <p className="field-help">{patch.explanation}</p>}
      {tab === 'security' && patch.securityTest ? (
        <div>
          <div className="file-path mono">{patch.securityTest.path}</div>
          <p className="field-help">
            Fails on the original code (vulnerability reproduced) and passes on the patch.
          </p>
          <pre className="code-block">{patch.securityTest.content}</pre>
        </div>
      ) : tab === 'diff' ? (
        <pre className="code-block">
          {patch.unifiedDiff.split('\n').map((line, i) => (
            <span
              key={i}
              className={
                line.startsWith('+') ? 'diff-add' : line.startsWith('-') ? 'diff-remove' : ''
              }
            >
              {line}
              {'\n'}
            </span>
          ))}
        </pre>
      ) : (
        patch.files.map((file) => (
          <div key={file.path}>
            <div className="file-path mono">{file.path}</div>
            <pre className="code-block">{tab === 'original' ? file.original : file.proposed}</pre>
          </div>
        ))
      )}
      <div className="artifact-reference mono">
        RUN / {patch.runId} · FINDING / {patch.findingId}
      </div>
    </article>
  );
}
export function EvidenceTimeline({
  events,
  verification,
}: {
  events: RunEvent[];
  verification: VerificationRun[];
}) {
  const items = [
    ...events.map((event) => ({
      id: event.id,
      time: event.createdAt,
      title: event.kind.replaceAll('_', ' '),
      body: event.message,
      run: event.runId,
      artifact: event.artifactId,
      verification: null as VerificationRun | null,
    })),
    ...verification.map((item) => ({
      id: item.id,
      time: item.createdAt,
      title: item.stage.replaceAll('_', ' '),
      body: item.logs,
      run: item.runId,
      artifact: item.artifactId,
      verification: item,
    })),
  ].sort((a, b) => a.time.localeCompare(b.time));
  return (
    <section className="panel details evidence-timeline">
      {items.map((item) => (
        <article className="timeline-item" key={item.id}>
          <span className="timeline-dot" />
          <div className="artifact-heading">
            <h3>{item.title}</h3>
            {item.verification && <Status value={item.verification.status} />}
          </div>
          <time className="mono muted">{date(item.time)}</time>
          <p>{item.body}</p>
          {item.verification && (
            <>
              <div className="mono">EXIT CODE / {item.verification.exitCode ?? 'NOT RECORDED'}</div>
              {item.verification.tests && (
                <div className="mono">
                  TESTS / {item.verification.tests.passed} passed · {item.verification.tests.failed}{' '}
                  failed · {item.verification.tests.errors} errors · {item.verification.tests.skipped}{' '}
                  skipped ({item.verification.tests.total})
                </div>
              )}
              <pre className="code-block">{JSON.stringify(item.verification.command)}</pre>
            </>
          )}
          <code>
            RUN / {item.run}
            <br />
            RECORD / {item.id}
            {item.artifact && (
              <>
                <br />
                ARTIFACT /{' '}
                {/^[0-9a-f]{40}$/.test(item.artifact) ? (
                  <a
                    className="lime-text"
                    href={`/api/runs/${item.run}/artifacts/${item.artifact}`}
                    download
                  >
                    {item.artifact.slice(0, 12)} ↓
                  </a>
                ) : (
                  item.artifact
                )}
              </>
            )}
          </code>
        </article>
      ))}
    </section>
  );
}
