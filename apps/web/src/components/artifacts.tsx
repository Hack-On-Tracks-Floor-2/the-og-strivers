import type { Finding, Patch, VerificationRun, RunEvent } from '@proofpatch/shared';
import { ChevronDown, Download, FileCode2 } from 'lucide-react';
import { Eyebrow, Status, date } from './ui';
import { durationMs, formatDuration, owaspLabel, stageLabels } from '../lib/security-data';
import { PatchWorkspace } from './patches/PatchWorkspace';

export function FindingCard({ finding }: { finding: Finding }) {
  return (
    <article className="panel details finding-card" id={`finding-${finding.id}`}>
      <div className="artifact-heading">
        <div>
          <Eyebrow>
            {finding.cwe ?? 'CWE NOT SUPPLIED'}
            {owaspLabel(finding.cwe) ? ` · ${owaspLabel(finding.cwe)}` : ''}
          </Eyebrow>
          <h2>{finding.category}</h2>
        </div>
        <Status value={finding.severity} />
      </div>
      <div className="finding-location">
        <FileCode2 size={16} />
        <code>
          {finding.file}:{finding.startLine}–{finding.endLine}
        </code>
      </div>
      <div className="finding-source">
        <span>
          Detection source{' '}
          <strong>
            {finding.source === 'scanner+ai'
              ? 'Static scanner + AI'
              : finding.source === 'scanner'
                ? 'Static scanner'
                : 'AI investigation'}
          </strong>
        </span>
        {finding.scanners.length > 0 && (
          <span>
            Detected by <strong>{finding.scanners.join(', ')}</strong>
          </span>
        )}
        <span>
          Model confidence <strong>{Math.round(finding.confidence * 100)}%</strong>
        </span>
      </div>
      <p className="field-help">
        Confidence describes the detection assessment; severity is the backend’s separate risk
        classification.
      </p>
      <div className="finding-body">
        <section>
          <h3>Root cause</h3>
          <p>{finding.rootCause}</p>
        </section>
        <section>
          <h3>Recommended remediation</h3>
          <p>{finding.recommendation}</p>
        </section>
      </div>
      <details className="supporting-evidence">
        <summary>
          Supporting evidence{' '}
          <span>
            {finding.evidence.length} recorded {finding.evidence.length === 1 ? 'item' : 'items'}
          </span>
        </summary>
        {finding.evidence.length ? (
          <ul>
            {finding.evidence.map((text, index) => (
              <li key={index}>{text}</li>
            ))}
          </ul>
        ) : (
          <p>No supporting evidence text was supplied.</p>
        )}
      </details>
      <div className="artifact-reference mono">
        Finding {finding.id} · Run {finding.runId}
      </div>
    </article>
  );
}
// Retained export for any teammate components using the previous entry point.
export function PatchViewer({ patch }: { patch: Patch }) {
  return <PatchWorkspace patch={patch} />;
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
      message: event.message,
      run: event.runId,
      artifact: event.artifactId,
      execution: null as VerificationRun | null,
    })),
    ...verification.map((record) => ({
      id: record.id,
      time: record.createdAt,
      title: stageLabels[record.stage],
      message: '',
      run: record.runId,
      artifact: record.artifactId,
      execution: record,
    })),
  ].sort((a, b) => a.time.localeCompare(b.time) || a.id.localeCompare(b.id));
  return (
    <section className="panel details evidence-timeline">
      {items.map((item) => {
        const record = item.execution;
        const skipped =
          record?.tests && record.tests.total > 0 && record.tests.skipped === record.tests.total;
        const status = skipped ? 'skipped' : record?.status;
        return (
          <details
            className={`timeline-item evidence-disclosure ${status ? `evidence-${status}` : ''}`}
            key={item.id}
            open={status === 'failed' || undefined}
          >
            <summary>
              <span className="timeline-dot" />
              <div className="evidence-summary">
                <h3>{item.title}</h3>
                <time>{date(item.time)}</time>
              </div>
              {status && <Status value={status} />}
              <ChevronDown className="disclosure-chevron" size={16} />
            </summary>
            <div className="evidence-detail">
              {item.message && <p>{item.message}</p>}
              {record && (
                <>
                  <div className="execution-facts">
                    <span>
                      Exit code <strong>{record.exitCode ?? 'Not recorded'}</strong>
                    </span>
                    <span>
                      Duration{' '}
                      <strong>
                        {formatDuration(durationMs(record.createdAt, record.completedAt))}
                      </strong>
                    </span>
                    <span>
                      Patch <code>{record.patchId.slice(0, 8)}</code>
                    </span>
                  </div>
                  {record.stage === 'reproduction' && (
                    <p className="evidence-context">
                      The security test is expected to fail against the current source. A successful
                      reproduction stage records that expected failure; it does not mean the
                      vulnerable code passed a security test.
                    </p>
                  )}
                  {skipped && (
                    <p className="evidence-context">
                      Every test in this stage was skipped. This provides no passing security
                      evidence.
                    </p>
                  )}
                  {record.tests && (
                    <>
                      <div className="test-counts">
                        <span>{record.tests.passed} passed</span>
                        <span>{record.tests.failed} failed</span>
                        <span>{record.tests.errors} errors</span>
                        <span>{record.tests.skipped} skipped</span>
                        <span>{record.tests.total} total</span>
                      </div>
                      <details className="test-case-disclosure">
                        <summary>Individual test outcomes ({record.tests.cases.length})</summary>
                        <ul>
                          {record.tests.cases.map((test, index) => (
                            <li key={`${test.id}:${index}`}>
                              <code>{test.id}</code>
                              <Status value={test.outcome} />
                            </li>
                          ))}
                        </ul>
                      </details>
                    </>
                  )}
                  <h4>Recorded command</h4>
                  <pre className="code-block execution-command">
                    {record.command.length
                      ? record.command.map((argument) => JSON.stringify(argument)).join(' ')
                      : 'No command was recorded.'}
                  </pre>
                  <h4>Execution log</h4>
                  <pre className="code-block execution-log">
                    {record.logs || 'No log content was recorded.'}
                  </pre>
                </>
              )}
              <div className="evidence-references">
                <code>
                  Run {item.run}
                  <br />
                  Record {item.id}
                  {item.artifact && (
                    <>
                      <br />
                      Artifact {item.artifact}
                    </>
                  )}
                </code>
                {item.artifact && /^[0-9a-f]{40}$/.test(item.artifact) && (
                  <a
                    className="button secondary small-button"
                    href={`/api/runs/${item.run}/artifacts/${item.artifact}`}
                    download
                  >
                    <Download size={14} /> Download artifact
                  </a>
                )}
              </div>
            </div>
          </details>
        );
      })}
    </section>
  );
}
