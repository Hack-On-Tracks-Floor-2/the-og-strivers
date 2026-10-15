import { useState, type FormEvent } from 'react';
import {
  MLModelInfoSchema,
  MLPredictionSchema,
  MLExampleSchema,
  type MLPrediction,
} from '@proofpatch/shared';
import { api } from '../lib/api';
import { useResource } from '../hooks/useResource';
import { PageTitle, ErrorBox, Loading, Status, date } from '../components/ui';

const percent = (value: number) => `${(value * 100).toFixed(2)}%`;
export function MLIntelligencePage() {
  const info = useResource(() => api('/ml/model-info', MLModelInfoSchema));
  const [code, setCode] = useState('');
  const [language, setLanguage] = useState('java');
  const [result, setResult] = useState<MLPrediction>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [example, setExample] = useState('');
  async function loadExample() {
    setError('');
    try {
      const saved = await api('/ml/example', MLExampleSchema);
      setCode(saved.code);
      setLanguage('java');
      setResult(undefined);
      setExample(`${saved.exampleId} · official held-out label: ${saved.expectedLabel}`);
    } catch (cause) {
      setError((cause as Error).message);
    }
  }
  async function classify(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError('');
    setResult(undefined);
    try {
      setResult(await api('/ml/classify', MLPredictionSchema, { code, language }));
    } catch (cause) {
      setError((cause as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <PageTitle
        eyebrow="EXPERIMENTAL / JAVA CLASSIFICATION"
        title="ML INTELLIGENCE"
        description="Inspect the trained OWASP baseline and run a genuine server-side classification. This does not confirm a vulnerability."
      />
      {info.loading ? (
        <Loading />
      ) : info.error ? (
        <ErrorBox message={info.error} retry={info.reload} />
      ) : (
        info.data && (
          <>
            <section className="panel details">
              <div className="section-header">
                <div>
                  <span className="eyebrow">SAVED TRAINED MODEL</span>
                  <h2>{info.data.model}</h2>
                </div>
                <Status
                  value={info.data.availability === 'available' ? 'available' : 'not_configured'}
                />
              </div>
              <p>
                OWASP Benchmark Java {info.data.dataset.version} ·{' '}
                {info.data.training.trainSamples.toLocaleString()} training examples ·{' '}
                {info.data.training.testSamples.toLocaleString()} held-out examples. Template-group
                overlap: {info.data.training.sharedGroups}.
              </p>
              <dl>
                <dt>Model version</dt>
                <dd>
                  <code>{info.data.modelVersion}</code>
                </dd>
                <dt>Dataset commit</dt>
                <dd>
                  <a
                    href={`${info.data.dataset.repository}/commit/${info.data.dataset.commit}`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    <code>{info.data.dataset.commit}</code>
                  </a>
                </dd>
                <dt>Trained</dt>
                <dd>{date(info.data.trainedAt)}</dd>
                <dt>Supported categories</dt>
                <dd>{info.data.supportedCwes.join(' · ')} · Benchmark negative</dd>
                <dt>Dataset license</dt>
                <dd>{info.data.dataset.license}</dd>
              </dl>
              {info.data.reason && <p role="status">{info.data.reason}</p>}
            </section>
            <div className="repository-metrics">
              {[
                ['Macro precision', info.data.metrics.precisionMacro],
                ['Macro recall', info.data.metrics.recallMacro],
                ['Macro F1', info.data.metrics.f1Macro],
                ['Negative-example recall', info.data.metrics.negativeRecall],
              ].map(([label, value]) => (
                <div className="repository-metric" key={label}>
                  <span>{label}</span>
                  <strong>{percent(Number(value))}</strong>
                  <small>Recorded grouped hold-out evaluation</small>
                </div>
              ))}
            </div>
            <p className="scope-explanation">
              These scores apply to this Java benchmark. Limited negative-example recall means some
              benchmark-negative examples are incorrectly classified as weaknesses. No
              cross-language or production accuracy is claimed.
            </p>
            <section className="panel details">
              <div className="section-header">
                <div>
                  <span className="eyebrow">REAL MODEL INFERENCE</span>
                  <h2>Classify a Java snippet</h2>
                </div>
                <button
                  className="button secondary small-button"
                  onClick={loadExample}
                  disabled={busy}
                >
                  Load held-out example
                </button>
              </div>
              <p>
                Submitted source is treated as text and is never executed. The first prediction may
                take a moment while Python loads the saved model.
              </p>
              <form onSubmit={classify}>
                <label>
                  Source language
                  <select
                    value={language}
                    disabled={busy}
                    onChange={(event) => {
                      setLanguage(event.target.value);
                      setResult(undefined);
                    }}
                  >
                    <option value="java">Java</option>
                    <option value="python">Python — unsupported</option>
                    <option value="javascript">JavaScript — unsupported</option>
                  </select>
                </label>
                <label className="ml-code-label">
                  Source code
                  <textarea
                    className="ml-source-input"
                    rows={14}
                    required
                    maxLength={20000}
                    value={code}
                    onChange={(event) => {
                      setCode(event.target.value);
                      setExample('');
                      setResult(undefined);
                    }}
                    placeholder="Paste Java source code here…"
                    spellCheck={false}
                    disabled={busy}
                  />
                </label>
                <div className="result-summary">
                  <span>{code.length.toLocaleString()} / 20,000 characters</span>
                  <span>{example}</span>
                </div>
                <button
                  className="button primary"
                  disabled={busy || !code.trim() || info.data.availability !== 'available'}
                >
                  {busy ? 'Classifying with saved model…' : 'Classify Code'}
                </button>
              </form>
              {busy && (
                <p role="status">Running server-side TF-IDF and Logistic Regression inference…</p>
              )}
              {error && <ErrorBox message={error} />}{' '}
              {result && (
                <section className="ml-prediction" aria-live="polite">
                  <div className="artifact-heading">
                    <h3>
                      {result.status === 'predicted'
                        ? result.predicted_category === 'BENCHMARK_NEGATIVE'
                          ? 'Benchmark-negative classification'
                          : result.cwe
                        : result.status === 'unsupported'
                          ? 'Unsupported language'
                          : 'Unknown / uncertain classification'}
                    </h3>
                    <Status value={result.status} />
                  </div>
                  {result.probability !== null && (
                    <p>
                      Model probability: <strong>{percent(result.probability)}</strong> ·
                      uncalibrated
                    </p>
                  )}
                  {result.reason && <p>{result.reason}</p>}
                  <p>
                    {result.note ??
                      'This prediction is a category estimate, not execution evidence or a confirmed vulnerability.'}
                  </p>
                  <code>{result.modelVersion}</code>
                </section>
              )}
            </section>
            <details className="panel details">
              <summary>Model scope and limitations</summary>
              <ul>
                {info.data.limitations.map((value) => (
                  <li key={value}>{value}</li>
                ))}
              </ul>
              <p>
                Predictions below the recorded threshold of {percent(info.data.rejectionThreshold)}{' '}
                return unknown. Unknown-category rejection is not guaranteed.
              </p>
            </details>
          </>
        )
      )}
    </>
  );
}
