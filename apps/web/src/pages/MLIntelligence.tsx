import { useEffect, useRef, useState, type FormEvent } from 'react';
import {
  MLModelCatalogSchema,
  MLPredictionSchema,
  MLExampleSchema,
  type MLModelCatalog,
  type MLPrediction,
} from '@proofpatch/shared';
import { api } from '../lib/api';
import { useResource } from '../hooks/useResource';
import { PageTitle, ErrorBox, Loading, Status, date } from '../components/ui';
import { useAuth } from '../features/auth';
import { RepositoryMLReview } from '../components/ml/RepositoryMLReview';

type Language = MLModelCatalog['models'][number]['language'];
const languageName: Record<Language, string> = {
  java: 'Java',
  python: 'Python',
  javascript: 'JavaScript',
  typescript: 'TypeScript',
};
const percent = (value: number) => `${(value * 100).toFixed(2)}%`;

export function MLIntelligencePage() {
  const { user } = useAuth();
  const catalog = useResource(() => api('/ml/models', MLModelCatalogSchema));
  const [code, setCode] = useState('');
  const [language, setLanguage] = useState<Language>('java');
  const [filePath, setFilePath] = useState('');
  const [result, setResult] = useState<MLPrediction>();
  const [pending, setPending] = useState<'example' | 'classify'>();
  const [error, setError] = useState('');
  const [example, setExample] = useState('');
  const requestVersion = useRef(0);
  const models = catalog.data?.models;
  const trainedModels = models?.filter((entry) => entry.info);
  const selected = models?.find((entry) => entry.language === language);
  const info = selected?.info;
  const busy = pending !== undefined;
  const canClassify =
    selected?.status === 'available' &&
    info?.availability === 'available' &&
    info.activation?.enabled !== false;

  useEffect(
    () => () => {
      requestVersion.current += 1;
    },
    [],
  );
  useEffect(() => {
    if (!models || models.some((entry) => entry.language === language && entry.info)) return;
    const first = models.find((entry) => entry.info);
    if (first) {
      requestVersion.current += 1;
      setLanguage(first.language);
      setResult(undefined);
      setExample('');
    }
  }, [models, language]);

  function changeLanguage(value: Language) {
    requestVersion.current += 1;
    setLanguage(value);
    setResult(undefined);
    setExample('');
    setError('');
  }
  async function loadExample() {
    const version = ++requestVersion.current;
    setPending('example');
    setError('');
    setResult(undefined);
    setExample('');
    try {
      const saved = await api(`/ml/example?language=${language}`, MLExampleSchema);
      if (version !== requestVersion.current) return;
      setCode(saved.code);
      setFilePath('');
      setExample(`${saved.exampleId} · held-out label: ${saved.expectedLabel} · ${saved.source}`);
    } catch (cause) {
      if (version === requestVersion.current) setError((cause as Error).message);
    } finally {
      if (version === requestVersion.current) setPending(undefined);
    }
  }
  async function classify(event: FormEvent) {
    event.preventDefault();
    if (!canClassify || busy || !code.trim() || code.length > 20000) return;
    const version = ++requestVersion.current;
    setPending('classify');
    setError('');
    setResult(undefined);
    try {
      const prediction = await api('/ml/classify', MLPredictionSchema, {
        code,
        language,
        ...(filePath.trim() ? { filePath: filePath.trim() } : {}),
      });
      if (version === requestVersion.current) setResult(prediction);
    } catch (cause) {
      if (version === requestVersion.current) setError((cause as Error).message);
    } finally {
      if (version === requestVersion.current) setPending(undefined);
    }
  }

  return (
    <>
      <PageTitle
        eyebrow="EXPERIMENTAL / LANGUAGE-SPECIFIC CLASSIFICATION"
        title="ML INTELLIGENCE"
      />
      {user?.role === 'reviewer' && <RepositoryMLReview />}
      {catalog.loading ? (
        <Loading />
      ) : catalog.error ? (
        <ErrorBox message={catalog.error} retry={catalog.reload} />
      ) : (
        <>
          <section className="panel details">
            <div className="section-header">
              <div>
                <h2>Language-specific models</h2>
              </div>
            </div>
            {trainedModels?.length ? (
              <label>
                Source language
                <select
                  value={language}
                  disabled={busy}
                  onChange={(event) => changeLanguage(event.target.value as Language)}
                >
                  {trainedModels.map((entry) => (
                    <option value={entry.language} key={entry.language}>
                      {languageName[entry.language]}
                      {entry.status !== 'available' ? ` — ${entry.status}` : ''}
                    </option>
                  ))}
                </select>
              </label>
            ) : (
              <p role="status">No evaluated model is available to inspect on this backend.</p>
            )}
            <ul>
              {models?.map((entry) => (
                <li key={entry.language}>
                  <strong>{languageName[entry.language]}</strong> · {entry.status}
                </li>
              ))}
            </ul>
          </section>
          {info && selected && (
            <>
              <section className="panel details">
                <div className="section-header">
                  <div>
                    <h2>{info.model}</h2>
                  </div>
                  <Status value={selected.status} />
                </div>
                <p>
                  {info.training.trainSamples.toLocaleString()} training ·{' '}
                  {info.training.testSamples.toLocaleString()} held-out examples
                </p>
                <dl>
                  <dt>Model version</dt>
                  <dd><code>{info.modelVersion}</code></dd>
                  <dt>Dataset source</dt>
                  <dd>
                    <a href={info.dataset.repository} target="_blank" rel="noreferrer">
                      {info.dataset.repository}
                    </a>
                  </dd>
                  <dt>Source revision</dt>
                  <dd><code>{info.dataset.commit}</code></dd>
                  <dt>Trained</dt>
                  <dd>{date(info.trainedAt)}</dd>
                  <dt>Supported categories</dt>
                  <dd>{info.supportedCwes.join(' · ')} · Dataset negative</dd>
                  <dt>Dataset license</dt>
                  <dd>{info.dataset.license}</dd>
                </dl>
              </section>
              <div className="repository-metrics">
                {[
                  ['Macro precision', info.metrics.precisionMacro],
                  ['Macro recall', info.metrics.recallMacro],
                  ['Macro F1', info.metrics.f1Macro],
                  ['Negative-example recall', info.metrics.negativeRecall],
                  ...(info.metrics.negativeFalsePositiveRate === undefined
                    ? []
                    : [['Negative false-positive rate', info.metrics.negativeFalsePositiveRate]]),
                ].map(([label, value]) => (
                  <div className="repository-metric" key={label}>
                    <span>{label}</span>
                    <strong>{percent(Number(value))}</strong>
                  </div>
                ))}
              </div>
              <details className="panel details">
                <summary>Model Playground</summary>
                <div className="section-header">
                  <div>
                    <h2>Classify a {languageName[language]} snippet</h2>
                  </div>
                  <button
                    className="button secondary small-button"
                    onClick={loadExample}
                    disabled={busy}
                  >
                    {pending === 'example' ? 'Loading held-out example…' : 'Load held-out example'}
                  </button>
                </div>
                {!canClassify && (
                  <p role="status">
                    Classification is disabled for this model.
                  </p>
                )}
                <form onSubmit={classify}>
                  <label>
                    Source path (optional metadata)
                    <input
                      value={filePath}
                      maxLength={500}
                      onChange={(event) => {
                        setFilePath(event.target.value);
                        setResult(undefined);
                      }}
                      disabled={busy}
                      placeholder="Path within the repository"
                    />
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
                      placeholder={`Paste ${languageName[language]} source code here…`}
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
                    disabled={busy || !code.trim() || code.length > 20000 || !canClassify}
                  >
                    {pending === 'classify' ? 'Classifying with saved model…' : 'Classify Code'}
                  </button>
                </form>
                {pending === 'classify' && (
                  <p role="status">Running server-side TF-IDF and Logistic Regression inference…</p>
                )}
                {error && <ErrorBox message={error} />}
                {result && (
                  <section className="ml-prediction" aria-live="polite">
                    <div className="artifact-heading">
                      <h3>
                        {result.status === 'predicted'
                          ? result.cwe ?? 'Dataset-negative classification'
                          : result.status === 'unsupported'
                            ? 'Unsupported language or model'
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
                    <code>{result.modelVersion}</code>
                  </section>
                )}
              </details>
              <details className="panel details">
                <summary>Model scope and limitations</summary>
                <ul>
                  {info.limitations.map((value) => <li key={value}>{value}</li>)}
                </ul>
                <p>
                  Predictions below the recorded threshold of {percent(info.rejectionThreshold)}
                  {' '}return unknown. Unknown-category rejection is not guaranteed.
                </p>
              </details>
            </>
          )}
        </>
      )}
    </>
  );
}
