import { Component, Suspense, lazy, useEffect, useRef, useState, type ReactNode } from 'react';
import { Copy, Download, Maximize2, Minimize2, ChevronsUpDown } from 'lucide-react';
import type { Patch } from '@proofpatch/shared';
import { codeLanguage, diffStatistics } from '../../lib/security-data';

const MonacoWorkspace = lazy(() => import('./MonacoWorkspace'));
class EditorBoundary extends Component<
  { children: ReactNode; fallback: ReactNode },
  { failed: boolean }
> {
  state = { failed: false };
  static getDerivedStateFromError() {
    return { failed: true };
  }
  render() {
    return this.state.failed ? this.props.fallback : this.props.children;
  }
}
export function DiffViewer({
  patch,
}: {
  patch: Pick<Patch, 'id' | 'files' | 'unifiedDiff' | 'securityTest'>;
}) {
  const [mode, setMode] = useState<'comparison' | 'unified' | 'security'>('comparison');
  const [path, setPath] = useState(patch.files[0]?.path ?? '');
  const [collapse, setCollapse] = useState(true);
  const [side, setSide] = useState<'current' | 'proposed'>('proposed');
  const [fullscreen, setFullscreen] = useState(false);
  const [notice, setNotice] = useState('');
  const root = useRef<HTMLDivElement>(null);
  const file = patch.files.find((item) => item.path === path) ?? patch.files[0];
  const stats = diffStatistics(patch.unifiedDiff);
  const fileStats = file ? stats.files[file.path] : null;
  useEffect(() => {
    const change = () => setFullscreen(document.fullscreenElement === root.current);
    document.addEventListener('fullscreenchange', change);
    return () => document.removeEventListener('fullscreenchange', change);
  }, []);
  async function copy(value: string, label: string) {
    try {
      await navigator.clipboard.writeText(value);
      setNotice(`${label} copied.`);
    } catch {
      setNotice('Clipboard access is unavailable. Select and copy text in the editor.');
    }
  }
  async function toggleFullscreen() {
    try {
      if (document.fullscreenElement === root.current) await document.exitFullscreen();
      else await root.current?.requestFullscreen();
    } catch {
      setNotice('Fullscreen is unavailable in this browser. The comparison remains resizable.');
    }
  }
  function download() {
    const blob = new Blob([patch.unifiedDiff], { type: 'text/x-diff;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `proofpatch-${patch.id.slice(0, 8)}.patch`;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    setNotice('Recorded patch exported.');
  }
  const fallback = (
    <div className="editor-fallback">
      <p role="alert">The comparison editor could not load. Source text is available below.</p>
      {mode === 'comparison' ? (
        <div className="source-fallback-grid">
          <section>
            <h3>Current source</h3>
            <pre>{file?.original ?? ''}</pre>
          </section>
          <section>
            <h3>Proposed revision</h3>
            <pre>{file?.proposed ?? ''}</pre>
          </section>
        </div>
      ) : (
        <pre>{mode === 'security' ? patch.securityTest?.content : patch.unifiedDiff}</pre>
      )}
    </div>
  );
  return (
    <div className="comparison-workspace" ref={root}>
      <div className="comparison-toolbar">
        <div className="segmented-control" role="group" aria-label="Code view">
          <button aria-pressed={mode === 'comparison'} onClick={() => setMode('comparison')}>
            Side-by-side
          </button>
          <button aria-pressed={mode === 'unified'} onClick={() => setMode('unified')}>
            Unified diff
          </button>
          {patch.securityTest && (
            <button aria-pressed={mode === 'security'} onClick={() => setMode('security')}>
              Security test
            </button>
          )}
        </div>
        <div className="comparison-tools">
          <button className="icon-label" onClick={download} disabled={!patch.unifiedDiff}>
            <Download size={14} /> Export patch
          </button>
          <button
            className="icon-label"
            onClick={toggleFullscreen}
            aria-label={fullscreen ? 'Exit fullscreen comparison' : 'Open fullscreen comparison'}
          >
            {fullscreen ? <Minimize2 size={16} /> : <Maximize2 size={16} />}
            <span>{fullscreen ? 'Exit fullscreen' : 'Fullscreen'}</span>
          </button>
        </div>
      </div>
      {mode !== 'security' && (
        <div className="file-toolbar">
          <label>
            Changed file
            <select
              value={file?.path ?? ''}
              onChange={(event) => setPath(event.target.value)}
              disabled={!patch.files.length}
            >
              {!patch.files.length && <option value="">No source snapshots supplied</option>}
              {patch.files.map((item) => (
                <option key={item.path} value={item.path}>
                  {item.path}
                </option>
              ))}
            </select>
          </label>
          <div className="file-change-counts" aria-label="Changes recorded in Git diff">
            <span className="addition">+{fileStats?.added ?? stats.added}</span>
            <span className="deletion">−{fileStats?.removed ?? stats.removed}</span>
          </div>
          {mode === 'comparison' && (
            <button
              className="icon-label collapse-context"
              aria-pressed={collapse}
              onClick={() => setCollapse(!collapse)}
            >
              <ChevronsUpDown size={14} />
              {collapse ? 'Expand context' : 'Collapse context'}
            </button>
          )}
        </div>
      )}
      {mode === 'comparison' && file && (
        <>
          <div className="source-column-headings">
            <span>
              <i className="source-state current" />
              Current source <small>Read only</small>
              <button
                aria-label="Copy current source"
                onClick={() => copy(file.original, 'Current source')}
              >
                <Copy size={14} />
              </button>
            </span>
            <span>
              <i className="source-state revision" />
              Proposed revision <small>Read only</small>
              <button
                aria-label="Copy proposed revision"
                onClick={() => copy(file.proposed, 'Proposed revision')}
              >
                <Copy size={14} />
              </button>
            </span>
          </div>
          <div
            className="mobile-source-switch segmented-control"
            role="group"
            aria-label="Source revision"
          >
            <button aria-pressed={side === 'current'} onClick={() => setSide('current')}>
              Current source
            </button>
            <button aria-pressed={side === 'proposed'} onClick={() => setSide('proposed')}>
              Proposed revision
            </button>
            <button
              aria-label="Copy displayed source"
              onClick={() =>
                copy(side === 'current' ? file.original : file.proposed, 'Source code')
              }
            >
              <Copy size={14} />
            </button>
          </div>
          {(file.original === '' || file.proposed === '') && (
            <div className="source-empty-note">
              {file.original === '' ? 'Current source is an empty file. ' : ''}
              {file.proposed === '' ? 'Proposed revision is an empty file.' : ''}
            </div>
          )}
        </>
      )}
      {mode === 'security' && patch.securityTest && (
        <div className="security-test-caption">
          <span className="mono">{patch.securityTest.path}</span>
          <button
            className="icon-label"
            onClick={() => copy(patch.securityTest!.content, 'Security test')}
          >
            <Copy size={14} /> Copy test
          </button>
          <p>
            Generated test source. Consult the recorded evidence for its actual execution outcome.
          </p>
        </div>
      )}
      {mode === 'comparison' && !file ? (
        <div className="editor-unavailable">
          <h3>Source snapshots unavailable</h3>
          <p>
            This patch contains no original/proposed file content. Inspect its recorded unified diff
            instead.
          </p>
          <button className="button secondary" onClick={() => setMode('unified')}>
            Open unified diff
          </button>
        </div>
      ) : (
        <div className="monaco-host">
          <EditorBoundary key={`${patch.id}:${file?.path}:${mode}`} fallback={fallback}>
            <Suspense
              fallback={
                <div className="editor-loading" role="status">
                  Loading comparison tools…
                </div>
              }
            >
              <MonacoWorkspace
                original={file?.original ?? ''}
                proposed={file?.proposed ?? ''}
                language={codeLanguage(
                  mode === 'security' ? (patch.securityTest?.path ?? '') : (file?.path ?? ''),
                )}
                modelKey={`${patch.id}/${encodeURIComponent(file?.path ?? 'diff')}`}
                mode={mode}
                text={mode === 'security' ? (patch.securityTest?.content ?? '') : patch.unifiedDiff}
                collapse={collapse}
                mobileSide={side}
              />
            </Suspense>
          </EditorBoundary>
        </div>
      )}
      <div className="comparison-footer">
        <span className="mono">
          {mode === 'security' ? 'Generated security test' : ''}
        </span>
        <span role="status" aria-live="polite">
          {notice}
        </span>
      </div>
    </div>
  );
}
