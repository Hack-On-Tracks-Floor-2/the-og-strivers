import { useEffect, useState } from 'react';
import { DiffEditor, Editor, loader } from '@monaco-editor/react';
import * as monaco from 'monaco-editor/editor/editor.api';
import 'monaco-editor/basic-languages/monaco.contribution';
import 'monaco-editor/language/json/monaco.contribution';
import EditorWorker from 'monaco-editor/editor/editor.worker?worker';
import JsonWorker from 'monaco-editor/language/json/json.worker?worker';

// Bundle editor and worker locally. Repository content never reaches a CDN.
self.MonacoEnvironment = {
  getWorker: (_moduleId, label) => (label === 'json' ? new JsonWorker() : new EditorWorker()),
};
loader.config({ monaco });
// The unified view preserves the backend's text; only its Git line markers are colored.
monaco.languages.register({ id: 'diff' });
monaco.languages.setMonarchTokensProvider('diff', {
  tokenizer: {
    root: [
      [/^(?:diff --git|index |--- |\+\+\+ |@@).*/, 'keyword'],
      [/^\+.*/, 'string'],
      [/^-.*/, 'invalid'],
      [/^\\.*/, 'comment'],
    ],
  },
});
monaco.editor.defineTheme('proofpatch-dark', {
  base: 'vs-dark',
  inherit: true,
  rules: [],
  colors: {
    'editor.background': '#0B0B0D',
    'editor.foreground': '#F4F4F0',
    'editorLineNumber.foreground': '#85858F',
    'editorLineNumber.activeForeground': '#F4F4F0',
    'editorGutter.background': '#0B0B0D',
    'editor.lineHighlightBackground': '#1B1B1F',
    'diffEditor.insertedTextBackground': '#395B3B55',
    'diffEditor.removedTextBackground': '#713B4155',
    'diffEditor.insertedLineBackground': '#213F282D',
    'diffEditor.removedLineBackground': '#4B282D3D',
    'editor.selectionBackground': '#39472B',
    'editorWidget.background': '#141416',
    'editorOverviewRuler.border': '#29292D',
    'scrollbar.shadow': '#00000000',
  },
});

type Props = {
  original: string;
  proposed: string;
  language: string;
  modelKey: string;
  mode: 'comparison' | 'unified' | 'security';
  text: string;
  collapse: boolean;
  mobileSide: 'current' | 'proposed';
};
export default function MonacoWorkspace({
  original,
  proposed,
  language,
  modelKey,
  mode,
  text,
  collapse,
  mobileSide,
}: Props) {
  const [compact, setCompact] = useState(() => window.matchMedia('(max-width:850px)').matches);
  useEffect(() => {
    const media = window.matchMedia('(max-width:850px)');
    const update = () => setCompact(media.matches);
    media.addEventListener('change', update);
    return () => media.removeEventListener('change', update);
  }, []);
  const common: monaco.editor.IStandaloneEditorConstructionOptions = {
    readOnly: true,
    domReadOnly: true,
    fontSize: 14,
    lineHeight: 23,
    fontFamily: '"JetBrains Mono", "Cascadia Code", Consolas, monospace',
    minimap: { enabled: false },
    scrollBeyondLastLine: false,
    wordWrap: 'off',
    lineNumbers: 'on',
    renderWhitespace: 'selection',
    automaticLayout: true,
    padding: { top: 16, bottom: 16 },
    stickyScroll: { enabled: false },
    tabSize: 4,
    unicodeHighlight: { ambiguousCharacters: false },
    ariaLabel:
      mode === 'security'
        ? 'Generated security test'
        : mode === 'unified'
          ? 'Recorded unified Git diff'
          : mobileSide === 'current'
            ? 'Current source code'
            : 'Proposed revision code',
  };
  if (mode !== 'comparison' || compact)
    return (
      <Editor
        key={`${modelKey}:${mode}:${compact ? mobileSide : ''}`}
        theme="proofpatch-dark"
        height="100%"
        language={mode === 'unified' ? 'diff' : language}
        value={mode === 'comparison' ? (mobileSide === 'current' ? original : proposed) : text}
        options={common}
        loading={
          <div className="editor-loading" role="status">
            Loading local code editor…
          </div>
        }
      />
    );
  return (
    <DiffEditor
      key={modelKey}
      height="100%"
      theme="proofpatch-dark"
      language={language}
      original={original}
      modified={proposed}
      originalModelPath={`proofpatch://${modelKey}/current`}
      modifiedModelPath={`proofpatch://${modelKey}/revision`}
      options={{
        ...common,
        originalEditable: false,
        renderSideBySide: true,
        useInlineViewWhenSpaceIsLimited: false,
        enableSplitViewResizing: true,
        ignoreTrimWhitespace: false,
        renderIndicators: true,
        renderOverviewRuler: false,
        maxComputationTime: 5000,
        hideUnchangedRegions: {
          enabled: collapse,
          contextLineCount: 3,
          minimumLineCount: 8,
          revealLineCount: 12,
        },
      }}
      onMount={(editor) => {
        editor.getOriginalEditor().updateOptions({ ariaLabel: 'Current source code, read only' });
        editor
          .getModifiedEditor()
          .updateOptions({ ariaLabel: 'Proposed revision code, read only' });
      }}
      loading={
        <div className="editor-loading" role="status">
          Preparing source comparison…
        </div>
      }
    />
  );
}
