'use client';

import * as React from 'react';
import CodeMirror, { EditorView, type Extension } from '@uiw/react-codemirror';
import { json } from '@codemirror/lang-json';
import { useTheme } from 'next-themes';
import { regoLanguage } from '@/components/policy/rego-language';
import type { CodeEditorProps } from '@/components/shared/json-editor';

export function CodeEditorInner({
  value,
  onChange,
  language,
  ariaLabel,
  height = '320px',
  readOnly = false,
  id,
}: CodeEditorProps) {
  const { resolvedTheme } = useTheme();
  const extensions = React.useMemo<Extension[]>(
    () => [
      language === 'json' ? json() : regoLanguage(),
      EditorView.lineWrapping,
      EditorView.contentAttributes.of({ 'aria-label': ariaLabel, ...(id ? { id } : {}) }),
    ],
    [language, ariaLabel, id],
  );
  return (
    <div className="overflow-hidden rounded-md border" style={{ height }}>
      <CodeMirror
        value={value}
        height={height}
        theme={resolvedTheme === 'dark' ? 'dark' : 'light'}
        extensions={extensions}
        onChange={onChange}
        readOnly={readOnly}
        editable={!readOnly}
        basicSetup={{
          lineNumbers: true,
          foldGutter: true,
          highlightActiveLine: !readOnly,
          autocompletion: false,
          tabSize: 2,
        }}
      />
    </div>
  );
}
