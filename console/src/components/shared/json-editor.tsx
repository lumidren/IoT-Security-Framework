'use client';

import dynamic from 'next/dynamic';
import { Skeleton } from '@/components/ui/skeleton';

export interface CodeEditorProps {
  value: string;
  onChange?: (value: string) => void;
  language: 'json' | 'rego';
  ariaLabel: string;
  /** CSS height, e.g. "320px". Reserved while loading to avoid layout shift. */
  height?: string;
  readOnly?: boolean;
  id?: string;
}

/** CodeMirror is loaded on demand; the skeleton reserves the editor's height. */
export const CodeEditor = dynamic(
  () => import('@/components/shared/code-editor-inner').then((m) => m.CodeEditorInner),
  {
    ssr: false,
    loading: () => <Skeleton className="w-full rounded-md" style={{ height: '320px' }} />,
  },
);
