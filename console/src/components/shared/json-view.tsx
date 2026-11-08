import * as React from 'react';
import { cn } from '@/lib/utils';

export function JsonView({
  value,
  className,
  maxHeight = 'max-h-96',
  label,
}: {
  value: unknown;
  className?: string;
  maxHeight?: string;
  label?: string;
}) {
  const text = React.useMemo(() => {
    try {
      return JSON.stringify(value, null, 2) ?? 'null';
    } catch {
      return String(value);
    }
  }, [value]);
  return (
    <pre
      aria-label={label}
      tabIndex={0}
      className={cn(
        'overflow-auto rounded-md border bg-muted/50 p-3 font-mono text-xs leading-relaxed',
        maxHeight,
        className,
      )}
    >
      {text}
    </pre>
  );
}
