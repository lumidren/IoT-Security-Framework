import * as React from 'react';
import { cn } from '@/lib/utils';

export function KeyValueList({
  items,
  className,
  columns = 2,
}: {
  items: Array<{ label: string; value: React.ReactNode; mono?: boolean }>;
  className?: string;
  columns?: 1 | 2 | 3;
}) {
  return (
    <dl
      className={cn(
        'grid gap-x-6 gap-y-3 text-sm',
        columns === 1 && 'grid-cols-1',
        columns === 2 && 'grid-cols-1 sm:grid-cols-2',
        columns === 3 && 'grid-cols-1 sm:grid-cols-2 lg:grid-cols-3',
        className,
      )}
    >
      {items.map((item) => (
        <div key={item.label} className="flex min-w-0 flex-col gap-0.5">
          <dt className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
            {item.label}
          </dt>
          <dd className={cn('min-w-0 break-words', item.mono && 'font-mono text-xs')}>
            {item.value}
          </dd>
        </div>
      ))}
    </dl>
  );
}
