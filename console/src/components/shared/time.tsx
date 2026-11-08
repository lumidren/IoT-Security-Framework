'use client';

import { useNow } from '@/hooks/use-now';
import { formatDateTime, formatDuration, formatRelative } from '@/lib/utils';

export function TimeAgo({
  value,
  className,
}: {
  value: string | null | undefined;
  className?: string;
}) {
  const now = useNow(30_000);
  if (!value) return <span className={className}>—</span>;
  return (
    <time dateTime={value} title={formatDateTime(value)} className={className}>
      {formatRelative(value, now)}
    </time>
  );
}

export function DateTime({
  value,
  className,
}: {
  value: string | null | undefined;
  className?: string;
}) {
  if (!value) return <span className={className}>—</span>;
  return (
    <time dateTime={value} className={className}>
      {formatDateTime(value)}
    </time>
  );
}

/** Live countdown ("expires in 5d 3h" / "expired 2h ago"). */
export function Countdown({
  until,
  className,
}: {
  until: string | null | undefined;
  className?: string;
}) {
  const now = useNow(60_000);
  if (!until) return <span className={className}>—</span>;
  const diff = (new Date(until).getTime() - now) / 1000;
  const text = diff >= 0 ? `in ${formatDuration(diff)}` : `${formatDuration(-diff)} ago`;
  return (
    <time dateTime={until} title={formatDateTime(until)} className={className}>
      {text}
    </time>
  );
}
