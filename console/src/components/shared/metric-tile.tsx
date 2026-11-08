import * as React from 'react';
import Link from 'next/link';
import type { LucideIcon } from 'lucide-react';
import { Card } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { cn } from '@/lib/utils';

export function MetricTile({
  label,
  value,
  hint,
  icon: Icon,
  href,
  tone = 'default',
  isLoading = false,
}: {
  label: string;
  value: React.ReactNode;
  hint?: React.ReactNode;
  icon?: LucideIcon;
  href?: string;
  tone?: 'default' | 'danger' | 'warning' | 'success';
  isLoading?: boolean;
}) {
  const body = (
    <Card
      className={cn(
        'h-full gap-2 px-4 py-3',
        href && 'transition-colors hover:bg-accent/40',
        tone === 'danger' && 'border-red-300 dark:border-red-900',
        tone === 'warning' && 'border-amber-300 dark:border-amber-900',
        tone === 'success' && 'border-emerald-300 dark:border-emerald-900',
      )}
    >
      <div className="flex items-center justify-between gap-2 text-sm text-muted-foreground">
        <span>{label}</span>
        {Icon && <Icon className="size-4 shrink-0" aria-hidden="true" />}
      </div>
      {isLoading ? (
        <Skeleton className="h-8 w-20" />
      ) : (
        <div className="tabular text-2xl font-semibold">{value}</div>
      )}
      <div className="min-h-4 text-xs text-muted-foreground">{hint}</div>
    </Card>
  );
  if (href) {
    return (
      <Link
        href={href}
        className="block rounded-xl focus-visible:ring-[3px] focus-visible:outline-none"
        aria-label={`${label}: open details`}
      >
        {body}
      </Link>
    );
  }
  return body;
}
