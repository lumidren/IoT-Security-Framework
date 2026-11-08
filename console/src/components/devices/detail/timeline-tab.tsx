'use client';

import * as React from 'react';
import {
  BellIcon,
  FileJsonIcon,
  FileLockIcon,
  FingerprintIcon,
  KeyRoundIcon,
  RefreshCwIcon,
  RocketIcon,
  ShieldBanIcon,
  ShieldXIcon,
  TerminalIcon,
  WifiIcon,
  WifiOffIcon,
  type LucideIcon,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { JsonView } from '@/components/shared/json-view';
import { EmptyState, ErrorState } from '@/components/shared/states';
import { DateTime } from '@/components/shared/time';
import { useDeviceTimeline } from '@/lib/api/hooks';
import { TIMELINE_KINDS, type TimelineKind } from '@/lib/api/schemas';
import { cn, titleCase } from '@/lib/utils';

const KIND_ICON: Record<TimelineKind, LucideIcon> = {
  lifecycle: RefreshCwIcon,
  connect: WifiIcon,
  disconnect: WifiOffIcon,
  enroll: FingerprintIcon,
  renew: KeyRoundIcon,
  revoke: ShieldXIcon,
  command: TerminalIcon,
  ota: RocketIcon,
  alert: BellIcon,
  config: FileLockIcon,
  twin: FileJsonIcon,
  authz_denied: ShieldBanIcon,
};

const KIND_TONE: Partial<Record<TimelineKind, string>> = {
  alert: 'text-destructive',
  revoke: 'text-destructive',
  authz_denied: 'text-warning',
  connect: 'text-success',
};

export function DeviceTimeline({
  deviceId,
  compact = false,
}: {
  deviceId: string;
  compact?: boolean;
}) {
  const [kinds, setKinds] = React.useState<TimelineKind[]>([]);
  const timeline = useDeviceTimeline(deviceId, { kinds });
  const items = timeline.data?.pages.flatMap((p) => p.items) ?? [];
  const [expanded, setExpanded] = React.useState<string | null>(null);

  const toggle = (kind: TimelineKind) =>
    setKinds((prev) => (prev.includes(kind) ? prev.filter((k) => k !== kind) : [...prev, kind]));

  return (
    <div className="flex flex-col gap-4">
      {!compact && (
        <fieldset className="flex flex-wrap gap-2">
          <legend className="sr-only">Filter timeline by event kind</legend>
          {TIMELINE_KINDS.map((kind) => {
            const active = kinds.includes(kind);
            return (
              <Button
                key={kind}
                type="button"
                size="sm"
                variant={active ? 'default' : 'outline'}
                aria-pressed={active}
                onClick={() => toggle(kind)}
              >
                {titleCase(kind)}
              </Button>
            );
          })}
          {kinds.length > 0 && (
            <Button type="button" size="sm" variant="ghost" onClick={() => setKinds([])}>
              Clear
            </Button>
          )}
        </fieldset>
      )}
      {timeline.isError && (
        <ErrorState error={timeline.error} onRetry={() => void timeline.refetch()} />
      )}
      {timeline.isLoading && <Skeleton className="h-64 w-full" />}
      {!timeline.isLoading && items.length === 0 && (
        <EmptyState
          title="No events"
          description="Nothing has been recorded for this device with the selected filters."
        />
      )}
      <ol className="relative flex flex-col gap-0 border-l pl-6" aria-label="Device timeline">
        {items.map((event) => {
          const Icon = KIND_ICON[event.kind];
          const open = expanded === event.id;
          const hasData = event.data && Object.keys(event.data).length > 0;
          return (
            <li key={event.id} className="relative pb-5">
              <span
                className={cn(
                  'absolute top-0.5 -left-[31px] flex size-6 items-center justify-center rounded-full border bg-background',
                  KIND_TONE[event.kind],
                )}
                aria-hidden="true"
              >
                <Icon className="size-3.5" />
              </span>
              <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
                <p className="text-sm">
                  <span className="mr-2 text-xs font-medium tracking-wide text-muted-foreground uppercase">
                    {titleCase(event.kind)}
                  </span>
                  {event.summary}
                </p>
                <DateTime value={event.at} className="text-xs text-muted-foreground" />
              </div>
              {hasData && (
                <div className="mt-1">
                  <button
                    type="button"
                    className="text-xs text-primary underline-offset-4 hover:underline"
                    aria-expanded={open}
                    onClick={() => setExpanded(open ? null : event.id)}
                  >
                    {open ? 'Hide details' : 'Show details'}
                  </button>
                  {open && (
                    <JsonView
                      value={event.data}
                      maxHeight="max-h-48"
                      className="mt-1"
                      label="Event details"
                    />
                  )}
                </div>
              )}
            </li>
          );
        })}
      </ol>
      {timeline.hasNextPage && (
        <Button
          variant="outline"
          onClick={() => void timeline.fetchNextPage()}
          disabled={timeline.isFetchingNextPage}
          className="self-center"
        >
          {timeline.isFetchingNextPage ? 'Loading…' : 'Load older events'}
        </Button>
      )}
    </div>
  );
}

export function TimelineTab({ deviceId }: { deviceId: string }) {
  return <DeviceTimeline deviceId={deviceId} />;
}
