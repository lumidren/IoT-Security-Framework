'use client';

import * as React from 'react';
import { getCoreRowModel, useReactTable, type ColumnDef } from '@tanstack/react-table';
import { DownloadIcon, FilterXIcon } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { DataTable } from '@/components/shared/data-table';
import { JsonView } from '@/components/shared/json-view';
import { PaginationControls } from '@/components/shared/pagination-controls';
import { ErrorState } from '@/components/shared/states';
import { DateTime } from '@/components/shared/time';
import { useCursorPagination } from '@/hooks/use-cursor-pagination';
import { useQueryState } from '@/hooks/use-query-state';
import { buildUrl } from '@/lib/api/client';
import { useAudit } from '@/lib/api/hooks';
import type { AuditEvent } from '@/lib/api/schemas';
import { usePermission } from '@/providers/session-context';

const FILTER_KEYS = ['actor', 'action', 'target_type', 'target_id', 'from', 'to'] as const;
type FilterKey = (typeof FILTER_KEYS)[number];

function toIsoOrUndefined(value: string): string | undefined {
  if (!value) return undefined;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? new Date(ms).toISOString() : undefined;
}

function DetailsCell({ event }: { event: AuditEvent }) {
  const [open, setOpen] = React.useState(false);
  if (!event.details || Object.keys(event.details).length === 0)
    return <span className="text-muted-foreground">—</span>;
  return (
    <div>
      <button
        type="button"
        className="text-xs text-primary underline-offset-4 hover:underline"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
      >
        {open ? 'Hide' : 'Show'} details
      </button>
      {open && (
        <JsonView
          value={event.details}
          maxHeight="max-h-40"
          className="mt-1 min-w-64 whitespace-pre"
          label="Audit event details"
        />
      )}
    </div>
  );
}

export function AuditView() {
  const { get, set } = useQueryState();
  const filters = React.useMemo(
    () => Object.fromEntries(FILTER_KEYS.map((k) => [k, get(k)])) as Record<FilterKey, string>,
    [get],
  );
  const [draft, setDraft] = React.useState(filters);
  React.useEffect(() => setDraft(filters), [filters]);
  const pagination = useCursorPagination();
  const canExport = usePermission('audit.export');

  const audit = useAudit({
    actor: filters.actor || undefined,
    action: filters.action || undefined,
    target_type: filters.target_type || undefined,
    target_id: filters.target_id || undefined,
    from: toIsoOrUndefined(filters.from),
    to: toIsoOrUndefined(filters.to),
    cursor: pagination.cursor,
  });

  const columns = React.useMemo<ColumnDef<AuditEvent>[]>(
    () => [
      {
        accessorKey: 'at',
        header: 'When',
        cell: ({ row }) => <DateTime value={row.original.at} className="text-xs" />,
      },
      {
        id: 'actor',
        header: 'Actor',
        cell: ({ row }) => (
          <span className="flex flex-col">
            <span className="text-sm">{row.original.actor.name ?? row.original.actor.id}</span>
            <span className="text-xs text-muted-foreground">{row.original.actor.type}</span>
          </span>
        ),
      },
      {
        accessorKey: 'action',
        header: 'Action',
        cell: ({ row }) => <span className="font-mono text-xs">{row.original.action}</span>,
      },
      {
        id: 'target',
        header: 'Target',
        cell: ({ row }) => (
          <span className="flex flex-col">
            <span className="font-mono text-xs">{row.original.target.id}</span>
            <span className="text-xs text-muted-foreground">{row.original.target.type}</span>
          </span>
        ),
      },
      {
        accessorKey: 'outcome',
        header: 'Outcome',
        cell: ({ row }) => (
          <Badge variant={row.original.outcome === 'success' ? 'success' : 'danger'}>
            {row.original.outcome}
          </Badge>
        ),
      },
      {
        accessorKey: 'ip',
        header: 'IP',
        cell: ({ row }) => <span className="font-mono text-xs">{row.original.ip ?? '—'}</span>,
      },
      { id: 'details', header: 'Details', cell: ({ row }) => <DetailsCell event={row.original} /> },
    ],
    [],
  );
  const table = useReactTable({
    data: audit.data?.items ?? [],
    columns,
    getCoreRowModel: getCoreRowModel(),
    getRowId: (e) => e.id,
  });

  const exportHref = buildUrl('registry', '/v1/audit/export', {
    from: toIsoOrUndefined(filters.from),
    to: toIsoOrUndefined(filters.to),
    format: 'ndjson',
  });
  const filtered = Object.values(filters).some(Boolean);

  return (
    <div className="flex flex-col gap-4">
      <form
        role="search"
        aria-label="Filter audit events"
        className="grid gap-3 rounded-lg border p-3 sm:grid-cols-2 lg:grid-cols-7"
        onSubmit={(e) => {
          e.preventDefault();
          set(Object.fromEntries(FILTER_KEYS.map((k) => [k, draft[k].trim() || null])));
          pagination.reset();
        }}
      >
        {(
          [
            ['actor', 'Actor', 'text', 'name or id'],
            ['action', 'Action', 'text', 'device.quarantine'],
            ['target_type', 'Target type', 'text', 'device'],
            ['target_id', 'Target id', 'text', 'dev-…'],
            ['from', 'From', 'datetime-local', ''],
            ['to', 'To', 'datetime-local', ''],
          ] as const
        ).map(([key, label, type, placeholder]) => (
          <div key={key} className="flex flex-col gap-1.5">
            <Label htmlFor={`audit-${key}`}>{label}</Label>
            <Input
              id={`audit-${key}`}
              type={type}
              value={draft[key]}
              placeholder={placeholder}
              onChange={(e) => setDraft((d) => ({ ...d, [key]: e.target.value }))}
              className={
                key.startsWith('target') || key === 'action' ? 'font-mono text-xs' : undefined
              }
            />
          </div>
        ))}
        <div className="flex items-end gap-2">
          <Button type="submit" variant="secondary">
            Apply
          </Button>
          {filtered && (
            <Button
              type="button"
              variant="ghost"
              onClick={() => {
                set(Object.fromEntries(FILTER_KEYS.map((k) => [k, null])));
                pagination.reset();
              }}
            >
              <FilterXIcon aria-hidden="true" /> Clear
            </Button>
          )}
        </div>
      </form>
      <div className="flex items-center justify-between gap-2">
        <p className="text-sm text-muted-foreground">
          Events are retained for the tenant retention period and forwarded to the SIEM.
        </p>
        {canExport && (
          <Button asChild variant="outline" size="sm">
            <a href={exportHref} download="ironmesh-audit.ndjson">
              <DownloadIcon aria-hidden="true" /> Export NDJSON
            </a>
          </Button>
        )}
      </div>
      {audit.isError ? (
        <ErrorState error={audit.error} onRetry={() => void audit.refetch()} />
      ) : (
        <>
          <DataTable
            table={table}
            isLoading={audit.isLoading}
            caption="Audit events matching the current filters"
            emptyTitle="No audit events"
            renderCard={(event) => (
              <Card className="gap-1 px-4 py-3 text-sm">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-xs">{event.action}</span>
                  <Badge variant={event.outcome === 'success' ? 'success' : 'danger'}>
                    {event.outcome}
                  </Badge>
                </div>
                <p className="text-xs text-muted-foreground">
                  {event.actor.name ?? event.actor.id} → {event.target.type} {event.target.id}
                </p>
                <DateTime value={event.at} className="text-xs text-muted-foreground" />
              </Card>
            )}
          />
          <PaginationControls
            page={pagination.page}
            hasPrevious={pagination.hasPrevious}
            hasNext={Boolean(audit.data?.next_cursor)}
            onPrevious={pagination.previous}
            onNext={() => pagination.next(audit.data?.next_cursor)}
            isFetching={audit.isFetching}
            count={audit.data?.items.length}
          />
        </>
      )}
    </div>
  );
}
