'use client';

import * as React from 'react';
import Link from 'next/link';
import { getCoreRowModel, useReactTable, type ColumnDef } from '@tanstack/react-table';
import { FilterXIcon } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { DataTable } from '@/components/shared/data-table';
import { PaginationControls } from '@/components/shared/pagination-controls';
import { ErrorState } from '@/components/shared/states';
import { AlertStateBadge, SeverityBadge } from '@/components/shared/status-badges';
import { TimeAgo } from '@/components/shared/time';
import { AlertActions } from '@/components/alerts/alert-actions';
import { useCursorPagination } from '@/hooks/use-cursor-pagination';
import { useQueryState } from '@/hooks/use-query-state';
import { useAlerts } from '@/lib/api/hooks';
import { ALERT_RULES, ALERT_STATES, SEVERITIES, type Alert } from '@/lib/api/schemas';
import { titleCase } from '@/lib/utils';

const ALL = '__all__';

function FilterSelect({
  id,
  label,
  value,
  onChange,
  options,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: readonly string[];
}) {
  return (
    <div className="flex min-w-36 flex-col gap-1.5">
      <Label htmlFor={id}>{label}</Label>
      <Select value={value || ALL} onValueChange={(v) => onChange(v === ALL ? '' : v)}>
        <SelectTrigger id={id} className="w-full">
          <SelectValue placeholder="All" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value={ALL}>All</SelectItem>
          {options.map((o) => (
            <SelectItem key={o} value={o}>
              {titleCase(o)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}

export function AlertsView() {
  const { get, set } = useQueryState();
  const filters = {
    state: get('state'),
    severity: get('severity'),
    rule: get('rule'),
    device_id: get('device_id'),
  };
  const pagination = useCursorPagination();
  const [deviceInput, setDeviceInput] = React.useState(filters.device_id);
  React.useEffect(() => setDeviceInput(filters.device_id), [filters.device_id]);
  const alerts = useAlerts({
    state: filters.state || undefined,
    severity: filters.severity || undefined,
    rule: filters.rule || undefined,
    device_id: filters.device_id || undefined,
    cursor: pagination.cursor,
  });

  const apply = (patch: Record<string, string | null>) => {
    set(patch);
    pagination.reset();
  };

  const columns = React.useMemo<ColumnDef<Alert>[]>(
    () => [
      {
        accessorKey: 'severity',
        header: 'Severity',
        cell: ({ row }) => <SeverityBadge severity={row.original.severity} />,
      },
      {
        accessorKey: 'rule',
        header: 'Rule',
        cell: ({ row }) => (
          <Link href={`/alerts/${row.original.id}`} className="font-medium hover:underline">
            {titleCase(row.original.rule)}
          </Link>
        ),
      },
      {
        accessorKey: 'device_id',
        header: 'Device',
        cell: ({ row }) => (
          <Link
            href={`/devices/${row.original.device_id}`}
            className="font-mono text-xs hover:underline"
          >
            {row.original.device_id}
          </Link>
        ),
      },
      {
        accessorKey: 'score',
        header: 'Score',
        cell: ({ row }) => <span className="tabular">{row.original.score.toFixed(2)}</span>,
      },
      {
        accessorKey: 'explanation',
        header: 'Explanation',
        cell: ({ row }) => (
          <span className="block max-w-md truncate text-sm" title={row.original.explanation}>
            {row.original.explanation}
          </span>
        ),
      },
      {
        accessorKey: 'state',
        header: 'State',
        cell: ({ row }) => <AlertStateBadge state={row.original.state} />,
      },
      {
        accessorKey: 'created_at',
        header: 'Raised',
        cell: ({ row }) => <TimeAgo value={row.original.created_at} />,
      },
      {
        id: 'actions',
        header: 'Actions',
        cell: ({ row }) => <AlertActions alert={row.original} />,
      },
    ],
    [],
  );
  const table = useReactTable({
    data: alerts.data?.items ?? [],
    columns,
    getCoreRowModel: getCoreRowModel(),
    getRowId: (a) => a.id,
  });
  const filtered = Object.values(filters).some(Boolean);

  return (
    <div className="flex flex-col gap-4">
      <form
        role="search"
        aria-label="Filter alerts"
        className="flex flex-col gap-3 rounded-lg border p-3 md:flex-row md:flex-wrap md:items-end"
        onSubmit={(e) => {
          e.preventDefault();
          apply({ device_id: deviceInput.trim() || null });
        }}
      >
        <FilterSelect
          id="alert-state"
          label="State"
          value={filters.state}
          onChange={(v) => apply({ state: v || null })}
          options={ALERT_STATES}
        />
        <FilterSelect
          id="alert-severity"
          label="Severity"
          value={filters.severity}
          onChange={(v) => apply({ severity: v || null })}
          options={SEVERITIES}
        />
        <FilterSelect
          id="alert-rule"
          label="Rule"
          value={filters.rule}
          onChange={(v) => apply({ rule: v || null })}
          options={ALERT_RULES}
        />
        <div className="flex min-w-48 flex-col gap-1.5">
          <Label htmlFor="alert-device">Device id</Label>
          <Input
            id="alert-device"
            value={deviceInput}
            onChange={(e) => setDeviceInput(e.target.value)}
            placeholder="dev-…"
            className="font-mono text-xs"
          />
        </div>
        <div className="flex gap-2">
          <Button type="submit" variant="secondary">
            Apply
          </Button>
          {filtered && (
            <Button
              type="button"
              variant="ghost"
              onClick={() => apply({ state: null, severity: null, rule: null, device_id: null })}
            >
              <FilterXIcon aria-hidden="true" /> Clear
            </Button>
          )}
        </div>
      </form>
      {alerts.isError ? (
        <ErrorState error={alerts.error} onRetry={() => void alerts.refetch()} />
      ) : (
        <>
          <DataTable
            table={table}
            isLoading={alerts.isLoading}
            caption="Alerts matching the current filters"
            emptyTitle="No alerts"
            emptyDescription="Nothing matches these filters."
            renderCard={(alert) => (
              <Card className="gap-2 px-4 py-3 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={alert.severity} />
                  <AlertStateBadge state={alert.state} />
                  <Link href={`/alerts/${alert.id}`} className="font-medium hover:underline">
                    {titleCase(alert.rule)}
                  </Link>
                </div>
                <Link
                  href={`/devices/${alert.device_id}`}
                  className="font-mono text-xs hover:underline"
                >
                  {alert.device_id}
                </Link>
                <p className="line-clamp-2 text-xs text-muted-foreground">{alert.explanation}</p>
                <div className="flex items-center justify-between">
                  <TimeAgo value={alert.created_at} className="text-xs text-muted-foreground" />
                  <AlertActions alert={alert} />
                </div>
              </Card>
            )}
          />
          <PaginationControls
            page={pagination.page}
            hasPrevious={pagination.hasPrevious}
            hasNext={Boolean(alerts.data?.next_cursor)}
            onPrevious={pagination.previous}
            onNext={() => pagination.next(alerts.data?.next_cursor)}
            isFetching={alerts.isFetching}
            count={alerts.data?.items.length}
          />
        </>
      )}
    </div>
  );
}
