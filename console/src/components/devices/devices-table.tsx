'use client';

import * as React from 'react';
import Link from 'next/link';
import {
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
  type RowSelectionState,
} from '@tanstack/react-table';
import { BellIcon } from 'lucide-react';
import { Checkbox } from '@/components/ui/checkbox';
import { Card } from '@/components/ui/card';
import { DataTable } from '@/components/shared/data-table';
import {
  AssuranceBadge,
  CertStatusBadge,
  ConnectionIndicator,
  DeviceStateBadge,
} from '@/components/shared/status-badges';
import { TimeAgo } from '@/components/shared/time';
import type { DeviceSummary } from '@/lib/api/schemas';

export function DevicesTable({
  devices,
  isLoading,
  rowSelection,
  onRowSelectionChange,
  selectable = true,
}: {
  devices: DeviceSummary[];
  isLoading: boolean;
  rowSelection: RowSelectionState;
  onRowSelectionChange: (state: RowSelectionState) => void;
  selectable?: boolean;
}) {
  const columns = React.useMemo<ColumnDef<DeviceSummary>[]>(() => {
    const cols: ColumnDef<DeviceSummary>[] = [];
    if (selectable) {
      cols.push({
        id: 'select',
        size: 40,
        header: ({ table }) => (
          <Checkbox
            checked={
              table.getIsAllPageRowsSelected()
                ? true
                : table.getIsSomePageRowsSelected()
                  ? 'indeterminate'
                  : false
            }
            onCheckedChange={(value) => table.toggleAllPageRowsSelected(value === true)}
            aria-label="Select all devices on this page"
          />
        ),
        cell: ({ row }) => (
          <Checkbox
            checked={row.getIsSelected()}
            onCheckedChange={(value) => row.toggleSelected(value === true)}
            aria-label={`Select device ${row.original.id}`}
          />
        ),
        enableSorting: false,
      });
    }
    cols.push(
      {
        accessorKey: 'id',
        header: 'Device',
        cell: ({ row }) => (
          <div className="flex flex-col">
            <Link
              href={`/devices/${row.original.id}`}
              className="font-mono text-xs font-medium hover:underline"
            >
              {row.original.id}
            </Link>
            <span className="text-xs text-muted-foreground">
              {row.original.product} · {row.original.hw_revision}
            </span>
          </div>
        ),
      },
      {
        accessorKey: 'state',
        header: 'State',
        cell: ({ row }) => <DeviceStateBadge state={row.original.state} />,
      },
      {
        accessorKey: 'connected',
        header: 'Connectivity',
        cell: ({ row }) => <ConnectionIndicator connected={row.original.connected} />,
      },
      {
        accessorKey: 'assurance_level',
        header: 'Assurance',
        cell: ({ row }) => <AssuranceBadge level={row.original.assurance_level} />,
      },
      {
        accessorKey: 'fw_version',
        header: 'Firmware',
        cell: ({ row }) => <span className="tabular">{row.original.fw_version ?? '—'}</span>,
      },
      {
        id: 'cert',
        header: 'Certificate',
        cell: ({ row }) => <CertStatusBadge status={row.original.cert.status} />,
      },
      {
        accessorKey: 'groups',
        header: 'Groups',
        cell: ({ row }) => (
          <span
            className="max-w-48 truncate text-xs text-muted-foreground"
            title={row.original.groups.join(', ')}
          >
            {row.original.groups.join(', ') || '—'}
          </span>
        ),
      },
      {
        accessorKey: 'open_alerts',
        header: 'Alerts',
        cell: ({ row }) =>
          row.original.open_alerts > 0 ? (
            <Link
              href={`/alerts?device_id=${row.original.id}&state=open`}
              className="inline-flex items-center gap-1 text-sm text-destructive hover:underline"
            >
              <BellIcon className="size-3.5" aria-hidden="true" /> {row.original.open_alerts}
            </Link>
          ) : (
            <span className="text-muted-foreground">0</span>
          ),
      },
      {
        accessorKey: 'last_seen_at',
        header: 'Last seen',
        cell: ({ row }) => <TimeAgo value={row.original.last_seen_at} className="text-sm" />,
      },
    );
    return cols;
  }, [selectable]);

  const table = useReactTable({
    data: devices,
    columns,
    state: { rowSelection },
    onRowSelectionChange: (updater) =>
      onRowSelectionChange(typeof updater === 'function' ? updater(rowSelection) : updater),
    getRowId: (row) => row.id,
    enableRowSelection: selectable,
    getCoreRowModel: getCoreRowModel(),
  });

  return (
    <DataTable
      table={table}
      isLoading={isLoading}
      caption="Devices matching the current filters"
      emptyTitle="No devices match these filters"
      emptyDescription="Adjust the filters or clear them to see the whole fleet."
      renderCard={(device) => (
        <Card className="gap-2 px-4 py-3">
          <div className="flex items-start justify-between gap-2">
            <div className="min-w-0">
              <Link
                href={`/devices/${device.id}`}
                className="font-mono text-xs font-medium hover:underline"
              >
                {device.id}
              </Link>
              <p className="text-xs text-muted-foreground">
                {device.product} · {device.fw_version ?? 'no firmware'}
              </p>
            </div>
            {selectable && (
              <Checkbox
                checked={Boolean(rowSelection[device.id])}
                onCheckedChange={(value) =>
                  onRowSelectionChange({ ...rowSelection, [device.id]: value === true })
                }
                aria-label={`Select device ${device.id}`}
              />
            )}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <DeviceStateBadge state={device.state} />
            <AssuranceBadge level={device.assurance_level} />
            <CertStatusBadge status={device.cert.status} />
          </div>
          <div className="flex items-center justify-between text-xs">
            <ConnectionIndicator connected={device.connected} />
            <TimeAgo value={device.last_seen_at} className="text-muted-foreground" />
          </div>
        </Card>
      )}
    />
  );
}
