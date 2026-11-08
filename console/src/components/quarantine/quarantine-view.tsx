'use client';

import * as React from 'react';
import Link from 'next/link';
import { getCoreRowModel, useReactTable, type ColumnDef } from '@tanstack/react-table';
import { ShieldCheckIcon } from 'lucide-react';
import { toast } from 'sonner';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { ConfirmDialog } from '@/components/shared/confirm-dialog';
import { DataTable } from '@/components/shared/data-table';
import { PaginationControls } from '@/components/shared/pagination-controls';
import { ErrorState } from '@/components/shared/states';
import { DateTime, TimeAgo } from '@/components/shared/time';
import { useCursorPagination } from '@/hooks/use-cursor-pagination';
import { useQuarantineList, useReleaseDevice } from '@/lib/api/hooks';
import type { QuarantineEntry } from '@/lib/api/schemas';
import { usePermission } from '@/providers/session-context';

export function QuarantineView() {
  const pagination = useCursorPagination();
  const list = useQuarantineList(pagination.cursor);
  const canRelease = usePermission('device.release');
  const release = useReleaseDevice();
  const [releasing, setReleasing] = React.useState<QuarantineEntry | null>(null);

  const columns = React.useMemo<ColumnDef<QuarantineEntry>[]>(
    () => [
      {
        accessorKey: 'device_id',
        header: 'Device',
        cell: ({ row }) => (
          <Link
            href={`/devices/${row.original.device_id}`}
            className="font-mono text-xs font-medium hover:underline"
          >
            {row.original.device_id}
          </Link>
        ),
      },
      {
        accessorKey: 'reason',
        header: 'Reason',
        cell: ({ row }) => (
          <span className="block max-w-md text-sm whitespace-normal">{row.original.reason}</span>
        ),
      },
      {
        accessorKey: 'by',
        header: 'By',
        cell: ({ row }) =>
          row.original.by === 'auto' ? (
            <Badge variant="purple">Automatic</Badge>
          ) : (
            <Badge variant="secondary">{row.original.by.replace(/^user:/, '')}</Badge>
          ),
      },
      {
        accessorKey: 'alert_id',
        header: 'Alert',
        cell: ({ row }) =>
          row.original.alert_id ? (
            <Link
              href={`/alerts/${row.original.alert_id}`}
              className="text-sm text-primary underline-offset-4 hover:underline"
            >
              View alert
            </Link>
          ) : (
            <span className="text-muted-foreground">—</span>
          ),
      },
      {
        accessorKey: 'quarantined_at',
        header: 'Since',
        cell: ({ row }) => (
          <span className="flex flex-col">
            <TimeAgo value={row.original.quarantined_at} />
            <DateTime
              value={row.original.quarantined_at}
              className="text-xs text-muted-foreground"
            />
          </span>
        ),
      },
      ...(canRelease
        ? [
            {
              id: 'actions',
              header: 'Actions',
              cell: ({ row }) => (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => setReleasing(row.original)}
                  aria-label={`Release ${row.original.device_id}`}
                >
                  <ShieldCheckIcon aria-hidden="true" /> Release
                </Button>
              ),
            } satisfies ColumnDef<QuarantineEntry>,
          ]
        : []),
    ],
    [canRelease],
  );
  const table = useReactTable({
    data: list.data?.items ?? [],
    columns,
    getCoreRowModel: getCoreRowModel(),
    getRowId: (q) => `${q.device_id}-${q.quarantined_at}`,
  });

  if (list.isError) return <ErrorState error={list.error} onRetry={() => void list.refetch()} />;

  return (
    <div className="flex flex-col gap-4">
      <DataTable
        table={table}
        isLoading={list.isLoading}
        caption="Quarantined devices"
        emptyTitle="No devices in quarantine"
        emptyDescription="Devices appear here when a critical rule fires with auto-quarantine enabled or an operator isolates them."
        renderCard={(entry) => (
          <Card className="gap-2 px-4 py-3 text-sm">
            <div className="flex items-center justify-between">
              <Link
                href={`/devices/${entry.device_id}`}
                className="font-mono text-xs font-medium hover:underline"
              >
                {entry.device_id}
              </Link>
              {entry.by === 'auto' ? (
                <Badge variant="purple">Automatic</Badge>
              ) : (
                <Badge variant="secondary">{entry.by.replace(/^user:/, '')}</Badge>
              )}
            </div>
            <p>{entry.reason}</p>
            <TimeAgo value={entry.quarantined_at} className="text-xs text-muted-foreground" />
            {canRelease && (
              <Button
                size="sm"
                variant="outline"
                className="self-start"
                onClick={() => setReleasing(entry)}
              >
                Release
              </Button>
            )}
          </Card>
        )}
      />
      <PaginationControls
        page={pagination.page}
        hasPrevious={pagination.hasPrevious}
        hasNext={Boolean(list.data?.next_cursor)}
        onPrevious={pagination.previous}
        onNext={() => pagination.next(list.data?.next_cursor)}
        isFetching={list.isFetching}
        count={list.data?.items.length}
      />
      <ConfirmDialog
        open={releasing !== null}
        onOpenChange={(open) => !open && setReleasing(null)}
        title={`Release ${releasing?.device_id ?? ''}?`}
        description="The device returns to active and must re-enroll through EST with a fresh attestation before it can connect."
        confirmLabel="Release device"
        reasonLabel="Release note"
        isPending={release.isPending}
        error={release.error}
        onConfirm={({ reason }) => {
          if (!releasing) return;
          release.mutate(
            { id: releasing.device_id, note: reason },
            {
              onSuccess: () => {
                toast.success('Device released from quarantine');
                setReleasing(null);
              },
            },
          );
        }}
      />
    </div>
  );
}
