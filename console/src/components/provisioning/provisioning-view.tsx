'use client';

import * as React from 'react';
import Link from 'next/link';
import { getCoreRowModel, useReactTable, type ColumnDef } from '@tanstack/react-table';
import { CheckIcon, XIcon } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ConfirmDialog } from '@/components/shared/confirm-dialog';
import { DataTable } from '@/components/shared/data-table';
import { PaginationControls } from '@/components/shared/pagination-controls';
import { ErrorState, errorMessage } from '@/components/shared/states';
import { ProvisioningStateBadge } from '@/components/shared/status-badges';
import { DateTime, TimeAgo } from '@/components/shared/time';
import { useCursorPagination } from '@/hooks/use-cursor-pagination';
import { useQueryState } from '@/hooks/use-query-state';
import { useApproveProvisioning, useProvisioning, useRejectProvisioning } from '@/lib/api/hooks';
import {
  ProvisioningStateSchema,
  type ProvisioningItem,
  type ProvisioningState,
} from '@/lib/api/schemas';
import { shortHex } from '@/lib/utils';
import { usePermission } from '@/providers/session-context';

export function ProvisioningView() {
  const { get, set } = useQueryState();
  const requested = get('state');
  const state: ProvisioningState = ProvisioningStateSchema.safeParse(requested).success
    ? (requested as ProvisioningState)
    : 'manufactured';
  const pagination = useCursorPagination();
  const items = useProvisioning(state, pagination.cursor);
  const canReview = usePermission('provisioning.review');
  const approve = useApproveProvisioning();
  const reject = useRejectProvisioning();
  const [rejecting, setRejecting] = React.useState<ProvisioningItem | null>(null);
  const approveMutate = approve.mutate;
  const approvePending = approve.isPending;

  const onApprove = React.useCallback(
    (item: ProvisioningItem) =>
      approveMutate(item.device_id, {
        onSuccess: (device) => toast.success(`${device.id} is now ${device.state}`),
        onError: (error) => toast.error(errorMessage(error)),
      }),
    [approveMutate],
  );

  const columns = React.useMemo<ColumnDef<ProvisioningItem>[]>(
    () => [
      {
        accessorKey: 'device_id',
        header: 'Device',
        cell: ({ row }) => (
          <div className="flex flex-col">
            <Link
              href={`/devices/${row.original.device_id}`}
              className="font-mono text-xs font-medium hover:underline"
            >
              {row.original.device_id}
            </Link>
            <span className="text-xs text-muted-foreground">
              {row.original.product} · {row.original.se_type ?? 'unknown SE'}
            </span>
          </div>
        ),
      },
      {
        accessorKey: 'state',
        header: 'State',
        cell: ({ row }) => <ProvisioningStateBadge state={row.original.state} />,
      },
      {
        accessorKey: 'bootstrap_serial_hex',
        header: 'Bootstrap serial',
        cell: ({ row }) => (
          <span className="font-mono text-xs">
            {shortHex(row.original.bootstrap_serial_hex, 8)}
          </span>
        ),
      },
      {
        accessorKey: 'created_at',
        header: 'Manufactured',
        cell: ({ row }) => <DateTime value={row.original.created_at} />,
      },
      {
        accessorKey: 'last_attempt_at',
        header: 'Last attempt',
        cell: ({ row }) => <TimeAgo value={row.original.last_attempt_at} />,
      },
      {
        accessorKey: 'attempts',
        header: 'Attempts',
        cell: ({ row }) => <span className="tabular">{row.original.attempts}</span>,
      },
      {
        accessorKey: 'last_error',
        header: 'Last error',
        cell: ({ row }) => (
          <span
            className="block max-w-xs truncate text-xs whitespace-normal text-destructive"
            title={row.original.last_error ?? undefined}
          >
            {row.original.last_error ?? '—'}
          </span>
        ),
      },
      ...(canReview
        ? [
            {
              id: 'actions',
              header: 'Actions',
              cell: ({ row }) => (
                <div className="flex gap-1">
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => onApprove(row.original)}
                    disabled={approvePending}
                    aria-label={`Approve ${row.original.device_id}`}
                  >
                    <CheckIcon aria-hidden="true" /> Approve
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => setRejecting(row.original)}
                    aria-label={`Reject ${row.original.device_id}`}
                  >
                    <XIcon aria-hidden="true" /> Reject
                  </Button>
                </div>
              ),
            } satisfies ColumnDef<ProvisioningItem>,
          ]
        : []),
    ],
    [canReview, approvePending, onApprove],
  );

  const table = useReactTable({
    data: items.data?.items ?? [],
    columns,
    getCoreRowModel: getCoreRowModel(),
    getRowId: (r) => r.device_id,
  });

  return (
    <div className="flex flex-col gap-4">
      <Tabs
        value={state}
        onValueChange={(value) => {
          set({ state: value === 'manufactured' ? null : value });
          pagination.reset();
        }}
      >
        <TabsList aria-label="Provisioning state">
          <TabsTrigger value="manufactured">Awaiting enrollment</TabsTrigger>
          <TabsTrigger value="provisioned">Enrolled, pending activation</TabsTrigger>
          <TabsTrigger value="failed">Failed</TabsTrigger>
        </TabsList>
      </Tabs>
      <p className="text-sm text-muted-foreground">
        {state === 'manufactured' &&
          'Manufactured devices with a bootstrap certificate that have not completed EST enrollment. Approving moves them to provisioned.'}
        {state === 'provisioned' &&
          'Devices that passed attestation. When the tenant requires manual approval, activate them here.'}
        {state === 'failed' &&
          'Enrollment attempts rejected by the PKI (attestation, nonce or assurance policy). Approve to retry or reject to record a decision.'}
      </p>
      {items.isError ? (
        <ErrorState error={items.error} onRetry={() => void items.refetch()} />
      ) : (
        <>
          <DataTable
            table={table}
            isLoading={items.isLoading}
            caption={`Provisioning items in state ${state}`}
            emptyTitle="Queue is empty"
            emptyDescription="New devices appear here in real time as the factory manufactures them."
            renderCard={(item) => (
              <Card className="gap-2 px-4 py-3 text-sm">
                <div className="flex items-center justify-between gap-2">
                  <Link
                    href={`/devices/${item.device_id}`}
                    className="font-mono text-xs font-medium hover:underline"
                  >
                    {item.device_id}
                  </Link>
                  <ProvisioningStateBadge state={item.state} />
                </div>
                <p className="text-xs text-muted-foreground">
                  {item.product} · {item.se_type ?? 'unknown SE'} · {item.attempts} attempt
                  {item.attempts === 1 ? '' : 's'}
                </p>
                {item.last_error && <p className="text-xs text-destructive">{item.last_error}</p>}
                {canReview && (
                  <div className="flex gap-2 pt-1">
                    <Button size="sm" variant="outline" onClick={() => onApprove(item)}>
                      Approve
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => setRejecting(item)}>
                      Reject
                    </Button>
                  </div>
                )}
              </Card>
            )}
          />
          <PaginationControls
            page={pagination.page}
            hasPrevious={pagination.hasPrevious}
            hasNext={Boolean(items.data?.next_cursor)}
            onPrevious={pagination.previous}
            onNext={() => pagination.next(items.data?.next_cursor)}
            isFetching={items.isFetching}
            count={items.data?.items.length}
          />
        </>
      )}
      <ConfirmDialog
        open={rejecting !== null}
        onOpenChange={(open) => !open && setRejecting(null)}
        title={`Reject ${rejecting?.device_id ?? ''}?`}
        description="The enrollment is marked failed with your reason. The device keeps its bootstrap certificate and can be approved later."
        confirmLabel="Reject enrollment"
        destructive
        reasonLabel="Reason"
        isPending={reject.isPending}
        error={reject.error}
        onConfirm={({ reason }) => {
          if (!rejecting) return;
          reject.mutate(
            { deviceId: rejecting.device_id, reason },
            {
              onSuccess: () => {
                toast.success('Enrollment rejected');
                setRejecting(null);
              },
            },
          );
        }}
      />
    </div>
  );
}
