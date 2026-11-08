'use client';

import * as React from 'react';
import { getCoreRowModel, useReactTable, type ColumnDef } from '@tanstack/react-table';
import { Card } from '@/components/ui/card';
import { CopyButton } from '@/components/shared/copy-button';
import { DataTable } from '@/components/shared/data-table';
import { ErrorState } from '@/components/shared/states';
import { CertStatusBadge } from '@/components/shared/status-badges';
import { DateTime } from '@/components/shared/time';
import { useDeviceCertificates } from '@/lib/api/hooks';
import type { Certificate, CertStatus } from '@/lib/api/schemas';
import { shortHex } from '@/lib/utils';

export function certificateStatus(cert: Certificate, now = Date.now()): CertStatus {
  if (cert.revoked_at) return 'revoked';
  const notAfter = Date.parse(cert.not_after);
  if (notAfter < now) return 'expired';
  if (notAfter - now < 7 * 86_400_000) return 'expiring';
  return 'valid';
}

export function CertificatesTab({ deviceId }: { deviceId: string }) {
  const certificates = useDeviceCertificates(deviceId);
  const columns = React.useMemo<ColumnDef<Certificate>[]>(
    () => [
      {
        accessorKey: 'serial_hex',
        header: 'Serial',
        cell: ({ row }) => (
          <span className="inline-flex items-center gap-1">
            <span className="font-mono text-xs">{shortHex(row.original.serial_hex, 8)}</span>
            <CopyButton
              value={row.original.serial_hex}
              label={`Copy serial ${shortHex(row.original.serial_hex, 4)}`}
            />
          </span>
        ),
      },
      {
        id: 'status',
        header: 'Status',
        cell: ({ row }) => <CertStatusBadge status={certificateStatus(row.original)} />,
      },
      {
        accessorKey: 'not_before',
        header: 'Valid from',
        cell: ({ row }) => <DateTime value={row.original.not_before} />,
      },
      {
        accessorKey: 'not_after',
        header: 'Valid until',
        cell: ({ row }) => <DateTime value={row.original.not_after} />,
      },
      {
        accessorKey: 'revoked_at',
        header: 'Revoked',
        cell: ({ row }) => <DateTime value={row.original.revoked_at} />,
      },
      {
        accessorKey: 'revocation_reason',
        header: 'Reason',
        cell: ({ row }) => row.original.revocation_reason ?? '—',
      },
      {
        accessorKey: 'issuer',
        header: 'Issuer',
        cell: ({ row }) => (
          <span className="text-xs text-muted-foreground">{row.original.issuer}</span>
        ),
      },
    ],
    [],
  );
  const table = useReactTable({
    data: certificates.data ?? [],
    columns,
    getCoreRowModel: getCoreRowModel(),
    getRowId: (c) => c.serial_hex,
  });

  if (certificates.isError)
    return <ErrorState error={certificates.error} onRetry={() => void certificates.refetch()} />;

  return (
    <DataTable
      table={table}
      isLoading={certificates.isLoading}
      caption="Certificates issued to this device"
      emptyTitle="No certificates issued"
      emptyDescription="Certificates appear once the device completes EST enrollment."
      renderCard={(cert) => (
        <Card className="gap-2 px-4 py-3 text-sm">
          <div className="flex items-center justify-between">
            <span className="font-mono text-xs">{shortHex(cert.serial_hex, 8)}</span>
            <CertStatusBadge status={certificateStatus(cert)} />
          </div>
          <p className="text-xs text-muted-foreground">
            <DateTime value={cert.not_before} /> → <DateTime value={cert.not_after} />
          </p>
          {cert.revoked_at && (
            <p className="text-xs text-destructive">
              Revoked <DateTime value={cert.revoked_at} /> · {cert.revocation_reason}
            </p>
          )}
        </Card>
      )}
    />
  );
}
