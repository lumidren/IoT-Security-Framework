'use client';

import * as React from 'react';
import Link from 'next/link';
import { getCoreRowModel, useReactTable, type ColumnDef } from '@tanstack/react-table';
import { PlusIcon } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { Progress } from '@/components/ui/progress';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { DataTable } from '@/components/shared/data-table';
import { PageHeader } from '@/components/shared/page-header';
import { PaginationControls } from '@/components/shared/pagination-controls';
import { ErrorState } from '@/components/shared/states';
import { CampaignStateBadge, FirmwareSeverityBadge } from '@/components/shared/status-badges';
import { TimeAgo } from '@/components/shared/time';
import { useCursorPagination } from '@/hooks/use-cursor-pagination';
import { useQueryState } from '@/hooks/use-query-state';
import { useCampaigns } from '@/lib/api/hooks';
import { CAMPAIGN_STATES, type Campaign } from '@/lib/api/schemas';
import { titleCase } from '@/lib/utils';
import { usePermission } from '@/providers/session-context';

const ALL = '__all__';

export function campaignProgress(campaign: Campaign): number {
  const targeted = campaign.totals.targeted;
  if (targeted === 0) return 0;
  return Math.round(
    ((campaign.totals.success +
      campaign.totals.failed +
      campaign.totals.rolled_back +
      campaign.totals.rejected) /
      targeted) *
      100,
  );
}

export function CampaignsView() {
  const { get, set } = useQueryState();
  const state = get('state');
  const pagination = useCursorPagination();
  const campaigns = useCampaigns(state || undefined, pagination.cursor);
  const canCreate = usePermission('campaign.create');

  const columns = React.useMemo<ColumnDef<Campaign>[]>(
    () => [
      {
        accessorKey: 'name',
        header: 'Campaign',
        cell: ({ row }) => (
          <div className="flex flex-col">
            <Link href={`/campaigns/${row.original.id}`} className="font-medium hover:underline">
              {row.original.name}
            </Link>
            <span className="text-xs text-muted-foreground">
              {row.original.firmware.product}/{row.original.firmware.version}
              {row.original.delta ? ' · delta' : ''}
            </span>
          </div>
        ),
      },
      {
        accessorKey: 'state',
        header: 'State',
        cell: ({ row }) => <CampaignStateBadge state={row.original.state} />,
      },
      {
        accessorKey: 'severity',
        header: 'Severity',
        cell: ({ row }) => <FirmwareSeverityBadge severity={row.original.severity} />,
      },
      {
        id: 'progress',
        header: 'Progress',
        cell: ({ row }) => {
          const pct = campaignProgress(row.original);
          return (
            <div className="flex min-w-40 items-center gap-2">
              <Progress
                value={pct}
                aria-label={`${pct}% of targeted devices finished`}
                className="h-2"
              />
              <span className="tabular text-xs">{pct}%</span>
            </div>
          );
        },
      },
      {
        id: 'stage',
        header: 'Stage',
        cell: ({ row }) => {
          const stage = row.original.stages[row.original.current_stage];
          return (
            <span className="text-sm">
              {stage
                ? `${row.original.current_stage + 1}/${row.original.stages.length} (${stage.percent}%)`
                : '—'}
            </span>
          );
        },
      },
      {
        id: 'counts',
        header: 'Success / failed',
        cell: ({ row }) => (
          <span className="tabular text-sm">
            <span className="text-success">{row.original.totals.success}</span> /{' '}
            <span className="text-destructive">{row.original.totals.failed}</span> of{' '}
            {row.original.totals.targeted}
          </span>
        ),
      },
      {
        accessorKey: 'created_at',
        header: 'Created',
        cell: ({ row }) => <TimeAgo value={row.original.created_at} />,
      },
    ],
    [],
  );
  const table = useReactTable({
    data: campaigns.data?.items ?? [],
    columns,
    getCoreRowModel: getCoreRowModel(),
    getRowId: (c) => c.id,
  });

  return (
    <>
      <PageHeader
        title="OTA campaigns"
        description="Staged firmware rollouts with dwell times, failure budgets and one-click rollback."
        actions={
          canCreate ? (
            <Button asChild>
              <Link href="/campaigns/new">
                <PlusIcon aria-hidden="true" /> New campaign
              </Link>
            </Button>
          ) : null
        }
      />
      <div className="flex flex-col gap-4">
        <div className="flex items-end gap-3">
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="campaign-state">State</Label>
            <Select
              value={state || ALL}
              onValueChange={(value) => {
                set({ state: value === ALL ? null : value });
                pagination.reset();
              }}
            >
              <SelectTrigger id="campaign-state" className="w-44">
                <SelectValue placeholder="All" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={ALL}>All</SelectItem>
                {CAMPAIGN_STATES.map((s) => (
                  <SelectItem key={s} value={s}>
                    {titleCase(s)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
        {campaigns.isError ? (
          <ErrorState error={campaigns.error} onRetry={() => void campaigns.refetch()} />
        ) : (
          <>
            <DataTable
              table={table}
              isLoading={campaigns.isLoading}
              caption="OTA campaigns"
              emptyTitle="No campaigns"
              emptyDescription="Create a campaign to roll out a signed firmware image in stages."
              renderCard={(campaign) => (
                <Card className="gap-2 px-4 py-3 text-sm">
                  <div className="flex items-center justify-between gap-2">
                    <Link
                      href={`/campaigns/${campaign.id}`}
                      className="font-medium hover:underline"
                    >
                      {campaign.name}
                    </Link>
                    <CampaignStateBadge state={campaign.state} />
                  </div>
                  <p className="text-xs text-muted-foreground">
                    {campaign.firmware.product}/{campaign.firmware.version} ·{' '}
                    <FirmwareSeverityBadge severity={campaign.severity} />
                  </p>
                  <Progress
                    value={campaignProgress(campaign)}
                    aria-label={`${campaignProgress(campaign)}% finished`}
                    className="h-2"
                  />
                </Card>
              )}
            />
            <PaginationControls
              page={pagination.page}
              hasPrevious={pagination.hasPrevious}
              hasNext={Boolean(campaigns.data?.next_cursor)}
              onPrevious={pagination.previous}
              onNext={() => pagination.next(campaigns.data?.next_cursor)}
              isFetching={campaigns.isFetching}
              count={campaigns.data?.items.length}
            />
          </>
        )}
      </div>
    </>
  );
}
