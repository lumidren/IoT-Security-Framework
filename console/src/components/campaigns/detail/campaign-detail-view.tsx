'use client';

import * as React from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { getCoreRowModel, useReactTable, type ColumnDef } from '@tanstack/react-table';
import {
  OctagonAlertIcon,
  PauseIcon,
  PlayIcon,
  ShieldAlertIcon,
  Undo2Icon,
  XIcon,
} from 'lucide-react';
import { toast } from 'sonner';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { Progress } from '@/components/ui/progress';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ConfirmDialog } from '@/components/shared/confirm-dialog';
import { DataTable } from '@/components/shared/data-table';
import { KeyValueList } from '@/components/shared/key-value';
import { PageHeader } from '@/components/shared/page-header';
import { EmptyState, ErrorState } from '@/components/shared/states';
import {
  CampaignDeviceStateBadge,
  CampaignStateBadge,
  FirmwareSeverityBadge,
  StageStateBadge,
} from '@/components/shared/status-badges';
import { DateTime, TimeAgo } from '@/components/shared/time';
import { useQueryState } from '@/hooks/use-query-state';
import {
  useCampaign,
  useCampaignAction,
  useCampaignAudit,
  useCampaignDevices,
  type CampaignAction,
} from '@/lib/api/hooks';
import {
  CampaignDeviceStateSchema,
  type Campaign,
  type CampaignDevice,
  type Stage,
} from '@/lib/api/schemas';
import { formatDuration, shortHex, titleCase } from '@/lib/utils';
import { usePermission } from '@/providers/session-context';
import { useWsTopics } from '@/providers/ws-provider';

const ALL = '__all__';

function stageProgress(stage: Stage): number {
  if (stage.counts.targeted === 0) return stage.state === 'passed' ? 100 : 0;
  return Math.round(
    ((stage.counts.success +
      stage.counts.failed +
      stage.counts.rolled_back +
      stage.counts.rejected) /
      stage.counts.targeted) *
      100,
  );
}

function StageCard({ stage, current }: { stage: Stage; current: boolean }) {
  const pct = stageProgress(stage);
  const failureRate = stage.counts.targeted > 0 ? stage.counts.failed / stage.counts.targeted : 0;
  return (
    <li className={`rounded-lg border p-3 ${current ? 'border-primary' : ''}`}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="font-medium">
          Stage {stage.index + 1} · {stage.percent}% of targets
        </p>
        <StageStateBadge state={stage.state} />
      </div>
      <Progress
        value={pct}
        className="mt-2 h-2"
        aria-label={`Stage ${stage.index + 1}: ${pct}% complete`}
        indicatorClassName={stage.state === 'halted' ? 'bg-destructive' : undefined}
      />
      <dl className="tabular mt-2 grid grid-cols-3 gap-x-3 gap-y-1 text-xs sm:grid-cols-5">
        {(
          [
            'targeted',
            'notified',
            'downloading',
            'applying',
            'success',
            'failed',
            'rolled_back',
            'rejected',
          ] as const
        ).map((key) => (
          <div key={key} className="flex flex-col">
            <dt className="text-muted-foreground">{titleCase(key)}</dt>
            <dd
              className={
                key === 'failed' && stage.counts.failed > 0
                  ? 'font-medium text-destructive'
                  : key === 'success'
                    ? 'font-medium text-success'
                    : ''
              }
            >
              {stage.counts[key]}
            </dd>
          </div>
        ))}
        <div className="flex flex-col">
          <dt className="text-muted-foreground">Dwell</dt>
          <dd>{stage.dwell_s > 0 ? formatDuration(stage.dwell_s) : 'none'}</dd>
        </div>
        <div className="flex flex-col">
          <dt className="text-muted-foreground">Failure budget</dt>
          <dd
            className={failureRate > stage.max_failure_rate ? 'font-medium text-destructive' : ''}
          >
            {(failureRate * 100).toFixed(1)}% / {(stage.max_failure_rate * 100).toFixed(0)}%
          </dd>
        </div>
      </dl>
      {(stage.started_at || stage.finished_at) && (
        <p className="mt-2 text-xs text-muted-foreground">
          {stage.started_at && (
            <>
              started <DateTime value={stage.started_at} />
            </>
          )}
          {stage.finished_at && (
            <>
              {' '}
              · finished <DateTime value={stage.finished_at} />
            </>
          )}
        </p>
      )}
    </li>
  );
}

function CampaignControls({ campaign }: { campaign: Campaign }) {
  const router = useRouter();
  const canControl = usePermission('campaign.control');
  const canRollback = usePermission('campaign.rollback');
  const action = useCampaignAction(campaign.id);
  const [dialog, setDialog] = React.useState<CampaignAction | null>(null);
  if (!canControl && !canRollback) return null;

  const run = (type: CampaignAction, reason?: string) =>
    action.mutate(
      { action: type, reason },
      {
        onSuccess: (result) => {
          setDialog(null);
          if (type === 'rollback') {
            toast.success('Rollback campaign created and started');
            router.push(`/campaigns/${result.id}`);
          } else {
            toast.success(`Campaign ${titleCase(result.state)}`);
          }
        },
        onError: (error) => {
          if (!dialog) toast.error(error instanceof Error ? error.message : 'Action failed');
        },
      },
    );

  const s = campaign.state;
  return (
    <>
      {canControl && s === 'draft' && (
        <Button onClick={() => run('start')} disabled={action.isPending}>
          <PlayIcon aria-hidden="true" /> Start
        </Button>
      )}
      {canControl && s === 'running' && (
        <Button variant="outline" onClick={() => run('pause')} disabled={action.isPending}>
          <PauseIcon aria-hidden="true" /> Pause
        </Button>
      )}
      {canControl && s === 'paused' && (
        <Button onClick={() => run('resume')} disabled={action.isPending}>
          <PlayIcon aria-hidden="true" /> Resume
        </Button>
      )}
      {canControl && (s === 'running' || s === 'paused') && (
        <Button variant="destructive" onClick={() => setDialog('halt')}>
          <OctagonAlertIcon aria-hidden="true" /> Halt
        </Button>
      )}
      {canControl && (s === 'draft' || s === 'running' || s === 'paused') && (
        <Button variant="ghost" onClick={() => setDialog('cancel')}>
          <XIcon aria-hidden="true" /> Cancel
        </Button>
      )}
      {canRollback &&
        (s === 'running' || s === 'paused' || s === 'halted' || s === 'completed') && (
          <Button variant="outline" onClick={() => setDialog('rollback')}>
            <Undo2Icon aria-hidden="true" /> Roll back
          </Button>
        )}

      <ConfirmDialog
        open={dialog === 'halt'}
        onOpenChange={(open) => !open && setDialog(null)}
        title="Halt this campaign?"
        description="Devices that have not been notified stay on their current firmware. Devices mid-update finish or roll back on their own health check."
        confirmLabel="Halt campaign"
        destructive
        reasonLabel="Reason"
        isPending={action.isPending}
        error={action.error}
        onConfirm={({ reason }) => run('halt', reason)}
      />
      <ConfirmDialog
        open={dialog === 'cancel'}
        onOpenChange={(open) => !open && setDialog(null)}
        title="Cancel this campaign?"
        description="The campaign is closed and cannot be resumed."
        confirmLabel="Cancel campaign"
        destructive
        isPending={action.isPending}
        error={action.error}
        onConfirm={() => run('cancel')}
      />
      <ConfirmDialog
        open={dialog === 'rollback'}
        onOpenChange={(open) => !open && setDialog(null)}
        title="Roll back this campaign?"
        description="A child campaign re-signs the previous image with a higher version code so devices accept it under the anti-rollback rule, then rolls it out to the same target at 100%."
        confirmLabel="Create rollback campaign"
        destructive
        reasonLabel="Reason"
        isPending={action.isPending}
        error={action.error}
        onConfirm={({ reason }) => run('rollback', reason)}
      >
        {campaign.severity === 'security' && (
          <Alert variant="warning">
            <ShieldAlertIcon aria-hidden="true" />
            <AlertTitle>Four-eyes rule</AlertTitle>
            <AlertDescription>
              This is a security rollout. Rolling it back re-exposes the fleet to the fixed
              vulnerability: a second administrator must review this reason in the audit log before
              the rollback starts.
            </AlertDescription>
          </Alert>
        )}
      </ConfirmDialog>
    </>
  );
}

function CampaignDevicesTable({ campaignId }: { campaignId: string }) {
  const [state, setState] = React.useState('');
  const devices = useCampaignDevices(campaignId, state || undefined);
  const items = React.useMemo(
    () => devices.data?.pages.flatMap((p) => p.items) ?? [],
    [devices.data],
  );
  const columns = React.useMemo<ColumnDef<CampaignDevice>[]>(
    () => [
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
        accessorKey: 'state',
        header: 'State',
        cell: ({ row }) => <CampaignDeviceStateBadge state={row.original.state} />,
      },
      {
        accessorKey: 'progress_pct',
        header: 'Progress',
        cell: ({ row }) => (
          <div className="flex min-w-32 items-center gap-2">
            <Progress
              value={row.original.progress_pct}
              className="h-1.5"
              aria-label={`${row.original.progress_pct}%`}
            />
            <span className="tabular text-xs">{Math.round(row.original.progress_pct)}%</span>
          </div>
        ),
      },
      {
        accessorKey: 'notified_at',
        header: 'Notified',
        cell: ({ row }) => <TimeAgo value={row.original.notified_at} />,
      },
      {
        accessorKey: 'updated_at',
        header: 'Updated',
        cell: ({ row }) => <TimeAgo value={row.original.updated_at} />,
      },
      {
        accessorKey: 'fw_hash_hex',
        header: 'Applied hash',
        cell: ({ row }) => (
          <span className="font-mono text-xs">{shortHex(row.original.fw_hash_hex, 6)}</span>
        ),
      },
      {
        accessorKey: 'error',
        header: 'Error',
        cell: ({ row }) => (
          <span className="block max-w-xs text-xs whitespace-normal text-destructive">
            {row.original.error ?? '—'}
          </span>
        ),
      },
    ],
    [],
  );
  const table = useReactTable({
    data: items,
    columns,
    getCoreRowModel: getCoreRowModel(),
    getRowId: (d) => d.device_id,
  });
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="campaign-device-state">Device state</Label>
        <Select value={state || ALL} onValueChange={(v) => setState(v === ALL ? '' : v)}>
          <SelectTrigger id="campaign-device-state" className="w-44">
            <SelectValue placeholder="All" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL}>All</SelectItem>
            {CampaignDeviceStateSchema.options.map((s) => (
              <SelectItem key={s} value={s}>
                {titleCase(s)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      {devices.isError ? (
        <ErrorState error={devices.error} onRetry={() => void devices.refetch()} />
      ) : (
        <DataTable
          table={table}
          isLoading={devices.isLoading}
          caption="Devices in this campaign"
          emptyTitle="No devices yet"
          emptyDescription="Devices are assigned to stages when the campaign starts."
          renderCard={(d) => (
            <Card className="gap-2 px-4 py-3 text-sm">
              <div className="flex items-center justify-between">
                <Link
                  href={`/devices/${d.device_id}`}
                  className="font-mono text-xs hover:underline"
                >
                  {d.device_id}
                </Link>
                <CampaignDeviceStateBadge state={d.state} />
              </div>
              <Progress
                value={d.progress_pct}
                className="h-1.5"
                aria-label={`${d.progress_pct}%`}
              />
              {d.error && <p className="text-xs text-destructive">{d.error}</p>}
            </Card>
          )}
        />
      )}
      {devices.hasNextPage && (
        <Button
          variant="outline"
          size="sm"
          className="self-center"
          onClick={() => void devices.fetchNextPage()}
          disabled={devices.isFetchingNextPage}
        >
          Load more
        </Button>
      )}
    </div>
  );
}

function CampaignAudit({ campaignId }: { campaignId: string }) {
  const audit = useCampaignAudit(campaignId);
  const items = audit.data?.pages.flatMap((p) => p.items) ?? [];
  if (audit.isError) return <ErrorState error={audit.error} onRetry={() => void audit.refetch()} />;
  if (audit.isLoading) return <Skeleton className="h-40 w-full" />;
  if (items.length === 0)
    return (
      <EmptyState
        title="No audit events"
        description="Lifecycle actions on this campaign are recorded here."
      />
    );
  return (
    <ol className="divide-y rounded-lg border" aria-label="Campaign audit events">
      {items.map((event) => (
        <li
          key={event.id}
          className="flex flex-wrap items-baseline justify-between gap-2 px-4 py-2 text-sm"
        >
          <span>
            <span className="font-mono text-xs font-medium">{event.action}</span> by{' '}
            {event.actor.name ?? event.actor.id}
            {event.outcome === 'failure' && <span className="text-destructive"> (failed)</span>}
            {event.details && typeof event.details['reason'] === 'string' && (
              <span className="text-muted-foreground"> — {event.details['reason']}</span>
            )}
          </span>
          <DateTime value={event.at} className="text-xs text-muted-foreground" />
        </li>
      ))}
      {audit.hasNextPage && (
        <li className="p-2 text-center">
          <Button variant="outline" size="sm" onClick={() => void audit.fetchNextPage()}>
            Load more
          </Button>
        </li>
      )}
    </ol>
  );
}

export function CampaignDetailView({ id }: { id: string }) {
  const campaign = useCampaign(id);
  const { get, set } = useQueryState();
  const tab = get('tab') === 'audit' ? 'audit' : 'devices';
  useWsTopics([`campaign:${id}`]);

  if (campaign.isError) {
    return (
      <>
        <PageHeader
          title="Campaign"
          crumbs={[{ label: 'Campaigns', href: '/campaigns' }, { label: id }]}
        />
        <ErrorState error={campaign.error} onRetry={() => void campaign.refetch()} />
      </>
    );
  }
  const data = campaign.data;
  if (!data) return <Skeleton className="h-96 w-full" />;

  return (
    <>
      <PageHeader
        crumbs={[{ label: 'Campaigns', href: '/campaigns' }, { label: data.name }]}
        title={data.name}
        description={
          <span className="flex flex-wrap items-center gap-2">
            <CampaignStateBadge state={data.state} />
            <FirmwareSeverityBadge severity={data.severity} />
            <span>
              {data.firmware.product}/{data.firmware.version} · code {data.firmware.version_code}
              {data.delta ? ' · delta' : ''}
            </span>
          </span>
        }
        actions={<CampaignControls campaign={data} />}
      />
      {data.halt_reason && (
        <Alert variant="destructive" className="mb-4">
          <OctagonAlertIcon aria-hidden="true" />
          <AlertTitle>{data.state === 'rolled_back' ? 'Rolled back' : 'Halted'}</AlertTitle>
          <AlertDescription>{data.halt_reason}</AlertDescription>
        </Alert>
      )}
      {data.parent_campaign_id && (
        <p className="mb-4 text-sm text-muted-foreground">
          Rollback of{' '}
          <Link
            href={`/campaigns/${data.parent_campaign_id}`}
            className="underline-offset-4 hover:underline"
          >
            {data.parent_campaign_id}
          </Link>
        </p>
      )}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Stages</CardTitle>
            <CardDescription>
              Stage {Math.min(data.current_stage + 1, data.stages.length)} of {data.stages.length} ·{' '}
              {data.totals.success} succeeded, {data.totals.failed} failed of {data.totals.targeted}{' '}
              targeted
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ol className="flex flex-col gap-3">
              {data.stages.map((stage) => (
                <StageCard
                  key={stage.index}
                  stage={stage}
                  current={stage.index === data.current_stage && data.state === 'running'}
                />
              ))}
            </ol>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Details</CardTitle>
          </CardHeader>
          <CardContent>
            <KeyValueList
              columns={1}
              items={[
                {
                  label: 'Image SHA-256',
                  value: shortHex(data.firmware.sha256_hex, 10),
                  mono: true,
                },
                {
                  label: 'Signing',
                  value: `${data.firmware.signing_key_id ?? '—'}${data.firmware.pq_signed ? ' + ML-DSA-65' : ''}`,
                },
                { label: 'Groups', value: data.target.groups.join(', ') || '—' },
                {
                  label: 'Tags',
                  value:
                    Object.entries(data.target.tags)
                      .map(([k, v]) => `${k}:${v}`)
                      .join(', ') || '—',
                },
                { label: 'Explicit devices', value: data.target.device_ids.length },
                { label: 'Created', value: <DateTime value={data.created_at} /> },
                { label: 'Started', value: <DateTime value={data.started_at} /> },
                { label: 'Finished', value: <DateTime value={data.finished_at} /> },
                { label: 'Created by', value: data.created_by ?? '—' },
              ]}
            />
          </CardContent>
        </Card>
      </div>
      <Tabs
        value={tab}
        onValueChange={(v) => set({ tab: v === 'devices' ? null : v })}
        className="mt-6"
      >
        <TabsList aria-label="Campaign sections">
          <TabsTrigger value="devices">Devices</TabsTrigger>
          <TabsTrigger value="audit">Audit</TabsTrigger>
        </TabsList>
        <TabsContent value="devices" className="pt-2">
          <CampaignDevicesTable campaignId={id} />
        </TabsContent>
        <TabsContent value="audit" className="pt-2">
          <CampaignAudit campaignId={id} />
        </TabsContent>
      </Tabs>
    </>
  );
}
