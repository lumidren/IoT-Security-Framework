'use client';

import * as React from 'react';
import dynamic from 'next/dynamic';
import Link from 'next/link';
import { ShieldBanIcon } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { ConfirmDialog } from '@/components/shared/confirm-dialog';
import { KeyValueList } from '@/components/shared/key-value';
import { PageHeader } from '@/components/shared/page-header';
import { ErrorState } from '@/components/shared/states';
import {
  AlertStateBadge,
  DeviceStateBadge,
  SeverityBadge,
} from '@/components/shared/status-badges';
import { DateTime } from '@/components/shared/time';
import { AlertActions } from '@/components/alerts/alert-actions';
import { DeviceTimeline } from '@/components/devices/detail/timeline-tab';
import { useAlert, useBaseline, useDevice, useQuarantineDevice } from '@/lib/api/hooks';
import { titleCase } from '@/lib/utils';
import { usePermission } from '@/providers/session-context';

const ScoreSparkline = dynamic(
  () => import('@/components/alerts/score-sparkline').then((m) => m.ScoreSparkline),
  {
    ssr: false,
    loading: () => <Skeleton className="h-[120px] w-full" />,
  },
);

function formatFeature(value: unknown): string {
  if (typeof value === 'number') return Number.isInteger(value) ? String(value) : value.toFixed(3);
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) return value.map(formatFeature).join(', ');
  return JSON.stringify(value);
}

export function AlertDetailView({ id }: { id: string }) {
  const alert = useAlert(id);
  const device = useDevice(alert.data?.device_id ?? '', Boolean(alert.data));
  const baseline = useBaseline(alert.data?.device_id ?? '');
  const canQuarantine = usePermission('device.quarantine');
  const quarantine = useQuarantineDevice();
  const [quarantineOpen, setQuarantineOpen] = React.useState(false);

  if (alert.isError) {
    return (
      <>
        <PageHeader title="Alert" crumbs={[{ label: 'Alerts', href: '/alerts' }, { label: id }]} />
        <ErrorState error={alert.error} onRetry={() => void alert.refetch()} />
      </>
    );
  }
  const data = alert.data;
  if (!data) return <Skeleton className="h-96 w-full" />;
  const alreadyQuarantined = device.data?.state === 'quarantined';
  const terminal = device.data?.state === 'decommissioned';

  return (
    <>
      <PageHeader
        crumbs={[{ label: 'Alerts', href: '/alerts' }, { label: titleCase(data.rule) }]}
        title={`${titleCase(data.rule)} on ${data.device_id}`}
        description={
          <span className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={data.severity} />
            <AlertStateBadge state={data.state} />
            <span>
              score {data.score.toFixed(2)} · raised <DateTime value={data.created_at} />
            </span>
            {data.false_positive && (
              <span className="text-muted-foreground">· marked false positive</span>
            )}
          </span>
        }
        actions={
          <>
            <AlertActions alert={data} size="default" />
            {canQuarantine && !alreadyQuarantined && !terminal && (
              <Button variant="destructive" onClick={() => setQuarantineOpen(true)}>
                <ShieldBanIcon aria-hidden="true" /> Quarantine device
              </Button>
            )}
          </>
        }
      />
      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Explanation</CardTitle>
            <CardDescription>
              Why the rule fired, in plain language, with the features that drove the score.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <p className="text-sm leading-relaxed">{data.explanation}</p>
            <div className="rounded-lg border">
              <Table>
                <caption className="sr-only">Features that contributed to the alert</caption>
                <TableHeader>
                  <TableRow>
                    <TableHead>Feature</TableHead>
                    <TableHead>Value</TableHead>
                    <TableHead>Baseline mean</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {Object.entries(data.features).map(([key, value]) => (
                    <TableRow key={key}>
                      <TableCell className="font-mono text-xs">{key}</TableCell>
                      <TableCell className="tabular whitespace-normal">
                        {formatFeature(value)}
                      </TableCell>
                      <TableCell className="tabular text-muted-foreground">
                        {baseline.data?.feature_means[key] !== undefined
                          ? formatFeature(baseline.data.feature_means[key])
                          : '—'}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            <div>
              <p className="mb-1 text-sm font-medium">Actions taken</p>
              {data.actions.length === 0 ? (
                <p className="text-sm text-muted-foreground">No automatic action.</p>
              ) : (
                <ul className="text-sm">
                  {data.actions.map((action, i) => (
                    <li key={i} className="flex flex-wrap gap-x-2">
                      <span className="font-medium">{titleCase(action.type)}</span>
                      <DateTime value={action.at} className="text-muted-foreground" />
                      {action.result && (
                        <span className="text-muted-foreground">— {action.result}</span>
                      )}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </CardContent>
        </Card>
        <div className="flex flex-col gap-4">
          <Card>
            <CardHeader>
              <CardTitle>Anomaly score</CardTitle>
              <CardDescription>
                Recent scores from the device baseline; the dashed line is the alert threshold.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {baseline.isError && (
                <ErrorState error={baseline.error} onRetry={() => void baseline.refetch()} />
              )}
              {baseline.isLoading && <Skeleton className="h-[120px] w-full" />}
              {baseline.data && (
                <>
                  <ScoreSparkline baseline={baseline.data} />
                  <KeyValueList
                    className="mt-3"
                    items={[
                      { label: 'Device class', value: baseline.data.device_class },
                      { label: 'Samples', value: baseline.data.samples.toLocaleString() },
                      { label: 'Threshold', value: baseline.data.score_threshold },
                      { label: 'Trained', value: <DateTime value={baseline.data.trained_at} /> },
                    ]}
                  />
                </>
              )}
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Device</CardTitle>
            </CardHeader>
            <CardContent>
              {device.data ? (
                <KeyValueList
                  columns={1}
                  items={[
                    {
                      label: 'Device',
                      value: (
                        <Link
                          href={`/devices/${device.data.id}`}
                          className="font-mono text-xs hover:underline"
                        >
                          {device.data.id}
                        </Link>
                      ),
                    },
                    { label: 'State', value: <DeviceStateBadge state={device.data.state} /> },
                    { label: 'Product', value: device.data.product },
                    { label: 'Firmware', value: device.data.fw_version ?? '—' },
                    { label: 'Open alerts', value: device.data.open_alerts },
                  ]}
                />
              ) : (
                <Skeleton className="h-32 w-full" />
              )}
            </CardContent>
          </Card>
        </div>
      </div>
      <Card className="mt-4">
        <CardHeader>
          <CardTitle>Device timeline</CardTitle>
          <CardDescription>Events around the alert for {data.device_id}.</CardDescription>
        </CardHeader>
        <CardContent>
          <DeviceTimeline deviceId={data.device_id} compact />
        </CardContent>
      </Card>
      <ConfirmDialog
        open={quarantineOpen}
        onOpenChange={setQuarantineOpen}
        title={`Quarantine ${data.device_id}?`}
        description="Revokes all certificates, denies the device in the policy cache and kicks its session within 10 seconds."
        confirmLabel="Quarantine device"
        destructive
        reasonLabel="Reason"
        isPending={quarantine.isPending}
        error={quarantine.error}
        onConfirm={({ reason }) =>
          quarantine.mutate(
            { id: data.device_id, reason: `${reason} (alert ${data.id})` },
            {
              onSuccess: () => {
                toast.success('Device quarantined');
                setQuarantineOpen(false);
              },
            },
          )
        }
      />
    </>
  );
}
