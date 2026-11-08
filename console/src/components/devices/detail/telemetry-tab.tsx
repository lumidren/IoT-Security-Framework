'use client';

import * as React from 'react';
import dynamic from 'next/dynamic';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { ErrorState } from '@/components/shared/states';
import { useDeviceTelemetry } from '@/lib/api/hooks';
import type { DeviceDetail } from '@/lib/api/schemas';

const TelemetryCharts = dynamic(
  () => import('@/components/devices/detail/telemetry-charts').then((m) => m.TelemetryCharts),
  { ssr: false, loading: () => <Skeleton className="h-[640px] w-full" /> },
);

const RANGES: Array<{ value: string; label: string; ms: number; step: string }> = [
  { value: '15m', label: 'Last 15 minutes', ms: 15 * 60_000, step: '10s' },
  { value: '1h', label: 'Last hour', ms: 3_600_000, step: '30s' },
  { value: '6h', label: 'Last 6 hours', ms: 6 * 3_600_000, step: '60s' },
  { value: '24h', label: 'Last 24 hours', ms: 24 * 3_600_000, step: '5m' },
  { value: '7d', label: 'Last 7 days', ms: 7 * 24 * 3_600_000, step: '1h' },
];

export function TelemetryTab({ device }: { device: DeviceDetail }) {
  const [range, setRange] = React.useState('1h');
  const selected = RANGES.find((r) => r.value === range) ?? RANGES[1]!;
  const isEsp = device.product.includes('esp32') || device.last_telemetry?.rssi != null;
  const metrics = React.useMemo(
    () => [
      'cpu_pct',
      'mem_pct',
      'temp_c',
      'net_rx_bytes',
      'net_tx_bytes',
      ...(isEsp ? ['rssi', 'free_heap'] : []),
    ],
    [isEsp],
  );
  // Anchor the window on mount / range change so the query key stays stable while live frames append.
  const [to, setTo] = React.useState(() => Date.now());
  React.useEffect(() => setTo(Date.now()), [range]);
  const params = React.useMemo(
    () => ({
      from: new Date(to - selected.ms).toISOString(),
      to: new Date(to).toISOString(),
      metrics,
      step: selected.step,
    }),
    [to, selected, metrics],
  );
  const telemetry = useDeviceTelemetry(device.id, params);

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="telemetry-range">Time range</Label>
          <Select value={range} onValueChange={setRange}>
            <SelectTrigger id="telemetry-range" className="w-48">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {RANGES.map((r) => (
                <SelectItem key={r.value} value={r.value}>
                  {r.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <p className="text-xs text-muted-foreground">
          Live samples arrive over the WebSocket (max 1/s) and are appended to the charts.
        </p>
      </div>
      {telemetry.isError ? (
        <ErrorState error={telemetry.error} onRetry={() => void telemetry.refetch()} />
      ) : telemetry.data ? (
        <TelemetryCharts series={telemetry.data.series} rangeMs={selected.ms} />
      ) : (
        <Skeleton className="h-[640px] w-full" />
      )}
    </div>
  );
}
