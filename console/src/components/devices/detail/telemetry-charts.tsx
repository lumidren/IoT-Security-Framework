'use client';

import * as React from 'react';
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import type { TelemetrySeries } from '@/lib/api/schemas';
import { formatBytes, formatNumber } from '@/lib/utils';

interface ChartSpec {
  title: string;
  metrics: Array<{ key: string; label: string; color: string }>;
  unit: string;
  format: (value: number) => string;
  domain?: [number | 'auto', number | 'auto'];
}

const CHARTS: ChartSpec[] = [
  {
    title: 'CPU and memory',
    metrics: [
      { key: 'cpu_pct', label: 'CPU %', color: 'var(--chart-1)' },
      { key: 'mem_pct', label: 'Memory %', color: 'var(--chart-2)' },
    ],
    unit: '%',
    format: (v) => `${formatNumber(v, 1)} %`,
    domain: [0, 100],
  },
  {
    title: 'Temperature',
    metrics: [{ key: 'temp_c', label: 'Temperature °C', color: 'var(--chart-3)' }],
    unit: '°C',
    format: (v) => `${formatNumber(v, 1)} °C`,
  },
  {
    title: 'Network (cumulative bytes)',
    metrics: [
      { key: 'net_rx_bytes', label: 'Received', color: 'var(--chart-1)' },
      { key: 'net_tx_bytes', label: 'Transmitted', color: 'var(--chart-5)' },
    ],
    unit: 'bytes',
    format: (v) => formatBytes(v),
  },
  {
    title: 'Radio signal (RSSI)',
    metrics: [{ key: 'rssi', label: 'RSSI dBm', color: 'var(--chart-4)' }],
    unit: 'dBm',
    format: (v) => `${formatNumber(v)} dBm`,
    domain: [-100, -20],
  },
  {
    title: 'Free heap',
    metrics: [{ key: 'free_heap', label: 'Free heap', color: 'var(--chart-2)' }],
    unit: 'bytes',
    format: (v) => formatBytes(v),
  },
];

type Row = { ts: number } & Record<string, number | null>;

function toRows(series: TelemetrySeries['series'], keys: string[]): Row[] {
  const byTs = new Map<number, Row>();
  for (const s of series) {
    if (!keys.includes(s.metric)) continue;
    for (const [rawTs, value] of s.points) {
      const ts =
        typeof rawTs === 'number' ? (rawTs < 1e12 ? rawTs * 1000 : rawTs) : Date.parse(rawTs);
      if (!Number.isFinite(ts)) continue;
      const row = byTs.get(ts) ?? ({ ts } as Row);
      row[s.metric] = value;
      byTs.set(ts, row);
    }
  }
  return [...byTs.values()].sort((a, b) => a.ts - b.ts);
}

function formatTick(ts: number, rangeMs: number): string {
  const date = new Date(ts);
  if (rangeMs > 2 * 24 * 3_600_000) {
    return new Intl.DateTimeFormat(undefined, {
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
    }).format(date);
  }
  return new Intl.DateTimeFormat(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  }).format(date);
}

export function TelemetryCharts({
  series,
  rangeMs,
}: {
  series: TelemetrySeries['series'];
  rangeMs: number;
}) {
  const available = new Set(series.map((s) => s.metric));
  const charts = CHARTS.filter((c) => c.metrics.some((m) => available.has(m.key)));
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      {charts.map((chart) => {
        const keys = chart.metrics.map((m) => m.key);
        const rows = toRows(series, keys);
        const latest = rows[rows.length - 1];
        return (
          <Card key={chart.title} className="gap-2">
            <CardHeader>
              <CardTitle className="text-base">{chart.title}</CardTitle>
              <p className="text-xs text-muted-foreground">
                {chart.metrics
                  .filter((m) => available.has(m.key))
                  .map(
                    (m) =>
                      `${m.label}: ${latest && typeof latest[m.key] === 'number' ? chart.format(latest[m.key] as number) : '—'}`,
                  )
                  .join(' · ')}
              </p>
            </CardHeader>
            <CardContent>
              <div
                className="h-[220px] w-full"
                role="img"
                aria-label={`${chart.title} line chart, latest ${chart.metrics.map((m) => `${m.label} ${latest && typeof latest[m.key] === 'number' ? chart.format(latest[m.key] as number) : 'no data'}`).join(', ')}`}
              >
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={rows} margin={{ top: 8, right: 8, bottom: 0, left: -8 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                    <XAxis
                      dataKey="ts"
                      type="number"
                      domain={['dataMin', 'dataMax']}
                      tickFormatter={(v: number) => formatTick(v, rangeMs)}
                      tick={{ fill: 'var(--muted-foreground)', fontSize: 11 }}
                      tickLine={false}
                      axisLine={{ stroke: 'var(--border)' }}
                      minTickGap={32}
                    />
                    <YAxis
                      domain={chart.domain ?? ['auto', 'auto']}
                      tickFormatter={(v: number) =>
                        chart.unit === 'bytes' ? formatBytes(v) : String(v)
                      }
                      tick={{ fill: 'var(--muted-foreground)', fontSize: 11 }}
                      tickLine={false}
                      axisLine={false}
                      width={chart.unit === 'bytes' ? 72 : 40}
                    />
                    <Tooltip
                      labelFormatter={(v) => new Date(Number(v)).toLocaleString()}
                      formatter={(value, name) => [chart.format(Number(value)), String(name)]}
                      contentStyle={{
                        background: 'var(--popover)',
                        color: 'var(--popover-foreground)',
                        border: '1px solid var(--border)',
                        borderRadius: 8,
                        fontSize: 12,
                      }}
                    />
                    {chart.metrics
                      .filter((m) => available.has(m.key))
                      .map((m) => (
                        <Line
                          key={m.key}
                          type="monotone"
                          dataKey={m.key}
                          name={m.label}
                          stroke={m.color}
                          strokeWidth={2}
                          dot={false}
                          isAnimationActive={false}
                          connectNulls
                        />
                      ))}
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}
