'use client';

import * as React from 'react';
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { Card, CardContent } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { EmptyState, ErrorState } from '@/components/shared/states';
import { useFleetSummary } from '@/lib/api/hooks';

export function FirmwareChart() {
  const summary = useFleetSummary();
  const data = React.useMemo(
    () =>
      (summary.data?.firmware ?? [])
        .slice(0, 12)
        .map((f) => ({ version: f.version, count: f.count })),
    [summary.data],
  );

  if (summary.isError)
    return <ErrorState error={summary.error} onRetry={() => void summary.refetch()} />;

  return (
    <Card className="py-4">
      <CardContent>
        {summary.isLoading ? (
          <Skeleton className="h-[260px] w-full" />
        ) : data.length === 0 ? (
          <EmptyState title="No firmware reported yet" className="h-[260px]" />
        ) : (
          <>
            <div
              className="h-[260px] w-full"
              role="img"
              aria-label="Bar chart of device count per firmware version"
            >
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={data} margin={{ top: 8, right: 8, bottom: 8, left: -16 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                  <XAxis
                    dataKey="version"
                    tick={{ fill: 'var(--muted-foreground)', fontSize: 12 }}
                    tickLine={false}
                    axisLine={{ stroke: 'var(--border)' }}
                    interval={0}
                    angle={data.length > 6 ? -20 : 0}
                    height={data.length > 6 ? 56 : 30}
                    textAnchor={data.length > 6 ? 'end' : 'middle'}
                  />
                  <YAxis
                    allowDecimals={false}
                    tick={{ fill: 'var(--muted-foreground)', fontSize: 12 }}
                    tickLine={false}
                    axisLine={false}
                  />
                  <Tooltip
                    cursor={{ fill: 'var(--accent)' }}
                    contentStyle={{
                      background: 'var(--popover)',
                      color: 'var(--popover-foreground)',
                      border: '1px solid var(--border)',
                      borderRadius: 8,
                      fontSize: 12,
                    }}
                  />
                  <Bar
                    dataKey="count"
                    name="Devices"
                    fill="var(--chart-1)"
                    radius={[4, 4, 0, 0]}
                    maxBarSize={56}
                  />
                </BarChart>
              </ResponsiveContainer>
            </div>
            <table className="sr-only">
              <caption>Devices per firmware version</caption>
              <thead>
                <tr>
                  <th scope="col">Firmware</th>
                  <th scope="col">Devices</th>
                </tr>
              </thead>
              <tbody>
                {data.map((row) => (
                  <tr key={row.version}>
                    <th scope="row">{row.version}</th>
                    <td>{row.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </CardContent>
    </Card>
  );
}
