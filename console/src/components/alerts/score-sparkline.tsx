'use client';

import { Line, LineChart, ReferenceLine, ResponsiveContainer, Tooltip, YAxis } from 'recharts';
import type { Baseline } from '@/lib/api/schemas';

export function ScoreSparkline({ baseline }: { baseline: Baseline }) {
  const data = baseline.recent_scores.map(([ts, score]) => ({
    ts: typeof ts === 'number' ? (ts < 1e12 ? ts * 1000 : ts) : Date.parse(ts),
    score,
  }));
  const latest = data[data.length - 1]?.score;
  const max = data.reduce((m, d) => Math.max(m, d.score), 0);
  return (
    <div
      className="h-[120px] w-full"
      role="img"
      aria-label={`Anomaly score over the last ${data.length} samples; latest ${latest?.toFixed(2) ?? 'n/a'}, peak ${max.toFixed(2)}, threshold ${baseline.score_threshold}`}
    >
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data} margin={{ top: 6, right: 6, bottom: 6, left: 6 }}>
          <YAxis domain={[0, 1]} hide />
          <ReferenceLine
            y={baseline.score_threshold}
            stroke="var(--destructive)"
            strokeDasharray="4 4"
          />
          <Tooltip
            labelFormatter={(_, payload) => {
              const ts = payload?.[0]?.payload?.ts;
              return typeof ts === 'number' ? new Date(ts).toLocaleString() : '';
            }}
            formatter={(value) => [Number(value).toFixed(3), 'score']}
            contentStyle={{
              background: 'var(--popover)',
              color: 'var(--popover-foreground)',
              border: '1px solid var(--border)',
              borderRadius: 8,
              fontSize: 12,
            }}
          />
          <Line
            type="monotone"
            dataKey="score"
            stroke="var(--chart-4)"
            strokeWidth={2}
            dot={false}
            isAnimationActive={false}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
