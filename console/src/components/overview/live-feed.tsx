'use client';

import * as React from 'react';
import Link from 'next/link';
import {
  BellIcon,
  FactoryIcon,
  RefreshCwIcon,
  RocketIcon,
  WifiIcon,
  WifiOffIcon,
  type LucideIcon,
} from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { TimeAgo } from '@/components/shared/time';
import type { WsFrame } from '@/lib/api/schemas';
import { useWs } from '@/providers/ws-provider';

const FEED_TYPES = new Set([
  'device.connected',
  'device.disconnected',
  'device.state_changed',
  'alert.created',
  'campaign.updated',
  'provisioning.updated',
]);

function describe(frame: WsFrame): {
  icon: LucideIcon;
  text: string;
  href: string | null;
  tone: string;
} {
  const data = (frame.data ?? {}) as Record<string, unknown>;
  const deviceId = typeof data['device_id'] === 'string' ? data['device_id'] : null;
  switch (frame.type) {
    case 'device.connected':
      return {
        icon: WifiIcon,
        text: 'connected',
        href: deviceId ? `/devices/${deviceId}` : null,
        tone: 'text-success',
      };
    case 'device.disconnected':
      return {
        icon: WifiOffIcon,
        text: 'disconnected',
        href: deviceId ? `/devices/${deviceId}` : null,
        tone: 'text-muted-foreground',
      };
    case 'device.state_changed':
      return {
        icon: RefreshCwIcon,
        text: `state → ${String(data['state'] ?? 'changed')}`,
        href: deviceId ? `/devices/${deviceId}` : null,
        tone: 'text-warning',
      };
    case 'alert.created':
      return {
        icon: BellIcon,
        text: `alert ${String(data['severity'] ?? '')} ${String(data['rule'] ?? '')}`.trim(),
        href: typeof data['id'] === 'string' ? `/alerts/${data['id']}` : null,
        tone: 'text-destructive',
      };
    case 'campaign.updated':
      return {
        icon: RocketIcon,
        text: `campaign ${String(data['state'] ?? 'updated')}`,
        href: typeof data['id'] === 'string' ? `/campaigns/${data['id']}` : null,
        tone: 'text-primary',
      };
    case 'provisioning.updated':
      return {
        icon: FactoryIcon,
        text: 'provisioning updated',
        href: '/provisioning',
        tone: 'text-primary',
      };
    default:
      return { icon: RefreshCwIcon, text: frame.type, href: null, tone: 'text-muted-foreground' };
  }
}

export function LiveFeed() {
  const { recent, status } = useWs();
  const items = React.useMemo(
    () => recent.filter((f) => FEED_TYPES.has(f.type)).slice(0, 25),
    [recent],
  );

  return (
    <Card className="h-[420px] gap-0 py-0">
      <CardContent className="flex h-full flex-col px-0">
        <p className="border-b px-4 py-2 text-xs text-muted-foreground">
          Connect, disconnect, state and alert events as they happen ·{' '}
          {status === 'open' ? 'live' : status}
        </p>
        <ol className="flex-1 divide-y overflow-y-auto" aria-label="Recent fleet events">
          {items.length === 0 && (
            <li className="px-4 py-8 text-center text-sm text-muted-foreground">
              {status === 'open' ? 'Waiting for events…' : 'Live updates are not connected.'}
            </li>
          )}
          {items.map((frame, index) => {
            const { icon: Icon, text, href, tone } = describe(frame);
            const data = (frame.data ?? {}) as Record<string, unknown>;
            const subject =
              typeof data['device_id'] === 'string'
                ? data['device_id']
                : typeof data['id'] === 'string'
                  ? data['id']
                  : '';
            return (
              <li key={`${frame.at}-${index}`} className="flex items-start gap-3 px-4 py-2 text-sm">
                <Icon className={`mt-0.5 size-4 shrink-0 ${tone}`} aria-hidden="true" />
                <div className="min-w-0 flex-1">
                  {href ? (
                    <Link href={href} className="font-mono text-xs hover:underline">
                      {subject || text}
                    </Link>
                  ) : (
                    <span className="font-mono text-xs">{subject || text}</span>
                  )}
                  {subject && <span className="text-muted-foreground"> {text}</span>}
                </div>
                <TimeAgo value={frame.at} className="shrink-0 text-xs text-muted-foreground" />
              </li>
            );
          })}
        </ol>
      </CardContent>
    </Card>
  );
}
