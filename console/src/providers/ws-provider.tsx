'use client';

import * as React from 'react';
import { useQueryClient, type QueryClient } from '@tanstack/react-query';
import { ApiError, parseProblem } from '@/lib/api/client';
import { queryKeys } from '@/lib/api/keys';
import {
  WsTicketSchema,
  WsTelemetryDataSchema,
  type TelemetrySeries,
  type WsFrame,
} from '@/lib/api/schemas';
import { resolveWsUrl } from '@/lib/env';
import { ReconnectingWsClient, type WsStatus } from '@/lib/ws';
import { invalidationsFor } from '@/lib/ws-invalidation';

type FrameListener = (frame: WsFrame) => void;

interface WsContextValue {
  status: WsStatus;
  /** Last 100 frames, newest first — drives the live feeds. */
  recent: WsFrame[];
  subscribe: (topics: readonly string[]) => () => void;
  addListener: (listener: FrameListener) => () => void;
}

const WsContext = React.createContext<WsContextValue | null>(null);

const MAX_RECENT = 100;

/** Appends sampled telemetry frames to any cached telemetry series for the device. */
export function applyTelemetryFrame(client: QueryClient, frame: WsFrame): void {
  const parsed = WsTelemetryDataSchema.safeParse(frame.data);
  if (!parsed.success) return;
  const { device_id, sample } = parsed.data;
  const prefix = ['devices', 'detail', device_id, 'telemetry'];
  client.setQueriesData<TelemetrySeries>({ queryKey: prefix }, (current) => {
    if (!current) return current;
    return {
      series: current.series.map((series) => {
        const value = sample[series.metric];
        if (typeof value !== 'number') return series;
        const points = [...series.points, [sample.ts, value] as [string, number]];
        return { ...series, points: points.length > 2000 ? points.slice(-2000) : points };
      }),
    };
  });
  client.setQueryData(queryKeys.devices.detail(device_id), (current: unknown) => {
    if (!current || typeof current !== 'object') return current;
    return { ...(current as Record<string, unknown>), last_telemetry: sample, connected: true };
  });
}

/** Mints a ticket through the console's own route handler, then builds the socket URL. */
async function fetchWsUrl(): Promise<string> {
  const response = await fetch('/api/ws/ticket', {
    method: 'POST',
    headers: { accept: 'application/json' },
    credentials: 'same-origin',
  });
  if (!response.ok) {
    throw new ApiError(parseProblem(response.status, await response.text()));
  }
  const ticket = WsTicketSchema.parse(await response.json());
  const base = ticket.url || resolveWsUrl();
  const url = new URL(base);
  url.searchParams.set('ticket', ticket.ticket);
  return url.toString();
}

export function WsProvider({ children }: { children: React.ReactNode }) {
  const queryClient = useQueryClient();
  const [status, setStatus] = React.useState<WsStatus>('idle');
  const [recent, setRecent] = React.useState<WsFrame[]>([]);
  const listeners = React.useRef(new Set<FrameListener>());
  const clientRef = React.useRef<ReconnectingWsClient | null>(null);
  const pendingInvalidations = React.useRef(new Map<string, ReturnType<typeof setTimeout>>());

  React.useEffect(() => {
    const client = new ReconnectingWsClient({
      getUrl: fetchWsUrl,
      onStatus: (next) => setStatus(next),
      onFrame: (frame) => {
        if (frame.type === 'device.telemetry') {
          applyTelemetryFrame(queryClient, frame);
        } else {
          // Debounce invalidations per key so bursts do not refetch repeatedly.
          for (const key of invalidationsFor(frame)) {
            const id = JSON.stringify(key);
            const existing = pendingInvalidations.current.get(id);
            if (existing) clearTimeout(existing);
            pendingInvalidations.current.set(
              id,
              setTimeout(() => {
                pendingInvalidations.current.delete(id);
                void queryClient.invalidateQueries({ queryKey: key });
              }, 250),
            );
          }
        }
        if (frame.type !== 'pong') {
          setRecent((prev) => [frame, ...prev].slice(0, MAX_RECENT));
        }
        for (const listener of listeners.current) listener(frame);
      },
    });
    clientRef.current = client;
    client.start();
    const pending = pendingInvalidations.current;
    return () => {
      client.stop();
      clientRef.current = null;
      for (const timer of pending.values()) clearTimeout(timer);
      pending.clear();
    };
  }, [queryClient]);

  const subscribe = React.useCallback((topics: readonly string[]) => {
    return clientRef.current?.subscribe(topics) ?? (() => undefined);
  }, []);

  const addListener = React.useCallback((listener: FrameListener) => {
    listeners.current.add(listener);
    return () => {
      listeners.current.delete(listener);
    };
  }, []);

  const value = React.useMemo<WsContextValue>(
    () => ({ status, recent, subscribe, addListener }),
    [status, recent, subscribe, addListener],
  );

  return <WsContext.Provider value={value}>{children}</WsContext.Provider>;
}

export function useWs(): WsContextValue {
  const ctx = React.useContext(WsContext);
  if (!ctx) throw new Error('useWs must be used inside WsProvider');
  return ctx;
}

/** Subscribes to extra WS topics (`device:<id>`, `campaign:<id>`) for the lifetime of the component. */
export function useWsTopics(topics: readonly string[]) {
  const { subscribe } = useWs();
  const key = topics.join('|');
  React.useEffect(() => {
    if (!key) return;
    return subscribe(key.split('|'));
  }, [key, subscribe]);
}

/** Runs `handler` for every frame whose type is in `types`. */
export function useWsEvent(types: readonly string[], handler: FrameListener) {
  const { addListener } = useWs();
  const handlerRef = React.useRef(handler);
  handlerRef.current = handler;
  const key = types.join('|');
  React.useEffect(() => {
    const wanted = new Set(key.split('|'));
    return addListener((frame) => {
      if (wanted.has(frame.type)) handlerRef.current(frame);
    });
  }, [key, addListener]);
}
