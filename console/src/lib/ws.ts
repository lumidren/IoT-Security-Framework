import { WsFrameSchema, type WsFrame } from '@/lib/api/schemas';

export type WsStatus = 'idle' | 'connecting' | 'open' | 'reconnecting' | 'closed';

export interface WsClientOptions {
  /** Resolves the fully qualified WebSocket URL including the one-time ticket. */
  getUrl: () => Promise<string>;
  onFrame: (frame: WsFrame) => void;
  onStatus?: (status: WsStatus, detail?: { attempt: number; delayMs?: number }) => void;
  /** Injected for tests; defaults to the global `WebSocket`. */
  WebSocketImpl?: typeof WebSocket;
  baseDelayMs?: number;
  maxDelayMs?: number;
  pingIntervalMs?: number;
  /** Deterministic jitter source for tests. */
  random?: () => number;
  setTimeoutFn?: typeof setTimeout;
  clearTimeoutFn?: typeof clearTimeout;
  setIntervalFn?: typeof setInterval;
  clearIntervalFn?: typeof clearInterval;
}

export const DEFAULT_TOPICS = ['fleet', 'alerts'] as const;

/** Exponential backoff with full jitter: random() * min(max, base * 2^attempt). */
export function backoffDelay(
  attempt: number,
  baseMs: number,
  maxMs: number,
  random: () => number = Math.random,
): number {
  const ceiling = Math.min(maxMs, baseMs * 2 ** Math.min(attempt, 30));
  return Math.floor(random() * ceiling);
}

/**
 * Reconnecting WebSocket client for `GET /v1/ws`. Fetches a fresh ticket on every (re)connect,
 * re-subscribes the active topic set, pings every 30 s and parses frames with Zod before
 * handing them to `onFrame`.
 */
export class ReconnectingWsClient {
  private socket: WebSocket | null = null;
  private attempt = 0;
  private stopped = true;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private pingTimer: ReturnType<typeof setInterval> | null = null;
  private readonly topics = new Map<string, number>();
  private statusValue: WsStatus = 'idle';
  private connectToken = 0;

  constructor(private readonly options: WsClientOptions) {
    for (const topic of DEFAULT_TOPICS) this.topics.set(topic, 1);
  }

  get status(): WsStatus {
    return this.statusValue;
  }

  get activeTopics(): string[] {
    return [...this.topics.keys()];
  }

  start(): void {
    if (!this.stopped) return;
    this.stopped = false;
    this.attempt = 0;
    void this.connect();
  }

  stop(): void {
    this.stopped = true;
    this.connectToken += 1;
    this.clearTimers();
    if (this.socket) {
      const socket = this.socket;
      this.socket = null;
      socket.onopen = null;
      socket.onmessage = null;
      socket.onerror = null;
      socket.onclose = null;
      try {
        socket.close(1000, 'client stop');
      } catch {
        // already closed
      }
    }
    this.setStatus('closed');
  }

  /** Ref-counted subscription; returns an unsubscribe function. */
  subscribe(topics: readonly string[]): () => void {
    const added: string[] = [];
    for (const topic of topics) {
      const count = this.topics.get(topic) ?? 0;
      this.topics.set(topic, count + 1);
      if (count === 0) added.push(topic);
    }
    if (added.length > 0) this.send({ type: 'subscribe', topics: added });
    let released = false;
    return () => {
      if (released) return;
      released = true;
      const removed: string[] = [];
      for (const topic of topics) {
        const count = this.topics.get(topic) ?? 0;
        if (count <= 1) {
          this.topics.delete(topic);
          removed.push(topic);
        } else {
          this.topics.set(topic, count - 1);
        }
      }
      if (removed.length > 0) this.send({ type: 'unsubscribe', topics: removed });
    };
  }

  private send(message: unknown): boolean {
    if (!this.socket || this.socket.readyState !== 1 /* OPEN */) return false;
    try {
      this.socket.send(JSON.stringify(message));
      return true;
    } catch {
      return false;
    }
  }

  private setStatus(status: WsStatus, detail?: { attempt: number; delayMs?: number }) {
    this.statusValue = status;
    this.options.onStatus?.(status, detail);
  }

  private clearTimers() {
    const clearT = this.options.clearTimeoutFn ?? clearTimeout;
    const clearI = this.options.clearIntervalFn ?? clearInterval;
    if (this.reconnectTimer) {
      clearT(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.pingTimer) {
      clearI(this.pingTimer);
      this.pingTimer = null;
    }
  }

  private async connect(): Promise<void> {
    if (this.stopped) return;
    const token = ++this.connectToken;
    this.setStatus(this.attempt === 0 ? 'connecting' : 'reconnecting', { attempt: this.attempt });
    let url: string;
    try {
      url = await this.options.getUrl();
    } catch {
      if (token !== this.connectToken || this.stopped) return;
      this.scheduleReconnect();
      return;
    }
    if (token !== this.connectToken || this.stopped) return;

    const Impl = this.options.WebSocketImpl ?? globalThis.WebSocket;
    let socket: WebSocket;
    try {
      socket = new Impl(url);
    } catch {
      this.scheduleReconnect();
      return;
    }
    this.socket = socket;

    socket.onopen = () => {
      if (this.socket !== socket) return;
      this.attempt = 0;
      this.setStatus('open', { attempt: 0 });
      const topics = this.activeTopics;
      if (topics.length > 0) this.send({ type: 'subscribe', topics });
      const setI = this.options.setIntervalFn ?? setInterval;
      this.pingTimer = setI(
        () => this.send({ type: 'ping' }),
        this.options.pingIntervalMs ?? 30_000,
      );
    };
    socket.onmessage = (event: MessageEvent) => {
      if (this.socket !== socket) return;
      const frame = parseFrame(event.data);
      if (frame) this.options.onFrame(frame);
    };
    socket.onerror = () => {
      // The close event that follows drives the reconnect.
    };
    socket.onclose = () => {
      if (this.socket !== socket) return;
      this.socket = null;
      this.clearTimers();
      if (this.stopped) return;
      this.scheduleReconnect();
    };
  }

  private scheduleReconnect() {
    if (this.stopped || this.reconnectTimer) return;
    const delay = backoffDelay(
      this.attempt,
      this.options.baseDelayMs ?? 1_000,
      this.options.maxDelayMs ?? 30_000,
      this.options.random ?? Math.random,
    );
    this.attempt += 1;
    this.setStatus('reconnecting', { attempt: this.attempt, delayMs: delay });
    const setT = this.options.setTimeoutFn ?? setTimeout;
    this.reconnectTimer = setT(() => {
      this.reconnectTimer = null;
      void this.connect();
    }, delay);
  }
}

export function parseFrame(raw: unknown): WsFrame | null {
  if (typeof raw !== 'string') return null;
  try {
    const parsed = WsFrameSchema.safeParse(JSON.parse(raw));
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}
