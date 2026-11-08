import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ReconnectingWsClient, backoffDelay, parseFrame } from './ws';

class FakeSocket {
  static instances: FakeSocket[] = [];
  readyState = 0;
  sent: string[] = [];
  onopen: ((ev: Event) => void) | null = null;
  onmessage: ((ev: MessageEvent) => void) | null = null;
  onerror: ((ev: Event) => void) | null = null;
  onclose: ((ev: CloseEvent) => void) | null = null;
  constructor(public url: string) {
    FakeSocket.instances.push(this);
  }
  send(data: string) {
    this.sent.push(data);
  }
  close() {
    this.readyState = 3;
    this.onclose?.(new Event('close') as CloseEvent);
  }
  open() {
    this.readyState = 1;
    this.onopen?.(new Event('open'));
  }
  message(data: unknown) {
    this.onmessage?.(new MessageEvent('message', { data }));
  }
  drop() {
    this.readyState = 3;
    this.onclose?.(new Event('close') as CloseEvent);
  }
}

/** Drains pending promises under fake timers (a plain setTimeout would never fire). */
const flush = async () => {
  await vi.advanceTimersByTimeAsync(0);
};

describe('backoffDelay', () => {
  it('grows exponentially with full jitter and respects the cap', () => {
    expect(backoffDelay(0, 1000, 30000, () => 1)).toBe(1000);
    expect(backoffDelay(3, 1000, 30000, () => 1)).toBe(8000);
    expect(backoffDelay(10, 1000, 30000, () => 1)).toBe(30000);
    expect(backoffDelay(2, 1000, 30000, () => 0.5)).toBe(2000);
    expect(backoffDelay(2, 1000, 30000, () => 0)).toBe(0);
  });
});

describe('parseFrame', () => {
  it('accepts well-formed frames and rejects garbage', () => {
    expect(
      parseFrame(JSON.stringify({ type: 'device.connected', at: 'x', data: {} })),
    ).toMatchObject({ type: 'device.connected' });
    expect(parseFrame('not json')).toBeNull();
    expect(parseFrame(JSON.stringify({ type: 'x' }))).toBeNull();
    expect(parseFrame(new ArrayBuffer(2))).toBeNull();
  });
});

describe('ReconnectingWsClient', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    FakeSocket.instances = [];
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  function makeClient(
    overrides: Partial<ConstructorParameters<typeof ReconnectingWsClient>[0]> = {},
  ) {
    const onFrame = vi.fn();
    const onStatus = vi.fn();
    const getUrl = vi.fn().mockResolvedValue('ws://localhost/v1/ws?ticket=t1');
    const client = new ReconnectingWsClient({
      getUrl,
      onFrame,
      onStatus,
      WebSocketImpl: FakeSocket as unknown as typeof WebSocket,
      baseDelayMs: 1000,
      maxDelayMs: 30000,
      pingIntervalMs: 30000,
      random: () => 1,
      ...overrides,
    });
    return { client, onFrame, onStatus, getUrl };
  }

  it('fetches a ticket, subscribes to default topics on open and delivers parsed frames', async () => {
    const { client, onFrame, onStatus, getUrl } = makeClient();
    client.start();
    await flush();
    expect(getUrl).toHaveBeenCalledTimes(1);
    const socket = FakeSocket.instances[0]!;
    expect(socket.url).toBe('ws://localhost/v1/ws?ticket=t1');
    socket.open();
    expect(onStatus).toHaveBeenLastCalledWith('open', { attempt: 0 });
    expect(JSON.parse(socket.sent[0]!)).toEqual({ type: 'subscribe', topics: ['fleet', 'alerts'] });

    socket.message(JSON.stringify({ type: 'alert.created', at: 'now', data: { id: 'a1' } }));
    socket.message('garbage');
    expect(onFrame).toHaveBeenCalledTimes(1);
    expect(onFrame.mock.calls[0]?.[0]).toMatchObject({ type: 'alert.created' });
    client.stop();
  });

  it('reconnects with exponential backoff and a fresh ticket, then resets the attempt counter', async () => {
    const { client, onStatus, getUrl } = makeClient();
    client.start();
    await flush();
    FakeSocket.instances[0]!.open();
    FakeSocket.instances[0]!.drop();
    expect(onStatus).toHaveBeenLastCalledWith('reconnecting', { attempt: 1, delayMs: 1000 });

    await vi.advanceTimersByTimeAsync(999);
    expect(FakeSocket.instances).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1);
    await flush();
    expect(FakeSocket.instances).toHaveLength(2);
    expect(getUrl).toHaveBeenCalledTimes(2);

    // Second consecutive failure doubles the delay.
    FakeSocket.instances[1]!.drop();
    expect(onStatus).toHaveBeenLastCalledWith('reconnecting', { attempt: 2, delayMs: 2000 });
    await vi.advanceTimersByTimeAsync(2000);
    await flush();
    expect(FakeSocket.instances).toHaveLength(3);
    FakeSocket.instances[2]!.open();
    expect(onStatus).toHaveBeenLastCalledWith('open', { attempt: 0 });
    client.stop();
  });

  it('retries when the ticket request fails', async () => {
    const getUrl = vi
      .fn()
      .mockRejectedValueOnce(new Error('401'))
      .mockResolvedValue('ws://localhost/v1/ws?ticket=t2');
    const { client } = makeClient({ getUrl });
    client.start();
    await flush();
    expect(FakeSocket.instances).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(1000);
    await flush();
    expect(FakeSocket.instances).toHaveLength(1);
    client.stop();
  });

  it('re-subscribes active topics after reconnecting and ref-counts subscriptions', async () => {
    const { client } = makeClient();
    client.start();
    await flush();
    const first = FakeSocket.instances[0]!;
    first.open();
    const unsubA = client.subscribe(['device:dev-1']);
    const unsubB = client.subscribe(['device:dev-1', 'campaign:c1']);
    expect(first.sent.map((s) => JSON.parse(s))).toEqual([
      { type: 'subscribe', topics: ['fleet', 'alerts'] },
      { type: 'subscribe', topics: ['device:dev-1'] },
      { type: 'subscribe', topics: ['campaign:c1'] },
    ]);
    unsubA();
    expect(first.sent).toHaveLength(3); // still referenced by B
    first.drop();
    await vi.advanceTimersByTimeAsync(1000);
    await flush();
    const second = FakeSocket.instances[1]!;
    second.open();
    expect(JSON.parse(second.sent[0]!)).toEqual({
      type: 'subscribe',
      topics: ['fleet', 'alerts', 'device:dev-1', 'campaign:c1'],
    });
    unsubB();
    expect(JSON.parse(second.sent[1]!)).toEqual({
      type: 'unsubscribe',
      topics: ['device:dev-1', 'campaign:c1'],
    });
    client.stop();
  });

  it('pings every 30 s while open and stops cleanly', async () => {
    const { client, onStatus } = makeClient();
    client.start();
    await flush();
    const socket = FakeSocket.instances[0]!;
    socket.open();
    await vi.advanceTimersByTimeAsync(30000);
    expect(socket.sent.at(-1)).toBe(JSON.stringify({ type: 'ping' }));
    client.stop();
    expect(socket.readyState).toBe(3);
    expect(onStatus).toHaveBeenLastCalledWith('closed', undefined);
    await vi.advanceTimersByTimeAsync(60000);
    expect(FakeSocket.instances).toHaveLength(1);
  });
});
