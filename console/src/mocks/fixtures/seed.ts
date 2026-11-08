/** Deterministic PRNG (mulberry32) so fixtures are identical across reloads and test runs. */
export function createRng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export type Rng = () => number;

export function int(rng: Rng, min: number, max: number): number {
  return Math.floor(rng() * (max - min + 1)) + min;
}

export function pick<T>(rng: Rng, items: readonly T[]): T {
  const item = items[Math.floor(rng() * items.length)];
  if (item === undefined) throw new Error('pick() on empty list');
  return item;
}

export function hex(rng: Rng, length: number): string {
  let out = '';
  for (let i = 0; i < length; i += 1) out += int(rng, 0, 15).toString(16);
  return out;
}

export function uuid(rng: Rng): string {
  const h = hex(rng, 32).split('');
  h[12] = '4';
  h[16] = pick(rng, ['8', '9', 'a', 'b']);
  const s = h.join('');
  return `${s.slice(0, 8)}-${s.slice(8, 12)}-${s.slice(12, 16)}-${s.slice(16, 20)}-${s.slice(20)}`;
}

export function deviceId(rng: Rng): string {
  return `dev-${hex(rng, 16)}`;
}

export function iso(ms: number): string {
  return new Date(ms).toISOString();
}

export const HOUR = 3_600_000;
export const DAY = 24 * HOUR;

/** Stable hash of a string into a 32-bit seed. */
export function hashSeed(value: string): number {
  let h = 2166136261;
  for (let i = 0; i < value.length; i += 1) {
    h ^= value.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}
