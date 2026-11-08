import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDateTime(value: string | number | Date | null | undefined): string {
  if (value === null || value === undefined || value === '') return '—';
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(date);
}

export function formatDate(value: string | number | Date | null | undefined): string {
  if (value === null || value === undefined || value === '') return '—';
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
  }).format(date);
}

const RELATIVE_UNITS: Array<[Intl.RelativeTimeFormatUnit, number]> = [
  ['year', 365 * 24 * 3600],
  ['month', 30 * 24 * 3600],
  ['week', 7 * 24 * 3600],
  ['day', 24 * 3600],
  ['hour', 3600],
  ['minute', 60],
  ['second', 1],
];

/** "3 minutes ago" / "in 2 days", relative to `now`. */
export function formatRelative(
  value: string | number | Date | null | undefined,
  now: number = Date.now(),
): string {
  if (value === null || value === undefined || value === '') return '—';
  const date = value instanceof Date ? value : new Date(value);
  const ms = date.getTime();
  if (Number.isNaN(ms)) return String(value);
  const diffSeconds = Math.round((ms - now) / 1000);
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
  for (const [unit, seconds] of RELATIVE_UNITS) {
    if (Math.abs(diffSeconds) >= seconds || unit === 'second') {
      return rtf.format(Math.round(diffSeconds / seconds), unit);
    }
  }
  return rtf.format(0, 'second');
}

/** Compact "5d 3h" / "42m" / "12s" duration, used for countdowns and dwell times. */
export function formatDuration(totalSeconds: number): string {
  if (!Number.isFinite(totalSeconds)) return '—';
  const sign = totalSeconds < 0 ? '-' : '';
  let s = Math.abs(Math.round(totalSeconds));
  const days = Math.floor(s / 86400);
  s -= days * 86400;
  const hours = Math.floor(s / 3600);
  s -= hours * 3600;
  const minutes = Math.floor(s / 60);
  s -= minutes * 60;
  const parts: string[] = [];
  if (days) parts.push(`${days}d`);
  if (hours && parts.length < 2) parts.push(`${hours}h`);
  if (minutes && parts.length < 2) parts.push(`${minutes}m`);
  if (parts.length === 0) parts.push(`${s}s`);
  return sign + parts.join(' ');
}

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || !Number.isFinite(bytes)) return '—';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let value = Math.abs(bytes);
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index += 1;
  }
  const unit = units[index] ?? 'B';
  return `${bytes < 0 ? '-' : ''}${value.toFixed(index === 0 ? 0 : 1)} ${unit}`;
}

export function formatNumber(value: number | null | undefined, digits = 0): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—';
  return new Intl.NumberFormat(undefined, { maximumFractionDigits: digits }).format(value);
}

export function formatPercent(value: number | null | undefined, digits = 0): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—';
  return `${new Intl.NumberFormat(undefined, { maximumFractionDigits: digits }).format(value)}%`;
}

/** Shortens long hex strings: `3fa1…9c2b`. */
export function shortHex(value: string | null | undefined, keep = 6): string {
  if (!value) return '—';
  if (value.length <= keep * 2 + 1) return value;
  return `${value.slice(0, keep)}…${value.slice(-keep)}`;
}

export function titleCase(value: string): string {
  return value.replace(/[_-]+/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

export function toIso(value: Date | number): string {
  return new Date(value).toISOString();
}

export function tagsToString(tags: Record<string, string>): string {
  return Object.entries(tags)
    .map(([k, v]) => `${k}:${v}`)
    .join(', ');
}

/** Parses `key:value` pairs separated by commas or newlines. Returns `null` on malformed input. */
export function parseTags(text: string): Record<string, string> | null {
  const tags: Record<string, string> = {};
  for (const raw of text.split(/[\n,]/)) {
    const part = raw.trim();
    if (!part) continue;
    const idx = part.indexOf(':');
    if (idx <= 0) return null;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (!key) return null;
    tags[key] = value;
  }
  return tags;
}

export function safeJsonParse(
  text: string,
): { ok: true; value: unknown } | { ok: false; error: string } {
  try {
    return { ok: true, value: JSON.parse(text) };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : 'Invalid JSON' };
  }
}

export function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}
