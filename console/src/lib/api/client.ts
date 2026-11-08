import type { z } from 'zod';
import {
  ProblemDetailsSchema,
  pageSchema,
  type Page,
  type ProblemDetails,
  type ProblemError,
} from '@/lib/api/schemas';

export type Service = 'registry' | 'ota' | 'anomaly' | 'policy';
export const SERVICES: readonly Service[] = ['registry', 'ota', 'anomaly', 'policy'];

export const API_BASE = '/api/proxy';

export type QueryValue = string | number | boolean | null | undefined;
export type Query = Record<string, QueryValue | readonly string[]>;

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

export interface RequestOptions<T> {
  method?: HttpMethod;
  query?: Query;
  /** JSON-serialised unless it is a `FormData`. */
  body?: unknown;
  headers?: Record<string, string>;
  schema?: z.ZodType<T>;
  signal?: AbortSignal;
  idempotencyKey?: string;
  /** `X-IronMesh-Tenant`, platform admins only. */
  tenantId?: string;
}

/** Error thrown for non-2xx responses (RFC 9457 body) and for responses that fail schema parsing. */
export class ApiError extends Error {
  readonly status: number;
  readonly problem: ProblemDetails;
  readonly replayed: boolean;

  constructor(problem: ProblemDetails, options: { replayed?: boolean; cause?: unknown } = {}) {
    super(problem.detail ? `${problem.title}: ${problem.detail}` : problem.title, {
      cause: options.cause,
    });
    this.name = 'ApiError';
    this.status = problem.status;
    this.problem = problem;
    this.replayed = options.replayed ?? false;
  }

  get title(): string {
    return this.problem.title;
  }

  get detail(): string | null {
    return this.problem.detail ?? null;
  }

  get errors(): ProblemError[] {
    return this.problem.errors ?? [];
  }

  get isUnauthorized(): boolean {
    return this.status === 401;
  }

  get isForbidden(): boolean {
    return this.status === 403;
  }

  get isConflict(): boolean {
    return this.status === 409;
  }

  get isValidation(): boolean {
    return this.status === 422;
  }
}

export function isApiError(error: unknown): error is ApiError {
  return error instanceof ApiError;
}

const STATUS_TITLES: Record<number, string> = {
  400: 'Bad request',
  401: 'Authentication required',
  403: 'Forbidden',
  404: 'Not found',
  409: 'Conflict',
  422: 'Validation failed',
  429: 'Too many requests',
  500: 'Internal server error',
  502: 'Bad gateway',
  503: 'Service unavailable',
  504: 'Gateway timeout',
};

/** Turns any error response into problem details, tolerating non-JSON and malformed bodies. */
export function parseProblem(status: number, bodyText: string): ProblemDetails {
  const fallback: ProblemDetails = {
    type: 'about:blank',
    title: STATUS_TITLES[status] ?? `HTTP ${status}`,
    status,
    detail: bodyText.trim().length > 0 && bodyText.length < 500 ? bodyText.trim() : undefined,
  };
  if (!bodyText) return fallback;
  try {
    const json: unknown = JSON.parse(bodyText);
    const parsed = ProblemDetailsSchema.safeParse(json);
    if (parsed.success) return { ...parsed.data, status: parsed.data.status || status };
    if (json && typeof json === 'object') {
      const obj = json as Record<string, unknown>;
      // FastAPI-style `{detail: ...}` without the RFC 9457 envelope.
      const detail = obj['detail'];
      if (typeof detail === 'string') return { ...fallback, detail };
      if (Array.isArray(detail)) {
        return {
          ...fallback,
          title: STATUS_TITLES[status] ?? 'Request failed',
          errors: detail.map((d) => {
            const r = ProblemErrorSchemaLoose(d);
            return r;
          }),
        };
      }
    }
    return fallback;
  } catch {
    return fallback;
  }
}

function ProblemErrorSchemaLoose(value: unknown): ProblemError {
  if (value && typeof value === 'object') return value as ProblemError;
  return { message: String(value) };
}

/** Human-readable single line for a validation error / compiler diagnostic. */
export function formatProblemError(error: ProblemError): string {
  const location =
    error.line !== undefined
      ? `line ${error.line}${error.col !== undefined ? `:${error.col}` : ''}`
      : error.field
        ? error.field
        : error.loc && error.loc.length > 0
          ? error.loc.filter((p) => p !== 'body').join('.')
          : null;
  const text = error.message ?? error.msg ?? error.detail ?? 'Invalid value';
  return location ? `${location}: ${text}` : text;
}

export function buildQuery(query: Query | undefined): string {
  if (!query) return '';
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === '') continue;
    if (Array.isArray(value)) {
      if (value.length > 0) params.set(key, value.join(','));
      continue;
    }
    params.set(key, String(value));
  }
  const s = params.toString();
  return s ? `?${s}` : '';
}

export function buildUrl(service: Service, path: string, query?: Query): string {
  const normalised = path.startsWith('/') ? path : `/${path}`;
  return `${API_BASE}/${service}${normalised}${buildQuery(query)}`;
}

async function readText(response: Response): Promise<string> {
  try {
    return await response.text();
  } catch {
    return '';
  }
}

/**
 * Typed fetch against the console proxy. Throws `ApiError` on non-2xx responses and when the
 * response does not match `schema`.
 */
export async function apiFetch<T = unknown>(
  service: Service,
  path: string,
  options: RequestOptions<T> = {},
): Promise<T> {
  const method = options.method ?? 'GET';
  const headers = new Headers(options.headers);
  headers.set('accept', 'application/json, application/problem+json');
  let body: BodyInit | undefined;
  if (options.body instanceof FormData) {
    body = options.body;
  } else if (options.body !== undefined) {
    headers.set('content-type', 'application/json');
    body = JSON.stringify(options.body);
  }
  if (options.idempotencyKey) headers.set('idempotency-key', options.idempotencyKey);
  if (options.tenantId) headers.set('x-ironmesh-tenant', options.tenantId);

  let response: Response;
  try {
    response = await fetch(buildUrl(service, path, options.query), {
      method,
      headers,
      body,
      signal: options.signal,
      credentials: 'same-origin',
    });
  } catch (cause) {
    if (cause instanceof DOMException && cause.name === 'AbortError') throw cause;
    throw new ApiError(
      {
        type: 'about:blank',
        title: 'Network error',
        status: 0,
        detail: `Could not reach the console API (${service}).`,
      },
      { cause },
    );
  }

  const replayed = response.headers.get('idempotency-replayed') === 'true';
  if (!response.ok) {
    throw new ApiError(parseProblem(response.status, await readText(response)), { replayed });
  }
  if (response.status === 204 || response.status === 205) {
    return undefined as T;
  }
  const text = await readText(response);
  if (text.length === 0) return undefined as T;
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch (cause) {
    throw new ApiError(
      {
        type: 'about:blank',
        title: 'Unexpected response',
        status: response.status,
        detail: `${service} returned a non-JSON body.`,
      },
      { cause },
    );
  }
  if (!options.schema) return json as T;
  const parsed = options.schema.safeParse(json);
  if (!parsed.success) {
    throw new ApiError(
      {
        type: 'about:blank',
        title: 'Unexpected response shape',
        status: response.status,
        detail: `${service} ${method} ${path} did not match the API contract.`,
        errors: parsed.error.issues.map((issue) => ({
          loc: issue.path.map((p) => (typeof p === 'symbol' ? p.toString() : p)),
          message: issue.message,
          code: issue.code,
        })),
      },
      { cause: parsed.error },
    );
  }
  return parsed.data;
}

export interface PageQuery extends Query {
  cursor?: string | null;
  limit?: number;
}

/** Fetches a single page of a cursor-paginated collection. */
export async function fetchPage<T>(
  service: Service,
  path: string,
  itemSchema: z.ZodType<T>,
  query: PageQuery = {},
  options: Omit<RequestOptions<Page<T>>, 'schema' | 'query' | 'method' | 'body'> = {},
): Promise<Page<T>> {
  const schema = pageSchema(itemSchema) as unknown as z.ZodType<Page<T>>;
  return apiFetch<Page<T>>(service, path, { ...options, query, schema });
}

export interface FetchAllOptions {
  /** Stop after this many pages even if a cursor remains (defaults to 50). */
  maxPages?: number;
  limit?: number;
  signal?: AbortSignal;
}

/** Walks `next_cursor` until exhausted or `maxPages` is hit; returns items and whether it was truncated. */
export async function fetchAllPages<T>(
  service: Service,
  path: string,
  itemSchema: z.ZodType<T>,
  query: Query = {},
  options: FetchAllOptions = {},
): Promise<{ items: T[]; truncated: boolean }> {
  const maxPages = options.maxPages ?? 50;
  const items: T[] = [];
  let cursor: string | null = null;
  let pages = 0;
  do {
    const page: Page<T> = await fetchPage(
      service,
      path,
      itemSchema,
      { ...query, cursor, limit: options.limit ?? 200 },
      { signal: options.signal },
    );
    items.push(...page.items);
    cursor = page.next_cursor;
    pages += 1;
    if (cursor && pages >= maxPages) return { items, truncated: true };
  } while (cursor);
  return { items, truncated: false };
}

/** Random idempotency key for command / campaign mutations. */
export function newIdempotencyKey(): string {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) return crypto.randomUUID();
  return `${Date.now().toString(16)}-${Math.random().toString(16).slice(2, 14)}`;
}
