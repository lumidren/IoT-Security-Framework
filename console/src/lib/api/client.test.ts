import { afterEach, describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import {
  ApiError,
  apiFetch,
  buildQuery,
  buildUrl,
  fetchAllPages,
  fetchPage,
  formatProblemError,
  newIdempotencyKey,
  parseProblem,
  setStepUpHandler,
} from './client';
import { stepUpProblemBody } from '@/lib/security/step-up';

function jsonResponse(body: unknown, init: ResponseInit = {}) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
    ...init,
  });
}

const Item = z.object({ id: z.string() });

describe('buildQuery / buildUrl', () => {
  it('drops empty values and joins arrays with commas', () => {
    expect(buildQuery({ a: 1, b: '', c: null, d: undefined, e: ['x', 'y'], f: false })).toBe(
      '?a=1&e=x%2Cy&f=false',
    );
    expect(buildQuery(undefined)).toBe('');
  });

  it('targets the console proxy for the given service', () => {
    expect(buildUrl('registry', '/v1/devices', { state: 'active' })).toBe(
      '/api/proxy/registry/v1/devices?state=active',
    );
    expect(buildUrl('ota', 'v1/campaigns')).toBe('/api/proxy/ota/v1/campaigns');
  });
});

describe('parseProblem', () => {
  it('parses RFC 9457 bodies', () => {
    const problem = parseProblem(
      422,
      JSON.stringify({
        type: 'about:blank',
        title: 'Validation failed',
        status: 422,
        errors: [{ field: 'name', message: 'required' }],
      }),
    );
    expect(problem.title).toBe('Validation failed');
    expect(problem.errors).toHaveLength(1);
  });

  it('falls back to a status title for non-JSON bodies', () => {
    const problem = parseProblem(502, '<html>bad gateway</html>');
    expect(problem.status).toBe(502);
    expect(problem.title).toBe('Bad gateway');
    expect(problem.detail).toContain('bad gateway');
  });

  it('wraps FastAPI style detail lists', () => {
    const problem = parseProblem(
      422,
      JSON.stringify({ detail: [{ loc: ['body', 'ttl_s'], msg: 'too small' }] }),
    );
    expect(problem.errors?.[0]).toMatchObject({ msg: 'too small' });
    expect(formatProblemError(problem.errors![0]!)).toBe('ttl_s: too small');
  });

  it('formats compiler diagnostics with line and column', () => {
    expect(formatProblemError({ line: 12, col: 3, message: 'unexpected }' })).toBe(
      'line 12:3: unexpected }',
    );
  });
});

describe('apiFetch', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('sends JSON, parses the response with the schema and forwards idempotency / tenant headers', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ id: 'dev-1' }));
    vi.stubGlobal('fetch', fetchMock);
    const result = await apiFetch('registry', '/v1/devices', {
      method: 'POST',
      body: { product: 'gateway-rpi' },
      schema: Item,
      idempotencyKey: 'key-1',
      tenantId: 'tenant-1',
    });
    expect(result).toEqual({ id: 'dev-1' });
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/proxy/registry/v1/devices');
    expect(init.method).toBe('POST');
    const headers = init.headers as Headers;
    expect(headers.get('content-type')).toBe('application/json');
    expect(headers.get('idempotency-key')).toBe('key-1');
    expect(headers.get('x-ironmesh-tenant')).toBe('tenant-1');
    expect(init.body).toBe(JSON.stringify({ product: 'gateway-rpi' }));
  });

  it('does not set a JSON content type for FormData bodies', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ id: 'fw-1' }));
    vi.stubGlobal('fetch', fetchMock);
    const form = new FormData();
    form.append('metadata', '{}');
    await apiFetch('ota', '/v1/firmware', { method: 'POST', body: form, schema: Item });
    const init = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect((init.headers as Headers).get('content-type')).toBeNull();
    expect(init.body).toBe(form);
  });

  it('throws ApiError carrying the problem details for non-2xx responses', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        jsonResponse(
          {
            type: 'about:blank',
            title: 'Version conflict',
            status: 409,
            detail: 'Twin is at version 4',
          },
          { status: 409, headers: { 'content-type': 'application/problem+json' } },
        ),
      ),
    );
    const error = await apiFetch('registry', '/v1/devices/x/twin/desired', {
      method: 'PATCH',
      body: {},
    }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    const apiError = error as ApiError;
    expect(apiError.status).toBe(409);
    expect(apiError.isConflict).toBe(true);
    expect(apiError.message).toBe('Version conflict: Twin is at version 4');
  });

  it('marks idempotent replays', async () => {
    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        .mockResolvedValue(
          jsonResponse(
            { title: 'Conflict', status: 409 },
            { status: 409, headers: { 'idempotency-replayed': 'true' } },
          ),
        ),
    );
    const error = (await apiFetch('registry', '/x', { method: 'POST' }).catch(
      (e: unknown) => e,
    )) as ApiError;
    expect(error.replayed).toBe(true);
  });

  it('returns undefined for 204 responses', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(null, { status: 204 })));
    await expect(
      apiFetch('registry', '/v1/api-keys/1', { method: 'DELETE' }),
    ).resolves.toBeUndefined();
  });

  it('rejects responses that violate the schema', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse({ id: 42 })));
    const error = (await apiFetch('registry', '/v1/devices/1', { schema: Item }).catch(
      (e: unknown) => e,
    )) as ApiError;
    expect(error).toBeInstanceOf(ApiError);
    expect(error.title).toBe('Unexpected response shape');
    expect(error.errors[0]?.loc).toEqual(['id']);
  });

  it('converts network failures into a status-0 ApiError', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('Failed to fetch')));
    const error = (await apiFetch('anomaly', '/v1/alerts').catch((e: unknown) => e)) as ApiError;
    expect(error.status).toBe(0);
    expect(error.title).toBe('Network error');
  });
});

describe('pagination helpers', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('fetchPage validates items and passes cursor / limit', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(jsonResponse({ items: [{ id: 'a' }], next_cursor: 'c2' }));
    vi.stubGlobal('fetch', fetchMock);
    const page = await fetchPage('registry', '/v1/devices', Item, {
      cursor: 'c1',
      limit: 10,
      state: 'active',
    });
    expect(page.items).toEqual([{ id: 'a' }]);
    expect(page.next_cursor).toBe('c2');
    expect(fetchMock.mock.calls[0]?.[0]).toBe(
      '/api/proxy/registry/v1/devices?cursor=c1&limit=10&state=active',
    );
  });

  it('fetchAllPages walks next_cursor until exhausted', async () => {
    const pages: Record<string, unknown> = {
      '': { items: [{ id: 'a' }, { id: 'b' }], next_cursor: 'p2' },
      p2: { items: [{ id: 'c' }], next_cursor: 'p3' },
      p3: { items: [{ id: 'd' }], next_cursor: null },
    };
    const fetchMock = vi.fn().mockImplementation((url: string) => {
      const cursor = new URL(url, 'http://localhost').searchParams.get('cursor') ?? '';
      return Promise.resolve(jsonResponse(pages[cursor]));
    });
    vi.stubGlobal('fetch', fetchMock);
    const result = await fetchAllPages('registry', '/v1/devices', Item);
    expect(result.items.map((i) => i.id)).toEqual(['a', 'b', 'c', 'd']);
    expect(result.truncated).toBe(false);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it('fetchAllPages stops at maxPages and reports truncation', async () => {
    // A fresh Response per call: bodies can only be read once.
    const fetchMock = vi
      .fn()
      .mockImplementation(() =>
        Promise.resolve(jsonResponse({ items: [{ id: 'x' }], next_cursor: 'more' })),
      );
    vi.stubGlobal('fetch', fetchMock);
    const result = await fetchAllPages('registry', '/v1/devices', Item, {}, { maxPages: 2 });
    expect(result.items).toHaveLength(2);
    expect(result.truncated).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});

describe('newIdempotencyKey', () => {
  it('produces unique keys', () => {
    const keys = new Set(Array.from({ length: 50 }, () => newIdempotencyKey()));
    expect(keys.size).toBe(50);
  });
});

describe('apiFetch step-up handling', () => {
  function stepUpResponse() {
    return new Response(JSON.stringify(stepUpProblemBody('policy.save', 300)), {
      status: 401,
      headers: { 'content-type': 'application/problem+json' },
    });
  }

  afterEach(() => {
    setStepUpHandler(null);
    vi.unstubAllGlobals();
  });

  it('retries once with the same body and idempotency key after re-authentication', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(stepUpResponse())
      .mockResolvedValueOnce(jsonResponse({ version: 2 }));
    vi.stubGlobal('fetch', fetchMock);
    const handler = vi.fn().mockResolvedValue(true);
    setStepUpHandler(handler);

    const result = await apiFetch('policy', '/v1/policy', {
      method: 'PUT',
      body: { rego: 'package x' },
      idempotencyKey: 'key-1',
    });
    expect(result).toEqual({ version: 2 });
    expect(handler).toHaveBeenCalledOnce();
    expect(handler.mock.calls[0]?.[0]).toMatchObject({ code: 'step_up_required' });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const second = fetchMock.mock.calls[1]?.[1] as RequestInit;
    expect(second.body).toBe(JSON.stringify({ rego: 'package x' }));
    expect(new Headers(second.headers).get('idempotency-key')).toBe('key-1');
  });

  it('throws the step-up problem when re-authentication is declined or fails again', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation(async () => stepUpResponse()),
    );
    setStepUpHandler(vi.fn().mockResolvedValue(false));
    const declined = apiFetch('policy', '/v1/policy', { method: 'PUT', body: {} });
    await expect(declined).rejects.toMatchObject({ status: 401, isStepUpRequired: true });

    const fetchMock = vi.fn().mockImplementation(async () => stepUpResponse());
    vi.stubGlobal('fetch', fetchMock);
    const handler = vi.fn().mockResolvedValue(true);
    setStepUpHandler(handler);
    await expect(
      apiFetch('policy', '/v1/policy', { method: 'PUT', body: {} }),
    ).rejects.toBeInstanceOf(ApiError);
    // One retry only: no re-authentication loop.
    expect(handler).toHaveBeenCalledOnce();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});
