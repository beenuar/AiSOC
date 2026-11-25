/**
 * `alertsApi.list` — response-envelope contract.
 *
 * `AlertListResponse` in `services/api/app/api/v1/endpoints/alerts.py` returns
 * the rows under `items`. The client read `raw.alerts`, which is never present,
 * so `Array.isArray(undefined)` was false and every page resolved to `[]` while
 * `total` carried the real count — the queue rendered a row count above an
 * empty table, with no error to explain it.
 *
 * These tests pin the envelope in both directions so the two halves cannot
 * drift apart again silently.
 */

import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest';
import { alertsApi } from './api';

const ALERT_ROW = {
  id: '11111111-1111-4111-8111-111111111111',
  title: 'Suspicious PowerShell download cradle',
  severity: 'high',
  status: 'new',
  created_at: '2026-05-06T12:00:00Z',
};

function jsonResponse(body: unknown) {
  return {
    ok: true,
    status: 200,
    statusText: 'OK',
    headers: new Headers({ 'content-type': 'application/json' }),
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as unknown as Response;
}

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  fetchMock = vi.fn();
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('alertsApi.list envelope', () => {
  it('sends entity filters using the API vocabulary and preserves reserved characters', async () => {
    fetchMock.mockResolvedValue(jsonResponse({ items: [], total: 0 }));
    await alertsApi.list({
      entityType: 'user', entityValue: 'Finance & Legal+ops@example.com',
      severity: 'high', page: 2, pageSize: 25,
    });
    const url = new URL(String(fetchMock.mock.calls[0][0]), 'http://localhost');
    expect(url.searchParams.get('entity_type')).toBe('user');
    expect(url.searchParams.get('entity_value')).toBe('Finance & Legal+ops@example.com');
    expect(url.searchParams.get('severity')).toBe('high');
    expect(url.searchParams.get('page')).toBe('2');
    expect(url.searchParams.has('entityType')).toBe(false);
    expect(url.searchParams.has('entityValue')).toBe(false);
  });

  it('reads the rows the API actually sends, under `items`', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({ items: [ALERT_ROW], total: 1, page: 1, page_size: 50, pages: 1 }),
    );

    const result = await alertsApi.list();

    // Against the pre-fix client this is 0: it only looked at `raw.alerts`.
    expect(result.alerts).toHaveLength(1);
    expect(result.alerts[0].id).toBe(ALERT_ROW.id);
    expect(result.total).toBe(1);
  });

  it('never reports a total it has no rows for', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({ items: [ALERT_ROW, { ...ALERT_ROW, id: 'b' }], total: 2, page: 1, page_size: 50 }),
    );

    const result = await alertsApi.list();

    // The symptom users saw: "2 alerts" above an empty table.
    expect(result.alerts.length).toBe(result.total);
  });

  it('still accepts the legacy `alerts` key so responder routes keep working', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({ alerts: [ALERT_ROW], total: 1, page: 1, pageSize: 25 }),
    );

    const result = await alertsApi.list();

    expect(result.alerts).toHaveLength(1);
    expect(result.pageSize).toBe(25);
  });

  it('returns an empty page without throwing when the API sends neither key', async () => {
    fetchMock.mockResolvedValue(jsonResponse({ total: 0, page: 1, page_size: 50 }));

    const result = await alertsApi.list();

    expect(result.alerts).toEqual([]);
    expect(result.total).toBe(0);
  });
});

/**
 * `facets` is the whole-result-set aggregate the stat strip renders. The strip
 * used to derive those numbers from the loaded page, so they were capped at
 * `page_size` and sat beside a `total` in the hundreds.
 */
describe('alertsApi.list facets', () => {
  it('reads the snake_case aggregate the API sends', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({
        items: [ALERT_ROW],
        total: 522,
        page: 1,
        page_size: 25,
        facets: {
          by_severity: { critical: 118, high: 64 },
          by_status: { new: 200, triaging: 90 },
          unresolved: 290,
        },
      }),
    );

    const result = await alertsApi.list();

    expect(result.facets).toEqual({
      bySeverity: { critical: 118, high: 64 },
      byStatus: { new: 200, triaging: 90 },
      unresolved: 290,
    });
  });

  it('leaves facets absent when the server sends none', async () => {
    // Absent is not empty: an empty-but-present object would let the strip
    // print a confident 0 for a count nobody made.
    fetchMock.mockResolvedValue(jsonResponse({ items: [], total: 0, page: 1, page_size: 25 }));

    expect((await alertsApi.list()).facets).toBeUndefined();
  });

  it('keeps a zero the server did send', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({
        items: [],
        total: 0,
        page: 1,
        page_size: 25,
        facets: { by_severity: {}, by_status: {}, unresolved: 0 },
      }),
    );

    expect((await alertsApi.list()).facets).toEqual({
      bySeverity: {},
      byStatus: {},
      unresolved: 0,
    });
  });
});

/**
 * `sort` is how the console avoids a flood burying a critical. The API
 * defaults to `newest` for its SDK clients, so the console has to ask.
 */
describe('alertsApi.list ordering', () => {
  it('sends the sort the caller asked for', async () => {
    fetchMock.mockResolvedValue(jsonResponse({ items: [], total: 0, page: 1, page_size: 25 }));

    await alertsApi.list({ page: 1, pageSize: 25, sort: 'priority' });

    const url = String(fetchMock.mock.calls[0][0]);
    expect(url).toContain('sort=priority');
  });
});

describe('alertsApi.list request parameters', () => {
  beforeEach(() => {
    fetchMock.mockResolvedValue(jsonResponse({ items: [], total: 0, page: 1, page_size: 25 }));
  });

  it('sends the backend query names while preserving the existing alert filters', async () => {
    await alertsApi.list({
      page: 2,
      pageSize: 50,
      severity: 'critical',
      status: 'escalated',
      source: 'connector',
      assignee: 'analyst@example.com',
      search: 'PowerShell + download',
      sort: 'priority',
      startTime: '2026-05-06T00:00:00+00:00',
      endTime: '2026-05-07T00:00:00+00:00',
      unresolvedOnly: true,
      createdWithinHours: 24,
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const url = new URL(String(fetchMock.mock.calls[0][0]), window.location.origin);
    expect(url.pathname).toBe('/api/v1/alerts');
    expect(Object.fromEntries(url.searchParams)).toEqual({
      page: '2',
      page_size: '50',
      severity: 'critical',
      status: 'escalated',
      source: 'connector',
      assignee: 'analyst@example.com',
      search: 'PowerShell + download',
      sort: 'priority',
      event_since: '2026-05-06T00:00:00+00:00',
      event_until: '2026-05-07T00:00:00+00:00',
      unresolved_only: 'true',
      created_within_hours: '24',
    });
  });

  it('preserves the responder queue page size without adding drilldown filters', async () => {
    await alertsApi.list({ pageSize: 100 });

    const url = new URL(String(fetchMock.mock.calls[0][0]), window.location.origin);
    expect(Object.fromEntries(url.searchParams)).toEqual({ page_size: '100' });
  });

  it('omits unset and empty filters so the server defaults still apply', async () => {
    await alertsApi.list({
      page: undefined,
      pageSize: undefined,
      severity: '',
      status: '',
      source: '',
      assignee: '',
      search: '',
      startTime: '',
      endTime: undefined,
      unresolvedOnly: undefined,
      createdWithinHours: undefined,
    });

    const url = new URL(String(fetchMock.mock.calls[0][0]), window.location.origin);
    expect(url.search).toBe('');
  });

  it('retains an explicit false value when unresolved filtering is disabled', async () => {
    await alertsApi.list({ unresolvedOnly: false });

    const url = new URL(String(fetchMock.mock.calls[0][0]), window.location.origin);
    expect(Object.fromEntries(url.searchParams)).toEqual({ unresolved_only: 'false' });
  });
});
