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
