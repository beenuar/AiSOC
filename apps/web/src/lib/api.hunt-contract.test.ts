/**
 * `huntApi.search` — response contract against what the backend actually sends.
 *
 * `POST /api/v1/hunt/search` is served by `services/agents/app/api/hunt_search.py`,
 * not by `services/api`. Its `HuntResponse` sends `took_ms`, `query`, `source`
 * and `notice`; its `HuntHit` sends `raw`, `highlights` and `event_type`. The
 * hand-written client type declared `took`, `fields`, `highlight` and a
 * `severity` the handler has never sent — seven names, none of them shared.
 *
 * Nothing caught it because `request<HuntResponse>(...)` *asserts* the shape
 * rather than validating it, so the type checker believed `took` existed. The
 * tell was already in `HuntView.tsx`: the sample-source banner read the
 * honesty marker through an inline `(res as { source?: string }).source` cast,
 * used precisely because the declared type lacked the field.
 *
 * These tests drive the real client through a stubbed `fetch` with the body
 * the handler serialises, so the wire shape and the view shape cannot drift
 * apart again without one of them failing here. Same family, and the same
 * remedy, as `api.alerts-list.test.ts`.
 */

import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest';
import { huntApi, type HuntSearchWire } from './api';

/**
 * Byte-for-byte what `hunt_search.hunt_search()` returns.
 *
 * Typed as `HuntSearchWire`, so `pnpm typecheck` fails if this fixture and
 * the declared wire type drift; `scripts/check_console_wire_contract.py`
 * holds that type against the service's own OpenAPI document. The fixture is
 * therefore pinned to the handler at both ends rather than hand-maintained.
 */
const WIRE: HuntSearchWire = {
  query: 'process.name:powershell.exe',
  total: 2,
  took_ms: 7,
  hits: [
    {
      id: '8f6a2f4e-1c22-4a0b-9f1e-4f0d2b5c7a01',
      timestamp: '2026-11-02T00:19:15+00:00',
      source: 'crowdstrike',
      event_type: 'ProcessCreation',
      raw: {
        process_name: 'cmd.exe',
        parent_name: 'explorer.exe',
        cmdline: 'cmd.exe /c process.name:powershell.exe',
        user: 'DOMAIN\\analyst',
        host: 'WS-DEV-01',
      },
      highlights: ['process.name:powershell.exe'],
    },
    {
      id: '8f6a2f4e-1c22-4a0b-9f1e-4f0d2b5c7a02',
      timestamp: '2026-11-02T00:19:15+00:00',
      source: 'azure_ad',
      event_type: 'SignInLog',
      raw: { userPrincipalName: 'user@corp.example', ipAddress: '192.0.2.42' },
      highlights: [],
    },
  ],
  source: 'sample',
  notice: 'These are illustrative sample events, not results from your telemetry.',
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
  fetchMock = vi.fn().mockResolvedValue(jsonResponse(WIRE));
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('huntApi.search normalises the backend response at the boundary', () => {
  it('reads the latency the backend measured, under `took_ms`', async () => {
    const result = await huntApi.search({ query: WIRE.query });

    // Against the pre-fix client this is `undefined`, which is the crash:
    // `HuntView` called `.toLocaleString()` on it.
    expect(result.tookMs).toBe(7);
  });

  it('reads the event body the backend sends, under `raw`', async () => {
    const result = await huntApi.search({ query: WIRE.query });

    // Against the pre-fix client this is `undefined`: the client read
    // `fields`, which the handler has never sent.
    expect(result.hits[0].fields).toEqual(WIRE.hits[0].raw);
    expect(result.hits[0].fields.host).toBe('WS-DEV-01');
  });

  it('keeps the honesty marker as a declared field, not an inline cast', async () => {
    const result = await huntApi.search({ query: WIRE.query });

    expect(result.source).toBe('sample');
    expect(result.notice).toBe(WIRE.notice);
  });

  it('carries the plural `highlights` the backend sends, as a list', async () => {
    const result = await huntApi.search({ query: WIRE.query });

    expect(result.hits[0].highlights).toEqual(['process.name:powershell.exe']);
    expect(result.hits[1].highlights).toEqual([]);
  });

  it('carries `event_type` and the echoed query, which the client never declared', async () => {
    const result = await huntApi.search({ query: WIRE.query });

    expect(result.hits[0].eventType).toBe('ProcessCreation');
    expect(result.query).toBe('process.name:powershell.exe');
  });

  it('leaves severity absent, because this endpoint does not classify', async () => {
    const result = await huntApi.search({ query: WIRE.query });

    // The client declared `severity?: AlertSeverity` for a field no response
    // has ever carried. Absent is the honest value; the row renders "event".
    expect(result.hits[0].severity).toBeUndefined();
  });
});

describe('an unmeasurable latency is absent, never zero', () => {
  it('reports `null` when the backend sent no `took_ms`', async () => {
    const { took_ms: _dropped, ...withoutLatency } = WIRE;
    fetchMock.mockResolvedValue(jsonResponse(withoutLatency));

    const result = await huntApi.search({ query: WIRE.query });

    // `?? 0` here would render "0ms" under a live-backend pill — a confident
    // measurement of something nobody measured.
    expect(result.tookMs).toBeNull();
  });

  it('keeps a zero the backend did send', async () => {
    fetchMock.mockResolvedValue(jsonResponse({ ...WIRE, took_ms: 0 }));

    expect((await huntApi.search({ query: WIRE.query })).tookMs).toBe(0);
  });
});
