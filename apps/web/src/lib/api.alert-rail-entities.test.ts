/**
 * `alertsApi.get` — Investigation Rail related-entity contract.
 *
 * `RelatedEntity` in `services/api/app/services/alert_rail.py` serialises as
 * `{group, kind, value, label, pivot}`. The client mapper read `e.type` and
 * `e.pivot_path`, neither of which the API has ever sent, and fed `e.kind`
 * ("host") into its own `kind`, which is the rail *column* ("principal").
 *
 * All three were wrong in the same direction, so the failure was silent:
 * `pivotPath` resolved to `null` and no chip was ever a link; `type` was
 * empty; and `ENTITY_KIND_CONFIG[kind]` missed on every row, so
 * `RelatedEntitiesSection` rendered its header and count with no chips
 * underneath. Observed against a live core stack: an alert whose API payload
 * carried a host and a user rendered "RELATED ENTITIES (4)" with an empty
 * body and zero anchors in the DOM.
 *
 * The consequence worth pinning is that the `/graph?entity=…` route
 * correction and its URL encoding — both unit-tested on the server — could
 * not be reached from the console at all. `InvestigationRail.test.tsx`
 * constructs the client-side type directly, so it never crossed this
 * boundary.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { alertsApi } from './api';

/** Exactly what `GET /api/v1/alerts/{id}` returned on a live stack. */
const API_PAYLOAD = {
  id: '28f0699a-423b-4111-8111-1e59c15fa35f',
  title: 'SuspiciousPowerShell',
  severity: 'medium',
  status: 'new',
  created_at: '2026-09-23T23:20:12Z',
  related_entities: [
    { group: 'principal', kind: 'host', value: 'Finance & Legal #2', label: null, pivot: '/graph?entity=host%3AFinance%20%26%20Legal%20%232' },
    { group: 'principal', kind: 'user', value: 'CORP\\svc backup', label: null, pivot: '/graph?entity=user%3ACORP%5Csvc%20backup' },
    { group: 'workflow', kind: 'rule', value: 'CrowdStrike Falcon', label: null, pivot: null },
  ],
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

describe('alertsApi.get related entities', () => {
  it('carries the pivot the API sends, so a chip can be a link', async () => {
    fetchMock.mockResolvedValue(jsonResponse(API_PAYLOAD));

    const alert = await alertsApi.get(API_PAYLOAD.id);
    const host = alert.relatedEntities?.find((e) => e.type === 'host');

    // Against the pre-fix client this is `null` for every entity.
    expect(host?.pivotPath).toBe('/graph?entity=host%3AFinance%20%26%20Legal%20%232');
  });

  it('preserves the encoding, so an ampersand does not truncate the pivot', async () => {
    fetchMock.mockResolvedValue(jsonResponse(API_PAYLOAD));

    const alert = await alertsApi.get(API_PAYLOAD.id);
    const host = alert.relatedEntities?.find((e) => e.type === 'host');

    expect(host?.pivotPath).toContain('%26');
    expect(host?.pivotPath).toContain('%232');
    expect(decodeURIComponent(host!.pivotPath!.split('entity=')[1])).toBe('host:Finance & Legal #2');
  });

  it('maps the rail column onto `kind` so the grouped render finds its bucket', async () => {
    fetchMock.mockResolvedValue(jsonResponse(API_PAYLOAD));

    const alert = await alertsApi.get(API_PAYLOAD.id);

    // `RelatedEntitiesSection` keys `ENTITY_KIND_CONFIG` off `kind`, whose
    // valid values are the rail columns. Pre-fix this was 'host'/'user', which
    // matched no bucket, so the chips were dropped from the output entirely.
    expect(alert.relatedEntities?.map((e) => e.kind)).toEqual(['principal', 'principal', 'workflow']);
  });

  it('maps the concrete entity type onto `type` so the chip has a label', async () => {
    fetchMock.mockResolvedValue(jsonResponse(API_PAYLOAD));

    const alert = await alertsApi.get(API_PAYLOAD.id);

    expect(alert.relatedEntities?.map((e) => e.type)).toEqual(['host', 'user', 'rule']);
    expect(alert.relatedEntities?.every((e) => e.type !== '')).toBe(true);
  });

  it('leaves an informational entity without a pivot', async () => {
    fetchMock.mockResolvedValue(jsonResponse(API_PAYLOAD));

    const alert = await alertsApi.get(API_PAYLOAD.id);

    expect(alert.relatedEntities?.find((e) => e.type === 'rule')?.pivotPath).toBeNull();
  });

  it('still reads the older `pivot_path` spelling', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({
        ...API_PAYLOAD,
        related_entities: [{ kind: 'principal', type: 'host', value: 'web-01', pivot_path: '/graph?entity=host%3Aweb-01' }],
      }),
    );

    const alert = await alertsApi.get(API_PAYLOAD.id);

    expect(alert.relatedEntities?.[0].pivotPath).toBe('/graph?entity=host%3Aweb-01');
    expect(alert.relatedEntities?.[0].type).toBe('host');
  });

  it('does not throw when the API sends no entities', async () => {
    fetchMock.mockResolvedValue(jsonResponse({ ...API_PAYLOAD, related_entities: [] }));

    const alert = await alertsApi.get(API_PAYLOAD.id);

    expect(alert.relatedEntities).toEqual([]);
  });
});
