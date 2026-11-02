/**
 * `HuntView` against the response the hunt backend actually returns.
 *
 * Reported as issue #1648: pressing "Run hunt" threw
 * `TypeError: Cannot read properties of undefined (reading 'toLocaleString')`
 * on the results header, because `HuntResponse` in `apps/web/src/lib/api.ts`
 * declared `took` while `services/agents/app/api/hunt_search.py` sends
 * `took_ms`. `HuntHit` disagreed the same way: `fields` against `raw`.
 *
 * `HuntHonesty.test.tsx` has a case called "renders the real results the
 * backend returned" and it passed throughout, because its double returned
 * `{ took: 7, hits: [{ fields: … }] }` — the *client's* declared shape, which
 * no response has ever carried. The test mocked exactly the boundary the
 * defect lived at, so it could only ever confirm the client agreed with
 * itself.
 *
 * This file does not mock `@/lib/api`. The payload goes in at `fetch` and
 * comes out on screen, so the normalisation boundary is on the path under
 * test. The wire fixture is typed `HuntSearchWire`, which
 * `scripts/check_console_wire_contract.py` holds against the agents service's
 * own OpenAPI document — so a handler rename fails the gate rather than this
 * fixture quietly describing a response nobody sends.
 */

import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { __setDemoModeForTests } from '@/lib/demoMode';
import type { HuntSearchWire } from '@/lib/api';

const swrData = vi.hoisted(() => new Map<string, unknown>());

vi.mock('swr', () => ({
  __esModule: true,
  default: (key: unknown) => ({
    data: swrData.get(typeof key === 'string' ? key : JSON.stringify(key)),
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  }),
}));

// Monaco is loaded through `next/dynamic` and needs a real browser.
vi.mock('next/dynamic', () => ({
  __esModule: true,
  default: () => function EditorStub() {
    return null;
  },
}));

import { HuntView } from './HuntView';

/** What `hunt_search.hunt_search()` serialises, field for field. */
const WIRE: HuntSearchWire = {
  query: 'process.name:powershell.exe',
  total: 1,
  took_ms: 7,
  hits: [
    {
      id: '8f6a2f4e-1c22-4a0b-9f1e-4f0d2b5c7a01',
      timestamp: '2026-11-02T00:19:15+00:00',
      source: 'crowdstrike',
      event_type: 'ProcessCreation',
      raw: { host: 'WS-DEV-01', user: 'DOMAIN\\analyst', process_name: 'cmd.exe' },
      highlights: ['process.name:powershell.exe'],
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

const runHunt = () => userEvent.click(screen.getByRole('button', { name: /Run hunt/i }));

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  swrData.clear();
  fetchMock = vi.fn().mockResolvedValue(jsonResponse(WIRE));
  vi.stubGlobal('fetch', fetchMock);
  __setDemoModeForTests(false);
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  __setDemoModeForTests(null);
});

describe('running a hunt against the real backend response', () => {
  it(
    'renders the results instead of throwing on an undefined latency',
    async () => {
      render(<HuntView />);
      await runHunt();

      await waitFor(
        () => {
          expect(screen.getByText(/1 hits/)).toBeTruthy();
        },
        { timeout: 4000 },
      );
      // The crash: `results.took` was undefined, so `.toLocaleString()` threw
      // before this line could render.
      expect(screen.getByText(/7ms/)).toBeTruthy();
    },
    15000,
  );

  it(
    'renders the event body the backend sent under `raw`',
    async () => {
      render(<HuntView />);
      await runHunt();

      // `ResultRow` read `result.fields`, which `?? {}` turned into an empty
      // row: a hit with no host, no user and no fields to expand.
      await waitFor(
        () => {
          expect(screen.getByText('WS-DEV-01')).toBeTruthy();
        },
        { timeout: 4000 },
      );
      expect(screen.getByText('DOMAIN\\analyst')).toBeTruthy();
    },
    15000,
  );

  it(
    'reads the sample-source marker as a declared field',
    async () => {
      render(<HuntView />);
      await runHunt();

      await waitFor(
        () => {
          expect(screen.getByText(/illustrative sample events/i)).toBeTruthy();
        },
        { timeout: 4000 },
      );
    },
    15000,
  );
});

describe('latency is published only when it was measured', () => {
  it('publishes none on first paint, before any hunt has run', () => {
    render(<HuntView />);

    // The error branch runs before the list, so first paint is its own case.
    expect(screen.queryByText(/ms$/)).toBeNull();
    expect(screen.getByText(/Press Run to begin/i)).toBeTruthy();
  });

  it(
    'says so rather than printing 0ms when the backend measured none',
    async () => {
      const { took_ms: _dropped, ...withoutLatency } = WIRE;
      fetchMock.mockResolvedValue(jsonResponse(withoutLatency));

      render(<HuntView />);
      await runHunt();

      await waitFor(
        () => {
          expect(screen.getByText(/latency not measured/i)).toBeTruthy();
        },
        { timeout: 4000 },
      );
      expect(screen.queryByText(/0ms/)).toBeNull();
    },
    15000,
  );

  it(
    'publishes no latency for sample events the hosted demo substituted',
    async () => {
      __setDemoModeForTests(true);
      fetchMock.mockRejectedValue(new Error('no backend in the demo'));

      render(<HuntView />);
      await runHunt();

      await waitFor(
        () => {
          expect(screen.getByText(/WORKSTATION-042/)).toBeTruthy();
        },
        { timeout: 4000 },
      );
      // `took: 0` was a query latency for a query that never ran — the same
      // claim as the `took: 42` removed before it, with a humbler number.
      expect(screen.queryByText(/0ms/)).toBeNull();
      expect(screen.getByText(/latency not measured/i)).toBeTruthy();
    },
    15000,
  );
});
