/**
 * The RBA queue must not invent entities, and its KPI cards must be covered
 * by the same disclosure as its rows.
 *
 * What a live acceptance pass saw: the console requested
 * `entity-risk/queue?tenant_id=default` — a tenant *slug* against a route
 * that declares `tenant_id: UUID` — got a 422, and rendered
 * `jsmith@acme.corp`, `updates.evil-cdn.xyz` and "last seen 5 months ago" on
 * a stack that had been up for an hour. Above those rows, and *outside* the
 * amber banner that disclosed them, four cards read "Contributing alerts 26"
 * and "Alert → Incident 13.0:1". The banner itself said "Fusion service
 * unreachable" while fusion was healthy.
 *
 * **Every test here asserts on first paint as well as on the error branch.**
 * That is the whole lesson of the bug this file descends from: two dashboards
 * wrapped their sample data in `demoFallback()` and then defeated it with
 * `const resolved = isValid ? data : MOCK`. `data` is undefined on first
 * paint *and* after an error, so a test that only drives the error branch
 * exercises a path that returns early — and a regression introduced there is
 * unreachable from the test, which is exactly how the original survived
 * review.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { axe } from 'vitest-axe';
import { __setDemoModeForTests } from '@/lib/demoMode';

const swrData = vi.hoisted(() => new Map<string, unknown>());
const swrErrors = vi.hoisted(() => new Map<string, unknown>());

vi.mock('swr', () => ({
  __esModule: true,
  default: (key: unknown) => {
    const k = typeof key === 'string' ? key : JSON.stringify(key);
    return {
      data: swrData.get(k),
      error: swrErrors.get(k),
      isLoading: false,
      mutate: vi.fn(),
    };
  },
}));

import { ApiError } from '@/lib/api';
import { EntityRiskQueue, describeQueueFailure } from './EntityRiskQueue';

const QUEUE_KEY = JSON.stringify(['entity-risk-queue', false]);
const STATS_KEY = 'entity-risk-stats';

/** Verbatim from `MOCK_ENTITIES` / `MOCK_ENTITY_STATS` in EntityRiskQueue.tsx. */
const FABRICATED_ENTITIES = [
  'jsmith@acme.corp',
  'WS-PROD-042',
  '198.51.100.42',
  'updates.evil-cdn.xyz',
  'admin@partner.co',
];

/** The figures the four cards published from the sample stats payload. */
const FABRICATED_COUNTS = ['26', '13.0:1'];

function expectNothingFabricated() {
  for (const value of FABRICATED_ENTITIES) {
    expect(
      screen.queryByText(value),
      `"${value}" is sample data and must never render as a tenant's entity`,
    ).toBeNull();
  }
  for (const value of FABRICATED_COUNTS) {
    expect(
      screen.queryByText(value),
      `"${value}" is derived from sample data and must not render as a measured count`,
    ).toBeNull();
  }
}

beforeEach(() => {
  swrData.clear();
  swrErrors.clear();
  __setDemoModeForTests(false);
});

afterEach(() => {
  cleanup();
  __setDemoModeForTests(null);
});

describe('EntityRiskQueue — first paint', () => {
  it('publishes no entities and no counts before either request resolves', () => {
    // The state a self-hoster is in for the first few hundred milliseconds of
    // every page load, and permanently whenever the backend is unreachable.
    render(<EntityRiskQueue />);

    expectNothingFabricated();
  });

  it('shows no banner on first paint, because nothing has failed yet', () => {
    render(<EntityRiskQueue />);

    expect(screen.queryByText(/queue unavailable/i)).toBeNull();
    expect(screen.queryByText(/unreachable/i)).toBeNull();
  });

  it('renders zeros rather than dashes once an empty queue really arrives', () => {
    // Measured emptiness and unknown emptiness are different claims, and the
    // cards have to be able to say both.
    swrData.set(QUEUE_KEY, { tenant_id: 't', entities: [], threshold: 80 });
    swrData.set(STATS_KEY, { tenant_id: 't', total: 0, promoted: 0, alert_count: 0, threshold: 80, bands: {} });

    render(<EntityRiskQueue />);

    expect(screen.getByText(/No entities are currently being tracked/i)).toBeTruthy();
    expect(screen.queryByText('not measured')).toBeNull();
  });
});

describe('EntityRiskQueue — the disclosure covers the KPI cards', () => {
  it('reports every card as not measured when the stats request fails', () => {
    swrErrors.set(STATS_KEY, new ApiError('API 422', 422, ''));
    swrErrors.set(QUEUE_KEY, new ApiError('API 422', 422, ''));

    render(<EntityRiskQueue />);

    // Four cards, each explicitly unmeasured rather than confidently zero.
    expect(screen.getAllByText('not measured').length).toBe(4);
    expectNothingFabricated();
  });

  it('does not derive a ratio from counts it does not have', () => {
    // `Alert → Incident` is computed from the two counts beside it, so it has
    // to be unknown whenever they are. It read "13.0:1" off the sample stats.
    swrErrors.set(STATS_KEY, new ApiError('API 422', 422, ''));
    swrErrors.set(QUEUE_KEY, new ApiError('API 422', 422, ''));

    render(<EntityRiskQueue />);

    expect(screen.queryByText(/:1$/)).toBeNull();
    expect(screen.queryByText(/2026 bar/)).toBeNull();
  });

  it('withholds sample rows and counts even in the hosted demo when the fetch fails', () => {
    // The production repro. Demo mode supplies `fallbackData`, SWR then
    // revalidates, the revalidation 422s — and the view showed the sample
    // queue with a banner over it and the sample counts above the banner.
    __setDemoModeForTests(true);
    swrData.set(QUEUE_KEY, {
      tenant_id: 'demo',
      threshold: 80,
      entities: [
        {
          tenant_id: 'demo',
          entity_type: 'user',
          entity_value: 'jsmith@acme.corp',
          score: 92.4,
          display_score: 92,
          threshold: 80,
          promoted: true,
          promoted_incident_id: null,
          alert_count: 8,
          severity_histogram: {},
          first_seen: new Date().toISOString(),
          last_seen: new Date().toISOString(),
          contributions: [],
        },
      ],
    });
    swrData.set(STATS_KEY, { tenant_id: 'demo', total: 5, promoted: 2, alert_count: 26, threshold: 80, bands: {} });
    swrErrors.set(QUEUE_KEY, new ApiError('API 422', 422, ''));
    swrErrors.set(STATS_KEY, new ApiError('API 422', 422, ''));

    render(<EntityRiskQueue />);

    expectNothingFabricated();
    expect(screen.getByText(/The entity queue could not be loaded/i)).toBeTruthy();
  });

  it('says the queue is unknown rather than empty when the rows cannot load', () => {
    swrErrors.set(QUEUE_KEY, new ApiError('API 422', 422, ''));

    render(<EntityRiskQueue />);

    expect(screen.getByText(/unknown rather than as an empty queue/i)).toBeTruthy();
    expect(screen.queryByText(/No entities are currently being tracked/i)).toBeNull();
  });
});

describe('accessibility (WCAG 2.1 AA)', () => {
  // Colour contrast is disabled for the same reason as the operations suite:
  // jsdom resolves no stylesheet, so every computed colour is the default.
  const axeOptions = { rules: { 'color-contrast': { enabled: false } } };

  it('has no violations in the degraded state, which is a new live region', async () => {
    swrErrors.set(QUEUE_KEY, new ApiError('API 422', 422, ''));
    swrErrors.set(STATS_KEY, new ApiError('API 422', 422, ''));

    const { container } = render(<EntityRiskQueue />);

    expect(await axe(container, axeOptions)).toHaveNoViolations();
  });

  it('has no violations on first paint', async () => {
    const { container } = render(<EntityRiskQueue />);

    expect(await axe(container, axeOptions)).toHaveNoViolations();
  });
});

describe('describeQueueFailure — names the subsystem that actually failed', () => {
  it('calls a 422 a console bug and does not blame fusion', () => {
    // The failure that happened. "Fusion service unreachable" sent whoever
    // read it to debug a healthy service.
    const message = describeQueueFailure(new ApiError('API 422', 422, ''));

    expect(message).toMatch(/console bug rather than an outage/i);
    expect(message).not.toMatch(/fusion/i);
    expect(message).not.toMatch(/unreachable/i);
  });

  it('blames fusion only when fusion actually returned an error', () => {
    expect(describeQueueFailure(new ApiError('API 503', 503, ''))).toMatch(/fusion service returned 503/i);
  });

  it('reports a transport failure as unreachable, which is what status 0 means', () => {
    expect(describeQueueFailure(new ApiError('Network error', 0, ''))).toMatch(/cannot reach the api/i);
  });

  it('distinguishes an authorisation refusal from an outage', () => {
    expect(describeQueueFailure(new ApiError('API 403', 403, ''))).toMatch(/not authorised/i);
    expect(describeQueueFailure(new ApiError('API 404', 404, ''))).toMatch(/does not expose/i);
  });

  it('stays vague rather than guessing a subsystem for an unrecognised failure', () => {
    const message = describeQueueFailure(new Error('boom'));

    expect(message).toContain('boom');
    expect(message).not.toMatch(/fusion/i);
  });

  it('always says the queue is unknown, never that it is empty', () => {
    for (const status of [0, 401, 403, 422, 500, 503, 418]) {
      const message = describeQueueFailure(new ApiError(`API ${status}`, status, ''));
      if (status === 404) continue;
      expect(message.toLowerCase()).toMatch(/unknown|not authorised|does not expose/);
    }
  });
});
