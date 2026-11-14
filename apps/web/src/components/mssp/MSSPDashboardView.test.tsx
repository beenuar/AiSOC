/**
 * Data-honesty gate for the managed-portfolio console.
 *
 * This view was a hardcoded table of six companies with invented alert counts,
 * MTTD/MTTR figures, risk scores, analyst headcounts and ARR, and it made no
 * API call at all. Every operator on every deployment saw the same six rows.
 *
 * The tests assert on **first paint** as well as the error branch. The error
 * branch returns early, so a regression injected there is unreachable from the
 * states that matter — and first paint (data undefined, no error yet) is
 * exactly where the previous generation of this bug lived across the console:
 * sample data wrapped in `demoFallback()` and then reinstated by
 * `const resolved = isValid ? data : MOCK`.
 *
 * The assertions are negative — these strings must never reach the DOM — which
 * is the form that stays meaningful as the component grows.
 */

import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';

const swrData = vi.hoisted(() => new Map<string, unknown>());
const swrErrors = vi.hoisted(() => new Map<string, unknown>());

vi.mock('swr', () => ({
  __esModule: true,
  default: (key: unknown) => {
    const k = typeof key === 'string' ? key : JSON.stringify(key);
    return {
      data: swrData.get(k),
      error: swrErrors.get(k),
      isLoading: !swrData.has(k) && !swrErrors.has(k),
      mutate: vi.fn(),
    };
  },
}));

// `ApiError` must be the same class the component's `instanceof` sees, so the
// mock owns it rather than re-exporting a second copy.
const apiMock = vi.hoisted(() => {
  class ApiError extends Error {
    status: number;
    body: string;
    constructor(message: string, status: number, body = '') {
      super(message);
      this.name = 'ApiError';
      this.status = status;
      this.body = body;
    }
  }
  return { ApiError };
});

vi.mock('@/lib/api', () => ({
  __esModule: true,
  ApiError: apiMock.ApiError,
  msspApi: {
    getPortfolio: vi.fn(),
    listPortfolioAlerts: vi.fn(),
  },
}));

vi.mock('next/link', () => ({
  __esModule: true,
  default: ({ children, href }: { children: React.ReactNode; href: string }) => <a href={href}>{children}</a>,
}));

import { ApiError } from '@/lib/api';
import MSSPDashboardView from './MSSPDashboardView';

/** Verbatim from the `TENANTS` array this view used to render. */
const FABRICATED_TENANTS = [
  'Acme Financial',
  'GlobalRetail Corp',
  'MedSecure Health',
  'NovaTech Industries',
  'Pinnacle Energy',
  'Stratos Logistics',
];

/** The invented revenue figures, and the columns that had no source at all. */
const FABRICATED_FIGURES = ['Total ARR', '$1290K', '$185K', 'Risk Score', 'Analysts', 'MTTD'];

function expectNoFabrication() {
  for (const name of [...FABRICATED_TENANTS, ...FABRICATED_FIGURES]) {
    expect(
      screen.queryByText(new RegExp(name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i')),
      `"${name}" was fabricated and must never render`,
    ).toBeNull();
  }
}

const REAL_TENANT = {
  tenant_id: '11111111-1111-1111-1111-111111111111',
  name: 'Northwind Manufacturing',
  slug: 'northwind',
  relationship: 'owner',
  is_active: true,
  open_alerts: 7,
  critical_alerts: 2,
  high_alerts: 3,
  untriaged_alerts: 4,
  synthetic_alerts: 0,
  open_cases: 3,
  sla_breached_cases: 1,
  mttr_minutes: 45,
  connectors: { total: 4, healthy: 3, stale: 1, error: 0 },
  last_event_at: '2026-09-20T10:00:00Z',
  limits: [],
  limits_exhausted: 0,
  limits_warning: 0,
};

const REAL_SUMMARY = {
  tenants: 1,
  tenants_active: 1,
  open_alerts: 7,
  critical_alerts: 2,
  high_alerts: 3,
  untriaged_alerts: 4,
  synthetic_alerts: 0,
  open_cases: 3,
  sla_breached_cases: 1,
  mttr_minutes: 45,
  connectors_total: 4,
  connectors_healthy: 3,
  connectors_stale: 1,
  connectors_error: 0,
  tenants_with_exhausted_limits: 0,
  tenants_with_limit_warnings: 0,
  tenants_without_connectors: 0,
};

function portfolio(overrides: Record<string, unknown> = {}) {
  return {
    org_id: '22222222-2222-2222-2222-222222222222',
    org_slug: 'acme-mssp',
    org_name: 'Example Operator',
    org_role: 'owner',
    portfolio_wide: true,
    scoped_tenants: 1,
    summary: REAL_SUMMARY,
    tenants: [REAL_TENANT],
    ...overrides,
  };
}

beforeEach(() => {
  swrData.clear();
  swrErrors.clear();
});

afterEach(() => cleanup());

describe('first paint — before any response has arrived', () => {
  it('renders a loading state rather than a table of invented tenants', () => {
    // Nothing seeded: `data` is undefined and there is no error, which is the
    // state the old code filled with six hardcoded companies.
    render(<MSSPDashboardView />);

    expectNoFabrication();
    expect(screen.getByRole('status')).toBeTruthy();
    expect(screen.getByText(/Loading portfolio/i)).toBeTruthy();
  });

  it('publishes no summary figures it has not received', () => {
    render(<MSSPDashboardView />);

    // The old KPI strip computed these from the hardcoded array.
    expect(screen.queryByText('6')).toBeNull();
    expect(screen.queryByText('31')).toBeNull();
    expect(screen.queryByText('67%')).toBeNull();
  });
});

describe('the API failed', () => {
  it('surfaces the failure instead of substituting sample data', () => {
    swrErrors.set('mssp-portfolio', new Error('503 Service Unavailable'));

    render(<MSSPDashboardView />);

    expectNoFabrication();
    expect(screen.getAllByText(/503 Service Unavailable/i).length).toBeGreaterThan(0);
  });
});

describe('the caller manages no tenants', () => {
  it('explains the 403 rather than reporting an outage', () => {
    swrErrors.set('mssp-portfolio', new ApiError('API 403 Forbidden', 403, ''));

    render(<MSSPDashboardView />);

    expect(screen.getByText(/You do not manage any tenants/i)).toBeTruthy();
    // A 403 here is a statement about the caller, not a broken backend.
    expect(screen.queryByRole('alert')).toBeNull();
    expectNoFabrication();
  });
});

describe('the portfolio is real but empty', () => {
  it('distinguishes an organisation with no tenants from a member with no grants', () => {
    swrData.set('mssp-portfolio', portfolio({ tenants: [], scoped_tenants: 0, summary: { ...REAL_SUMMARY, tenants: 0 } }));
    swrData.set('mssp-portfolio-alerts', []);

    render(<MSSPDashboardView />);

    expect(screen.getByText(/This organisation manages no tenants yet/i)).toBeTruthy();
    expectNoFabrication();
  });

  it('tells a scoped member their grants are empty, not that the org is', () => {
    swrData.set(
      'mssp-portfolio',
      portfolio({ tenants: [], scoped_tenants: 0, portfolio_wide: false, summary: { ...REAL_SUMMARY, tenants: 0 } }),
    );
    swrData.set('mssp-portfolio-alerts', []);

    render(<MSSPDashboardView />);

    expect(screen.getByText(/You have not been granted access to any tenants/i)).toBeTruthy();
  });
});

describe('real data', () => {
  it('renders the tenants the API returned and nothing else', () => {
    swrData.set('mssp-portfolio', portfolio());
    swrData.set('mssp-portfolio-alerts', []);

    render(<MSSPDashboardView />);

    expect(screen.getByText('Northwind Manufacturing')).toBeTruthy();
    expect(screen.getByText('Example Operator')).toBeTruthy();
    expectNoFabrication();
  });

  it('shows an unmeasured MTTR as not-measured, never as zero', () => {
    swrData.set(
      'mssp-portfolio',
      portfolio({
        tenants: [{ ...REAL_TENANT, mttr_minutes: null }],
        summary: { ...REAL_SUMMARY, mttr_minutes: null },
      }),
    );
    swrData.set('mssp-portfolio-alerts', []);

    render(<MSSPDashboardView />);

    // 0m would rank a tenant that has closed nothing top of the table.
    expect(screen.queryByText('0m')).toBeNull();
    expect(screen.getAllByText('—').length).toBeGreaterThan(0);
  });

  it('counts seeded demo rows apart from the tenant posture', () => {
    swrData.set(
      'mssp-portfolio',
      portfolio({
        tenants: [{ ...REAL_TENANT, synthetic_alerts: 15 }],
        summary: { ...REAL_SUMMARY, synthetic_alerts: 15 },
      }),
    );
    swrData.set('mssp-portfolio-alerts', []);

    render(<MSSPDashboardView />);

    // Both the per-tenant badge and the portfolio banner say so.
    expect(screen.getAllByText(/15 seeded/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/counted separately/i)).toBeTruthy();
  });

  it('never renders a revenue column, because no revenue data exists', () => {
    swrData.set('mssp-portfolio', portfolio());
    swrData.set('mssp-portfolio-alerts', []);

    render(<MSSPDashboardView />);

    expect(screen.queryByText(/ARR/)).toBeNull();
    expect(screen.queryByText(/\$\d/)).toBeNull();
  });
});

describe('the alert feed has its own states', () => {
  it('reports its own failure without claiming the portfolio failed', () => {
    swrData.set('mssp-portfolio', portfolio());
    swrErrors.set('mssp-portfolio-alerts', new Error('alert feed timeout'));

    render(<MSSPDashboardView />);

    expect(screen.getByText('Northwind Manufacturing')).toBeTruthy();
    expect(screen.getByText(/alert feed timeout/i)).toBeTruthy();
  });

  it('says there are no open alerts rather than inventing incidents', () => {
    swrData.set('mssp-portfolio', portfolio());
    swrData.set('mssp-portfolio-alerts', []);

    render(<MSSPDashboardView />);

    expect(screen.getByText(/No open alerts/i)).toBeTruthy();
    // Names from the deleted CrossTenantIncident sample.
    expect(screen.queryByText(/Wayne Enterprises/i)).toBeNull();
  });
});
