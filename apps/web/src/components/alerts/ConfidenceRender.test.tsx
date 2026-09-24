/**
 * `/alerts/[id]` rendered a confidence of 21 as **2100%**.
 *
 * `Alert.confidenceScore` is the canonical 0-100 integer (see
 * `lib/confidenceScale.test.ts`, which pins the boundary). This view treated
 * it as a [0,1] fraction and multiplied by 100, in two places — the header
 * chip and the "Detection Confidence" section — while the Investigation Rail
 * on the same page rendered the same field correctly as "21/100". Its mock
 * held `0.86`, so every test that used the mock agreed with the view.
 *
 * It also prefixed every rationale row with a literal `+`, so a factor that
 * argued *against* the verdict read `+-0.30`; and it clamped the signed
 * contribution-over-weight ratio to [0, 1], so a negative factor's bar
 * rendered at zero width — an invisible row with a nonsense label.
 *
 * Against the pre-change tree: the first block fails on `2100%`, the second
 * on `+-0.30`.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import type { Alert } from '@/lib/api';

const swrState = vi.hoisted(() => ({ data: undefined as unknown, isLoading: false }));

vi.mock('swr', () => ({
  __esModule: true,
  default: () => ({ data: swrState.data, error: undefined, isLoading: swrState.isLoading, mutate: vi.fn() }),
}));

vi.mock('next/navigation', () => ({
  __esModule: true,
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), back: vi.fn(), refresh: vi.fn() }),
  usePathname: () => '/alerts/a1',
  useSearchParams: () => new URLSearchParams(),
}));

vi.mock('next/link', () => ({
  __esModule: true,
  default: ({ children, href }: { children: React.ReactNode; href: string }) => <a href={href}>{children}</a>,
}));

vi.mock('react-hot-toast', () => ({ __esModule: true, default: { success: vi.fn(), error: vi.fn() } }));

// Each of these owns its own suite; none of them is about confidence.
vi.mock('@/components/copilot/ContextualActions', () => ({
  __esModule: true,
  ContextualActions: () => null,
}));
vi.mock('@/components/alerts/ExplainDrawer', () => ({ __esModule: true, ExplainDrawer: () => null }));
vi.mock('@/components/alerts/CreateCaseModal', () => ({ __esModule: true, CreateCaseModal: () => null }));

import { AlertDetailView } from './AlertDetailView';

/** The real payload shape, at the values the live acceptance pass saw. */
const ALERT: Alert = {
  id: 'a1',
  title: 'Unusual sign-in from an unrecognised location',
  description: 'An interactive sign-in succeeded from an ASN this identity has not used before.',
  severity: 'medium',
  status: 'new',
  source: 'okta',
  tenantId: '00000000-0000-0000-0000-000000000001',
  riskScore: 42,
  createdAt: '2026-09-23T22:25:56Z',
  updatedAt: '2026-09-23T22:25:56Z',
  confidenceLabel: 'low',
  confidenceScore: 21,
  confidenceRationale: [
    { factor: 'severity', label: 'Medium severity from source', value: 0.5, contribution: 0.2, weight: 0.2 },
    { factor: 'source_reliability', label: 'Single uncorroborated source', value: 0.2, contribution: -0.3, weight: 0.4 },
  ],
};

beforeEach(() => {
  swrState.data = ALERT;
  swrState.isLoading = false;
});

afterEach(() => cleanup());

describe('confidence is rendered on the scale it arrives on', () => {
  it('renders 21 as 21/100, not as a percentage of a fraction', () => {
    render(<AlertDetailView alertId="a1" />);

    expect(screen.queryByText(/2100\s*%/)).toBeNull();
    expect(screen.getAllByText(/21\/100/).length).toBeGreaterThan(0);
  });

  it('agrees with the Investigation Rail, which renders the same field as N/100', () => {
    render(<AlertDetailView alertId="a1" />);

    // Both the header chip and the Detection Confidence section.
    expect(screen.getAllByText(/21\/100/).length).toBe(2);
  });

  it('publishes no percentage sign for a value that is not a probability', () => {
    // Confidence is independent of severity and is not the probability that
    // the verdict is correct, which is why the rail's wording is "/100".
    render(<AlertDetailView alertId="a1" />);

    expect(screen.queryByText(/^score 21\.00/)).toBeNull();
  });
});

describe('a factor that argued against the verdict reads as negative', () => {
  it('renders a negative contribution with one sign, not "+-"', () => {
    render(<AlertDetailView alertId="a1" />);

    expect(screen.queryByText(/\+-0\.30/)).toBeNull();
    expect(screen.getByText(/\u22120\.30 \/ 0\.40/)).toBeTruthy();
  });

  it('still renders a positive contribution with a plus', () => {
    render(<AlertDetailView alertId="a1" />);

    expect(screen.getByText(/\+0\.20 \/ 0\.20/)).toBeTruthy();
  });

  it('gives a negative factor a visible bar sized by its magnitude', () => {
    // The old clamp took `contribution / weight` into [0, 1], so -0.30/0.40
    // became 0 and the row rendered with no bar at all.
    const { container } = render(<AlertDetailView alertId="a1" />);

    const widths = [...container.querySelectorAll('div[style*="width"]')]
      .map((el) => (el as HTMLElement).style.width)
      .filter((w) => w.endsWith('%'));

    // 0.30 / 0.40 = 75%
    expect(widths).toContain('75%');
  });
});
