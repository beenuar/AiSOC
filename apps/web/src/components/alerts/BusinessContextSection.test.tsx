/**
 * The rail's "Business context" section renders what the rules did and the
 * cited impact — and renders NOTHING when no rule fired.
 *
 * The second half is the load-bearing property: `businessContext` is null for
 * every alert on a tenant with no rules configured, and an empty shell there
 * would read as "the platform looked and found nothing", which is not a
 * measurement anyone made. First-paint is asserted, not just the happy path.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
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

import { InvestigationRail } from './InvestigationRail';

function alertWith(over: Partial<Alert>): Alert {
  return {
    id: 'a1',
    title: 'Encoded PowerShell on FIN-APP-03',
    description: '',
    severity: 'critical',
    status: 'open',
    source: 'edr',
    tenantId: 't1',
    createdAt: '2026-10-31T00:00:00Z',
    updatedAt: '2026-10-31T00:00:00Z',
    ...over,
  } as Alert;
}

afterEach(() => {
  cleanup();
  swrState.data = undefined;
});

describe('BusinessContextSection', () => {
  it('names the rules, the mutation and the cited impact', () => {
    swrState.data = alertWith({
      businessContext: {
        matchedRuleIds: ['dc-critical'],
        severityBefore: 'medium',
        severityAfter: 'critical',
        impactStatement: 'Payment path at risk',
        impactCitations: ['dc-critical'],
      },
    });
    render(<InvestigationRail alertId="a1" onClose={() => {}} />);
    fireEvent.click(screen.getByText('Details'));
    expect(screen.getByText('Business context')).toBeTruthy();
    expect(screen.getByText('dc-critical')).toBeTruthy();
    expect(screen.getByText('Payment path at risk')).toBeTruthy();
    expect(screen.getByText(/cites: dc-critical/)).toBeTruthy();
  });

  it('renders nothing at all when no rule fired', () => {
    swrState.data = alertWith({ businessContext: null });
    render(<InvestigationRail alertId="a1" onClose={() => {}} />);
    fireEvent.click(screen.getByText('Details'));
    expect(screen.queryByText('Business context')).toBeNull();
  });

  it('renders nothing when the field is absent (older API)', () => {
    swrState.data = alertWith({});
    render(<InvestigationRail alertId="a1" onClose={() => {}} />);
    fireEvent.click(screen.getByText('Details'));
    expect(screen.queryByText('Business context')).toBeNull();
  });
});
