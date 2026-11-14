/**
 * The welcome banner is the first thing a new operator reads, and it was
 * wrong in both directions a coaching card can be wrong.
 *
 * It advertised "26 vendors" against a registry of 84, and "25 named
 * runbooks" with nothing holding that to the pack on disk. And its second
 * CTA linked to `/cases/INC-RT-001`, a case that exists only after the demo
 * seed has run — so on every other deployment the banner's own call to action
 * was a 404, which is the dead-control rule as much as the honesty one.
 *
 * These assert on first paint with `?welcome=1`, which is the only state the
 * banner has.
 */

import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { __setDemoModeForTests } from '@/lib/demoMode';
import { CONNECTOR_COUNT } from '@/data/connectorCount';

vi.mock('next/link', () => ({
  __esModule: true,
  default: ({ children, href }: { children: React.ReactNode; href: string }) => (
    <a href={href}>{children}</a>
  ),
}));

const replaceMock = vi.hoisted(() => vi.fn());
vi.mock('next/navigation', () => ({
  __esModule: true,
  useRouter: () => ({ push: vi.fn(), replace: replaceMock, refresh: vi.fn() }),
  usePathname: () => '/dashboard',
  useSearchParams: () => new URLSearchParams('welcome=1'),
}));

import { DashboardWelcome } from './DashboardWelcome';

function hrefs(): string[] {
  return Array.from(document.querySelectorAll('a')).map((a) => a.getAttribute('href') ?? '');
}

beforeEach(() => {
  __setDemoModeForTests(false);
  replaceMock.mockReset();
});

afterEach(() => {
  cleanup();
  __setDemoModeForTests(null);
});

describe('DashboardWelcome outside demo mode', () => {
  it('quotes the connector count from the generated registry, not a literal', () => {
    render(<DashboardWelcome />);

    expect(screen.getByTestId('dashboard-welcome')).toBeTruthy();
    expect(screen.getByText(new RegExp(`Pick from ${CONNECTOR_COUNT} vendors`))).toBeTruthy();
    // The stale literal must be gone rather than merely nudged.
    expect(screen.queryByText(/26 vendors/)).toBeNull();
  });

  it('publishes no playbook count it cannot source', () => {
    render(<DashboardWelcome />);

    expect(screen.queryByText(/25 named runbooks/i)).toBeNull();
    expect(screen.getByText(/named runbooks for ransomware/i)).toBeTruthy();
  });

  it('offers no link to a case that only the demo seed creates', () => {
    render(<DashboardWelcome />);

    for (const href of hrefs()) {
      expect(href, 'seeded-case deeplink must be gated behind demo mode').not.toMatch(
        /INC-RT-001/,
      );
    }
    expect(screen.queryByText(/sample case/i)).toBeNull();
  });

  it('every remaining call to action points at a route the console defines', () => {
    render(<DashboardWelcome />);

    // Both survive on any deployment: the connector gallery and the playbook
    // gallery are static routes, not seeded content.
    expect(hrefs()).toEqual(['/onboarding', '/playbooks']);
  });
});

describe('DashboardWelcome in demo mode', () => {
  it('restores the sample-case tip and marks it as sample data', () => {
    __setDemoModeForTests(true);

    render(<DashboardWelcome />);

    expect(screen.getByText(/sample data, not tenant data/i)).toBeTruthy();
    expect(hrefs()).toContain('/cases/INC-RT-001?tab=ledger');
  });
});
