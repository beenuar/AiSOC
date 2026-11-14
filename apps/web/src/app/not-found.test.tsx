/**
 * The 404 page must not offer demo data on a build that has none.
 *
 * Its dashboard card advertised "Anonymous, pre-seeded investigation. No
 * signup. Demo data resets daily at 00:00 UTC." unconditionally. On a
 * self-hosted build with demo mode off that is an offer of seeded data that
 * does not exist and a reset schedule nothing runs — the same class of defect
 * as a console announcing demo resets over somebody's real alerts, pointing
 * the other way.
 *
 * Both directions, because deleting the copy outright would pass a one-sided
 * suite and quietly remove the one thing a visitor to the hosted demo most
 * wants to know.
 */
import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { __setDemoModeForTests } from '@/lib/demoMode';

vi.mock('next/link', () => ({
  __esModule: true,
  default: ({ children, href }: { children: React.ReactNode; href: string }) => <a href={href}>{children}</a>,
}));

vi.mock('@/components/landing/sections/StickyNav', () => ({
  __esModule: true,
  StickyNav: () => null,
}));

vi.mock('@/components/landing/sections/Footer', () => ({
  __esModule: true,
  Footer: () => null,
}));

import NotFoundPage from './not-found';

/** Every phrase that promises demo data exists. */
const DEMO_PROMISES = [/pre-seeded/i, /resets daily/i, /no signup/i, /00:00 UTC/i];

afterEach(() => {
  cleanup();
  __setDemoModeForTests(null);
});

describe('with demo mode off', () => {
  beforeEach(() => __setDemoModeForTests(false));

  it('promises no demo data', () => {
    render(<NotFoundPage />);
    for (const promise of DEMO_PROMISES) {
      expect(screen.queryByText(promise), `"${promise}" offers demo data this build does not have`).toBeNull();
    }
  });

  it('still points at the dashboard, and says what it actually is', () => {
    // Gating the copy must not cost the destination. A 404 page whose links
    // disappear is worse than one with an over-eager blurb.
    render(<NotFoundPage />);
    expect(screen.getAllByRole('link', { name: /open the dashboard/i }).length).toBeGreaterThan(0);
    expect(screen.getByText(/sign in to continue/i)).toBeInTheDocument();
  });

  it('does not call it "live"', () => {
    render(<NotFoundPage />);
    expect(screen.queryByText(/open the live dashboard/i)).toBeNull();
  });

  it('keeps the rest of the destinations', () => {
    render(<NotFoundPage />);
    for (const label of [/see pricing/i, /read the docs/i, /contact the team/i]) {
      expect(screen.getByRole('link', { name: label })).toBeInTheDocument();
    }
  });
});

describe('with demo mode on', () => {
  beforeEach(() => __setDemoModeForTests(true));

  it('says the demo is seeded and resets, because there it is true', () => {
    render(<NotFoundPage />);
    expect(screen.getByText(/pre-seeded/i)).toBeInTheDocument();
    expect(screen.getByText(/resets daily at 00:00 UTC/i)).toBeInTheDocument();
    expect(screen.getAllByRole('link', { name: /open the live dashboard/i }).length).toBeGreaterThan(0);
  });
});
