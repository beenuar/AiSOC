/**
 * WS-F2 — WCAG 2.1 AA accessibility sweep.
 *
 * Runs `axe-core` (via `vitest-axe`) against the highest-traffic surfaces a
 * buyer hits inside the first five minutes:
 *
 *   - Landing `Hero` (root marketing visual)
 *   - Onboarding `StartHero` (the three WS-A2 CTAs)
 *   - `ThemeToggle` (the WS-F1 chrome control)
 *   - `TopBar` (console chrome around every authenticated page)
 *   - `Sidebar` (primary navigation landmark — ARIA labels + hidden icons)
 *   - `EmptyState` (data-absent placeholder with role="status")
 *   - `CopilotDock` (collapsed state of the AI chat panel)
 *
 * Together these cover the marketing → onboarding → console journey. This
 * test runs inside the existing `web-test` CI job so any regression that
 * adds a missing label, breaks heading order, or leaves a non-button
 * interactive element ungated will fail the build.
 *
 * Note on `color-contrast`: jsdom doesn't compute styles for CSS variables,
 * so axe's `color-contrast` rule returns "incomplete" results that aren't
 * useful. We disable it here and rely on a manual contrast review (see
 * `apps/docs/docs/operations/theming.md`) plus the semantic-token layer
 * itself, which gives us a single place to tune contrast for both themes.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render } from '@testing-library/react';
import { axe } from 'vitest-axe';

// Shared mocks ----------------------------------------------------------

// Parity 4.7. The operator views below fetch through SWR, and without
// this they would render a loading spinner: axe would pass on a spinner
// and the suite would report coverage it does not have.
vi.mock('swr', () => ({
  // The key may be a string or a tuple: the Investigation Rail keys on
  // `['alerts', id, 'rail']`, and reading only the string form gave it
  // `undefined`, so it rendered its error state and axe passed on that.
  default: (key: unknown) => ({
    data: swrFixture(Array.isArray(key) ? key.join('/') : typeof key === 'string' ? key : ''),
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  }),
  mutate: vi.fn(),
  useSWRConfig: () => ({ mutate: vi.fn() }),
}));

vi.mock('next/link', () => ({
  default: ({
    children,
    href,
    ...rest
  }: {
    children: React.ReactNode;
    href: string;
  } & Record<string, unknown>) => (
    <a href={href} {...(rest as Record<string, unknown>)}>
      {children}
    </a>
  ),
}));

const pathnameMock = vi.fn(() => '/dashboard');

vi.mock('next/navigation', () => ({
  usePathname: () => pathnameMock(),
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
}));

// framer-motion's `motion.x` returns a real DOM tag and forwards refs. The
// production build pulls in IntersectionObserver and animation timers we
// don't need for static-DOM accessibility checks, so stub it out.
vi.mock('framer-motion', () => {
  const factory = (Tag: React.ElementType) =>
    function MotionStub(props: Record<string, unknown>) {
      const { children, ...rest } = props as {
        children?: React.ReactNode;
      } & Record<string, unknown>;
      delete (rest as Record<string, unknown>).initial;
      delete (rest as Record<string, unknown>).animate;
      delete (rest as Record<string, unknown>).exit;
      delete (rest as Record<string, unknown>).transition;
      delete (rest as Record<string, unknown>).whileHover;
      delete (rest as Record<string, unknown>).whileTap;
      return <Tag {...(rest as Record<string, unknown>)}>{children}</Tag>;
    };
  return {
    motion: new Proxy({}, { get: (_t, key: string) => factory(key as React.ElementType) }),
    AnimatePresence: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  };
});

vi.mock('react-hot-toast', () => ({
  default: { error: vi.fn(), success: vi.fn() },
}));

vi.mock('@/lib/api', () => ({
  authApi: {
    isAuthenticated: () => false,
    login: vi.fn(),
    currentUser: vi.fn(() => null),
    updateUserPreferences: vi.fn(),
  },
  copilotApi: {
    sendMessage: vi.fn(),
    getHistory: vi.fn(() => Promise.resolve([])),
  },
  tenantsApi: {
    me: vi.fn(() => Promise.reject(new Error('unauthenticated'))),
  },
  msspApi: {
    listChildren: vi.fn(() => Promise.resolve([])),
  },
  getActiveTenantId: vi.fn(() => ''),
  setActiveTenantId: vi.fn(),
}));

// Sidebar reads version from package.json — mock it so the import doesn't
// fail when running outside the actual apps/web working directory.
vi.mock('../../../package.json', () => ({
  default: { version: '0.0.0-test' },
}));

// Component imports go after the mocks so the mocks are resolved first.
import { Hero } from '../components/landing/Hero';
import { StartHero } from '../components/onboarding/StartHero';
import { ThemeToggle } from '../components/theme/ThemeToggle';
import { ThemeProvider } from '../components/theme/ThemeProvider';
import { TopBar } from '../components/layout/TopBar';
import { TimeWindowProvider } from '../components/layout/TimeWindowProvider';
import { TenantProvider } from '../components/layout/TenantProvider';
import { Sidebar } from '../components/layout/Sidebar';
import { EmptyState } from '../components/ui/EmptyState';
import { CopilotDock } from '../components/copilot/CopilotDock';

afterEach(() => {
  cleanup();
});

// jsdom lacks computed-style support for CSS variables, which is what
// axe's color-contrast rule needs. Skip it here; the semantic-token layer
// is the single source of truth for contrast and is reviewed manually.
const axeOptions = {
  rules: {
    'color-contrast': { enabled: false },
  },
};

/** Enough shape for each view to render its real markup rather than an
 * empty state. Deliberately small: this suite measures accessibility, not
 * data handling, and a large fixture would make a failure hard to read. */
function swrFixture(key: string): unknown {
  if (key.startsWith('alerts/') || (key.includes('/alerts/') && !key.endsWith('/alerts'))) {
    return {
      id: 'a1',
      title: 'Encoded PowerShell from Office',
      severity: 'high',
      status: 'new',
      confidence: 72,
      // camelCase: `normalizeAlert` has already run by the time the rail
      // reads this, so the fixture has to be the normalised shape rather
      // than the API's.
      createdAt: '2026-10-01T12:00:00Z',
      riskScore: 68,
      narrative: 'A macro-enabled document spawned an encoded PowerShell command.',
      entities: [{ group: 'host', kind: 'hostname', value: 'WIN-FIN-01', label: 'WIN-FIN-01' }],
      timeline: [{ id: 'e1', timestamp: '2026-10-01T12:00:00Z', title: 'Process created' }],
      recommended_actions: [{ id: 'r1', title: 'Isolate the host', risk: 'high' }],
    };
  }
  if (key.endsWith('/alerts') || key.includes('/alerts?')) {
    return {
      items: [
        {
          id: 'a1',
          title: 'Encoded PowerShell from Office',
          severity: 'high',
          status: 'new',
          created_at: '2026-10-01T12:00:00Z',
          connector_type: 'CrowdStrike Falcon',
        },
      ],
      total: 1,
    };
  }
  if (key.includes('/cases/')) {
    return {
      id: 'c1',
      title: 'Suspected macro delivery',
      status: 'open',
      severity: 'high',
      created_at: '2026-10-01T12:00:00Z',
      alerts: [],
      timeline: [],
    };
  }
  return undefined;
}

describe('WCAG 2.1 AA — high-traffic surfaces', () => {
  it('Landing Hero has no accessibility violations', async () => {
    const { container } = render(<Hero />);
    const results = await axe(container, axeOptions);
    expect(results).toHaveNoViolations();
  });

  it('Onboarding StartHero has no accessibility violations', async () => {
    const { container } = render(<StartHero />);
    const results = await axe(container, axeOptions);
    expect(results).toHaveNoViolations();
  });

  it('ThemeToggle has no accessibility violations', async () => {
    const { container } = render(
      <ThemeProvider>
        <ThemeToggle />
      </ThemeProvider>,
    );
    const results = await axe(container, axeOptions);
    expect(results).toHaveNoViolations();
  });

  it('TopBar has no accessibility violations', async () => {
    pathnameMock.mockReturnValue('/dashboard');
    const { container } = render(
      <ThemeProvider>
        <TimeWindowProvider>
          <TenantProvider>
            <TopBar />
          </TenantProvider>
        </TimeWindowProvider>
      </ThemeProvider>,
    );
    const results = await axe(container, axeOptions);
    expect(results).toHaveNoViolations();
  });

  it('Sidebar has no accessibility violations', async () => {
    pathnameMock.mockReturnValue('/alerts');
    const { container } = render(
      <ThemeProvider>
        <Sidebar />
      </ThemeProvider>,
    );
    const results = await axe(container, axeOptions);
    expect(results).toHaveNoViolations();
  });

  it('EmptyState has no accessibility violations', async () => {
    const { container } = render(
          <EmptyState
                icon={<svg aria-hidden="true" />}
                title="No alerts found"
                description="There are no alerts matching your filters."
                action={<button type="button">Clear filters</button>}
              />,
    );
    const results = await axe(container, axeOptions);
    expect(results).toHaveNoViolations();
  });

  /** axe passes on an empty div, so a view that rendered a spinner or an
   * error state would report coverage this suite does not have. Every
   * operator view below asserts it rendered something substantial first. */
  function assertRenderedSomething(container: HTMLElement, what: string) {
    const interactive = container.querySelectorAll(
      'button, a, input, select, textarea, [role="tab"], [role="button"], table, h1, h2',
    );
    expect(
      interactive.length,
      `${what} rendered ${interactive.length} interactive or structural elements, so axe ` +
        'passed on an empty or loading view rather than on the real one',
    ).toBeGreaterThan(2);
  }

  // ── Parity 4.7: the five operator views the plan names ──────────────
  //
  // 1.1 narrowed the "WCAG AA full accessibility pass" claim to the
  // components axe actually covered, which were the landing and chrome
  // ones above. These are the views an analyst spends their day in, and
  // they were covered by nothing.

  it('AlertsView (the queue and alert list) has no accessibility violations', async () => {
    pathnameMock.mockReturnValue('/alerts');
    const { AlertsView } = await import('@/components/alerts/AlertsView');
    const { container } = render(
      <ThemeProvider>
        <AlertsView />
      </ThemeProvider>,
    );
    assertRenderedSomething(container, 'AlertsView');
    const results = await axe(container, axeOptions);
    expect(results).toHaveNoViolations();
  });

  it('InvestigationRail has no accessibility violations', async () => {
    pathnameMock.mockReturnValue('/alerts');
    const { InvestigationRail } = await import('@/components/alerts/InvestigationRail');
    const { container } = render(
      <ThemeProvider>
        <InvestigationRail alertId="a1" onClose={() => {}} />
      </ThemeProvider>,
    );
    assertRenderedSomething(container, 'InvestigationRail');
    const results = await axe(container, axeOptions);
    expect(results).toHaveNoViolations();
  });

  it('SettingsView has no accessibility violations', async () => {
    pathnameMock.mockReturnValue('/settings');
    const { SettingsView } = await import('@/components/settings/SettingsView');
    const { container } = render(
      <ThemeProvider>
        <SettingsView />
      </ThemeProvider>,
    );
    assertRenderedSomething(container, 'SettingsView');
    const results = await axe(container, axeOptions);
    expect(results).toHaveNoViolations();
  });

  it('CopilotDock (collapsed) has no accessibility violations', async () => {
    pathnameMock.mockReturnValue('/dashboard');
    const { container } = render(
      <ThemeProvider>
        <CopilotDock />
      </ThemeProvider>,
    );
    const results = await axe(container, axeOptions);
    expect(results).toHaveNoViolations();
  });
});
