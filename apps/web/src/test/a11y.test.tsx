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
        <TopBar />
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
