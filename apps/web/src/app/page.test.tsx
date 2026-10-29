/**
 * The root of a self-hosted install must land an operator on their console.
 *
 * Discussion #1549: a clean server's `/` rendered the project's marketing
 * landing page — neither the dashboard nor the login page the operator was
 * looking for. The default is now a redirect to `/login` (which routes
 * onward: first run → onboarding, an authenticated session → `/dashboard`),
 * and the marketing landing renders only when the deployment opts in as the
 * public project site.
 *
 * Both directions are pinned, because a one-sided suite would pass equally
 * well on a tree that deleted the marketing page outright — and the page is
 * still the project site's homepage when asked for.
 *
 * `HomePage()` is called as a plain function: in console mode the redirect
 * throws before any JSX exists, and in marketing mode the returned element
 * tree is lazy, so none of the section components execute. That keeps this
 * test independent of every landing section.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';

const redirectMock = vi.hoisted(() =>
  vi.fn((target: string): never => {
    throw new Error(`NEXT_REDIRECT:${target}`);
  }),
);

vi.mock('next/navigation', () => ({
  __esModule: true,
  redirect: redirectMock,
}));

// `next/font/google` executes only under the Next compiler, and the four
// eagerly-imported sections are client components this test never renders
// (the dynamic ones are already lazy). Same pattern as not-found.test.tsx.
vi.mock('@/lib/marketing-fonts', () => ({ __esModule: true, velvetFontVariables: '' }));
vi.mock('@/components/landing/sections/StickyNav', () => ({ __esModule: true, StickyNav: () => null }));
vi.mock('@/components/landing/sections/Hero', () => ({ __esModule: true, Hero: () => null }));
vi.mock('@/components/landing/sections/ProofStrip', () => ({ __esModule: true, ProofStrip: () => null }));
vi.mock('@/components/landing/sections/Problem', () => ({ __esModule: true, Problem: () => null }));

import HomePage, { dynamic as routeDynamic } from './page';
import { __setMarketingHomeForTests, homeRouteReport } from '@/lib/homeRoute';

afterEach(() => {
  __setMarketingHomeForTests(null);
  vi.unstubAllEnvs();
  redirectMock.mockClear();
});

describe('the root route of a self-hosted install', () => {
  it('redirects to /login by default', () => {
    expect(() => HomePage()).toThrowError('NEXT_REDIRECT:/login');
    expect(redirectMock).toHaveBeenCalledWith('/login');
  });

  it('still redirects when the runtime flag is explicitly off', () => {
    vi.stubEnv('AISOC_MARKETING_HOME', 'false');
    expect(() => HomePage()).toThrowError('NEXT_REDIRECT:/login');
  });

  it('renders the marketing landing when the running container opts in', () => {
    vi.stubEnv('AISOC_MARKETING_HOME', 'true');
    const element = HomePage();
    expect(element).toBeTruthy();
    expect(redirectMock).not.toHaveBeenCalled();
  });

  it('is force-dynamic, so the answer comes from the container on every request', () => {
    // Statically optimised, the build machine's environment would be compiled
    // into the route and a pulled image could never be steered — the defect
    // class runtime-over-build exists to avoid.
    expect(routeDynamic).toBe('force-dynamic');
  });
});

describe('homeRouteReport', () => {
  it('defaults to the console and says so', () => {
    expect(homeRouteReport()).toEqual({ marketing: false, source: 'default' });
  });

  it('runtime value outranks the build-time value, in both directions', () => {
    vi.stubEnv('NEXT_PUBLIC_MARKETING_HOME', 'true');
    expect(homeRouteReport()).toEqual({ marketing: true, source: 'build' });

    vi.stubEnv('AISOC_MARKETING_HOME', 'false');
    expect(homeRouteReport()).toEqual({ marketing: false, source: 'runtime' });

    vi.stubEnv('AISOC_MARKETING_HOME', 'true');
    vi.stubEnv('NEXT_PUBLIC_MARKETING_HOME', 'false');
    expect(homeRouteReport()).toEqual({ marketing: true, source: 'runtime' });
  });

  it('reads the environment on every call rather than caching the first answer', () => {
    vi.stubEnv('AISOC_MARKETING_HOME', 'true');
    expect(homeRouteReport().marketing).toBe(true);
    vi.stubEnv('AISOC_MARKETING_HOME', 'false');
    expect(homeRouteReport().marketing).toBe(false);
  });
});
