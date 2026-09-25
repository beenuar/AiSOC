/**
 * Data-honesty gate for the coverage advisor.
 *
 * The page was fabricated end to end: no API call at all, and a module-scope
 * `TECHNIQUES` array of fifteen invented ATT&CK verdicts whose recommendation
 * column asserted deployment state the component could not know — "Existing
 * PowerShell & Bash rules active", "Ransomware canary files active". The four
 * headline cards were computed from that array, so "Coverage 50%" and
 * "Critical Gaps 5" were byte-identical on every deployment. Its only button
 * raised `toast.success('Detection rule draft created')` and created nothing.
 *
 * It now reads `GET /api/v1/detection/coverage`, the same endpoint the MITRE
 * heatmap and the operations panel already use, which reports per-technique
 * rule counts for the tenant's own corpus.
 *
 * The endpoint only returns techniques that have at least one rule, so the
 * page cannot speak about techniques with no rule at all. Saying so is part
 * of the contract: a "100% covered" headline over a corpus of three rules
 * would be the same class of false claim the invented table was.
 */

import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { axe } from 'vitest-axe';
import { __setDemoModeForTests } from '@/lib/demoMode';
import type { DetectionCoverage } from '@/lib/api';

const swrData = vi.hoisted(() => new Map<string, unknown>());
const swrErrors = vi.hoisted(() => new Map<string, unknown>());
const swrMutate = vi.hoisted(() => vi.fn());

vi.mock('swr', () => ({
  __esModule: true,
  default: (key: unknown) => {
    const k = typeof key === 'string' ? key : JSON.stringify(key);
    return {
      data: swrData.get(k),
      error: swrErrors.get(k),
      isLoading: false,
      mutate: swrMutate,
    };
  },
}));

const detectionApi = vi.hoisted(() => ({ coverage: vi.fn() }));

vi.mock('@/lib/api', () => ({
  __esModule: true,
  detectionApi,
}));

vi.mock('next/link', () => ({
  __esModule: true,
  default: ({ children, href }: { children: React.ReactNode; href: string }) => (
    <a href={href}>{children}</a>
  ),
}));

import CoverageAdvisorView from './CoverageAdvisorView';

const COVERAGE_KEY = 'coverage-advisor';

/** Strings the invented `TECHNIQUES` table would put on screen. */
const FABRICATED_STRINGS = [
  'Existing PowerShell & Bash rules active',
  'ScriptBlock logging rule deployed',
  'Deploy schtasks / cron anomaly detection',
  'Ransomware canary files active',
  'Rate-limit rules deployed across tenants',
  'Add entropy-based payload analysis',
  'Monitor DNS/ICMP tunneling patterns',
  'WAF log correlation with CVE feeds',
];

function expectNoFabrication() {
  for (const name of FABRICATED_STRINGS) {
    expect(
      document.body.textContent ?? '',
      `"${name}" asserts deployment state the component cannot know`,
    ).not.toContain(name);
  }
}

function coverage(overrides: Partial<DetectionCoverage> = {}): DetectionCoverage {
  return {
    tactics: ['Execution', 'Persistence'],
    cells: [
      {
        techniqueId: 'T1059',
        tactic: 'Execution',
        techniqueName: null,
        totalRules: 3,
        activeRules: 3,
        inactiveRules: 0,
      },
      {
        techniqueId: 'T1053',
        tactic: 'Persistence',
        techniqueName: null,
        totalRules: 2,
        activeRules: 0,
        inactiveRules: 2,
      },
    ],
    summary: {
      totalRules: 5,
      activeRules: 3,
      inactiveRules: 2,
      techniques: 2,
      coveredTechniques: 1,
    },
    generatedAt: '2026-05-06T12:00:00Z',
    ...overrides,
  };
}

beforeEach(() => {
  swrData.clear();
  swrErrors.clear();
  swrMutate.mockClear();
  detectionApi.coverage.mockReset();
  __setDemoModeForTests(false);
});

afterEach(() => {
  cleanup();
  __setDemoModeForTests(null);
});

describe('the coverage advisor reads the tenant corpus', () => {
  it('calls the coverage endpoint rather than rendering a baked-in table', () => {
    swrData.set(COVERAGE_KEY, coverage());

    render(<CoverageAdvisorView />);

    expectNoFabrication();
    // The real corpus, not the invented one.
    expect(screen.getByText('T1059')).toBeTruthy();
    expect(screen.getByText('T1053')).toBeTruthy();
  });

  it('derives the headline figures from the API summary', () => {
    swrData.set(COVERAGE_KEY, coverage());

    render(<CoverageAdvisorView />);

    // 1 of 2 techniques has an enabled rule.
    expect(screen.getByText('1 / 2')).toBeTruthy();
    // Neither of the invented headline numbers.
    expect(screen.queryByText('50%')).toBeNull();
    expect(screen.queryByText('5')).toBeNull();
  });

  it('says which techniques the endpoint cannot see', () => {
    swrData.set(COVERAGE_KEY, coverage());

    render(<CoverageAdvisorView />);

    // A technique with no rule never appears in `cells`, so a coverage
    // percentage over `cells` is not coverage of ATT&CK.
    expect(screen.getByText(/no rule at all do not appear/i)).toBeTruthy();
  });
});

describe('the coverage advisor is honest when it has nothing', () => {
  it('publishes no figures before the API has answered', () => {
    render(<CoverageAdvisorView />);

    expectNoFabrication();
    expect(screen.queryByText('50%')).toBeNull();
  });

  it('names the failure and offers a retry that re-issues the request', async () => {
    const { default: userEvent } = await import('@testing-library/user-event');
    swrErrors.set(COVERAGE_KEY, new Error('HTTP 503'));

    render(<CoverageAdvisorView />);

    expectNoFabrication();
    expect(screen.getByText(/HTTP 503/i)).toBeTruthy();
    await userEvent.click(screen.getByRole('button', { name: /retry/i }));
    expect(swrMutate).toHaveBeenCalled();
  });

  it('reads a tenant with no rules as empty', () => {
    swrData.set(
      COVERAGE_KEY,
      coverage({
        cells: [],
        tactics: [],
        summary: {
          totalRules: 0,
          activeRules: 0,
          inactiveRules: 0,
          techniques: 0,
          coveredTechniques: 0,
        },
      }),
    );

    render(<CoverageAdvisorView />);

    expectNoFabrication();
    expect(screen.getByText(/No detection rules/i)).toBeTruthy();
  });
});

describe('every control does what it says', () => {
  it('offers no button that reports work it did not do', () => {
    swrData.set(COVERAGE_KEY, coverage());

    render(<CoverageAdvisorView />);

    // `toast.success('Detection rule draft created for …')` created nothing.
    expect(screen.queryAllByRole('button', { name: /generate detection/i })).toHaveLength(0);
  });

  it('links an unenforced technique to the rules that are switched off', () => {
    swrData.set(COVERAGE_KEY, coverage());

    render(<CoverageAdvisorView />);

    // T1053 has two rules and none enabled — the actionable case.
    const link = screen.getByRole('link', { name: /2 rules? disabled/i });
    expect(link.getAttribute('href')).toContain('/detection');
  });
});

describe('accessibility', () => {
  // The page was rebuilt around new states, and the repo gates WCAG AA with
  // axe-core. Heading order is the rule most easily broken by adding one:
  // the error and empty branches sit between the `h1` and the table's `h2`.
  it.each([
    ['populated', () => coverage()],
    ['empty', () => coverage({ cells: [], tactics: [], summary: { totalRules: 0, activeRules: 0, inactiveRules: 0, techniques: 0, coveredTechniques: 0 } })],
  ])('has no violations in the %s state', async (_label, build) => {
    swrData.set(COVERAGE_KEY, build());

    const { container } = render(<CoverageAdvisorView />);

    expect(await axe(container, { rules: { 'color-contrast': { enabled: false } } })).toHaveNoViolations();
  });

  it('has no violations in the error state', async () => {
    swrErrors.set(COVERAGE_KEY, new Error('HTTP 503'));

    const { container } = render(<CoverageAdvisorView />);

    expect(await axe(container, { rules: { 'color-contrast': { enabled: false } } })).toHaveNoViolations();
  });
});
