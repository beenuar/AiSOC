/**
 * What `/detection` is allowed to say about rules it cannot see.
 *
 * Issue #1273: the page rendered "No detection rules yet" on a stack loading
 * and firing 2,586 of them. The sentence was the damage — an operator reading
 * it concludes their coverage is zero and stops looking, which is worse than
 * an error.
 *
 * Three properties are pinned here, and all three are about the **first
 * paint** rather than about an error branch. A view that fabricates does it
 * in the render path, so asserting only on the error branch grades the one
 * place the defect was not.
 *
 *   1. With the compiled corpus loaded, the rules render and the counts are
 *      the server's — not a client-side length that silently becomes the
 *      page size.
 *   2. With `catalogError` set, the page says the library could not be read
 *      and repeats the reason. It must not say there are no rules.
 *   3. With some artefacts missing, the page names them rather than
 *      publishing the smaller total as though it were the whole corpus.
 */

import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import type { DetectionRule, DetectionRuleListResult } from '@/lib/api';

const swrState = vi.hoisted(() => ({
  data: undefined as DetectionRuleListResult | undefined,
  error: undefined as Error | undefined,
  isLoading: false,
}));

vi.mock('swr', () => ({
  __esModule: true,
  default: () => ({
    data: swrState.data,
    error: swrState.error,
    isLoading: swrState.isLoading,
    mutate: vi.fn(),
  }),
}));

vi.mock('react-hot-toast', () => ({
  __esModule: true,
  default: Object.assign(vi.fn(), { success: vi.fn(), error: vi.fn() }),
}));

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<Record<string, unknown>>('@/lib/api');
  return {
    ...actual,
    detectionApi: { list: vi.fn(), update: vi.fn(), bulkToggle: vi.fn() },
  };
});

// The sibling panels each open their own SWR subscription; they are not what
// this file is about.
vi.mock('./ContributorLeaderboard', () => ({
  ContributorLeaderboard: () => null,
}));
vi.mock('./MitreRuleHeatmap', () => ({ MitreRuleHeatmap: () => null }));
vi.mock('./ConfidenceTrends', () => ({ ConfidenceTrends: () => null }));
vi.mock('./DriftInbox', () => ({ DriftInbox: () => null }));

import { DetectionsView } from './DetectionsView';

function builtin(id: string, name: string): DetectionRule {
  return {
    id,
    name,
    language: 'aisoc-match',
    body: '{}',
    enabled: true,
    severity: 'high',
    createdAt: '2026-10-01T00:00:00Z',
    updatedAt: '2026-10-01T00:00:00Z',
    isBuiltin: true,
    sourceId: `det-${id}`,
    tuned: false,
    timestampsFromArtefact: true,
  };
}

function page(
  overrides: Partial<DetectionRuleListResult> = {},
): DetectionRuleListResult {
  return {
    rules: [builtin('a', 'SQL Injection Attempt in HTTP Query')],
    total: 2586,
    builtinTotal: 2586,
    customTotal: 0,
    returned: 1,
    offset: 0,
    limit: 50,
    catalogError: null,
    missingArtefacts: [],
    ...overrides,
  };
}

beforeEach(() => {
  swrState.data = undefined;
  swrState.error = undefined;
  swrState.isLoading = false;
});

describe('the rule library on first paint', () => {
  it('states the library size from the server, not the page length', () => {
    swrState.data = page();
    render(<DetectionsView />);

    expect(
      screen.getByText('SQL Injection Attempt in HTTP Query'),
    ).toBeInTheDocument();
    // One rule is on this page; 2,586 are in the library. Rendering the page
    // length as the total is how a bounded list starts under-reporting.
    expect(screen.getByText(/2,586 in the library/)).toBeInTheDocument();
    expect(
      screen.queryByText(/No detection rules yet/i),
    ).not.toBeInTheDocument();
  });

  it('labels a rule the engine runs, and shows the id an alert carries', () => {
    swrState.data = page();
    render(<DetectionsView />);

    expect(screen.getByText('Built-in')).toBeInTheDocument();
    expect(screen.getByText('det-a')).toBeInTheDocument();
  });

  it('reports an unreadable corpus as unreadable, never as empty', () => {
    swrState.data = page({
      rules: [],
      total: 0,
      builtinTotal: 0,
      returned: 0,
      catalogError:
        'no compiled detection ruleset could be read. Looked for /app/app/data/detections/detection_ruleset.json',
    });
    render(<DetectionsView />);

    expect(
      screen.getByText(/could not be read/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/detection_ruleset\.json/),
    ).toBeInTheDocument();
    // The engine is still firing these rules. "No detection rules yet" here
    // is the single most misleading sentence the page can print.
    expect(
      screen.queryByText(/No detection rules yet/i),
    ).not.toBeInTheDocument();
  });

  it('names a partially missing corpus rather than publishing the short total', () => {
    swrState.data = page({
      total: 2583,
      builtinTotal: 2583,
      missingArtefacts: ['windowed_builtin_rules.json'],
    });
    render(<DetectionsView />);

    expect(
      screen.getByText(/windowed_builtin_rules\.json/),
    ).toBeInTheDocument();
    expect(screen.getByText(/incomplete/i)).toBeInTheDocument();
  });

  it('still says "no rules yet" when the library really is empty', () => {
    swrState.data = page({
      rules: [],
      total: 0,
      builtinTotal: 0,
      customTotal: 0,
      returned: 0,
    });
    render(<DetectionsView />);

    expect(screen.getByText('No detection rules yet')).toBeInTheDocument();
  });
});
