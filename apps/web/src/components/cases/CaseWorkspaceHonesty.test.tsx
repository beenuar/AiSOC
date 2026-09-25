/**
 * Data-honesty gate for the case workspace.
 *
 * Three separate ways this screen published invented incident state, all of
 * them reachable on any deployment whose backend was merely unreachable:
 *
 *   1. `const useFallback = !!error` — no demo gate at all. A failed case load
 *      rendered `buildDemoCase(caseId)`, which takes its id from the route
 *      param, so the fabrication presented *as the case the analyst opened*:
 *      a title, an assignee, four linked alert ids, three ATT&CK techniques
 *      and a five-event timeline including "Auto-investigation completed".
 *
 *   2. A failed `casesApi.investigate` was caught and turned into
 *      `status: 'completed'` with invented recon IOCs, a forensic root cause
 *      at 0.88 confidence drawn as a progress bar, three containment actions
 *      and a four-entry agent audit log. The structured panels carried no
 *      caveat — only a transient toast, which is gone by the time anyone
 *      reads the verdict.
 *
 *   3. `updateStatus` mutated the SWR cache optimistically and, on failure,
 *      toasted "writes disabled" without rolling back — so the workspace
 *      showed a status the database did not have.
 *
 * These assert the negative (no fabricated string reaches the DOM) plus the
 * positive half that stops the fix becoming "render nothing": the demo build
 * is still populated, and a real case still renders.
 */

import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { __setDemoModeForTests } from '@/lib/demoMode';
import type { Case } from '@/lib/api';

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

const casesApi = vi.hoisted(() => ({
  get: vi.fn(),
  update: vi.fn(),
  investigate: vi.fn(),
  getInvestigation: vi.fn(),
  addComment: vi.fn(),
  addTask: vi.fn(),
  updateTask: vi.fn(),
  openAutoSummaryHtml: vi.fn(),
  downloadReportPdf: vi.fn(),
  getAttackChain: vi.fn(),
}));

vi.mock('@/lib/api', () => ({
  __esModule: true,
  casesApi,
  graphApi: { getCaseAttackPath: vi.fn() },
  realtimeApi: { ticket: vi.fn().mockRejectedValue(new Error('no ticket')) },
}));

vi.mock('next/link', () => ({
  __esModule: true,
  default: ({ children, href }: { children: React.ReactNode; href: string }) => (
    <a href={href}>{children}</a>
  ),
}));

vi.mock('next/navigation', () => ({
  __esModule: true,
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn() }),
  usePathname: () => '/cases/INC-2026-0042',
  useSearchParams: () => new URLSearchParams(),
}));

// Both are exercised by their own suites and each opens its own requests.
vi.mock('./InvestigationLedger', () => ({
  __esModule: true,
  InvestigationLedger: () => null,
}));

vi.mock('@/components/copilot/ContextualActions', () => ({
  __esModule: true,
  ContextualActions: () => null,
}));

import { CaseWorkspace } from './CaseWorkspace';

/** The route param. `buildDemoCase` copied it, so the invention wore this id. */
const CASE_ID = 'INC-2026-0042';

const SWR_KEY = JSON.stringify(['case', CASE_ID]);

/** Every string `buildDemoCase()` would put on screen. */
const FABRICATED_CASE_STRINGS = [
  'Suspected lateral movement from finance subnet',
  'WIN-FIN-DB01',
  'BACKUP-SRV-12',
  'sasha.lin',
  'alert-9012',
  'alert-9024',
  'T1021.002',
  'Auto-investigation completed',
  'Rotate svc_backup credentials',
  'lateral-movement',
];

/** Every string the investigate `catch` block would put on screen. */
const FABRICATED_INVESTIGATION_STRINGS = [
  '192.168.1.105',
  'c2.evil-corp.io',
  'Compromised svc_backup service account used for lateral movement.',
  '88% confidence',
  'Isolate WIN-FIN-DB01',
  'Block C2 domain at perimeter',
  'ReconAgent',
  'ForensicAgent',
];

function expectNoFabrication(names: string[]) {
  for (const name of names) {
    expect(
      document.body.textContent ?? '',
      `"${name}" is fabricated case data and must not render outside demo mode`,
    ).not.toContain(name);
  }
}

/** A real case, as the API would return it. */
function realCase(overrides: Partial<Case> = {}): Case {
  return {
    id: CASE_ID,
    title: 'Unusual sign-in from an unrecognised ASN',
    description: 'One failed conditional-access challenge followed by a success.',
    status: 'open',
    severity: 'medium',
    alertIds: [],
    alertCount: 0,
    tags: [],
    mitre: [],
    createdBy: 'system',
    createdAt: '2026-05-06T09:00:00Z',
    updatedAt: '2026-05-06T09:05:00Z',
    timeline: [],
    tasks: [],
    ...overrides,
  } as Case;
}

beforeEach(() => {
  swrData.clear();
  swrErrors.clear();
  swrMutate.mockClear();
  for (const fn of Object.values(casesApi)) fn.mockReset();
  __setDemoModeForTests(false);
});

afterEach(() => {
  cleanup();
  __setDemoModeForTests(null);
});

describe('a failed case load does not invent the case', () => {
  it('renders an error naming the failure, not a fabricated incident', () => {
    swrErrors.set(SWR_KEY, new Error('503 Service Unavailable'));

    render(<CaseWorkspace caseId={CASE_ID} />);

    expectNoFabrication(FABRICATED_CASE_STRINGS);
    expect(screen.getByText(/Couldn't load case/i)).toBeTruthy();
    expect(screen.getByText(/503 Service Unavailable/i)).toBeTruthy();
  });

  it('offers a retry that re-issues the request', async () => {
    swrErrors.set(SWR_KEY, new Error('network down'));

    render(<CaseWorkspace caseId={CASE_ID} />);
    await userEvent.click(screen.getByRole('button', { name: /retry/i }));

    expect(swrMutate).toHaveBeenCalled();
  });

  it('still shows the seeded case in the hosted demo', () => {
    // The gate must not have become "never show sample data anywhere".
    __setDemoModeForTests(true);
    swrErrors.set(SWR_KEY, new Error('no backend in the demo'));

    render(<CaseWorkspace caseId={CASE_ID} />);

    expect(screen.getByText('Suspected lateral movement from finance subnet')).toBeTruthy();
  });
});

describe('a failed investigation is not reported as a completed one', () => {
  it('surfaces the failure instead of inventing IOCs and a root cause', async () => {
    swrData.set(SWR_KEY, realCase());
    casesApi.investigate.mockRejectedValue(new Error('agents service unreachable'));

    render(<CaseWorkspace caseId={CASE_ID} />);
    await userEvent.click(screen.getByRole('button', { name: /investigate with agent/i }));

    await waitFor(() => {
      expect(screen.getByText(/Investigation failed/i)).toBeTruthy();
    });
    expectNoFabrication(FABRICATED_INVESTIGATION_STRINGS);
    expect(screen.getByText(/agents service unreachable/i)).toBeTruthy();
  });

  it('does not claim the investigation completed', async () => {
    swrData.set(SWR_KEY, realCase());
    casesApi.investigate.mockRejectedValue(new Error('502 Bad Gateway'));

    render(<CaseWorkspace caseId={CASE_ID} />);
    await userEvent.click(screen.getByRole('button', { name: /investigate with agent/i }));

    await waitFor(() => {
      expect(screen.getByText(/Investigation failed/i)).toBeTruthy();
    });
    expect(screen.queryByText(/Investigation complete/i)).toBeNull();
    expect(screen.queryByText(/View full report/i)).toBeNull();
  });

  it('writes no report for an investigation that never ran', async () => {
    swrData.set(SWR_KEY, realCase());
    casesApi.investigate.mockRejectedValue(new Error('down'));

    render(<CaseWorkspace caseId={CASE_ID} />);
    await userEvent.click(screen.getByRole('button', { name: /investigate with agent/i }));
    await waitFor(() => {
      expect(screen.getByText(/Investigation failed/i)).toBeTruthy();
    });

    await userEvent.click(screen.getByRole('button', { name: /^report$/i }));

    expect(screen.getByText(/No report yet/i)).toBeTruthy();
    expect(screen.queryByText(/Incident Report — /i)).toBeNull();
  });
});

describe('a rejected status write does not stick in the UI', () => {
  it('rolls the optimistic mutation back when the API refuses it', async () => {
    swrData.set(SWR_KEY, realCase({ status: 'open' }));
    casesApi.update.mockRejectedValue(new Error('403 Forbidden'));

    render(<CaseWorkspace caseId={CASE_ID} />);
    await userEvent.selectOptions(screen.getByRole('combobox'), 'resolved');

    await waitFor(() => {
      expect(casesApi.update).toHaveBeenCalled();
    });

    // The last mutate call has to restore the status the server still holds.
    // Before the fix the only mutate was the optimistic one, so the workspace
    // sat on `resolved` for a case the database still had as `open`.
    await waitFor(() => {
      const restored = swrMutate.mock.calls.at(-1)?.[0] as Case | undefined;
      expect(restored?.status, 'the rejected write must be rolled back').toBe('open');
    });
  });

  it('keeps the write when the API accepts it', async () => {
    swrData.set(SWR_KEY, realCase({ status: 'open' }));
    casesApi.update.mockResolvedValue(realCase({ status: 'resolved' }));

    render(<CaseWorkspace caseId={CASE_ID} />);
    await userEvent.selectOptions(screen.getByRole('combobox'), 'resolved');

    await waitFor(() => {
      expect(casesApi.update).toHaveBeenCalled();
    });
    const last = swrMutate.mock.calls.at(-1)?.[0] as Case | undefined;
    expect(last?.status).toBe('resolved');
  });
});
