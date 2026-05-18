import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import type { AttackChainTimeline, Case } from '@/lib/api';

// We mock SWR rather than the real network layer so the test stays
// hermetic and so we can exercise both the loaded and fallback paths.
// The mock is key-aware so different panels in the workspace (the case
// header vs the attack-chain panel) can return different shapes.
const swrState = vi.hoisted(() => ({
  caseData: undefined as Case | undefined,
  caseError: undefined as Error | undefined,
  attackChainData: undefined as AttackChainTimeline | null | undefined,
  attackChainError: undefined as Error | undefined,
  attackChainLoading: false,
}));

function isAttackChainKey(key: unknown): boolean {
  if (Array.isArray(key)) return key[0] === 'case:attack-chain';
  return false;
}

function isAttackPathKey(key: unknown): boolean {
  return typeof key === 'string' && key.startsWith('case:') && key.endsWith(':attack-path');
}

vi.mock('swr', () => ({
  __esModule: true,
  default: (key: unknown) => {
    if (isAttackChainKey(key)) {
      return {
        data: swrState.attackChainData,
        error: swrState.attackChainError,
        isLoading:
          swrState.attackChainLoading ||
          (swrState.attackChainData === undefined && !swrState.attackChainError),
        mutate: vi.fn(async () => undefined),
      };
    }
    if (isAttackPathKey(key)) {
      // We don't exercise the attack-path tab in these tests; return an
      // empty resolved state so it doesn't show a phantom loading skeleton.
      return {
        data: null,
        error: undefined,
        isLoading: false,
        mutate: vi.fn(async () => undefined),
      };
    }
    // Default: case workspace fetch.
    return {
      data: swrState.caseData,
      error: swrState.caseError,
      isLoading: !swrState.caseData && !swrState.caseError,
      mutate: vi.fn(async () => undefined),
    };
  },
}));

vi.mock('next/link', () => ({
  __esModule: true,
  default: ({ children, href, ...rest }: { children: React.ReactNode; href: string }) => (
    <a href={href} {...rest}>
      {children}
    </a>
  ),
}));

const searchParamsState = vi.hoisted(() => ({ params: new URLSearchParams() }));

vi.mock('next/navigation', () => ({
  useSearchParams: () => searchParamsState.params,
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  usePathname: () => '/cases/INC-001',
}));

vi.mock('react-hot-toast', () => {
  const fn = vi.fn();
  // react-hot-toast exports both `toast()` and `toast.success/error`; mirror that.
  return {
    __esModule: true,
    default: Object.assign(fn, {
      success: vi.fn(),
      error: vi.fn(),
      loading: vi.fn(),
    }),
    toast: Object.assign(fn, {
      success: vi.fn(),
      error: vi.fn(),
      loading: vi.fn(),
    }),
    Toaster: () => null,
  };
});

// Stub the heavy children — they have their own SWR + WS deps and are
// not what we're smoke-testing here.
vi.mock('./InvestigationLedger', () => ({
  InvestigationLedger: () => <div data-testid="investigation-ledger" />,
}));

vi.mock('@/components/copilot/ContextualActions', () => ({
  ContextualActions: () => <div data-testid="contextual-actions" />,
}));

import { CaseWorkspace } from './CaseWorkspace';

const fakeCase: Case = {
  id: 'INC-001',
  title: 'Suspected lateral movement from finance subnet',
  description: 'Multiple high-severity alerts indicate a pivot via SMB.',
  status: 'in_progress',
  severity: 'critical',
  assignee: 'sasha.lin@example.com',
  tags: ['lateral-movement'],
  mitre: ['T1021.002', 'T1078'],
  alertIds: ['alert-1'],
  alertCount: 1,
  createdBy: 'system',
  createdAt: new Date(Date.now() - 60_000).toISOString(),
  updatedAt: new Date(Date.now() - 30_000).toISOString(),
  timeline: [],
  tasks: [],
};

describe('CaseWorkspace', () => {
  beforeEach(() => {
    swrState.caseData = fakeCase;
    swrState.caseError = undefined;
    swrState.attackChainData = undefined;
    swrState.attackChainError = undefined;
    swrState.attackChainLoading = false;
    searchParamsState.params = new URLSearchParams();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('renders the case header with title, severity, and MITRE chips', () => {
    render(<CaseWorkspace caseId="INC-001" />);

    expect(
      screen.getByRole('heading', { level: 1, name: /lateral movement from finance subnet/i }),
    ).toBeInTheDocument();
    expect(screen.getByText('critical')).toBeInTheDocument();

    // MITRE techniques should render as outbound links to attack.mitre.org.
    const t1021 = screen.getByRole('link', { name: /T1021\.002/ });
    expect(t1021).toHaveAttribute('href', 'https://attack.mitre.org/techniques/T1021/002/');
    expect(screen.getByRole('link', { name: /T1078/ })).toHaveAttribute(
      'href',
      'https://attack.mitre.org/techniques/T1078/',
    );
  });

  it('shows the demo banner when the backend errors out', () => {
    swrState.caseData = undefined;
    swrState.caseError = new Error('fetch failed');

    render(<CaseWorkspace caseId="INC-001" />);

    // Falls back to buildDemoCase, so the demo title renders…
    expect(
      screen.getByRole('heading', { level: 1, name: /lateral movement from finance subnet/i }),
    ).toBeInTheDocument();

    // …and the demo-mode banner is visible so the analyst knows it's not live data.
    expect(screen.getByText(/demo data — writes disabled/i)).toBeInTheDocument();
  });

  describe('attack-chain panel', () => {
    beforeEach(() => {
      // Force the attack-chain tab to render by setting ?tab=attack-chain.
      searchParamsState.params = new URLSearchParams('tab=attack-chain');
    });

    it('renders an empty state when the backend returns no chain', () => {
      swrState.attackChainData = null;

      render(<CaseWorkspace caseId="INC-001" />);

      expect(screen.getByText(/no attack chain yet/i)).toBeInTheDocument();
    });

    it('renders an error state when the chain request fails', () => {
      swrState.attackChainData = undefined;
      swrState.attackChainError = new Error('boom');

      render(<CaseWorkspace caseId="INC-001" />);

      expect(screen.getByText(/failed to load attack chain/i)).toBeInTheDocument();
    });

    it('renders chain links, confidence, and entity summary when data is loaded', () => {
      const now = new Date('2026-05-15T00:00:00Z').toISOString();
      const timeline: AttackChainTimeline = {
        caseId: 'INC-001',
        tenantId: 'tenant-1',
        window: '24h',
        seedAlertId: 'alert-seed',
        chainSignature: 'sig-xyz',
        confidence: 0.82,
        generatedAt: now,
        chain: [
          {
            alertId: 'alert-seed',
            title: 'Seed — Suspicious PowerShell on FIN-WS-01',
            severity: 'critical',
            eventTime: now,
            score: 1.0,
            distance: 0,
            dtSeconds: 0,
            sharedEntities: [],
            mitreTechniques: ['T1059.001'],
            connectorType: 'edr',
            sourceEventIds: ['evt-1'],
          },
          {
            alertId: 'alert-2',
            title: 'Lateral SMB session to FIN-DB-02',
            severity: 'high',
            eventTime: new Date('2026-05-15T00:05:00Z').toISOString(),
            score: 0.74,
            distance: 1,
            dtSeconds: 300,
            sharedEntities: [{ kind: 'user', value: 'svc-finance' }],
            mitreTechniques: ['T1021.002'],
            connectorType: 'edr',
            sourceEventIds: ['evt-2'],
          },
        ],
        entityGraph: {
          nodes: [
            { id: 'alert-seed', kind: 'alert', severity: 'critical', event_time: now },
            { id: 'alert-2', kind: 'alert', severity: 'high' },
            { id: 'user:svc-finance', kind: 'user', label: 'svc-finance' },
          ],
          edges: [{ source: 'alert-seed', target: 'alert-2', kind: 'shares_entity' }],
        },
      };
      swrState.attackChainData = timeline;

      render(<CaseWorkspace caseId="INC-001" />);

      // Both chain links should render.
      expect(screen.getByText(/Seed — Suspicious PowerShell on FIN-WS-01/i)).toBeInTheDocument();
      expect(screen.getByText(/Lateral SMB session to FIN-DB-02/i)).toBeInTheDocument();

      // Confidence is surfaced as a percentage to the analyst.
      expect(screen.getByText(/82%/)).toBeInTheDocument();

      // MITRE techniques from the chain should be visible.
      expect(screen.getByText('T1059.001')).toBeInTheDocument();
      expect(screen.getByText('T1021.002')).toBeInTheDocument();
    });

    it('honors the ?window=… deep link on first render', () => {
      // Regression for PR #145 review: the changelog claims the window
      // selection survives reload via ?window=…. Mount with both the
      // tab AND window params set, and assert the WindowSelector is
      // showing the linked value rather than the default `24h`.
      searchParamsState.params = new URLSearchParams('tab=attack-chain&window=72h');
      swrState.attackChainData = null;

      render(<CaseWorkspace caseId="INC-001" />);

      // The window selector must show 72h as the active choice. Since
      // `WindowSelector value={windowParam}` is bound directly to the
      // panel state, the selector reading 72h proves the URL value
      // flowed through `initialWindow` into the state — which in turn
      // is what SWR keys the fetch on.
      const selector = screen.getByLabelText(/attack chain time window/i) as HTMLSelectElement;
      expect(selector.value).toBe('72h');
    });

    it('falls back to the 24h default when ?window=… is missing or unknown', () => {
      // Just the tab, no window param → default `24h` (NOT the previous
      // `1h` default the PR shipped with; switched to 24h per review
      // because 1h showed an empty state for most realistic cases).
      searchParamsState.params = new URLSearchParams('tab=attack-chain');
      swrState.attackChainData = null;

      const { unmount } = render(<CaseWorkspace caseId="INC-001" />);
      let selector = screen.getByLabelText(/attack chain time window/i) as HTMLSelectElement;
      expect(selector.value).toBe('24h');
      unmount();

      // An obviously-invalid value must also fall back to the default
      // (defence-in-depth: the type guard refuses anything outside the
      // closed `AttackChainWindow` set), not crash the panel.
      searchParamsState.params = new URLSearchParams('tab=attack-chain&window=900years');
      swrState.attackChainData = null;

      render(<CaseWorkspace caseId="INC-001" />);
      selector = screen.getByLabelText(/attack chain time window/i) as HTMLSelectElement;
      expect(selector.value).toBe('24h');
    });
  });
});
