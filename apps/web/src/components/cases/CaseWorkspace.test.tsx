import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import type { Case } from '@/lib/api';

// We mock SWR rather than the real network layer so the test stays
// hermetic and so we can exercise both the loaded and fallback paths.
const swrState = vi.hoisted(() => ({
  data: undefined as Case | undefined,
  error: undefined as Error | undefined,
}));

vi.mock('swr', () => ({
  __esModule: true,
  default: () => ({
    data: swrState.data,
    error: swrState.error,
    isLoading: !swrState.data && !swrState.error,
    mutate: vi.fn(async () => undefined),
  }),
}));

vi.mock('next/link', () => ({
  __esModule: true,
  default: ({ children, href, ...rest }: { children: React.ReactNode; href: string }) => (
    <a href={href} {...rest}>
      {children}
    </a>
  ),
}));

vi.mock('next/navigation', () => ({
  useSearchParams: () => new URLSearchParams(),
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
  assignee: 'sasha.lin@aisoc.dev',
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
    swrState.data = fakeCase;
    swrState.error = undefined;
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
    swrState.data = undefined;
    swrState.error = new Error('fetch failed');

    render(<CaseWorkspace caseId="INC-001" />);

    // Falls back to buildDemoCase, so the demo title renders…
    expect(
      screen.getByRole('heading', { level: 1, name: /lateral movement from finance subnet/i }),
    ).toBeInTheDocument();

    // …and the demo-mode banner is visible so the analyst knows it's not live data.
    expect(screen.getByText(/demo data — backend offline/i)).toBeInTheDocument();
  });
});
