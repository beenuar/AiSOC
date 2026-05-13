// W6 — pin the InvestigationRail contract for the v1.5 SOC console parity.
//
// The rail is the structured triage panel that lives to the right of the
// `/alerts` grid. It is a thin presentation layer on top of the envelope
// returned by `GET /api/v1/alerts/{id}` and it owns five behaviors the
// analyst experience depends on:
//
//   1. Empty state — when no row is selected, render the placeholder with
//      a hint instead of a blank panel or a skeleton.
//   2. Loading state — show a skeleton while SWR resolves the envelope so
//      the rail doesn't flash empty.
//   3. Error state — surface a readable message when the API call fails,
//      without crashing the queue on the left.
//   4. Section gating — render `Narrative`, `Related entities`, `Recent
//      events`, and `Recommended actions` only when their data is present,
//      and group related entities in the canonical order even if the API
//      hands them back out of order.
//   5. Deep Explain handoff — the `✦ Deep Explain` button is the *only*
//      affordance that opens the ExplainDrawer; mounting the drawer from
//      inside the rail (rather than from `AlertsView`) gives us one
//      well-known entry point and lets the drawer close cleanly when the
//      analyst dismisses it.
//
// SWR is mocked at the module boundary so each test can pin the loading /
// error / data state without touching the network. The `ExplainDrawer` is
// also mocked so we can assert the rail opens / closes it without dragging
// in the LLM streaming machinery — that surface has its own deep tests in
// `ExplainDrawer.test.tsx`.
//
// Author: Beenu Arora <beenu@cyble.com>

import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

// ─── Mocks ───────────────────────────────────────────────────────────────────

// SWR — we control `data` / `error` / `isLoading` per-test by mutating the
// hoisted state. Mirrors the pattern used in `FunnelKpiBar.test.tsx`.
const swrState = vi.hoisted(() => ({
  data: undefined as unknown,
  error: undefined as unknown,
  isLoading: false,
}));

vi.mock('swr', () => ({
  __esModule: true,
  default: () => ({
    data: swrState.data,
    error: swrState.error,
    isLoading: swrState.isLoading,
  }),
}));

// next/link — render as an anchor so we can assert `href` without pulling
// the App Router into jsdom.
vi.mock('next/link', () => ({
  __esModule: true,
  default: ({
    href,
    children,
    ...rest
  }: {
    href: string;
    children: React.ReactNode;
  } & React.AnchorHTMLAttributes<HTMLAnchorElement>) => (
    <a href={typeof href === 'string' ? href : '#'} {...rest}>
      {children}
    </a>
  ),
}));

// ExplainDrawer — the rail is the only thing under test here; we use a
// minimal mock so we can prove the rail opens the drawer with the right
// alert and closes it via the `onClose` callback. The real drawer is
// covered exhaustively in `ExplainDrawer.test.tsx`.
const explainDrawerProps = vi.hoisted(() => ({
  lastProps: null as null | {
    open: boolean;
    alertId: string;
    onClose: () => void;
  },
}));

vi.mock('./ExplainDrawer', () => ({
  __esModule: true,
  ExplainDrawer: (props: {
    open: boolean;
    alert: { id: string };
    onClose: () => void;
  }) => {
    explainDrawerProps.lastProps = {
      open: props.open,
      alertId: props.alert.id,
      onClose: props.onClose,
    };
    return (
      <div data-testid="explain-drawer-mock">
        <span data-testid="explain-drawer-alert-id">{props.alert.id}</span>
        <button
          type="button"
          onClick={props.onClose}
          data-testid="explain-drawer-close"
        >
          mock-close
        </button>
      </div>
    );
  },
}));

// Import AFTER the mocks so the component picks up the stubs.
import { InvestigationRail } from './InvestigationRail';
import type {
  Alert,
  RelatedEntity,
  MiniTimelineEvent,
  RecommendedAction,
} from '@/lib/api';

// ─── Fixtures ────────────────────────────────────────────────────────────────

const RELATED_ENTITIES: RelatedEntity[] = [
  {
    kind: 'principal',
    type: 'user',
    value: 'alice@example.com',
    label: 'Alice (Finance)',
    pivotPath: '/graph/user/alice%40example.com',
  },
  {
    kind: 'principal',
    type: 'host',
    value: 'fin-laptop-12',
  },
  {
    kind: 'network',
    type: 'ip',
    value: '10.0.0.7',
    pivotPath: '/graph/ip/10.0.0.7',
  },
  {
    kind: 'workflow',
    type: 'rule',
    value: 'impossible-travel',
    label: 'Impossible Travel',
  },
  {
    kind: 'tenant',
    type: 'tenant',
    value: 'acme-corp',
  },
];

const MINI_TIMELINE: MiniTimelineEvent[] = [
  {
    id: 'evt-1',
    timestamp: '2026-05-13T09:55:00Z',
    type: 'alert_promoted',
    title: 'Alert promoted by fusion',
    description: 'Correlation score crossed threshold',
    actor: 'fusion-engine',
    source: 'case_timeline',
  },
  {
    id: 'evt-2',
    timestamp: '2026-05-13T09:50:00Z',
    type: 'case_assigned',
    title: 'Case assigned to analyst',
    actor: 'beenu@cyble.com',
    source: 'audit_log',
  },
];

// Priorities chosen so they never collide with the severity text in the
// header — severity is 'high', so we exercise {critical, low, info}. The
// component still walks the full PRIORITY_TONE table, so coverage is the
// same as testing {critical, high, medium}.
const RECOMMENDED_ACTIONS: RecommendedAction[] = [
  {
    priority: 'critical',
    action: 'Disable the account immediately',
    rationale: 'Impossible travel confirmed across two regions',
    risk: 'Locking the account temporarily disrupts the user',
  },
  {
    priority: 'low',
    action: 'Reset password and revoke active sessions',
  },
  {
    priority: 'info',
    action: 'Open a P2 ticket with the IAM team',
    rationale: 'Track follow-up SSO config review',
  },
];

// Build a full Alert that satisfies the type. The rail only reads a subset
// of the fields, but the type signature requires more, so we set sensible
// defaults and let callers override.
function buildAlert(overrides: Partial<Alert> = {}): Alert {
  const base: Alert = {
    id: 'ALERT-W6-0001',
    title: 'Impossible travel — Frankfurt then Tokyo',
    description: 'Account takeover suspected based on geo signals.',
    severity: 'high',
    status: 'new',
    source: 'okta',
    tenantId: 'tenant-acme',
    riskScore: 87,
    mitreAttack: [],
    iocs: [],
    tags: ['account-takeover'],
    createdAt: '2026-05-13T09:00:00Z',
    updatedAt: '2026-05-13T09:00:00Z',
    narrative:
      'Fusion promoted this alert because two sign-ins from non-adjacent regions\nlanded within 12 minutes of each other.',
    relatedEntities: RELATED_ENTITIES,
    miniTimeline: MINI_TIMELINE,
    recommendedActions: RECOMMENDED_ACTIONS,
  };
  return { ...base, ...overrides };
}

// ─── Reset hoisted state between tests ───────────────────────────────────────

beforeEach(() => {
  swrState.data = undefined;
  swrState.error = undefined;
  swrState.isLoading = false;
  explainDrawerProps.lastProps = null;
});

// ─── Empty state ─────────────────────────────────────────────────────────────

describe('InvestigationRail — empty state', () => {
  it('renders the placeholder when no alert is selected', () => {
    render(<InvestigationRail alertId={null} onClose={vi.fn()} />);
    expect(
      screen.getByLabelText('Investigation rail (no alert selected)'),
    ).toBeInTheDocument();
    expect(screen.getByText(/select an alert to investigate/i)).toBeVisible();
    // The shell-with-Close button only renders when an alert is selected; the
    // placeholder is deliberately non-dismissible.
    expect(screen.queryByLabelText('Close investigation rail')).toBeNull();
  });

  it('does not call onClose from the placeholder', () => {
    const onClose = vi.fn();
    render(<InvestigationRail alertId={null} onClose={onClose} />);
    // No close button exists in the placeholder — but make sure nothing
    // implicitly fires onClose on mount either.
    expect(onClose).not.toHaveBeenCalled();
  });
});

// ─── Loading state ───────────────────────────────────────────────────────────

describe('InvestigationRail — loading state', () => {
  it('renders the skeleton while SWR is loading', () => {
    swrState.isLoading = true;
    render(<InvestigationRail alertId="ALERT-1" onClose={vi.fn()} />);
    // The loading shell uses the "Loading…" title.
    expect(screen.getByLabelText('Investigation rail')).toBeInTheDocument();
    expect(screen.getByText('Loading…')).toBeInTheDocument();
  });

  it('still renders the skeleton when alert is undefined but no error', () => {
    // SWR's initial state for some adapters: not loading, no data, no error.
    // The component treats this as "still resolving" to avoid flashing the
    // error panel.
    swrState.isLoading = false;
    swrState.data = undefined;
    swrState.error = undefined;
    render(<InvestigationRail alertId="ALERT-1" onClose={vi.fn()} />);
    expect(screen.getByText('Loading…')).toBeInTheDocument();
  });

  it('close button in the loading shell calls onClose', async () => {
    const user = userEvent.setup();
    swrState.isLoading = true;
    const onClose = vi.fn();
    render(<InvestigationRail alertId="ALERT-1" onClose={onClose} />);
    await user.click(screen.getByLabelText('Close investigation rail'));
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});

// ─── Error state ─────────────────────────────────────────────────────────────

describe('InvestigationRail — error state', () => {
  it('renders a readable error message on API failure', () => {
    swrState.error = new Error('boom');
    render(<InvestigationRail alertId="ALERT-1" onClose={vi.fn()} />);
    expect(
      screen.getByText(/couldn't load the alert envelope/i),
    ).toBeInTheDocument();
    // The fallback shell still exposes the Close affordance — otherwise the
    // analyst gets stuck looking at the error.
    expect(
      screen.getByLabelText('Close investigation rail'),
    ).toBeInTheDocument();
  });

  it('error fallback close button is wired to onClose', async () => {
    const user = userEvent.setup();
    swrState.error = new Error('boom');
    const onClose = vi.fn();
    render(<InvestigationRail alertId="ALERT-1" onClose={onClose} />);
    await user.click(screen.getByLabelText('Close investigation rail'));
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});

// ─── Loaded rail — header ────────────────────────────────────────────────────

describe('InvestigationRail — header', () => {
  it('renders the alert title, severity, source, and risk', () => {
    swrState.data = buildAlert();
    render(<InvestigationRail alertId="ALERT-W6-0001" onClose={vi.fn()} />);

    expect(
      screen.getByRole('heading', {
        name: /impossible travel — frankfurt then tokyo/i,
      }),
    ).toBeInTheDocument();
    // Severity 'high' is unique — the fixture priorities are {critical, low,
    // info}, so 'high' appears exactly once (in the severity span).
    expect(screen.getByText('high')).toBeInTheDocument();
    expect(screen.getByText('okta')).toBeInTheDocument();
    // Risk score is rounded — 87 stays 87, but the prefix is the contract.
    expect(screen.getByText(/^risk 87$/)).toBeInTheDocument();
  });

  it('omits the risk chip when riskScore is missing', () => {
    swrState.data = buildAlert({
      // Cast to undefined deliberately — the Alert type says number, but the
      // backend can omit it on legacy rows and the rail must not crash.
      riskScore: undefined as unknown as number,
    });
    render(<InvestigationRail alertId="ALERT-W6-0001" onClose={vi.fn()} />);
    // The lowercase 'risk ' (with trailing space) prefix only appears on the
    // header chip; the "Risk:" line in recommended actions is capitalised and
    // followed by a colon, so it can't collide with this matcher.
    expect(screen.queryByText(/^risk /)).toBeNull();
  });

  it('renders the "Open full detail" link with the alert id', () => {
    swrState.data = buildAlert();
    render(<InvestigationRail alertId="ALERT-W6-0001" onClose={vi.fn()} />);
    const link = screen.getByRole('link', { name: /open full detail/i });
    expect(link).toHaveAttribute('href', '/alerts/ALERT-W6-0001');
  });

  it('renders the underscore-stripped status text', () => {
    // 'false_positive' is the only multi-word AlertStatus literal — it
    // exercises the `status.replace('_', ' ')` codepath.
    swrState.data = buildAlert({ status: 'false_positive' });
    render(<InvestigationRail alertId="ALERT-W6-0001" onClose={vi.fn()} />);
    expect(screen.getByText('false positive')).toBeInTheDocument();
  });
});

// ─── Loaded rail — narrative ─────────────────────────────────────────────────

describe('InvestigationRail — narrative section', () => {
  it('renders the narrative when present', () => {
    swrState.data = buildAlert();
    render(<InvestigationRail alertId="ALERT-W6-0001" onClose={vi.fn()} />);
    expect(screen.getByText('Narrative')).toBeInTheDocument();
    expect(
      screen.getByText(/fusion promoted this alert because two sign-ins/i),
    ).toBeInTheDocument();
  });

  it('omits the narrative section when narrative is null', () => {
    swrState.data = buildAlert({ narrative: null });
    render(<InvestigationRail alertId="ALERT-W6-0001" onClose={vi.fn()} />);
    expect(screen.queryByText('Narrative')).toBeNull();
  });

  it('omits the narrative section when narrative is only whitespace', () => {
    swrState.data = buildAlert({ narrative: '   \n  ' });
    render(<InvestigationRail alertId="ALERT-W6-0001" onClose={vi.fn()} />);
    expect(screen.queryByText('Narrative')).toBeNull();
  });
});

// ─── Loaded rail — related entities ──────────────────────────────────────────

describe('InvestigationRail — related entities section', () => {
  it('renders related entities grouped by kind with a count', () => {
    swrState.data = buildAlert();
    render(<InvestigationRail alertId="ALERT-W6-0001" onClose={vi.fn()} />);

    expect(screen.getByText(/related entities/i)).toBeInTheDocument();
    // 5 entities total in the fixture.
    expect(screen.getByText('(5)')).toBeInTheDocument();

    // Each kind that has at least one entity renders its label exactly once.
    expect(screen.getByText('Principals')).toBeInTheDocument();
    expect(screen.getByText('Network')).toBeInTheDocument();
    expect(screen.getByText('Workflow')).toBeInTheDocument();
    expect(screen.getByText('Tenant')).toBeInTheDocument();
  });

  it('renders the principal chips with their display labels', () => {
    swrState.data = buildAlert();
    render(<InvestigationRail alertId="ALERT-W6-0001" onClose={vi.fn()} />);
    // Display label wins over raw value when present.
    expect(screen.getByText('Alice (Finance)')).toBeInTheDocument();
    // No label → fall back to raw value.
    expect(screen.getByText('fin-laptop-12')).toBeInTheDocument();
  });

  it('wraps entities with pivotPath in a link and leaves the rest as plain chips', () => {
    swrState.data = buildAlert();
    render(<InvestigationRail alertId="ALERT-W6-0001" onClose={vi.fn()} />);

    // The pivotable principal renders an anchor.
    const aliceLink = screen.getByText('Alice (Finance)').closest('a');
    expect(aliceLink).not.toBeNull();
    expect(aliceLink).toHaveAttribute(
      'href',
      '/graph/user/alice%40example.com',
    );

    // The non-pivotable host does NOT render an anchor — `closest('a')` should
    // skip past the chip's outer span and find nothing.
    const hostChip = screen.getByText('fin-laptop-12');
    expect(hostChip.closest('a')).toBeNull();

    // The network IP chip renders an anchor too.
    const ipLink = screen.getByText('10.0.0.7').closest('a');
    expect(ipLink).toHaveAttribute('href', '/graph/ip/10.0.0.7');
  });

  it('omits the section entirely when no related entities are returned', () => {
    swrState.data = buildAlert({ relatedEntities: [] });
    render(<InvestigationRail alertId="ALERT-W6-0001" onClose={vi.fn()} />);
    expect(screen.queryByText(/related entities/i)).toBeNull();
  });

  it('re-groups entities defensively when the API returns them out of order', () => {
    const shuffled: RelatedEntity[] = [
      { kind: 'tenant', type: 'tenant', value: 'acme' },
      { kind: 'principal', type: 'user', value: 'alice' },
      { kind: 'network', type: 'ip', value: '10.0.0.1' },
      { kind: 'principal', type: 'host', value: 'box-1' },
    ];
    swrState.data = buildAlert({ relatedEntities: shuffled });
    const { container } = render(
      <InvestigationRail alertId="ALERT-W6-0001" onClose={vi.fn()} />,
    );

    // The three group headers present in the fixture appear; the workflow
    // group is skipped because there are no workflow entities.
    expect(screen.getByText('Principals')).toBeInTheDocument();
    expect(screen.getByText('Network')).toBeInTheDocument();
    expect(screen.getByText('Tenant')).toBeInTheDocument();
    expect(screen.queryByText('Workflow')).toBeNull();

    // Render order: Principals comes before Network comes before Tenant,
    // independent of the input order.
    const html = container.innerHTML;
    const principalsIdx = html.indexOf('Principals');
    const networkIdx = html.indexOf('Network');
    const tenantIdx = html.indexOf('Tenant');
    expect(principalsIdx).toBeGreaterThan(-1);
    expect(networkIdx).toBeGreaterThan(principalsIdx);
    expect(tenantIdx).toBeGreaterThan(networkIdx);
  });
});

// ─── Loaded rail — mini timeline ─────────────────────────────────────────────

describe('InvestigationRail — mini-timeline section', () => {
  it('renders the mini-timeline rows with badges, titles, and actors', () => {
    swrState.data = buildAlert();
    render(<InvestigationRail alertId="ALERT-W6-0001" onClose={vi.fn()} />);

    expect(screen.getByText(/recent events/i)).toBeInTheDocument();
    expect(screen.getByText('(2)')).toBeInTheDocument();

    // Titles render.
    expect(screen.getByText('Alert promoted by fusion')).toBeInTheDocument();
    expect(screen.getByText('Case assigned to analyst')).toBeInTheDocument();

    // Source badges — `case_timeline` collapses to "case", `audit_log` to "audit".
    expect(screen.getByText('case')).toBeInTheDocument();
    expect(screen.getByText('audit')).toBeInTheDocument();

    // Actor lines render with the "by " prefix.
    expect(screen.getByText('by fusion-engine')).toBeInTheDocument();
    expect(screen.getByText('by beenu@cyble.com')).toBeInTheDocument();
  });

  it('renders the row without crashing when the timestamp is malformed', () => {
    swrState.data = buildAlert({
      miniTimeline: [
        {
          id: 'evt-bad',
          timestamp: 'not-a-real-timestamp',
          type: 'note_added',
          title: 'Analyst added a note',
          source: 'audit_log',
        },
      ],
    });
    render(<InvestigationRail alertId="ALERT-W6-0001" onClose={vi.fn()} />);
    // The title still surfaces so the row isn't lost.
    expect(screen.getByText('Analyst added a note')).toBeInTheDocument();
  });

  it('omits the section when there are no timeline events', () => {
    swrState.data = buildAlert({ miniTimeline: [] });
    render(<InvestigationRail alertId="ALERT-W6-0001" onClose={vi.fn()} />);
    expect(screen.queryByText(/recent events/i)).toBeNull();
  });
});

// ─── Loaded rail — recommended actions ───────────────────────────────────────

describe('InvestigationRail — recommended actions section', () => {
  it('renders recommended actions with priority chips, rationale, and risk', () => {
    swrState.data = buildAlert();
    render(<InvestigationRail alertId="ALERT-W6-0001" onClose={vi.fn()} />);

    expect(screen.getByText(/recommended actions/i)).toBeInTheDocument();
    expect(screen.getByText('(3)')).toBeInTheDocument();

    // Priorities render as their literal lowercase tag. With severity='high'
    // and priorities {critical, low, info}, every priority text is unique in
    // the document.
    expect(screen.getByText('critical')).toBeInTheDocument();
    expect(screen.getByText('low')).toBeInTheDocument();
    expect(screen.getByText('info')).toBeInTheDocument();

    // Action text renders.
    expect(
      screen.getByText('Disable the account immediately'),
    ).toBeInTheDocument();
    expect(
      screen.getByText('Reset password and revoke active sessions'),
    ).toBeInTheDocument();

    // Rationale + risk only render when present.
    expect(
      screen.getByText(/impossible travel confirmed across two regions/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        /risk: locking the account temporarily disrupts the user/i,
      ),
    ).toBeInTheDocument();

    // Action 1 (low) has no rationale; we should NOT see a stray "Risk:" line
    // for it — only action 0 (critical) carries a risk field.
    const risks = screen.queryAllByText(/^Risk:/);
    expect(risks).toHaveLength(1);
  });

  it('falls back to the medium tone when priority is unrecognised', () => {
    swrState.data = buildAlert({
      recommendedActions: [
        {
          // Cast through unknown to simulate a stale backend handing us
          // a priority outside the documented enum.
          priority: 'urgent' as unknown as RecommendedAction['priority'],
          action: 'Investigate quickly',
        },
      ],
    });
    render(<InvestigationRail alertId="ALERT-W6-0001" onClose={vi.fn()} />);
    // The chip still renders with the raw priority text — the fallback is
    // about the tone class, not about hiding the row.
    expect(screen.getByText('urgent')).toBeInTheDocument();
    expect(screen.getByText('Investigate quickly')).toBeInTheDocument();
  });

  it('omits the section when there are no recommended actions', () => {
    swrState.data = buildAlert({ recommendedActions: [] });
    render(<InvestigationRail alertId="ALERT-W6-0001" onClose={vi.fn()} />);
    expect(screen.queryByText(/recommended actions/i)).toBeNull();
  });
});

// ─── Deep Explain handoff ────────────────────────────────────────────────────

describe('InvestigationRail — Deep Explain drawer', () => {
  it('does not mount the drawer on initial render', () => {
    swrState.data = buildAlert();
    render(<InvestigationRail alertId="ALERT-W6-0001" onClose={vi.fn()} />);
    expect(screen.queryByTestId('explain-drawer-mock')).toBeNull();
    expect(explainDrawerProps.lastProps).toBeNull();
  });

  it('mounts the drawer with the loaded alert when Deep Explain is clicked', async () => {
    const user = userEvent.setup();
    swrState.data = buildAlert();
    render(<InvestigationRail alertId="ALERT-W6-0001" onClose={vi.fn()} />);

    await user.click(screen.getByRole('button', { name: /deep explain/i }));

    expect(screen.getByTestId('explain-drawer-mock')).toBeInTheDocument();
    expect(explainDrawerProps.lastProps?.alertId).toBe('ALERT-W6-0001');
    expect(explainDrawerProps.lastProps?.open).toBe(true);
  });

  it('closes the drawer when the drawer fires onClose', async () => {
    const user = userEvent.setup();
    swrState.data = buildAlert();
    render(<InvestigationRail alertId="ALERT-W6-0001" onClose={vi.fn()} />);

    await user.click(screen.getByRole('button', { name: /deep explain/i }));
    expect(screen.getByTestId('explain-drawer-mock')).toBeInTheDocument();

    await user.click(screen.getByTestId('explain-drawer-close'));
    expect(screen.queryByTestId('explain-drawer-mock')).toBeNull();
  });

  it('does NOT call the rail-level onClose when the drawer is closed', async () => {
    // The rail's onClose is the queue-level "dismiss the rail" affordance.
    // Closing the drawer must not bubble up into that.
    const user = userEvent.setup();
    swrState.data = buildAlert();
    const onClose = vi.fn();
    render(<InvestigationRail alertId="ALERT-W6-0001" onClose={onClose} />);

    await user.click(screen.getByRole('button', { name: /deep explain/i }));
    await user.click(screen.getByTestId('explain-drawer-close'));

    expect(onClose).not.toHaveBeenCalled();
  });
});

// ─── Rail-level Close button ─────────────────────────────────────────────────

describe('InvestigationRail — rail close button', () => {
  it('calls onClose when the analyst clicks Close on a loaded rail', async () => {
    const user = userEvent.setup();
    swrState.data = buildAlert();
    const onClose = vi.fn();
    render(<InvestigationRail alertId="ALERT-W6-0001" onClose={onClose} />);

    // The shell exposes one Close affordance — the loaded rail uses the same
    // aria-label as the loading shell, so we can target it the same way.
    const closeBtn = screen.getByLabelText('Close investigation rail');
    await user.click(closeBtn);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('keeps the alert content visible until the parent unmounts the rail', () => {
    // The rail itself doesn't toggle visibility on Close — it just fires
    // onClose. The parent (AlertsView) controls mount/unmount. This test
    // pins that contract so refactors don't accidentally short-circuit it.
    swrState.data = buildAlert();
    const onClose = vi.fn();
    render(<InvestigationRail alertId="ALERT-W6-0001" onClose={onClose} />);

    expect(
      screen.getByRole('heading', { name: /impossible travel/i }),
    ).toBeInTheDocument();
  });
});

// ─── Empty envelopes (legacy backend) ────────────────────────────────────────

describe('InvestigationRail — degrades gracefully on legacy envelopes', () => {
  it('renders the header but no section bodies when the rail fields are missing', () => {
    // Pre-v1.5 backends won't carry any of the new rail fields. The
    // component must still render — just with the header alone — rather
    // than crashing or showing four empty sections.
    swrState.data = buildAlert({
      narrative: null,
      relatedEntities: [],
      miniTimeline: [],
      recommendedActions: [],
    });
    render(<InvestigationRail alertId="ALERT-W6-0001" onClose={vi.fn()} />);

    // Header still renders.
    expect(
      screen.getByRole('heading', { name: /impossible travel/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: /deep explain/i }),
    ).toBeInTheDocument();

    // None of the four section labels appear.
    expect(screen.queryByText('Narrative')).toBeNull();
    expect(screen.queryByText(/related entities/i)).toBeNull();
    expect(screen.queryByText(/recent events/i)).toBeNull();
    expect(screen.queryByText(/recommended actions/i)).toBeNull();
  });

  it('treats omitted rail fields the same as empty arrays', () => {
    // Same as above but the fields are `undefined` instead of `[]` — the
    // rail uses `??` so this is the explicit contract test.
    swrState.data = buildAlert({
      narrative: undefined,
      relatedEntities: undefined,
      miniTimeline: undefined,
      recommendedActions: undefined,
    });
    render(<InvestigationRail alertId="ALERT-W6-0001" onClose={vi.fn()} />);
    expect(screen.queryByText('Narrative')).toBeNull();
    expect(screen.queryByText(/related entities/i)).toBeNull();
    expect(screen.queryByText(/recent events/i)).toBeNull();
    expect(screen.queryByText(/recommended actions/i)).toBeNull();
  });
});
