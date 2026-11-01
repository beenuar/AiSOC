/**
 * The four operator pages that genuinely were not built.
 *
 * Wave 2, Phase 9.5. Branding, retention, rule packs and delegations each had
 * a complete backend — full CRUD, ownership checks, audit emission — and no
 * console binding at all. The prerequisite change corrected the matrix caveat
 * so it named only these four; this suite is the gate the row for them names.
 *
 * Why every case asserts on **first paint** as well as the error branch
 * --------------------------------------------------------------------
 * The recorded trap: the error branch and the loading branch both render with
 * no data, and a suite that drives only the error branch never exercises the
 * state every page load passes through. A `?? DEFAULTS` fallback is reachable
 * only during first paint, which is exactly where a fabricated value hides.
 *
 * The specific honesty property each panel is held to
 * ---------------------------------------------------
 * - **Retention** must not render 90/365/730 over a failed read. Those are
 *   the real defaults, they look exactly like an answer, and an operator who
 *   believes they are their windows will not set the ones they need. It must
 *   also say when the purge worker is off, because the windows are then a
 *   *stated* policy and nothing is deleted — a page with three editable
 *   numbers and a Save button asserts otherwise.
 * - **Delegations** must not render "No delegations" over a failed read.
 *   "Nobody holds a standing grant into a customer tenant" and "we could not
 *   read the grants" are opposite conclusions about an access-control
 *   surface, and the empty table quietly asserts the first.
 * - **Rule packs** must keep the two reads separate: a failed children read
 *   disables assignment and must not make the library look unreadable.
 * - **Branding** must treat the 409 (this tenant belongs to no operator
 *   organisation) as an answer rather than a failure, because it is one.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';

const api = vi.hoisted(() => ({
  branding: { get: vi.fn(), update: vi.fn(), uploadAsset: vi.fn(), deleteAsset: vi.fn(), logo: vi.fn() },
  retention: { get: vi.fn(), update: vi.fn() },
  rulePacks: { list: vi.fn(), create: vi.fn(), update: vi.fn(), remove: vi.fn(), assign: vi.fn() },
  delegations: { list: vi.fn(), create: vi.fn(), revoke: vi.fn() },
  mssp: { listChildren: vi.fn() },
}));

// Hoisted with the mock factory: `vi.mock` is lifted above every top-level
// declaration, so a plain `class` here is still in its temporal dead zone
// when the factory runs.
const FakeApiError = vi.hoisted(
  () =>
    class FakeApiError extends Error {
      status: number;
      body: string;
      constructor(message: string, status: number, body = '') {
        super(message);
        this.name = 'ApiError';
        this.status = status;
        this.body = body;
      }
    },
);

vi.mock('react-hot-toast', () => ({
  default: { success: vi.fn(), error: vi.fn() },
}));

vi.mock('@/lib/api', () => ({
  ApiError: FakeApiError,
  brandingApi: api.branding,
  retentionApi: api.retention,
  rulePacksApi: api.rulePacks,
  delegationsApi: api.delegations,
  msspApi: api.mssp,
}));

import { BrandingPanel } from './BrandingPanel';
import { RetentionPanel } from './RetentionPanel';
import { RulePacksPanel } from './RulePacksPanel';
import { DelegationsPanel } from './DelegationsPanel';

/** A promise that never settles, so the component stays on first paint. */
function pending<T>(): Promise<T> {
  return new Promise<T>(() => undefined);
}

beforeEach(() => {
  vi.clearAllMocks();
  api.mssp.listChildren.mockResolvedValue([]);
});

afterEach(() => {
  cleanup();
});

// ── Branding ────────────────────────────────────────────────────────────────

describe('BrandingPanel', () => {
  const branding = {
    product_name: 'AiSOC',
    primary_color: '#1d4ed8',
    accent_color: '#0ea5e9',
    support_email: 'soc@example.com',
    support_url: 'https://support.example.com',
    sender_name: 'Security Operations',
    footer_text: 'Internal use only',
    logo_url: null,
    org_id: 'org-1',
    is_white_labelled: true,
  };

  it('shows a loading state on first paint, with no fields to edit yet', () => {
    api.branding.get.mockReturnValue(pending());
    render(<BrandingPanel />);
    expect(screen.getByText('Loading branding…')).toBeInTheDocument();
    expect(screen.queryByLabelText('Product name')).not.toBeInTheDocument();
  });

  it('renders the failure, and never an editable form of blank defaults', async () => {
    api.branding.get.mockRejectedValue(new Error('branding read failed'));
    render(<BrandingPanel />);
    await waitFor(() => expect(screen.getByText('Could not load branding')).toBeInTheDocument());
    expect(screen.getByText('branding read failed')).toBeInTheDocument();
    // An empty form over a failed read invites an operator to "fix" values
    // they never set, overwriting whatever is actually stored.
    expect(screen.queryByLabelText('Product name')).not.toBeInTheDocument();
  });

  it('renders the stored values once the read succeeds', async () => {
    api.branding.get.mockResolvedValue(branding);
    render(<BrandingPanel />);
    await waitFor(() => expect(screen.getByLabelText('Product name')).toHaveValue('AiSOC'));
    expect(screen.getByLabelText('Support URL')).toHaveValue('https://support.example.com');
    expect(screen.getByText('This organisation is white-labelled.')).toBeInTheDocument();
    expect(screen.queryByTestId('branding-no-org')).not.toBeInTheDocument();
  });
});

// ── Retention ───────────────────────────────────────────────────────────────

describe('RetentionPanel', () => {
  const policy = {
    raw_events_days: 90,
    alerts_days: 365,
    audit_days: 730,
    purge_worker_enabled: false,
    purge_worker_dry_run: true,
  };

  it('shows a loading state on first paint, and not the default windows', () => {
    api.retention.get.mockReturnValue(pending());
    render(<RetentionPanel />);
    expect(screen.getByText('Loading retention policy…')).toBeInTheDocument();
    expect(screen.queryByLabelText('Raw events retention in days')).not.toBeInTheDocument();
  });

  it('renders the failure and no windows at all, because the defaults look like an answer', async () => {
    api.retention.get.mockRejectedValue(new Error('retention read failed'));
    render(<RetentionPanel />);
    await waitFor(() =>
      expect(screen.getByText('Could not load the retention policy')).toBeInTheDocument(),
    );
    expect(screen.queryByLabelText('Raw events retention in days')).not.toBeInTheDocument();
    // The precise regression this pins: 90/365/730 rendered over a failed
    // read is indistinguishable from the tenant's real policy.
    expect(screen.queryByDisplayValue('90')).not.toBeInTheDocument();
    expect(screen.queryByDisplayValue('365')).not.toBeInTheDocument();
    expect(screen.queryByDisplayValue('730')).not.toBeInTheDocument();
  });

  it('says plainly that nothing is deleted when the purge worker is off', async () => {
    api.retention.get.mockResolvedValue(policy);
    render(<RetentionPanel />);
    await waitFor(() => expect(screen.getByTestId('retention-enforcement')).toBeInTheDocument());
    expect(screen.getByTestId('retention-enforcement')).toHaveTextContent(/not enabled/i);
    expect(screen.getByTestId('retention-enforcement')).toHaveTextContent(/nothing is deleted/i);
    expect(screen.getByLabelText('Raw events retention in days')).toHaveValue('90');
  });

  it('distinguishes dry-run from off, because they need different operator actions', async () => {
    api.retention.get.mockResolvedValue({ ...policy, purge_worker_enabled: true, purge_worker_dry_run: true });
    render(<RetentionPanel />);
    await waitFor(() => expect(screen.getByTestId('retention-enforcement')).toBeInTheDocument());
    expect(screen.getByTestId('retention-enforcement')).toHaveTextContent(/dry-run/i);
    expect(screen.getByTestId('retention-enforcement')).not.toHaveTextContent(/not enabled/i);
  });

  it('confirms deletion only when the worker is enabled and not in dry-run', async () => {
    api.retention.get.mockResolvedValue({ ...policy, purge_worker_enabled: true, purge_worker_dry_run: false });
    render(<RetentionPanel />);
    await waitFor(() => expect(screen.getByTestId('retention-enforcement')).toBeInTheDocument());
    expect(screen.getByTestId('retention-enforcement')).toHaveTextContent(/is deleted/i);
  });
});

// ── Rule packs ──────────────────────────────────────────────────────────────

describe('RulePacksPanel', () => {
  const pack = {
    id: 'pack-1',
    name: 'Retail baseline',
    description: null,
    category: 'retail',
    is_default: false,
    created_at: '2026-10-01T00:00:00Z',
    updated_at: '2026-10-01T00:00:00Z',
  };

  it('shows a loading state on first paint, with no empty-library claim', () => {
    api.rulePacks.list.mockReturnValue(pending());
    render(<RulePacksPanel />);
    expect(screen.getByText('Loading rule packs…')).toBeInTheDocument();
    expect(screen.queryByText('No rule packs yet')).not.toBeInTheDocument();
  });

  it('renders the failure rather than an empty library', async () => {
    api.rulePacks.list.mockRejectedValue(new Error('rule pack read failed'));
    render(<RulePacksPanel />);
    await waitFor(() => expect(screen.getByText('Could not load rule packs')).toBeInTheDocument());
    // "No rule packs yet" tells an operator to go and create one. After a
    // failed read that is advice about a library we could not see.
    expect(screen.queryByText('No rule packs yet')).not.toBeInTheDocument();
  });

  it('says the server answered when there are genuinely no packs', async () => {
    api.rulePacks.list.mockResolvedValue([]);
    render(<RulePacksPanel />);
    await waitFor(() => expect(screen.getByText('No rule packs yet')).toBeInTheDocument());
  });

  it('keeps a failed children read from making the library look unreadable', async () => {
    api.rulePacks.list.mockResolvedValue([pack]);
    api.mssp.listChildren.mockRejectedValue(new Error('children read failed'));
    render(<RulePacksPanel />);
    await waitFor(() => expect(screen.getByText('Retail baseline')).toBeInTheDocument());
    expect(screen.getByTestId('rule-packs-children-unavailable')).toBeInTheDocument();
    expect(screen.queryByText('Could not load rule packs')).not.toBeInTheDocument();
    // Assignment is the thing that is unavailable, and it is disabled rather
    // than offering a picker that cannot work.
    expect(screen.getByLabelText('Assign Retail baseline to tenant')).toBeDisabled();
  });

  it('offers assignment when managed tenants are readable', async () => {
    api.rulePacks.list.mockResolvedValue([pack]);
    api.mssp.listChildren.mockResolvedValue([{ id: 'child-1', name: 'Acme', mssp_role: 'managed' }]);
    render(<RulePacksPanel />);
    await waitFor(() => expect(screen.getByLabelText('Assign Retail baseline to tenant')).toBeEnabled());
    expect(screen.getByRole('option', { name: 'Acme' })).toBeInTheDocument();
  });
});

// ── Delegations ─────────────────────────────────────────────────────────────

describe('DelegationsPanel', () => {
  const delegation = {
    id: 'del-1',
    parent_tenant_id: 'parent-1',
    child_tenant_id: 'child-1',
    granted_role: 'soc_analyst',
    granted_by_user: 'user-1',
    expires_at: null,
    revoked_at: null,
    created_at: '2026-10-01T00:00:00Z',
  };

  it('shows a loading state on first paint, with no "no delegations" claim', () => {
    api.delegations.list.mockReturnValue(pending());
    render(<DelegationsPanel />);
    expect(screen.getByText('Loading delegations…')).toBeInTheDocument();
    expect(screen.queryByText('No delegations')).not.toBeInTheDocument();
  });

  it('renders the failure rather than asserting nobody holds a grant', async () => {
    api.delegations.list.mockRejectedValue(new Error('delegation read failed'));
    render(<DelegationsPanel />);
    await waitFor(() => expect(screen.getByText('Could not load delegations')).toBeInTheDocument());
    expect(screen.getByText('delegation read failed')).toBeInTheDocument();
    // The whole point of the panel: an empty table over a failed read says
    // nobody has standing authority over a customer tenant. That is a claim
    // about access control made from no data.
    expect(screen.queryByText('No delegations')).not.toBeInTheDocument();
  });

  it('says the server answered when there are genuinely none', async () => {
    api.delegations.list.mockResolvedValue([]);
    render(<DelegationsPanel />);
    await waitFor(() => expect(screen.getByText('No delegations')).toBeInTheDocument());
  });

  it('states a never-expiring grant as a fact rather than a dash', async () => {
    api.delegations.list.mockResolvedValue([delegation]);
    api.mssp.listChildren.mockResolvedValue([{ id: 'child-1', name: 'Acme', mssp_role: 'managed' }]);
    render(<DelegationsPanel />);
    // Scoped to the table: "Acme" is also an <option> in the grant form, so
    // an unscoped query matches twice and fails for a reason that has
    // nothing to do with what this case is about.
    await waitFor(() => expect(screen.getByRole('table')).toBeInTheDocument());
    const table = within(screen.getByRole('table'));
    expect(table.getByText('Acme')).toBeInTheDocument();
    expect(table.getByText('Never')).toBeInTheDocument();
    expect(table.getByText('soc_analyst')).toBeInTheDocument();
  });

  it('falls back to the tenant id when names are unreadable, rather than hiding the grant', async () => {
    api.delegations.list.mockResolvedValue([delegation]);
    api.mssp.listChildren.mockRejectedValue(new Error('children read failed'));
    render(<DelegationsPanel />);
    await waitFor(() => expect(screen.getByText('child-1')).toBeInTheDocument());
    expect(screen.getByTestId('delegations-children-unavailable')).toBeInTheDocument();
  });
});
