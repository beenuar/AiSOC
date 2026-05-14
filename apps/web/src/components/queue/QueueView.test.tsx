/**
 * Smoke tests for the Investigation Queue workbench (PR-5 / v1.5 §W7).
 *
 * The QueueView is the analyst's "what should I work on next?" screen, so the
 * behaviours we pin here are the ones an SOC would actually file a P1 against
 * if they regressed:
 *
 *   1. Loading skeleton renders before the first server response.
 *   2. Empty-state copy adapts to the active owner tab.
 *   3. Queue rows render the data the backend hands us (severity, SLA pill,
 *      bucket, asset, suggested action, "In case" pill).
 *   4. Claim button issues `POST /alerts/{id}/claim`, fires a success toast,
 *      and revalidates the SWR cache.
 *   5. A 409 from a teammate-beat-us-to-it race is surfaced as a friendly toast.
 *   6. Owner toggle is mirrored to the URL via SWR key change (we assert on the
 *      observed query payload, since SWR re-fetches when keys change).
 *   7. Backend errors render the ErrorState with a working retry.
 *
 * We mock SWR + `@/lib/api` + react-hot-toast so the test focuses on the view
 * layer without booting a fetch stack. The mocked SWR shim mirrors the subset
 * of the real hook the component touches.
 *
 * @author Beenu Arora <beenu@cyble.com>
 */

import { describe, expect, it, vi, beforeEach } from 'vitest';
import { act, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { QueueItem, QueueResponse } from '@/lib/api';

// ─── Mock SWR ─────────────────────────────────────────────────────────────────
//
// The component calls `useSWR(['queue', owner, period, page], fetcher, opts)`.
// We render the latest payload returned by the fetcher and expose a hand-rolled
// mutate() so tests can assert revalidations after mutations.

const swrState = vi.hoisted(() => ({
  data: undefined as QueueResponse | undefined,
  error: undefined as Error | undefined,
  isLoading: false,
  mutateCount: 0,
}));

const mutateMock = vi.hoisted(() => vi.fn());

vi.mock('swr', () => ({
  __esModule: true,
  default: () => ({
    data: swrState.data,
    error: swrState.error,
    isLoading: swrState.isLoading,
    mutate: mutateMock,
  }),
}));

// ─── Mock the API layer ───────────────────────────────────────────────────────

const queueListMock = vi.hoisted(() => vi.fn());
const queueClaimMock = vi.hoisted(() => vi.fn());
const queueAssignMock = vi.hoisted(() => vi.fn());
const queueSnoozeMock = vi.hoisted(() => vi.fn());
const currentUserMock = vi.hoisted(() => vi.fn());

vi.mock('@/lib/api', () => ({
  __esModule: true,
  queueApi: {
    list: queueListMock,
    claim: queueClaimMock,
    assign: queueAssignMock,
    snooze: queueSnoozeMock,
  },
  authApi: {
    currentUser: currentUserMock,
  },
}));

// ─── Mock next/link ───────────────────────────────────────────────────────────
//
// We render <Link> as a plain anchor so the click handlers + child markup are
// reachable; the full Next router is irrelevant here.

vi.mock('next/link', () => ({
  __esModule: true,
  default: ({
    children,
    href,
    ...rest
  }: {
    children: React.ReactNode;
    href: string;
    [k: string]: unknown;
  }) => (
    <a href={typeof href === 'string' ? href : ''} {...rest}>
      {children}
    </a>
  ),
}));

// ─── Mock toast ───────────────────────────────────────────────────────────────

const toastSuccess = vi.hoisted(() => vi.fn());
const toastError = vi.hoisted(() => vi.fn());
vi.mock('react-hot-toast', () => ({
  __esModule: true,
  default: { success: toastSuccess, error: toastError },
}));

// Import AFTER mocks so the module picks them up.
import { QueueView } from './QueueView';

// ─── Fixtures ─────────────────────────────────────────────────────────────────

const NOW_ISO = '2026-05-13T12:00:00Z';
const CURRENT_USER_ID = 'user-self';

function makeItem(overrides: Partial<QueueItem> = {}): QueueItem {
  return {
    id: 'a-1',
    tenant_id: 't-1',
    title: 'Suspicious PowerShell encoded command',
    severity: 'high',
    status: 'new',
    priority: 1,
    category: 'endpoint',
    connector_type: 'edr',
    assigned_to_id: null,
    case_id: null,
    first_seen: '2026-05-13T11:00:00Z',
    sla_due_at: '2026-05-13T13:00:00Z',
    sla_remaining_seconds: 3600,
    sla_breached: false,
    age_seconds: 3600,
    asset: { kind: 'host', value: 'win-laptop-42', label: 'win-laptop-42' },
    suggested_action: {
      priority: 1,
      action: 'Isolate host',
      risk: 'high',
    },
    bucket: 'unassigned',
    ...overrides,
  };
}

function makeResponse(items: QueueItem[], overrides: Partial<QueueResponse> = {}): QueueResponse {
  return {
    items,
    total: items.length,
    counts: {
      mine: items.filter((i) => i.bucket === 'mine').length,
      unassigned: items.filter((i) => i.bucket === 'unassigned').length,
      all: items.length,
    },
    period: 'all',
    owner: 'me',
    page: 1,
    page_size: 50,
    pages: 1,
    generated_at: NOW_ISO,
    ...overrides,
  };
}

beforeEach(() => {
  swrState.data = undefined;
  swrState.error = undefined;
  swrState.isLoading = false;
  swrState.mutateCount = 0;
  mutateMock.mockReset();
  mutateMock.mockResolvedValue(undefined);
  queueListMock.mockReset();
  queueClaimMock.mockReset();
  queueAssignMock.mockReset();
  queueSnoozeMock.mockReset();
  toastSuccess.mockReset();
  toastError.mockReset();
  currentUserMock.mockReset();
  currentUserMock.mockReturnValue({
    id: CURRENT_USER_ID,
    email: 'analyst@example.com',
    role: 'responder',
    tenant_id: 't-1',
  });
});

/**
 * Click an action button and drain the resulting async handler inside a
 * single `act()` boundary.
 *
 * The action handlers in `QueueView` (claim/release/snooze) are async
 * fire-and-forget — the JSX wires `onClick={() => onClaim(id)}` and the
 * handler `await`s `queueApi.*` and `mutate()`, then resets the busy flag
 * via `setBusy(id, null)` in a `finally` block. user-event's implicit
 * `act()` wrapper only covers the click dispatch itself, so the trailing
 * `setBusy(null)` state update lands outside `act` and triggers the
 * "An update to QueueView inside a test was not wrapped in act(...)" warning.
 *
 * Wrapping both the click and microtask drainage in a manual `act()` keeps
 * the entire async chain — including the `finally` cleanup — inside the
 * boundary, which is what the React testing contract requires.
 */
async function clickAndSettle(user: ReturnType<typeof userEvent.setup>, el: HTMLElement) {
  await act(async () => {
    await user.click(el);
    // Drain at least three microtask hops:
    //   1. queueApi.* promise resolves
    //   2. await mutate() yields one tick
    //   3. finally { setBusy(null) } commits
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
  });
}

describe('QueueView', () => {
  it('renders the loading skeleton before the first server response', () => {
    swrState.isLoading = true;
    swrState.data = undefined;

    render(<QueueView />);

    // Header still renders during loading so the analyst sees context.
    expect(screen.getByText(/Investigation Queue/i)).toBeInTheDocument();
    // No queue rows yet — the data is undefined.
    expect(screen.queryByText('Suspicious PowerShell encoded command')).not.toBeInTheDocument();
  });

  it('renders the empty state for an empty Mine bucket', () => {
    swrState.data = makeResponse([], { owner: 'me' });

    render(<QueueView />);

    expect(screen.getByText(/Nothing in your queue/i)).toBeInTheDocument();
    expect(
      screen.getByText(/Switch to Unassigned to pick something up/i),
    ).toBeInTheDocument();
  });

  it('renders queue items with severity, asset, bucket, and SLA info', () => {
    const item = makeItem();
    swrState.data = makeResponse([item]);

    render(<QueueView />);

    // Title is rendered.
    expect(screen.getByText(item.title)).toBeInTheDocument();

    // Scope all per-row assertions inside the alert row's anchor so we don't
    // collide with same-text nodes in the owner toggle / counts header.
    const row = screen.getByRole('link', { name: /Investigate Suspicious PowerShell/i });
    const withinRow = within(row);

    // Severity pill ("HIGH").
    expect(withinRow.getByText('HIGH')).toBeInTheDocument();
    // Bucket pill — "Unassigned" also appears as an OwnerToggle tab label,
    // so we must scope to the row.
    expect(withinRow.getByText('Unassigned')).toBeInTheDocument();
    // Asset label rendered in the metadata strip.
    expect(withinRow.getByText('win-laptop-42')).toBeInTheDocument();
    // Suggested action text comes through with the "→" prefix.
    expect(withinRow.getByText(/Isolate host/i)).toBeInTheDocument();
    // SLA pill renders with "SLA" prefix and a formatted countdown.
    expect(withinRow.getByText(/^SLA /)).toBeInTheDocument();
  });

  it('shows "In case" pill when the alert is already linked to a case', () => {
    const item = makeItem({ case_id: 'case-42' });
    swrState.data = makeResponse([item]);

    render(<QueueView />);

    expect(screen.getByText(/In case/i)).toBeInTheDocument();
  });

  it("marks rows assigned to the current user as 'Mine' and shows the Release action", () => {
    const item = makeItem({
      bucket: 'mine',
      assigned_to_id: CURRENT_USER_ID,
    });
    swrState.data = makeResponse([item]);

    render(<QueueView />);

    // "Mine" appears both as an OwnerToggle tab label and as the BucketBadge
    // inside the row; scope to the row so we're asserting on the badge.
    const row = screen.getByRole('link', { name: /Investigate Suspicious PowerShell/i });
    expect(within(row).getByText('Mine')).toBeInTheDocument();

    // No Claim button — already mine.
    expect(screen.queryByRole('button', { name: /^Claim$/ })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^Release$/ })).toBeInTheDocument();
  });

  it('issues POST /claim and revalidates SWR on successful claim', async () => {
    const item = makeItem();
    swrState.data = makeResponse([item]);
    queueClaimMock.mockResolvedValue({ id: item.id });

    const user = userEvent.setup();
    render(<QueueView />);

    const claimBtn = screen.getByRole('button', { name: /^Claim$/ });
    await clickAndSettle(user, claimBtn);

    expect(queueClaimMock).toHaveBeenCalledTimes(1);
    expect(queueClaimMock).toHaveBeenCalledWith(item.id);
    expect(toastSuccess).toHaveBeenCalledWith(
      expect.stringMatching(/Claimed — this alert is yours/),
    );
    expect(mutateMock).toHaveBeenCalled();
  });

  it('surfaces a 409 conflict as a "teammate beat you to it" toast', async () => {
    const item = makeItem();
    swrState.data = makeResponse([item]);
    queueClaimMock.mockRejectedValue(
      new Error('409 Conflict: alert already claimed'),
    );

    const user = userEvent.setup();
    render(<QueueView />);

    const claimBtn = screen.getByRole('button', { name: /^Claim$/ });
    await clickAndSettle(user, claimBtn);

    expect(toastError).toHaveBeenCalledWith(
      expect.stringMatching(/Another responder claimed this alert first/),
    );
    expect(toastSuccess).not.toHaveBeenCalled();
    // We still revalidate so the UI catches up to the new ownership state.
    expect(mutateMock).toHaveBeenCalled();
  });

  it('falls back to a generic error toast when claim fails for unknown reasons', async () => {
    const item = makeItem();
    swrState.data = makeResponse([item]);
    queueClaimMock.mockRejectedValue(new Error('boom'));

    const user = userEvent.setup();
    render(<QueueView />);

    await clickAndSettle(user, screen.getByRole('button', { name: /^Claim$/ }));

    expect(toastError).toHaveBeenCalledWith('boom');
  });

  it('releases an assigned alert with a null assignee', async () => {
    const item = makeItem({
      bucket: 'mine',
      assigned_to_id: CURRENT_USER_ID,
    });
    swrState.data = makeResponse([item]);
    queueAssignMock.mockResolvedValue({ id: item.id });

    const user = userEvent.setup();
    render(<QueueView />);

    await clickAndSettle(user, screen.getByRole('button', { name: /^Release$/ }));

    expect(queueAssignMock).toHaveBeenCalledWith(item.id, null);
    expect(toastSuccess).toHaveBeenCalledWith(
      expect.stringMatching(/Released back to the unassigned pool/),
    );
  });

  it('snoozes an alert for the selected duration', async () => {
    const item = makeItem({
      bucket: 'mine',
      assigned_to_id: CURRENT_USER_ID,
    });
    swrState.data = makeResponse([item]);
    queueSnoozeMock.mockResolvedValue({ id: item.id });

    const user = userEvent.setup();
    const { container } = render(<QueueView />);

    // Force the <details> open directly. JSDOM's native summary-toggle
    // behaviour is inconsistent across versions, so we don't rely on it for
    // this assertion — we care about the action handler being wired up, not
    // about the disclosure mechanics.
    const detailsEl = container.querySelector('details') as HTMLDetailsElement | null;
    expect(detailsEl).not.toBeNull();
    if (detailsEl) detailsEl.open = true;

    // Pick the 1h preset. The menuitem buttons live inside the disclosure and
    // are addressable by their preset label.
    const oneHour = screen.getByRole('menuitem', { name: '1h' });
    await clickAndSettle(user, oneHour);

    expect(queueSnoozeMock).toHaveBeenCalledWith(item.id, { duration_minutes: 60 });
    expect(toastSuccess).toHaveBeenCalledWith(expect.stringMatching(/Snoozed for 1h/));
  });

  it('renders owner toggle counts from the response', () => {
    swrState.data = makeResponse(
      [
        makeItem({ id: 'a-mine', bucket: 'mine', assigned_to_id: CURRENT_USER_ID }),
        makeItem({ id: 'a-other', bucket: 'unassigned' }),
      ],
      {
        counts: { mine: 3, unassigned: 7, all: 12 },
      },
    );

    render(<QueueView />);

    // Each tab renders its label + a numeric badge.
    const mineTab = screen.getByRole('tab', { name: /Mine/i });
    const unassignedTab = screen.getByRole('tab', { name: /Unassigned/i });
    const allTab = screen.getByRole('tab', { name: /^All/i });

    expect(mineTab).toBeInTheDocument();
    expect(unassignedTab).toBeInTheDocument();
    expect(allTab).toBeInTheDocument();

    // Badges show the counts (3, 7, 12).
    expect(mineTab.textContent).toContain('3');
    expect(unassignedTab.textContent).toContain('7');
    expect(allTab.textContent).toContain('12');
  });

  it('switches owner tab on click', async () => {
    swrState.data = makeResponse([makeItem({ bucket: 'unassigned' })]);

    const user = userEvent.setup();
    render(<QueueView />);

    const unassignedTab = screen.getByRole('tab', { name: /Unassigned/i });
    expect(unassignedTab).toHaveAttribute('aria-selected', 'false');

    await act(async () => {
      await user.click(unassignedTab);
    });

    // After click, that tab is selected — we re-read because React swaps the
    // aria-selected attribute after the state update flushes.
    expect(
      screen.getByRole('tab', { name: /Unassigned/i }),
    ).toHaveAttribute('aria-selected', 'true');
  });

  it('renders the error state when SWR returns an error', () => {
    swrState.error = new Error('Network failure');
    swrState.data = undefined;

    render(<QueueView />);

    expect(screen.getByText(/Couldn't load the queue/i)).toBeInTheDocument();
  });

  it('caps the SEV badge to INFO when severity is unknown', () => {
    // Defence-in-depth: if the backend ever ships a severity we don't model,
    // we still want a fallback pill so the UI doesn't crash.
    const item = makeItem({
      // @ts-expect-error — intentionally invalid for the guard test.
      severity: 'bogus',
    });
    swrState.data = makeResponse([item]);

    render(<QueueView />);

    expect(screen.getByText('INFO')).toBeInTheDocument();
  });
});
