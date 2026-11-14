/**
 * The bulk triage bar: real writes, a surfaced preflight, and honest failure.
 *
 * Depth 9.3 (parity 5.6 remainder).
 *
 * Asserted by name below:
 *
 * * **first paint shows nothing invented** -- with no selection the bar is
 *   absent, and with a selection it shows the count the caller passed and no
 *   result text. A UI honesty test has to assert on first paint, not only on
 *   the error branch, because the error branch runs before the list does and
 *   a `data?.x ?? MOCK` is only reachable during first paint;
 * * **the button performs a real write** -- the fetch really happens, with
 *   the ids and the change the analyst chose;
 * * **the preflight 409 is surfaced, not swallowed** -- the real matched
 *   count is shown and nothing is retried automatically;
 * * **a failure renders as a failure** -- no success text, no cleared
 *   selection.
 */

import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { BulkTriageBar } from './BulkTriageBar';

const IDS = ['11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222'];

function mockFetch(impl: (url: string, init?: RequestInit) => Promise<Response>) {
  const spy = vi.fn(impl);
  vi.stubGlobal('fetch', spy as unknown as typeof fetch);
  return spy;
}

function ok(body: unknown): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } }),
  );
}

beforeEach(() => {
  vi.unstubAllGlobals();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('BulkTriageBar', () => {
  it('renders nothing when nothing is selected', () => {
    const { container } = render(
      <BulkTriageBar selectedIds={[]} onClearSelection={() => {}} onApplied={() => {}} />,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it('shows the real selection count on first paint and claims no result', () => {
    mockFetch(() => ok({}));
    render(<BulkTriageBar selectedIds={IDS} onClearSelection={() => {}} onApplied={() => {}} />);

    expect(screen.getByText('2 selected')).toBeInTheDocument();
    // Nothing has been applied, so nothing may say so. This is the first
    // paint, which is where an invented value would live.
    expect(screen.queryByText(/Updated/)).not.toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    // And no request has been made just by rendering.
    expect(fetch).not.toHaveBeenCalled();
  });

  it('refuses to apply until a change is chosen', () => {
    render(<BulkTriageBar selectedIds={IDS} onClearSelection={() => {}} onApplied={() => {}} />);
    expect(screen.getByRole('button', { name: 'Apply' })).toBeDisabled();
  });

  it('performs a real write with the chosen change and the selected ids', async () => {
    const user = userEvent.setup();
    const spy = mockFetch(() => ok({ matched_count: 2, updated_count: 2, changes: { status: 'in_progress' } }));
    const onApplied = vi.fn();
    const onClear = vi.fn();

    render(<BulkTriageBar selectedIds={IDS} onClearSelection={onClear} onApplied={onApplied} />);
    await user.selectOptions(screen.getByLabelText('Set status'), 'in_progress');
    await user.click(screen.getByRole('button', { name: 'Apply' }));

    await waitFor(() => expect(spy).toHaveBeenCalledTimes(1), { timeout: 4000 });
    const [url, init] = spy.mock.calls[0];
    expect(String(url)).toContain('/api/v1/case-depth/alerts/bulk-triage');
    const body = JSON.parse(String((init as RequestInit).body));
    expect(body.alert_ids).toEqual(IDS);
    expect(body.set_status).toBe('in_progress');
    expect(body.max_count).toBe(2);

    await screen.findByText(/Updated 2 alerts/);
    expect(onApplied).toHaveBeenCalledWith(2);
    expect(onClear).toHaveBeenCalled();
  }, 15_000);

  it('surfaces the preflight count and does not retry on its own', async () => {
    const user = userEvent.setup();
    const spy = mockFetch(() =>
      Promise.resolve(
        new Response('410 alert(s) match and max_count is 2. Nothing was changed.', { status: 409 }),
      ),
    );
    const onApplied = vi.fn();
    const onClear = vi.fn();

    render(<BulkTriageBar selectedIds={IDS} onClearSelection={onClear} onApplied={onApplied} />);
    await user.selectOptions(screen.getByLabelText('Set severity'), 'low');
    await user.click(screen.getByRole('button', { name: 'Apply' }));

    await screen.findByText(/410 alerts match and nothing was changed/);
    // Exactly one request. Retrying with a larger number on the analyst's
    // behalf would turn a deliberate guard into a formality.
    expect(spy).toHaveBeenCalledTimes(1);
    expect(onApplied).not.toHaveBeenCalled();
    expect(onClear).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Apply to all 410' })).toBeInTheDocument();
  }, 15_000);

  it('renders a failure as a failure and keeps the selection', async () => {
    const user = userEvent.setup();
    mockFetch(() => Promise.resolve(new Response('upstream exploded', { status: 500 })));
    const onApplied = vi.fn();
    const onClear = vi.fn();

    render(<BulkTriageBar selectedIds={IDS} onClearSelection={onClear} onApplied={onApplied} />);
    await user.selectOptions(screen.getByLabelText('Set status'), 'open');
    await user.click(screen.getByRole('button', { name: 'Apply' }));

    const alert = await screen.findByRole('alert');
    expect(alert).toBeInTheDocument();
    expect(screen.queryByText(/Updated/)).not.toBeInTheDocument();
    expect(onApplied).not.toHaveBeenCalled();
    // The selection survives a failure: clearing it would make the analyst
    // reselect rows whose state did not change.
    expect(onClear).not.toHaveBeenCalled();
    expect(screen.getByText('2 selected')).toBeInTheDocument();
  }, 15_000);
});
