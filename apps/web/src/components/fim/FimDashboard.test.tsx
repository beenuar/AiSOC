import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, waitFor } from '@testing-library/react';
import { SWRConfig } from 'swr';

// The SWR keys used to embed `sinceToISO(since)`, an absolute timestamp
// recomputed from `new Date()` on every render. Each render produced a new
// key, so each render fetched again: an unbounded request loop, and with the
// osquery service absent (the core profile) one error toast per attempt.

const getFimEvents = vi.fn();
const getFimSummary = vi.fn();
vi.mock('@/lib/osquery-api', () => ({
  getFimEvents: (...a: unknown[]) => getFimEvents(...a),
  getFimSummary: (...a: unknown[]) => getFimSummary(...a),
}));

const toastError = vi.fn();
vi.mock('react-hot-toast', () => ({ default: { error: (...a: unknown[]) => toastError(...a) } }));

import { FimDashboard } from './FimDashboard';

function renderDashboard() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0, shouldRetryOnError: false }}>
      <FimDashboard />
    </SWRConfig>,
  );
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe('FimDashboard', () => {
  beforeEach(() => {
    getFimEvents.mockReset();
    getFimSummary.mockReset();
    toastError.mockReset();
  });

  it('fetches once per window, not once per render, when the backend is down', async () => {
    getFimEvents.mockRejectedValue(new Error('500'));
    getFimSummary.mockRejectedValue(new Error('500'));
    renderDashboard();
    await waitFor(() => expect(getFimSummary).toHaveBeenCalled());
    await sleep(400);
    expect(getFimEvents.mock.calls.length).toBeLessThanOrEqual(1);
    expect(getFimSummary.mock.calls.length).toBeLessThanOrEqual(1);
  });

  it('fetches once per window, not once per render, when the backend answers', async () => {
    getFimEvents.mockResolvedValue({ events: [], total: 0, page: 1, page_size: 25 });
    getFimSummary.mockResolvedValue({ total_events: 0, by_action: [], top_paths: [], active_nodes: 0 });
    renderDashboard();
    await waitFor(() => expect(getFimSummary).toHaveBeenCalled());
    await sleep(400);
    expect(getFimEvents.mock.calls.length).toBeLessThanOrEqual(1);
    expect(getFimSummary.mock.calls.length).toBeLessThanOrEqual(1);
  });

  it('shows one toast per failing feed, not one per attempt', async () => {
    getFimEvents.mockRejectedValue(new Error('500'));
    getFimSummary.mockRejectedValue(new Error('500'));
    renderDashboard();
    await waitFor(() => expect(toastError).toHaveBeenCalled());
    await sleep(400);
    for (const call of toastError.mock.calls) {
      expect(call[1]).toEqual(expect.objectContaining({ id: expect.any(String) }));
    }
  });
});
