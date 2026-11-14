/**
 * AiEstateView — the three rendering decisions that are the page's point.
 *
 * 1. "not learned" in the colour of a finding, never a blank, for an
 *    unlinked person or device.
 * 2. A failed read says it could not load — never an empty estate, because
 *    "you have no shadow AI" is the most dangerous false sentence here.
 * 3. Nothing fabricated: the empty state names the sources that feed the
 *    list instead of inventing rows.
 *
 * SWR is mocked at the module boundary; the real fetcher's error path (throw
 * on !ok) is what the error state models.
 */
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const swrState: { data: unknown; error: unknown; isLoading: boolean } = {
  data: undefined,
  error: undefined,
  isLoading: false,
};
const mutateMock = vi.fn();

vi.mock('swr', () => ({
  __esModule: true,
  default: () => ({ data: swrState.data, error: swrState.error, isLoading: swrState.isLoading }),
  mutate: (...args: unknown[]) => mutateMock(...args),
}));

import AiEstateView from './AiEstateView';

function asset(overrides: Record<string, unknown> = {}) {
  return {
    id: 'a1',
    kind: 'coding_agent',
    externalId: 'agent-7',
    displayName: 'cursor',
    vendor: 'anysphere',
    discoverySource: 'endpoint',
    principal: 'alice@corp.example',
    device: 'MAC-0042',
    effectivePermissions: null,
    attributes: {},
    risk: 12,
    riskReasons: [],
    sanctioned: null,
    firstSeen: '2026-10-01T09:00:00Z',
    lastSeen: '2026-10-11T17:00:00Z',
    observationCount: 41,
    ...overrides,
  };
}

beforeEach(() => {
  swrState.data = undefined;
  swrState.error = undefined;
  swrState.isLoading = false;
  mutateMock.mockClear();
  vi.restoreAllMocks();
});

describe('AiEstateView', () => {
  it('loading claims nothing about the estate', () => {
    swrState.isLoading = true;
    render(<AiEstateView />);
    expect(screen.getByText('Loading the AI estate…')).toBeInTheDocument();
  });

  it('a failed read says so, and explicitly not that none exists', () => {
    swrState.error = new Error('HTTP 503');
    render(<AiEstateView />);
    expect(screen.getByText(/Could not load the AI estate/)).toBeInTheDocument();
    expect(screen.getByText(/not a report that none exists/)).toBeInTheDocument();
    expect(screen.queryByText(/No AI assets observed yet/)).not.toBeInTheDocument();
  });

  it('an empty estate names the sources that would fill it', () => {
    swrState.data = { items: [], total: 0, observedSources: [] };
    render(<AiEstateView />);
    expect(screen.getByText(/No AI assets observed yet/)).toBeInTheDocument();
    expect(screen.getByText(/if none of those is connected, this stays empty/)).toBeInTheDocument();
  });

  it('an unlinked person renders as "not learned" — a finding, not a blank', () => {
    swrState.data = {
      items: [asset({ principal: null, device: null })],
      total: 1,
      observedSources: ['provider_audit'],
    };
    render(<AiEstateView />);
    const notLearned = screen.getAllByText('not learned');
    expect(notLearned).toHaveLength(2); // person and device
    expect(notLearned[0]).toHaveAttribute('title', expect.stringContaining('No source linked a person'));
  });

  it('the source-limits legend states what each source cannot see', () => {
    swrState.data = { items: [asset()], total: 1, observedSources: ['endpoint', 'ai_runtime'] };
    render(<AiEstateView />);
    expect(screen.getByText(/knows the device and the binary. Never the model/)).toBeInTheDocument();
    expect(screen.getByText(/knows the agent, the model and the tools. Never the device/)).toBeInTheDocument();
  });

  it('sanction state renders all three ways, never a default of approved', () => {
    swrState.data = {
      items: [
        asset({ id: 'a1', sanctioned: true }),
        asset({ id: 'a2', externalId: 'agent-8', sanctioned: false }),
        asset({ id: 'a3', externalId: 'agent-9', sanctioned: null }),
      ],
      total: 3,
      observedSources: [],
    };
    render(<AiEstateView />);
    expect(screen.getByText('approved')).toBeInTheDocument();
    expect(screen.getByText('refused')).toBeInTheDocument();
    expect(screen.getByText('undecided')).toBeInTheDocument();
  });

  it('expanding a row explains the score, and an unraised score says so', async () => {
    swrState.data = { items: [asset({ risk: 12, riskReasons: [] })], total: 1, observedSources: [] };
    render(<AiEstateView />);
    await userEvent.click(screen.getByText('cursor'));
    expect(screen.getByText(/Why it scores 12/)).toBeInTheDocument();
    expect(screen.getByText('Nothing about this asset raised its score.')).toBeInTheDocument();
    expect(screen.getByText(/Seen 41 times via endpoint/)).toBeInTheDocument();
    expect(screen.getByText(/No permission snapshot was available/)).toBeInTheDocument();
  });

  it('risk reasons are listed when the score was earned', async () => {
    swrState.data = {
      items: [asset({ risk: 80, riskReasons: ['provider key with no owner', 'seen on 14 devices'] })],
      total: 1,
      observedSources: [],
    };
    render(<AiEstateView />);
    await userEvent.click(screen.getByText('cursor'));
    expect(screen.getByText('provider key with no owner')).toBeInTheDocument();
    expect(screen.getByText('seen on 14 devices')).toBeInTheDocument();
  });

  it('the sanction buttons post the decision and revalidate', async () => {
    swrState.data = { items: [asset()], total: 1, observedSources: [] };
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({}) });
    vi.stubGlobal('fetch', fetchMock);
    render(<AiEstateView />);
    await userEvent.click(screen.getByText('cursor'));
    await userEvent.click(screen.getByRole('button', { name: 'Approve' }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('/api/v1/ai-assets/a1/sanction');
    expect(JSON.parse((init as RequestInit).body as string)).toEqual({ sanctioned: true });
    await waitFor(() => expect(mutateMock).toHaveBeenCalled());
  });
});
