/**
 * Data-honesty gate for the IOC lookup panel.
 *
 * `LookupForm` held a `result` and a `notFound` flag, and its `catch` had
 * nowhere to put "this did not work" except the flag that means "we checked,
 * and it is clean". So every failure — a transport error, a 5xx, an endpoint
 * that does not exist — rendered a green **CLEAN · No threat indicators found
 * for this IOC**.
 *
 * It was not a latent branch. The lookup called `/api/v1/enrichment/lookup`,
 * which the API does not serve; measured against a running CORE stack that
 * path answers 404, so the panel took the `catch` on every lookup and had
 * only ever been capable of saying "clean". An analyst checking a live C2
 * address got an all-clear from a feature that had never once reached a
 * threat-intel store.
 *
 * The property under test is not that the wording changed. It is that a
 * lookup which did not complete can never render as a safety verdict, in
 * either direction: a failure must not read clean, and a genuine clean answer
 * must still read clean rather than being buried under a blanket warning.
 */

import { describe, expect, it, vi, afterEach } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const threatIntelApi = vi.hoisted(() => ({
  lookup: vi.fn(),
  list: vi.fn(),
}));

vi.mock('@/lib/api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/api')>();
  return { ...actual, threatIntelApi };
});

vi.mock('swr', () => ({
  __esModule: true,
  default: () => ({ data: undefined, error: undefined, isLoading: false, mutate: vi.fn() }),
}));

async function lookUp(value: string) {
  const { ThreatIntelView } = await import('./ThreatIntelView');
  render(<ThreatIntelView />);
  await userEvent.type(screen.getByPlaceholderText(/Enter IP, domain, hash, or URL/i), value);
  await userEvent.click(screen.getByRole('button', { name: /^Lookup$/i }));
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe('a lookup that did not complete is never a safety verdict', () => {
  it('does not render "clean" when the service could not be reached', async () => {
    threatIntelApi.lookup.mockResolvedValue({
      status: 'failed',
      reason: 'the threat-intel service could not be reached',
    });

    await lookUp('45.155.205.233');

    await waitFor(() => expect(screen.getByText(/not checked/i)).toBeInTheDocument());
    expect(screen.queryByText(/^clean$/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/No threat indicators found/i)).not.toBeInTheDocument();
  });

  it('names the indicator it did not check, so the answer cannot be read as being about it', async () => {
    threatIntelApi.lookup.mockResolvedValue({
      status: 'failed',
      reason: 'the threat-intel service answered HTTP 500',
    });

    await lookUp('45.155.205.233');

    await waitFor(() => expect(screen.getByText(/HTTP 500/)).toBeInTheDocument());
    expect(screen.getByText('45.155.205.233')).toBeInTheDocument();
    expect(screen.getByText(/never checked/i)).toBeInTheDocument();
  });

  it('does not render "clean" when the lookup call itself rejects', async () => {
    // The shape the old code could only get wrong. `catch { setNotFound(true) }`
    // is the whole defect, so this is the assertion that distinguishes the
    // fixed panel from the broken one; against the pre-fix component it finds
    // the green CLEAN badge and fails.
    threatIntelApi.lookup.mockRejectedValue(new Error('Network error talking to /api/v1/enrichment/lookup'));

    await lookUp('45.155.205.233');

    await waitFor(() => expect(screen.getByText(/not checked/i)).toBeInTheDocument());
    expect(screen.queryByText(/No threat indicators found/i)).not.toBeInTheDocument();
  });

  it('still says clean when the store answered and holds nothing', async () => {
    // The other direction. A gate that only forbids the green badge would
    // pass on a panel that had simply deleted it.
    threatIntelApi.lookup.mockResolvedValue({ status: 'clean' });

    await lookUp('8.8.8.8');

    await waitFor(() => expect(screen.getByText(/No threat indicators found/i)).toBeInTheDocument());
    expect(screen.queryByText(/not checked/i)).not.toBeInTheDocument();
  });

  it('reports a match as malicious', async () => {
    threatIntelApi.lookup.mockResolvedValue({
      status: 'match',
      indicator: {
        id: 'i-1',
        type: 'ip',
        value: '45.155.205.233',
        confidence: 91,
        severity: 'high',
        malicious: true,
        sources: ['cisa-kev'],
        description: 'Known command-and-control address',
      },
    });

    await lookUp('45.155.205.233');

    await waitFor(() => expect(screen.getByText(/Malicious indicator/i)).toBeInTheDocument());
    expect(screen.getByText(/Known command-and-control address/i)).toBeInTheDocument();
    expect(screen.queryByText(/No threat indicators found/i)).not.toBeInTheDocument();
  });
});

describe('the client turns a failed request into a failed outcome, not an empty one', () => {
  it('reports transport failure rather than resolving to no match', async () => {
    const { threatIntelApi: realApi, ApiError } = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
    const fetchMock = vi.fn().mockRejectedValue(new Error('connection refused'));
    vi.stubGlobal('fetch', fetchMock);

    const outcome = await realApi.lookup('45.155.205.233');

    expect(outcome.status).toBe('failed');
    expect(ApiError).toBeDefined();
    vi.unstubAllGlobals();
  });

  it('treats a degraded store as a failed lookup, because a partial index cannot support "we hold nothing"', async () => {
    const { threatIntelApi: realApi } = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        headers: { get: () => 'application/json' },
        json: async () => ({ indicators: [], degraded: true, reason: 'vector store unreachable' }),
        text: async () => '{}',
      }),
    );

    const outcome = await realApi.lookup('45.155.205.233');

    expect(outcome.status).toBe('failed');
    expect(outcome.status === 'failed' && outcome.reason).toMatch(/vector store unreachable/);
    vi.unstubAllGlobals();
  });
});
