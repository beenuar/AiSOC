/**
 * The indicator counters must know what the empty state beside them knows.
 *
 * `ThreatIntelView` already computes `storeUnknown` and uses it to write the
 * right sentence into the empty state — *"The threat-intel service did not
 * answer. This is not a report that no indicators exist."* Directly above
 * that sentence, the panel header printed `0 indicators`, and the five type
 * chips printed `All (0) IP (0) DOMAIN (0) HASH (0) URL (0)`.
 *
 * Six measured-looking zeros sitting on top of a paragraph explaining that
 * nothing was measured. The paragraph was right; the numbers were the ones
 * an analyst reads first.
 */
import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { __setDemoModeForTests } from '@/lib/demoMode';

const swrData = vi.hoisted(() => ({ value: undefined as unknown }));
const swrError = vi.hoisted(() => ({ value: undefined as unknown }));

vi.mock('swr', () => ({
  __esModule: true,
  default: () => ({
    data: swrData.value,
    error: swrError.value,
    isLoading: false,
    mutate: vi.fn(),
  }),
}));

vi.mock('@/lib/api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/api')>();
  return { ...actual, threatIntelApi: { ...actual.threatIntelApi, list: vi.fn(), lookup: vi.fn() } };
});

import { ThreatIntelView } from './ThreatIntelView';

function chipLabels(): string[] {
  return ['All', 'IP', 'DOMAIN', 'HASH', 'URL'].map((name) => {
    const btn = screen.getByRole('button', { name: new RegExp(`^${name}\\s*\\(`) });
    return (btn.textContent ?? '').trim();
  });
}

beforeEach(() => {
  swrData.value = undefined;
  swrError.value = undefined;
  __setDemoModeForTests(false);
});

afterEach(() => {
  cleanup();
  __setDemoModeForTests(null);
});

describe('an unreachable indicator store is not a count of zero', () => {
  it('does not print a zero in the panel header', () => {
    render(<ThreatIntelView />);

    expect(screen.queryByText(/^0 indicators$/)).toBeNull();
    expect(screen.getByText(/^— indicators$/)).toBeInTheDocument();
  });

  it('does not print zeros on the type chips', () => {
    render(<ThreatIntelView />);

    for (const label of chipLabels()) {
      expect(label, `"${label}" reads as a measured count`).toMatch(/\(—\)$/);
    }
  });

  it('agrees with the empty state it sits above', () => {
    render(<ThreatIntelView />);

    // The paragraph was already honest; the numbers were not.
    expect(screen.getByText(/this is not a report that no indicators exist/i)).toBeInTheDocument();
    expect(screen.getByText(/^— indicators$/)).toBeInTheDocument();
  });

  it('does not print a zero when the read failed', () => {
    swrError.value = new Error('503 Service Unavailable');

    render(<ThreatIntelView />);

    expect(screen.queryByText(/^0 indicators$/)).toBeNull();
    expect(screen.getByText(/^— indicators$/)).toBeInTheDocument();
  });

  it('still counts a genuinely empty store as zero', () => {
    // The other direction: a store that answered and holds nothing is a real
    // measurement, and an em-dash would hide it.
    swrData.value = { indicators: [], total: 0 };

    render(<ThreatIntelView />);

    expect(screen.getByText(/^0 indicators$/)).toBeInTheDocument();
    expect(screen.queryByText(/^— indicators$/)).toBeNull();
    for (const label of chipLabels()) {
      expect(label).toMatch(/\(0\)$/);
    }
  });

  it('does not print zeros when the route answered 200 but said it was degraded', () => {
    // The live shape, and the one `!data` could never catch. With no
    // threat-intel service reachable the route answers HTTP 200 with
    // `degraded: true` and a reason — an explicit non-measurement.
    swrData.value = {
      indicators: [],
      total: 0,
      degraded: true,
      reason: 'the threat-intel service did not answer (ConnectError); no indicators can be listed',
    };

    render(<ThreatIntelView />);

    expect(screen.queryByText(/^0 indicators$/)).toBeNull();
    expect(screen.getByText(/^— indicators$/)).toBeInTheDocument();
    for (const label of chipLabels()) {
      expect(label).toMatch(/\(—\)$/);
    }
    // And it says what the route said, rather than a generic sentence.
    expect(screen.getByText(/did not answer \(ConnectError\)/i)).toBeInTheDocument();
  });

  it('counts a populated store', () => {
    swrData.value = {
      indicators: [
        { id: 'i1', type: 'ip', value: '203.0.113.10', severity: 'high', confidence: 90, sources: ['feodo'], firstSeen: '2026-09-27T10:00:00Z', lastSeen: '2026-09-27T12:00:00Z' },
        { id: 'i2', type: 'domain', value: 'malicious.example', severity: 'medium', confidence: 70, sources: ['otx'], firstSeen: '2026-09-27T10:00:00Z', lastSeen: '2026-09-27T12:00:00Z' },
      ],
      total: 2,
    };

    render(<ThreatIntelView />);

    expect(screen.getByText(/^2 indicators$/)).toBeInTheDocument();
  });
});
