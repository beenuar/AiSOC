/**
 * The Live Feed's status pill has to describe what is on screen.
 *
 * The seeded events were gated behind `canUseDemoData()` in an earlier pass,
 * but `statusToLabel` was not. So outside the hosted demo the panel rendered
 * an empty box labelled "Demo", with a tooltip reading "showing demo data" —
 * asserting the presence of sample data that had just been correctly withheld.
 * Two different wrong answers to "is any of this real?".
 *
 * Every assertion here is on first paint. There is no error branch to hide
 * behind: an idle socket is the steady state for a fresh install, which is
 * exactly the reader most likely to be misled.
 */

import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { __setDemoModeForTests } from '@/lib/demoMode';

const channelState = vi.hoisted(() => ({
  status: 'open' as string,
  last: null as unknown,
}));

vi.mock('@/lib/realtime', () => ({
  __esModule: true,
  useRealtimeChannel: () => ({
    status: channelState.status,
    last: channelState.last,
    history: [],
    send: vi.fn(),
    reset: vi.fn(),
  }),
}));

import { LiveFeedPanel, statusToLabel } from './LiveFeedPanel';

/** A line from the seeded set, verbatim from `DEMO_EVENTS`. */
const SEEDED_TEXT = /Ransomware indicators detected on DESKTOP-7892/i;

beforeEach(() => {
  channelState.status = 'open';
  channelState.last = null;
  __setDemoModeForTests(false);
});

afterEach(() => {
  cleanup();
  __setDemoModeForTests(null);
});

describe('LiveFeedPanel outside demo mode', () => {
  it('does not label an empty feed "Demo" when the socket is open', () => {
    render(<LiveFeedPanel />);

    expect(screen.queryByText(SEEDED_TEXT)).toBeNull();
    expect(screen.getByTestId('live-feed-status').textContent).toBe('Connected');
  });

  it('does not label an empty feed "Demo" when the socket is down', () => {
    channelState.status = 'closed';

    render(<LiveFeedPanel />);

    expect(screen.queryByText(SEEDED_TEXT)).toBeNull();
    expect(screen.getByTestId('live-feed-status').textContent).toBe('Offline');
  });

  it('names what would fill the panel instead of leaving it blank', () => {
    render(<LiveFeedPanel />);

    const empty = screen.getByTestId('live-feed-empty');
    expect(empty.textContent).toMatch(/no alerts yet/i);
    expect(empty.textContent).toMatch(/connectors poll/i);
  });

  it('says the socket is down rather than that there is nothing to report', () => {
    channelState.status = 'error';

    render(<LiveFeedPanel />);

    expect(screen.getByTestId('live-feed-empty').textContent).toMatch(
      /not receiving events/i,
    );
  });

  it('never claims to be showing demo data in its tooltip', () => {
    for (const status of ['open', 'connecting', 'closing', 'closed', 'error']) {
      channelState.status = status;
      render(<LiveFeedPanel />);
      const pill = screen.getByTestId('live-feed-status');
      expect(pill.textContent, status).not.toBe('Demo');
      expect(pill.getAttribute('title') ?? '', status).not.toMatch(/demo data/i);
      cleanup();
    }
  });
});

describe('LiveFeedPanel in demo mode', () => {
  it('shows the seeded events and labels them as such', () => {
    __setDemoModeForTests(true);

    render(<LiveFeedPanel />);

    // The gate is "sample data is labelled", not "sample data is banned" —
    // the hosted demo has no backend and these events are the whole point.
    expect(screen.getByText(SEEDED_TEXT)).toBeTruthy();
    const pill = screen.getByTestId('live-feed-status');
    expect(pill.textContent).toBe('Demo');
    expect(pill.getAttribute('title')).toMatch(/seeded sample events, not tenant data/i);
    expect(screen.queryByTestId('live-feed-empty')).toBeNull();
  });
});

describe('statusToLabel', () => {
  it('only ever returns "Demo" when seeded events are actually rendered', () => {
    for (const status of ['open', 'connecting', 'closing', 'closed', 'error'] as const) {
      for (const hasReal of [true, false]) {
        const { label, tone } = statusToLabel(status, hasReal, false);
        expect(label, `${status}/${hasReal}`).not.toBe('Demo');
        expect(tone, `${status}/${hasReal}`).not.toBe('demo');
      }
    }
    expect(statusToLabel('closed', false, true).label).toBe('Demo');
  });

  it('reports a live socket carrying real events as live', () => {
    expect(statusToLabel('open', true, false).label).toBe('Live');
  });

  it('distinguishes a dropped socket that had events from one that never did', () => {
    expect(statusToLabel('closed', true, false).label).toBe('Reconnecting…');
    expect(statusToLabel('closed', false, false).label).toBe('Offline');
  });
});
