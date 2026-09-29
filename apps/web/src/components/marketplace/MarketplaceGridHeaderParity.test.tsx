/**
 * The grid must render exactly what its header says it rendered.
 *
 * `marketplace/index.json` shipped two entries whose `type:id` collided with
 * two others — `container-escape-response-v1` and
 * `suspicious-signin-response-v1` each appeared twice, once from
 * `playbooks/packs/v1/**` and once from `detections/playbooks/*.yaml`. The
 * grid keys its children on `type:id`, so two siblings shared a key.
 *
 * React does not merely warn about that. `mapRemainingChildren` keys the old
 * fibers by key, and a second fiber with the same key overwrites the first in
 * that map, so the overwritten fiber is never handed to `deleteChild`. It
 * stays mounted through every subsequent re-render. Switching the filter to
 * `Reference only` therefore left two installable playbooks in a view that by
 * definition holds only uninstallable content, and the grid rendered two more
 * children than its own header claimed.
 *
 * Counting grid children rather than asserting on names on purpose: the
 * symptom is an arithmetic disagreement between two surfaces reading the same
 * array, and that is what the assertion should be about.
 */
import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { MarketplaceItem } from './MarketplaceView';

const swrCalls = vi.hoisted(() => new Map<string, unknown>());
vi.mock('swr', () => ({
  __esModule: true,
  default: (key: string) => ({
    data: swrCalls.get(key),
    error: undefined,
    isLoading: false,
    mutate: vi.fn(async () => undefined),
  }),
}));

import { MarketplaceView } from './MarketplaceView';

function playbook(id: string, name: string): MarketplaceItem {
  return {
    id,
    type: 'playbook',
    name,
    description: 'Contains the blast radius and collects evidence.',
    version: '1.0.0',
    author: 'AiSOC',
    tags: ['ransomware'],
    tier: 'stable',
    source: 'core',
    verified: true,
  };
}

function detection(id: string, name: string, executable: boolean): MarketplaceItem {
  return {
    id,
    type: 'detection',
    name,
    description: 'Detects the technique on the host.',
    version: '1.0.0',
    author: 'AiSOC',
    tags: ['endpoint'],
    tier: 'stable',
    source: executable ? 'core' : 'chronicle-detection-rules',
    verified: executable,
    executable,
    quarantine_reason: executable ? undefined : 'upstream query language not executable by the engine yet',
    category: executable ? 'endpoint' : '_quarantine',
  };
}

/**
 * The collision the real index carried, reduced to the smallest shape that
 * reproduces it: same `type` and `id`, different `name`, both installable.
 */
const COLLIDING_A = playbook('container-escape-response-v1', 'Container Escape Response');
const COLLIDING_B = playbook('container-escape-response-v1', 'Container Escape: Runtime Breach Response');

const EXECUTABLE_RULE = detection('aws-root-console-login', 'AWS root console login', true);
const REFERENCE_RULE = detection('chronicle-scheduled-task', 'a_scheduled_task_was_created', false);

beforeEach(() => {
  swrCalls.clear();
  swrCalls.set('/api/v1/marketplace/installed', { total: 0, items: [] });
});

function setIndex(items: MarketplaceItem[]) {
  swrCalls.set('/marketplace/index.json', {
    version: '1',
    generated: '2026-09-28T00:00:00Z',
    items,
  });
}

/** The children of the card grid — what a reader actually counts on screen. */
function renderedCardCount(container: HTMLElement): number {
  const grid = container.querySelector('div.grid.grid-cols-1');
  return grid ? grid.children.length : 0;
}

/**
 * The runs-filter chip group. Scoped rather than queried globally because the
 * type filter also has a button labelled `All`.
 */
function runsFilter(container: HTMLElement) {
  const group = container.querySelector('[title^="Installable = every entry"]');
  if (!group) throw new Error('runs filter group not found');
  return within(group as HTMLElement);
}

/** The figure the sort bar publishes: `Showing N of M`. */
function headerShowingCount(): number {
  const label = screen.getByText(/Showing \d+ of \d+/);
  const m = /Showing (\d+) of (\d+)/.exec(label.textContent ?? '');
  if (!m) throw new Error(`could not parse header count from ${label.textContent}`);
  return Number(m[1]);
}

describe('the grid agrees with its own header under every filter', () => {
  it('keeps count when two entries share a type:id', async () => {
    // Every entry here is `tier: stable`, which is the default tier filter,
    // so all four are in scope before the runs filter narrows them.
    setIndex([COLLIDING_A, COLLIDING_B, EXECUTABLE_RULE, REFERENCE_RULE]);
    const user = userEvent.setup();
    const { container } = render(<MarketplaceView />);

    // `All` — the landing view.
    expect(renderedCardCount(container)).toBe(headerShowingCount());

    // `Executable` — the two playbooks plus the one loadable rule.
    await user.click(runsFilter(container).getByRole('button', { name: /^Installable\s*\(\d+\)$/ }));
    expect(renderedCardCount(container)).toBe(headerShowingCount());

    // `Reference only` — the filter where the orphaned children showed up as
    // installable playbooks inside a view of uninstallable content.
    await user.click(runsFilter(container).getByRole('button', { name: /^Reference only\s*\(\d+\)$/ }));
    expect(headerShowingCount()).toBe(1);
    expect(renderedCardCount(container)).toBe(1);

    // And back, so a stale child cannot hide behind a one-way transition.
    await user.click(runsFilter(container).getByRole('button', { name: /^All$/ }));
    expect(renderedCardCount(container)).toBe(headerShowingCount());
  });

  it('offers no Install control inside the reference-only view', async () => {
    setIndex([COLLIDING_A, COLLIDING_B, EXECUTABLE_RULE, REFERENCE_RULE]);
    const user = userEvent.setup();
    const { container } = render(<MarketplaceView />);

    await user.click(runsFilter(container).getByRole('button', { name: /^Reference only\s*\(\d+\)$/ }));

    // The whole point of the filter: nothing in it can be installed.
    expect(screen.queryAllByRole('button', { name: /^install$/i })).toHaveLength(0);
    expect(screen.queryByText('Container Escape Response')).toBeNull();
    expect(screen.queryByText('Container Escape: Runtime Breach Response')).toBeNull();
  });

  it('keeps count across the type filter too', async () => {
    setIndex([COLLIDING_A, COLLIDING_B, EXECUTABLE_RULE, REFERENCE_RULE]);
    const user = userEvent.setup();
    const { container } = render(<MarketplaceView />);

    await user.click(screen.getByRole('button', { name: /^Detections$/ }));
    expect(renderedCardCount(container)).toBe(headerShowingCount());

    await user.click(screen.getByRole('button', { name: /^Playbooks$/ }));
    expect(renderedCardCount(container)).toBe(headerShowingCount());
  });
});
