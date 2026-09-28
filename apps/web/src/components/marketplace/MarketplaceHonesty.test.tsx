/**
 * A catalogue entry that cannot fire must not read like one that can.
 *
 * 6,112 of the 7,155 entries in `marketplace/index.json` — 85% — are rules
 * the detection engine does not load. The only thing distinguishing them from
 * executable content was the *absence* of a green "Verified" badge. They were
 * sorted together, described identically, and offered the same Install
 * button, which for a rule the engine never loads flips a per-tenant flag and
 * enables nothing.
 *
 * This project's standing rule is that quarantined or aspirational content is
 * never presented as executable. These assertions are that rule, applied to
 * what a reader of the catalogue actually sees.
 *
 * Both directions. A view that had simply removed the Install button, or
 * badged everything "reference only", would pass a one-sided suite and be
 * just as wrong in the other direction.
 */
import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, within } from '@testing-library/react';
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

const executable: MarketplaceItem = {
  id: 'aws-root-console-login',
  type: 'detection',
  name: 'AWS root console login',
  description: 'The root account signed in to the console.',
  version: '1.0.0',
  author: 'AiSOC',
  tags: ['cloud'],
  tier: 'stable',
  source: 'core',
  verified: true,
  enabled: true,
  category: 'cloud',
};

const referenceOnly: MarketplaceItem = {
  id: 'chronicle-a-scheduled-task-was-created',
  type: 'detection',
  name: 'a_scheduled_task_was_created',
  description: 'Detects creation of a Windows scheduled task.',
  version: '1.0.0',
  author: 'AiSOC',
  tags: ['endpoint'],
  tier: 'stable', // `stable` on purpose: the tier is provenance, not capability
  source: 'chronicle-detection-rules',
  verified: false,
  enabled: false,
  quarantine_reason: 'imported rule; upstream query language not directly executable by the AiSOC engine yet',
  category: '_quarantine',
};

beforeEach(() => {
  swrCalls.clear();
  swrCalls.set('/marketplace/index.json', {
    version: '1',
    generated: '2026-09-28T00:00:00Z',
    items: [executable, referenceOnly],
    stats: { total: 2, playbooks: 0, detections: 2, plugins: 0, verified: 1, community: 0, executable: 1, quarantined: 1 },
  });
  swrCalls.set('/api/v1/marketplace/installed', { total: 0, items: [] });
});

function cardFor(name: string): HTMLElement {
  const heading = screen.getByText(name);
  const card = heading.closest('div.flex-col');
  expect(card).not.toBeNull();
  return card as HTMLElement;
}

describe('the catalogue distinguishes what runs from what does not', () => {
  it('badges an entry the engine does not load', () => {
    render(<MarketplaceView />);
    expect(within(cardFor('a_scheduled_task_was_created')).getByText(/reference only/i)).toBeInTheDocument();
  });

  it('says on the card that it cannot fire, and why', () => {
    render(<MarketplaceView />);
    const card = cardFor('a_scheduled_task_was_created');
    expect(within(card).getByText(/cannot fire/i)).toBeInTheDocument();
    expect(within(card).getByText(/upstream query language/i)).toBeInTheDocument();
  });

  it('does not offer to install it', () => {
    render(<MarketplaceView />);
    const card = cardFor('a_scheduled_task_was_created');
    expect(within(card).queryByRole('button', { name: /^install$/i })).toBeNull();
    expect(within(card).getByText(/cannot install/i)).toBeInTheDocument();
  });

  it('still offers to install one that does run', () => {
    // The other direction. Removing the Install button everywhere would pass
    // the assertion above and break the catalogue.
    render(<MarketplaceView />);
    const card = cardFor('AWS root console login');
    expect(within(card).getByRole('button', { name: /^install$/i })).toBeInTheDocument();
  });

  it('does not badge one that does run', () => {
    render(<MarketplaceView />);
    expect(within(cardFor('AWS root console login')).queryByText(/reference only/i)).toBeNull();
  });

  it('publishes the split as a headline figure', () => {
    render(<MarketplaceView />);
    // `Total` is not the only number a reader sees: both halves of the split
    // are stat cards of their own, each with its count.
    const cards = screen.getAllByText('Executable').map((label) => label.closest('div'));
    const statCard = cards.find((card) => card?.className.includes('text-center'));
    expect(statCard).toBeTruthy();
    expect(within(statCard as HTMLElement).getByText('1')).toBeInTheDocument();
    expect(screen.getAllByText(/reference only/i).length).toBeGreaterThan(0);
  });

  it('says so in the page description rather than only in a badge', () => {
    render(<MarketplaceView />);
    expect(screen.getByText(/on disk is not the same as running/i)).toBeInTheDocument();
  });

  it('lets a reader see only what runs, and only what does not', async () => {
    const userEvent = (await import('@testing-library/user-event')).default;
    const user = userEvent.setup();
    render(<MarketplaceView />);

    await user.click(screen.getByRole('button', { name: /Executable\s*\(1\)/ }));
    expect(screen.getByText('AWS root console login')).toBeInTheDocument();
    expect(screen.queryByText('a_scheduled_task_was_created')).toBeNull();

    await user.click(screen.getByRole('button', { name: /Reference only\s*\(1\)/ }));
    expect(screen.getByText('a_scheduled_task_was_created')).toBeInTheDocument();
    expect(screen.queryByText('AWS root console login')).toBeNull();
  });

  it('shows both by default, so the catalogue is never quietly smaller than it is', () => {
    render(<MarketplaceView />);
    expect(screen.getByText('AWS root console login')).toBeInTheDocument();
    expect(screen.getByText('a_scheduled_task_was_created')).toBeInTheDocument();
  });
});
