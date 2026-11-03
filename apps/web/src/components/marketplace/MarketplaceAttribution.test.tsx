/**
 * An imported rule must credit the person who wrote it, on the card.
 *
 * DRL-1.1, which the whole imported SigmaHQ corpus is licensed under, requires
 * author identification to travel with a shared copy. The catalogue carried
 * the source repository, the upstream path, the commit and the licence — and
 * not the author — while the item-level `author` defaulted to `AiSOC`. So the
 * console did not merely omit Tim Shelton from the rule he wrote; it showed
 * his rule credited to this project, on all 3,132 imported Sigma rules.
 * Reported as #1680 by Florian Roth, who created Sigma.
 *
 * These assertions are what a reader of the catalogue actually sees, and they
 * run in both directions: a view that printed a credit unconditionally would
 * pass a one-sided suite while inventing an author for content that has none.
 */
import { describe, expect, it, vi, beforeEach } from 'vitest';
import { fireEvent, render, screen, within } from '@testing-library/react';
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

/** The rule named in #1680, with the provenance the corpus now carries. */
const imported: MarketplaceItem = {
  id: 'sigmahq-sigma-002bdb95-0cf1-46a6-9e08-d38c128a6127',
  type: 'detection',
  name: 'WScript or CScript Dropper - File',
  description: 'Detects a file ending in jse, vbe, js, vba, vbs, wsf, wsh written by cscript.exe or wscript.exe',
  version: '1.0.0',
  author: 'Tim Shelton',
  tags: ['endpoint'],
  tier: 'imported',
  source: 'sigmahq',
  verified: false,
  enabled: true,
  executable: true,
  category: 'endpoint',
  provenance: {
    source: 'SigmaHQ/sigma',
    author: 'Tim Shelton',
    source_id: '002bdb95-0cf1-46a6-9e08-d38c128a6127',
    source_commit: 'df5c6a6',
    license: 'DRL-1.1',
    license_url: 'https://github.com/SigmaHQ/Detection-Rule-License',
    imported_at: '2026-05-04',
    upstream_path: 'rules/windows/file/file_event/file_event_win_cscript_wscript_dropper.yml',
  },
};

/** Several authors is the common case: 1,098 of the imported rules name more than one. */
const multiAuthor: MarketplaceItem = {
  ...imported,
  id: 'sigmahq-sigma-multi',
  name: 'Multi authored rule',
  author: 'frack113, Nasreddine Bencherchali (Nextron Systems)',
  provenance: { ...imported.provenance, author: 'frack113, Nasreddine Bencherchali (Nextron Systems)' },
};

/** First-party content has no upstream provenance and must gain no credit line. */
const firstParty: MarketplaceItem = {
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
  executable: true,
  category: 'cloud',
};

function seed(items: MarketplaceItem[]): void {
  swrCalls.clear();
  swrCalls.set('/marketplace/index.json', {
    version: '1',
    generated: '2026-11-03T00:00:00Z',
    items,
    stats: {
      total: items.length,
      playbooks: 0,
      detections: items.length,
      plugins: 0,
      verified: 0,
      community: 0,
      executable: items.length,
      quarantined: 0,
    },
  });
  swrCalls.set('/api/v1/marketplace/installed', { total: 0, items: [] });
}

beforeEach(() => seed([imported, firstParty]));

/**
 * Render and reveal every tier.
 *
 * The view defaults to the `stable` tier so imported content does not drown
 * the hand-authored rules, and an imported Sigma rule is tier `imported` — so
 * the fixtures keep their real tier and the test clicks through to them,
 * rather than mislabelling a Sigma import as `stable` to make it appear.
 */
function renderAllTiers(): void {
  render(<MarketplaceView />);
  fireEvent.click(screen.getByRole('button', { name: /^All tiers/ }));
}

function cardFor(name: string): HTMLElement {
  const heading = screen.getByText(name);
  const card = heading.closest('div.flex-col');
  expect(card).not.toBeNull();
  return card as HTMLElement;
}

describe('an imported rule credits its upstream author', () => {
  it('names the person who wrote it', () => {
    renderAllTiers();
    expect(within(cardFor('WScript or CScript Dropper - File')).getByText(/Tim Shelton/)).toBeInTheDocument();
  });

  it('never presents an imported rule as written by this project', () => {
    renderAllTiers();
    const card = cardFor('WScript or CScript Dropper - File');
    expect(within(card).queryByText(/written by\s+AiSOC/i)).toBeNull();
  });

  it('names the licence, because the credit without it is not the obligation', () => {
    renderAllTiers();
    expect(within(cardFor('WScript or CScript Dropper - File')).getByText('DRL-1.1')).toBeInTheDocument();
  });

  it('links to the rule at the commit we imported, not to a moving branch', () => {
    renderAllTiers();
    const link = within(cardFor('WScript or CScript Dropper - File')).getByRole('link', {
      name: 'SigmaHQ/sigma',
    });
    expect(link).toHaveAttribute(
      'href',
      'https://github.com/SigmaHQ/sigma/blob/df5c6a6/rules/windows/file/file_event/file_event_win_cscript_wscript_dropper.yml',
    );
  });

  it('keeps every co-author upstream named', () => {
    seed([multiAuthor]);
    renderAllTiers();
    const card = cardFor('Multi authored rule');
    expect(within(card).getByText(/frack113, Nasreddine Bencherchali \(Nextron Systems\)/)).toBeInTheDocument();
  });
});

describe('the credit line is not printed where there is nothing to credit', () => {
  it('adds no attribution to first-party content', () => {
    renderAllTiers();
    const card = cardFor('AWS root console login');
    expect(within(card).queryByText(/Written by/i)).toBeNull();
    expect(within(card).queryByText(/licensed under/i)).toBeNull();
  });

  it('says so plainly when upstream recorded no author, rather than inventing one', () => {
    seed([{ ...imported, author: 'SigmaHQ/sigma', provenance: { ...imported.provenance, author: null } }]);
    renderAllTiers();
    const card = cardFor('WScript or CScript Dropper - File');
    expect(within(card).getByText(/No upstream author recorded/i)).toBeInTheDocument();
    // The licence still travels, and no name is fabricated in the gap.
    expect(within(card).getByText('DRL-1.1')).toBeInTheDocument();
  });
});
