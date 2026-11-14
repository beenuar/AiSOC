/**
 * Locks in the heuristics that distinguish shipped reference packs from
 * user-created playbooks, plus the gallery filter / fork-body builders.
 * Future contributors who change PlaybookStore.create() or the pack tag
 * convention will see these tests fail.
 */

import { describe, expect, it } from 'vitest';
import type { Playbook } from './types';
import {
  isShippedPack,
  categoryOf,
  filterPlaybooks,
  countBySource,
  countByCategory,
  buildForkBody,
} from './packHelpers';

function makePlaybook(overrides: Partial<Playbook> = {}): Playbook {
  return {
    id: 'test-pack-v1',
    name: 'Test Playbook',
    description: 'Sample',
    version: '1.0.0',
    tags: [],
    trigger: { on: 'manual' },
    steps: [],
    author: 'AiSOC',
    enabled: true,
    created_at: '',
    updated_at: '',
    ...overrides,
  };
}

describe('isShippedPack', () => {
  it('classifies AiSOC-authored kebab-case ids as packs', () => {
    expect(isShippedPack(makePlaybook({ id: 'supply-vendor-breach-v1' }))).toBe(true);
  });

  it('rejects user-authored playbooks even with kebab-case ids', () => {
    expect(
      isShippedPack(makePlaybook({ id: 'my-custom-thing', author: 'alice' })),
    ).toBe(false);
  });

  it('rejects AiSOC-authored playbooks with UUID ids (treated as user copies)', () => {
    // PlaybookStore.create() generates UUIDs for forks/new playbooks.
    expect(
      isShippedPack(
        makePlaybook({ id: 'a3bb189e-8bf9-3888-9912-ace4e6543002', author: 'AiSOC' }),
      ),
    ).toBe(false);
  });

  it('rejects empty ids', () => {
    expect(isShippedPack(makePlaybook({ id: '' }))).toBe(false);
  });
});

describe('categoryOf', () => {
  it('returns the first matching category tag', () => {
    expect(categoryOf(makePlaybook({ tags: ['ransomware', 'high-severity'] }))).toBe(
      'ransomware',
    );
  });

  it('returns null when no category tag is present', () => {
    expect(categoryOf(makePlaybook({ tags: ['high-severity'] }))).toBeNull();
  });

  it('returns null when tags is missing', () => {
    expect(categoryOf(makePlaybook({ tags: [] }))).toBeNull();
  });
});

describe('filterPlaybooks', () => {
  const corpus: Playbook[] = [
    makePlaybook({ id: 'ransomware-pack-v1', tags: ['ransomware'], name: 'Ransom A' }),
    makePlaybook({ id: 'data-exfil-pack-v1', tags: ['data-exfil'], name: 'Exfil A' }),
    makePlaybook({
      id: 'a3bb189e-8bf9-3888-9912-ace4e6543002',
      author: 'alice',
      tags: ['custom'],
      name: 'My Workflow',
    }),
  ];

  it('source=pack returns only shipped packs', () => {
    const out = filterPlaybooks(corpus, { source: 'pack', category: 'all', search: '' });
    expect(out.map((pb) => pb.id)).toEqual(['ransomware-pack-v1', 'data-exfil-pack-v1']);
  });

  it('source=custom returns only non-pack playbooks', () => {
    const out = filterPlaybooks(corpus, { source: 'custom', category: 'all', search: '' });
    expect(out.map((pb) => pb.author)).toEqual(['alice']);
  });

  it('category filter narrows packs by tag', () => {
    const out = filterPlaybooks(corpus, {
      source: 'pack',
      category: 'ransomware',
      search: '',
    });
    expect(out).toHaveLength(1);
    expect(out[0].id).toBe('ransomware-pack-v1');
  });

  it('search matches name case-insensitively', () => {
    const out = filterPlaybooks(corpus, { source: 'all', category: 'all', search: 'EXFIL' });
    expect(out).toHaveLength(1);
    expect(out[0].name).toBe('Exfil A');
  });

  it('search matches tags', () => {
    const out = filterPlaybooks(corpus, { source: 'all', category: 'all', search: 'custom' });
    expect(out).toHaveLength(1);
    expect(out[0].author).toBe('alice');
  });
});

describe('counts', () => {
  it('countBySource splits packs vs custom correctly', () => {
    const corpus: Playbook[] = [
      makePlaybook({ id: 'pack-a-v1' }),
      makePlaybook({ id: 'pack-b-v1' }),
      makePlaybook({ id: 'a3bb189e-8bf9-3888-9912-ace4e6543002', author: 'bob' }),
    ];
    expect(countBySource(corpus)).toEqual({ all: 3, pack: 2, custom: 1 });
  });

  it('countByCategory only counts packs that have a recognized tag', () => {
    const corpus: Playbook[] = [
      makePlaybook({ id: 'a-v1', tags: ['ransomware'] }),
      makePlaybook({ id: 'b-v1', tags: ['ransomware'] }),
      makePlaybook({ id: 'c-v1', tags: ['data-exfil'] }),
      makePlaybook({ id: 'd-v1', tags: ['untagged'] }),
    ];
    const out = countByCategory(corpus);
    expect(out.ransomware).toBe(2);
    expect(out['data-exfil']).toBe(1);
    expect(out['account-takeover']).toBe(0);
  });
});

describe('buildForkBody', () => {
  it('clears id, marks fork in name + tags, disables, and sets author', () => {
    const original = makePlaybook({
      id: 'ransomware-pack-v1',
      name: 'Ransomware Triage',
      tags: ['ransomware'],
      enabled: true,
    });
    const body = buildForkBody(original, { author: 'alice' });

    expect(body.id).toBe('');
    expect(body.name).toBe('Ransomware Triage (fork)');
    expect(body.author).toBe('alice');
    expect(body.enabled).toBe(false);
    expect(body.tags).toContain('fork-of:ransomware-pack-v1');
    expect(body.tags).toContain('ransomware');
    expect(body.created_at).toBe('');
    expect(body.updated_at).toBe('');
  });

  it('falls back to author "you" when not provided', () => {
    const body = buildForkBody(makePlaybook({ id: 'pack-x-v1' }));
    expect(body.author).toBe('you');
  });

  it('does not duplicate the fork-of marker on chained forks', () => {
    const original = makePlaybook({
      id: 'pack-y-v1',
      tags: ['ransomware', 'fork-of:pack-y-v1'],
    });
    const body = buildForkBody(original);
    const occurrences = body.tags.filter((t) => t === 'fork-of:pack-y-v1').length;
    expect(occurrences).toBe(1);
  });
});
