/**
 * No machine key may reach a card as a label.
 *
 * `categories.endpoint` rendered as literal text at the bottom of 5,197
 * marketplace cards, and `tlp.white` on 878 more — the dotted form
 * `normalise_tags()` produces so that downstream code gets a `string[]`,
 * shown to a reader unchanged.
 *
 * The gate runs against the real index rather than a fixture, because the
 * thing that drifts is the data: a new importer adds a namespace, the
 * builder flattens it, and no one looks at a card again. It reads the
 * formatter's declared namespaces, so shipping a new one means deciding on a
 * label for it here first.
 *
 * Scope is `tags[]` and `category` — the two fields the card renders as
 * labels. Deliberately not `name` or `description`: those are prose, a
 * sentence may legitimately contain `winlogbeat.json` or a hostname, and a
 * gate that read them would be the false-positive machine the narrow one
 * avoids being.
 */
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import {
  formatTagLabel,
  KNOWN_TAG_NAMESPACES,
  LITERAL_DOTTED_TAGS,
  RAW_KEY_SHAPE,
} from './tagLabel';

const here = dirname(fileURLToPath(import.meta.url));
const INDEX_PATH = resolve(here, '../../../public/marketplace/index.json');

interface IndexItem {
  id: string;
  tags?: string[];
  category?: string;
  name?: string;
  description?: string;
}

const index = JSON.parse(readFileSync(INDEX_PATH, 'utf8')) as { items: IndexItem[] };

describe('the formatter', () => {
  it('turns the builder’s dotted encoding into text', () => {
    expect(formatTagLabel('categories.endpoint')).toEqual({ label: 'endpoint', title: 'categories.endpoint' });
    expect(formatTagLabel('tlp.white')).toEqual({ label: 'TLP:WHITE', title: 'tlp.white' });
    expect(formatTagLabel('data_source.osquery')).toEqual({ label: 'osquery', title: 'data_source.osquery' });
  });

  it('leaves dotted text that is not a known namespace alone', () => {
    // The other direction, and the one that matters. Satisfying the gate by
    // stripping everything before the first dot would pass every assertion
    // above and destroy each of these.
    for (const literal of ['example.com', 'winlogbeat.json', 'host.example.internal', 'v1.2.3']) {
      expect(formatTagLabel(literal).label).toBe(literal);
    }
  });

  it('leaves an undotted tag alone', () => {
    for (const plain of ['ransomware', 'kubernetes', 'runtime-security']) {
      expect(formatTagLabel(plain).label).toBe(plain);
    }
  });

  it('keeps the raw tag reachable rather than discarding it', () => {
    expect(formatTagLabel('categories.cloud').title).toBe('categories.cloud');
  });
});

describe('the shipped catalogue renders no machine keys', () => {
  it('has a label for every dotted tag namespace it ships', () => {
    const unknown = new Map<string, string>();
    for (const item of index.items) {
      for (const tag of item.tags ?? []) {
        if (!tag.includes('.') || LITERAL_DOTTED_TAGS.has(tag)) continue;
        const namespace = tag.slice(0, tag.indexOf('.'));
        if (!KNOWN_TAG_NAMESPACES.includes(namespace)) unknown.set(namespace, `${item.id} → ${tag}`);
      }
    }
    expect(
      Array.from(unknown, ([ns, where]) => `${ns} (first seen on ${where})`),
      'add a label in tagLabel.ts, or declare the tag literal',
    ).toEqual([]);
  });

  it('renders no tag that still looks like a machine key', () => {
    const leaking: string[] = [];
    for (const item of index.items) {
      for (const tag of item.tags ?? []) {
        const { label } = formatTagLabel(tag);
        if (RAW_KEY_SHAPE.test(label)) leaking.push(`${item.id} → ${tag} renders as "${label}"`);
      }
    }
    expect(leaking.slice(0, 10)).toEqual([]);
    expect(leaking).toHaveLength(0);
  });

  it('renders no category that looks like a machine key', () => {
    // The card's metadata row prints `item.category` with no formatter at
    // all, so a dotted value there would leak the same way.
    const leaking = index.items
      .filter((item) => item.category && RAW_KEY_SHAPE.test(item.category))
      .map((item) => `${item.id} → ${item.category}`);
    expect(leaking.slice(0, 10)).toEqual([]);
  });

  it('is actually looking at the shipped catalogue', () => {
    // A gate that silently read an empty array would pass forever.
    expect(index.items.length).toBeGreaterThan(1000);
    expect(index.items.some((i) => (i.tags ?? []).some((t) => t.includes('.')))).toBe(true);
  });
});
