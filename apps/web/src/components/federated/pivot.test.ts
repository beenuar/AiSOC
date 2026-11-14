/**
 * Pivot extraction from a federated SIEM row.
 *
 * The rule under test is conservative on purpose: recognise the field names we
 * actually know, and offer no pivot for anything else. A pivot on the wrong
 * entity is worse than no pivot — it widens the analyst's picture with an
 * unrelated node while looking exactly like a correct one.
 */

import { describe, expect, it } from 'vitest';
import { pivotPathForValue, pivotableFields } from './pivot';

describe('pivotableFields', () => {
  it('recognises the same entity across three vendors field-naming styles', () => {
    expect(pivotableFields({ src_ip: '10.0.0.7' })).toEqual([{ type: 'ip', value: '10.0.0.7' }]);
    expect(pivotableFields({ 'source.ip': '10.0.0.7' })).toEqual([{ type: 'ip', value: '10.0.0.7' }]);
    expect(pivotableFields({ SourceIP: '10.0.0.7' })).toEqual([{ type: 'ip', value: '10.0.0.7' }]);
  });

  it('pulls host, user, ip and domain out of one wide row', () => {
    const targets = pivotableFields({
      hostname: 'WIN-DC01',
      'user.name': 'svc_backup',
      dest_ip: '198.51.100.9',
      fqdn: 'updates.example.test',
    });

    expect(targets).toEqual([
      { type: 'host', value: 'WIN-DC01' },
      { type: 'user', value: 'svc_backup' },
      { type: 'ip', value: '198.51.100.9' },
      { type: 'domain', value: 'updates.example.test' },
    ]);
  });

  it('does not treat every field containing "ip" as an address', () => {
    // `zip`, `recipient` and `description` all contain "ip". A substring
    // heuristic would offer three wrong pivots for this row.
    const targets = pivotableFields({
      zip: '94107',
      recipient: 'ops@example.test',
      description: 'ip allowlist updated',
    });

    expect(targets).toEqual([]);
  });

  it('offers nothing for an unrecognised column', () => {
    expect(pivotableFields({ some_vendor_specific_column: 'value' })).toEqual([]);
  });

  it('skips vendor placeholders that would pivot to a node that cannot exist', () => {
    for (const placeholder of ['-', 'null', 'N/A', 'unknown', '(null)', '   ']) {
      expect(pivotableFields({ host: placeholder }), placeholder).toEqual([]);
    }
  });

  it('skips non-scalar and over-long values', () => {
    expect(pivotableFields({ host: { nested: true } })).toEqual([]);
    expect(pivotableFields({ host: 'x'.repeat(256) })).toEqual([]);
    // A numeric identifier is still an identifier.
    expect(pivotableFields({ host: 42 })).toEqual([{ type: 'host', value: '42' }]);
  });

  it('de-duplicates the same entity reached through two column names', () => {
    const targets = pivotableFields({ src: '10.0.0.7', src_ip: '10.0.0.7' });
    expect(targets).toEqual([{ type: 'ip', value: '10.0.0.7' }]);
  });

  it('caps the chip count so a wide row does not become a wall of links', () => {
    const wide = {
      host: 'h1',
      user: 'u1',
      src_ip: '10.0.0.1',
      domain: 'a.example.test',
      computer: 'h2',
      account: 'u2',
      dest_ip: '10.0.0.2',
    };
    expect(pivotableFields(wide)).toHaveLength(4);
    expect(pivotableFields(wide, 2)).toHaveLength(2);
  });
});

describe('pivotPathForValue', () => {
  it('targets the route the Investigation Rail entity chips already use', () => {
    expect(pivotPathForValue('host', 'WIN-DC01')).toBe('/graph?entity=host%3AWIN-DC01');
  });

  it('encodes exactly once, so a value with a slash or space survives', () => {
    expect(pivotPathForValue('user', 'CORP\\svc backup')).toBe(
      '/graph?entity=user%3ACORP%5Csvc%20backup',
    );
    const url = new URL(pivotPathForValue('user', 'CORP\\svc backup'), 'https://example.test');
    expect(url.searchParams.get('entity')).toBe('user:CORP\\svc backup');
  });
});
