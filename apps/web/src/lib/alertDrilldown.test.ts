import { describe, expect, it } from 'vitest';
import { mergeAlertFiltersFromUrl, readAlertDrilldown } from './alertDrilldown';

const get = (query: string) => {
  const params = new URLSearchParams(query);
  return (name: string) => params.get(name);
};

describe('readAlertDrilldown', () => {
  it('parses paging, search, and disposition query params with validation', () => {
    const { filters, viewMode } = readAlertDrilldown({
      get: get('view=alerts&page=3&pageSize=50&search=powershell&disposition=needs_review'),
    });
    expect(viewMode).toBe('alerts');
    expect(filters).toEqual({
      page: 3,
      pageSize: 50,
      search: 'powershell',
      disposition: 'needs_review',
    });
  });

  it('accepts page_size as an alias for pageSize', () => {
    expect(readAlertDrilldown({ get: get('page_size=100') }).filters.pageSize).toBe(100);
  });

  it('rejects invalid paging and queue values', () => {
    const { filters } = readAlertDrilldown({
      get: get('page=0&pageSize=15&search=&disposition=any&disposition=bad%20space'),
    });
    expect(filters.page).toBeUndefined();
    expect(filters.pageSize).toBeUndefined();
    expect(filters.search).toBeUndefined();
    expect(filters.disposition).toBeUndefined();
  });

  it('applies queue params from the URL without dropping unspecified defaults', () => {
    const merged = mergeAlertFiltersFromUrl(
      { page: 1, pageSize: 25, sort: 'priority' },
      readAlertDrilldown({ get: get('view=alerts&pageSize=50') }),
    );
    expect(merged).toEqual({ page: 1, pageSize: 50, sort: 'priority' });
  });

  it('clears stale local fields when the URL no longer carries them', () => {
    const merged = mergeAlertFiltersFromUrl(
      { page: 1, pageSize: 25, sort: 'priority', severity: 'critical', unresolvedOnly: true },
      readAlertDrilldown({ get: get('view=alerts') }),
    );
    expect(merged).toEqual({ page: 1, pageSize: 25, sort: 'priority' });
  });

  it('still parses drilldown posture filters', () => {
    const { filters } = readAlertDrilldown({
      get: get('severity=critical&status=escalated&unresolved_only=true&created_within_hours=24'),
    });
    expect(filters).toMatchObject({
      severity: 'critical',
      status: 'escalated',
      unresolvedOnly: true,
      createdWithinHours: 24,
    });
  });

  it('restores an exact entity value including URL punctuation and opens the Alerts tab', () => {
    const params = new URLSearchParams({ entity_type: 'url', entity_value: 'https://example.test/a?x=1&y=two+three#part' });
    expect(readAlertDrilldown(params)).toEqual({
      filters: { entityType: 'url', entityValue: 'https://example.test/a?x=1&y=two+three#part' },
      viewMode: 'alerts',
    });
    expect(readAlertDrilldown(new URLSearchParams({ entity_value: '  WIN-01  ' })).filters)
      .toEqual({ entityValue: 'WIN-01' });
  });

  it.each([
    { entity_type: 'unknown', entity_value: 'WIN-01' },
    { entity_type: '__proto__', entity_value: 'WIN-01' },
    { entity_type: 'host', entity_value: '  ' },
    { entity_type: 'host', entity_value: '' },
    { entity_type: 'host', entity_value: 'x'.repeat(2049) },
  ])('ignores an invalid entity pair together: $entity_type', (params) => {
    expect(readAlertDrilldown(new URLSearchParams(params)).filters).toEqual({});
  });

  it('clears both stale entity fields when removed from the live URL', () => {
    expect(mergeAlertFiltersFromUrl(
      { page: 1, entityType: 'host', entityValue: 'WIN-01', sort: 'priority' },
      readAlertDrilldown(new URLSearchParams('view=alerts')),
    )).toEqual({ page: 1, sort: 'priority' });
  });
});
