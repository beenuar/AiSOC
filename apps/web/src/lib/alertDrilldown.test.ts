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
});