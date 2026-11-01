/**
 * The base catalogue. Every other locale is checked against this one.
 *
 * Wave 2, Phase 9.3. Scope is the analyst surfaces gap-closure 13.4 names,
 * not the whole console: translating 72k lines of which most is marketing
 * and admin copy would be a large diff that proves nothing, while leaving
 * the five surfaces an analyst lives in half-done.
 *
 * Keys are dotted and grouped by surface. The grouping is not decoration —
 * `scripts/check_i18n_keys.py` reports missing keys by surface, so a
 * translator is told "the alerts queue is 4 keys short" rather than handed a
 * flat list of 690.
 */

export const en = {
  common: {
    save: 'Save',
    cancel: 'Cancel',
    retry: 'Retry',
    loading: 'Loading…',
    search: 'Search',
    close: 'Close',
    export: 'Export',
    unknown: 'Unknown',
    // Rendered where a value was never measured. Distinct from "0" on
    // purpose: the honest-state rule applies to a label as much as to a
    // panel, and "0%" over an unmeasured metric is a number nobody took.
    notMeasured: 'Not measured',
  },

  nav: {
    alerts: 'Alerts',
    cases: 'Cases',
    hunt: 'Hunt',
    explore: 'Explore',
    settings: 'Settings',
  },

  alerts: {
    title: 'Alerts',
    empty: 'No alerts',
    emptyHint: 'Nothing has matched your detections in this window.',
    loadFailed: 'Could not load alerts',
    // "We could not read the queue" and "the queue is empty" are different
    // facts about a SOC, and only one of them means there is nothing to do.
    loadFailedHint: 'The queue could not be read, so this is not an empty queue.',
    severity: 'Severity',
    status: 'Status',
    assignee: 'Assignee',
    firstSeen: 'First seen',
    lastSeen: 'Last seen',
    count: '{count} alerts',
    countOne: '1 alert',
  },

  severity: {
    critical: 'Critical',
    high: 'High',
    medium: 'Medium',
    low: 'Low',
    info: 'Info',
  },

  cases: {
    title: 'Cases',
    empty: 'No cases',
    loadFailed: 'Could not load cases',
    openedAt: 'Opened',
    closedAt: 'Closed',
  },

  hunt: {
    title: 'Hunt',
    ask: 'Ask in plain English',
    run: 'Run query',
    queryShown: 'The query that ran',
    noStore: 'No store was reached',
    unsupportedFilters: 'These parts of your question were not applied',
  },

  settings: {
    title: 'Settings',
    language: 'Language',
    branding: 'Branding',
    retention: 'Retention',
    rulePacks: 'Rule packs',
    delegations: 'Delegations',
  },
} as const;

export type Messages = typeof en;
