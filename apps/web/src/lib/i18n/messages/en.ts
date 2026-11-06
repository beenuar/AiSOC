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
    // Keeps the next action in the sentence. The first version of this key
    // read "Nothing has matched your detections in this window", which is
    // true and tells a first-run operator nothing about why their console
    // is empty or what to do about it — the copy it replaced on the alerts
    // queue did, so wiring the catalogue would have been a regression.
    emptyHint: 'Nothing has matched your detections yet. Connect a data source in Settings to start streaming events.',
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
    // `closedAt` was removed with the three `hunt.*` keys below: the case
    // card renders an opened timestamp and no closed one, so the label had
    // nowhere to go. It returns with the column that needs it.
  },

  // `queryShown`, `noStore` and `unsupportedFilters` were removed when the
  // catalogue was first wired: all three named controls the hunt surface
  // does not have, so they could never render. A base key nothing shows is
  // the same defect as a locale key the base lacks — invisible, and found
  // by no amount of using the console — and `check_i18n_keys.py` now fails
  // on it. They come back with the UI that needs them, not before.
  hunt: {
    title: 'Threat Hunting',
    ask: 'Ask in plain English',
    run: 'Run hunt',
  },

  settings: {
    title: 'Settings',
    language: 'Language',
    branding: 'Branding',
    retention: 'Retention',
    rulePacks: 'Rule packs',
    delegations: 'Delegations',
  },

  /**
   * The language switcher's own copy, including what it refuses to claim.
   *
   * This catalogue covers a fraction of the console's text, so a switcher
   * that silently translates a sliver reads as a *more* broken page than a
   * consistently English one. These keys exist so the switcher says so, in
   * the language the reader just chose — the person who needs the scope
   * note is precisely the one who cannot read it in English.
   *
   * A separate surface rather than more `settings.*` keys, because
   * `settings.*` is deliberately left untranslated in the pilot locale to
   * exercise the fallback on a real screen, and burying a translated string
   * in there would quietly undo that.
   */
  language: {
    description: 'Choose the language the console renders in. Stored on this device and synced to your profile.',
    scopeTitle: 'What this translates',
    scopeNote: 'Only the surfaces listed below are covered. The rest of the console stays in English whichever language you pick.',
    covered: 'Translated',
    fallback: 'Falls back to English',
    absent: 'Not translated',
    coverage: '{translated} of {total} strings',
    contribute: 'Your language missing? Add a catalogue beside the English one.',
  },
} as const;

export type Messages = typeof en;
