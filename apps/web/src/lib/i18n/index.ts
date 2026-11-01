/**
 * Translation lookup, locale-aware formatting, and direction.
 *
 * Wave 2, Phase 9.3.
 *
 * The decisions worth stating
 * ---------------------------
 * **A missing key renders the key, not a blank.** A blank label looks like a
 * layout bug and gets filed as one; `alerts.loadFailedHint` on screen tells
 * whoever sees it exactly what to add, and is impossible to mistake for
 * finished copy. The same reasoning as the honest-state rule for panels: the
 * failure must be legible as a failure.
 *
 * **Fallback is to the base locale, then to the key.** A partially
 * translated locale is the normal state of every real deployment, so the
 * fallback path is not an edge case — the pilot locale deliberately leaves
 * `settings.*` untranslated so it is exercised by a real locale on a real
 * surface rather than only in a test.
 *
 * **Formatting goes through `Intl`, never through string templates.**
 * `${n.toFixed(1)}%` is a decimal point an Arabic or German reader does not
 * use, and a date built by concatenation is a month order that means a
 * different day somewhere else. These are the bugs that make a translated
 * console feel machine-made.
 */

import { BASE_LOCALE, LOCALES, type LocaleCode } from './locales';
import { en } from './messages/en';
import { ar } from './messages/ar';

const CATALOGUES: Record<LocaleCode, unknown> = { en, ar };

/** Walk a dotted path, returning a string only if the leaf is one. */
function lookup(catalogue: unknown, path: string): string | undefined {
  let current: unknown = catalogue;
  for (const part of path.split('.')) {
    if (typeof current !== 'object' || current === null || !(part in current)) return undefined;
    current = (current as Record<string, unknown>)[part];
  }
  return typeof current === 'string' ? current : undefined;
}

/**
 * Substitute `{name}` placeholders.
 *
 * Values are inserted as text and never parsed, so a translated string can
 * never become markup. A placeholder with no value is left **as written**
 * rather than blanked, so the gap is visible in the sentence instead of
 * producing a confident claim with a hole in it.
 */
function interpolate(template: string, values?: Record<string, string | number>): string {
  if (!values) return template;
  return template.replace(/\{(\w+)\}/g, (whole, key: string) =>
    Object.prototype.hasOwnProperty.call(values, key) ? String(values[key]) : whole,
  );
}

export function translate(
  locale: LocaleCode,
  key: string,
  values?: Record<string, string | number>,
): string {
  if (!key.trim()) {
    // A blank key is a caller bug, and returning "" would render nothing at
    // all — the one outcome indistinguishable from correct empty copy. Found
    // by a test asserting this function never returns an empty string.
    return '[missing key]';
  }

  const direct = lookup(CATALOGUES[locale], key);
  if (direct !== undefined) return interpolate(direct, values);

  const base = lookup(CATALOGUES[BASE_LOCALE], key);
  if (base !== undefined) return interpolate(base, values);

  // Neither catalogue has it. Render the key: a blank reads as a layout bug
  // and gets filed as one, while the key names exactly what is missing.
  return key;
}

/** Whether `key` exists in `locale` itself, as opposed to falling back. */
export function hasTranslation(locale: LocaleCode, key: string): boolean {
  return lookup(CATALOGUES[locale], key) !== undefined;
}

export function direction(locale: LocaleCode): 'ltr' | 'rtl' {
  return LOCALES[locale].dir;
}

// ─── Formatting ───────────────────────────────────────────────────────────

export function formatNumber(locale: LocaleCode, value: number, options?: Intl.NumberFormatOptions): string {
  return new Intl.NumberFormat(locale, options).format(value);
}

/**
 * A percentage, from a 0–1 fraction.
 *
 * Takes a fraction rather than an already-multiplied number on purpose: the
 * recorded `2100%` defect came from two surfaces disagreeing about whether a
 * confidence was 0–1 or 0–100, and a formatter that accepts either cannot
 * tell them apart.
 */
export function formatPercent(locale: LocaleCode, fraction: number, digits = 0): string {
  return new Intl.NumberFormat(locale, {
    style: 'percent',
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  }).format(fraction);
}

export function formatDate(locale: LocaleCode, value: Date | string, options?: Intl.DateTimeFormatOptions): string {
  const date = typeof value === 'string' ? new Date(value) : value;
  if (Number.isNaN(date.getTime())) {
    // An unparseable timestamp is not rendered as an epoch or as today.
    return translate(locale, 'common.unknown');
  }
  return new Intl.DateTimeFormat(locale, options ?? { dateStyle: 'medium', timeStyle: 'short' }).format(date);
}

export { BASE_LOCALE, LOCALES, isLocaleCode, negotiateLocale } from './locales';
export type { LocaleCode, LocaleMeta } from './locales';
