/**
 * Translation lookup, fallback, direction and locale-aware formatting.
 *
 * Wave 2, Phase 9.3.
 *
 * The properties under test are the ones that make a translated console feel
 * built rather than machine-made:
 *
 * - a **missing key renders the key**, never a blank, because a blank label
 *   reads as a layout bug and gets filed as one;
 * - fallback goes to the base locale and is exercised by a **real locale on
 *   a real surface**, since a fallback that only runs in a test is one
 *   nobody has seen;
 * - every number and date goes through `Intl`, so a decimal separator and a
 *   month order are the reader's and not the author's;
 * - the pilot locale is right-to-left, because that is where layout breaks.
 */

import { describe, expect, it } from 'vitest';

import {
  BASE_LOCALE,
  LOCALES,
  direction,
  formatDate,
  formatNumber,
  formatPercent,
  hasTranslation,
  isLocaleCode,
  negotiateLocale,
  translate,
} from './index';

describe('translate', () => {
  it('returns the locale string when the locale has it', () => {
    expect(translate('ar', 'nav.alerts')).toBe('التنبيهات');
    expect(translate('en', 'nav.alerts')).toBe('Alerts');
  });

  it('falls back to the base locale for an untranslated key', () => {
    // `settings.*` is deliberately untranslated in the pilot locale, so this
    // is a real locale falling back on a real surface rather than a fixture.
    expect(hasTranslation('ar', 'settings.branding')).toBe(false);
    expect(translate('ar', 'settings.branding')).toBe('Branding');
  });

  it('renders the key itself when neither catalogue has it', () => {
    // A blank reads as a layout bug; the key names exactly what is missing.
    expect(translate('en', 'alerts.thisKeyDoesNotExist')).toBe('alerts.thisKeyDoesNotExist');
    expect(translate('ar', 'nope.nope')).toBe('nope.nope');
  });

  it('never returns an empty string for a missing key', () => {
    for (const key of ['', 'a', 'a.b.c.d', 'nav', 'common']) {
      expect(translate('en', key)).not.toBe('');
    }
  });

  it('does not return a parent object as a translation', () => {
    // `nav` is a group, not a string. Returning it would render "[object Object]".
    expect(translate('en', 'nav')).toBe('nav');
  });

  it('substitutes placeholders as text', () => {
    expect(translate('en', 'alerts.count', { count: 7 })).toBe('7 alerts');
  });

  it('leaves a placeholder with no value visible rather than blanking it', () => {
    // A hole in a sentence is obvious; a confident sentence with a silent
    // gap ("  alerts") is not.
    expect(translate('en', 'alerts.count')).toBe('{count} alerts');
  });

  it('inserts values as text, so a translation cannot become markup', () => {
    const out = translate('en', 'alerts.count', { count: '<script>x</script>' as unknown as string });
    expect(out).toContain('<script>');
    // It is a string, not parsed markup — React escapes it at render time;
    // what matters here is that interpolation does no parsing of its own.
    expect(typeof out).toBe('string');
  });
});

describe('locales', () => {
  it('ships a right-to-left pilot locale', () => {
    // A pilot in another LTR language proves the lookup and nothing about
    // the layout.
    expect(direction('ar')).toBe('rtl');
    expect(direction('en')).toBe('ltr');
    expect(Object.values(LOCALES).some((l) => l.dir === 'rtl')).toBe(true);
  });

  it('labels each locale in its own language', () => {
    expect(LOCALES.ar.label).toBe('العربية');
  });

  it('negotiates on the primary subtag', () => {
    expect(negotiateLocale(['ar-EG', 'en'])).toBe('ar');
    expect(negotiateLocale(['en-GB'])).toBe('en');
  });

  it('falls back to the base locale, not to an arbitrary supported one', () => {
    // "We do not have your language" should render the language the product
    // was written in.
    expect(negotiateLocale(['fr', 'de'])).toBe(BASE_LOCALE);
    expect(negotiateLocale([])).toBe(BASE_LOCALE);
  });

  it('rejects an unknown locale code', () => {
    expect(isLocaleCode('fr')).toBe(false);
    expect(isLocaleCode('en')).toBe(true);
  });
});

describe('formatting', () => {
  it('formats numbers through Intl rather than by template', () => {
    // The assertion is deliberately about grouping rather than about digit
    // glyphs. Whether `ar` renders Arabic-Indic digits depends on the ICU
    // data the runtime was built with, so asserting the glyphs would pass or
    // fail on the build rather than on this code — a test that is
    // environment-dependent is worse evidence than one that is narrower.
    // What is stable, and what actually matters, is that the output is not
    // `String(n)`.
    expect(formatNumber('en', 1234567)).toBe('1,234,567');
    expect(formatNumber('en', 1234567)).not.toBe(String(1234567));
    for (const locale of ['en', 'ar'] as const) {
      expect(formatNumber(locale, 1234567)).not.toBe(String(1234567));
    }
  });

  it('takes a fraction for a percentage, not an already-multiplied number', () => {
    // The recorded 2100% defect came from two surfaces disagreeing about
    // whether a confidence was 0-1 or 0-100. A formatter accepting either
    // cannot tell them apart, so this one accepts only the fraction.
    expect(formatPercent('en', 0.421, 1)).toBe('42.1%');
  });

  it('renders an unparseable date as unknown rather than as an epoch or today', () => {
    expect(formatDate('en', 'not-a-date')).toBe('Unknown');
  });

  it('formats a real date through Intl', () => {
    const out = formatDate('en', '2026-07-12T08:00:00Z', { dateStyle: 'medium' });
    expect(out).toContain('2026');
    expect(out).not.toContain('T08:00');
  });
});
