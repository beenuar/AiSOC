/**
 * Locales the console ships, and which way they read.
 *
 * Wave 2, Phase 9.3.
 *
 * Deliberately no i18n library. The console needs a lookup, a fallback and a
 * direction; a runtime dependency for that would add a resolution chain,
 * a provider and a bundle cost to replace about forty lines. If pluralisation
 * rules or message interpolation grow past what `Intl` gives, that is the
 * point to reconsider — and it is a smaller change than removing a library
 * already wired through every component.
 *
 * `dir` is metadata rather than a guess from the language tag, because the
 * mapping is not derivable: Kurdish is written both ways depending on script.
 */

export type LocaleCode = 'en' | 'ar';

export interface LocaleMeta {
  code: LocaleCode;
  /** Endonym: what speakers call the language, which is what they look for. */
  label: string;
  dir: 'ltr' | 'rtl';
}

export const LOCALES: Record<LocaleCode, LocaleMeta> = {
  en: { code: 'en', label: 'English', dir: 'ltr' },
  /**
   * The pilot locale is deliberately **right-to-left**.
   *
   * A pilot in another left-to-right language proves the lookup works and
   * nothing about the layout. RTL is where a console breaks: hardcoded
   * `margin-left`, chevrons that point the wrong way, truncation from the
   * wrong end. Choosing it as the pilot means those are found now rather
   * than by the first customer who needs them.
   */
  ar: { code: 'ar', label: 'العربية', dir: 'rtl' },
};

export const BASE_LOCALE: LocaleCode = 'en';

export function isLocaleCode(value: string): value is LocaleCode {
  return Object.prototype.hasOwnProperty.call(LOCALES, value);
}

/**
 * Pick the best supported locale for a list of preferences.
 *
 * Matches on the primary subtag, so `ar-EG` resolves to `ar`. Unknown
 * preferences fall through to the base rather than to the first supported
 * locale, because "we do not have your language" should render the language
 * the product was written in, not an arbitrary other one.
 */
export function negotiateLocale(preferred: readonly string[]): LocaleCode {
  for (const candidate of preferred) {
    const primary = candidate.toLowerCase().split('-')[0];
    if (isLocaleCode(primary)) return primary;
  }
  return BASE_LOCALE;
}
