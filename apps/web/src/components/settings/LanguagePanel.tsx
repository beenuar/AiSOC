'use client';

import { clsx } from 'clsx';
import { useLocale } from '@/components/i18n/LocaleProvider';
import {
  BASE_LOCALE,
  LOCALES,
  localeCoverage,
  surfaceCoverage,
  type LocaleCode,
} from '@/lib/i18n';

/**
 * The console's language switcher, and its honest scope statement.
 *
 * Lives in Settings beside Theme and Density because that is what it is: a
 * display preference, stored per device and synced to the profile.
 *
 * ## Why half of this component is a disclosure
 *
 * The catalogue covers the analyst surfaces, not the console. Wiring it and
 * saying nothing would translate a page header and a column heading and
 * leave the filters, the pagination and the navigation in English, which
 * reads as *more* broken than a page that was never translated at all. So
 * the switcher states its own scope, and states it by **measuring the
 * catalogue** rather than by a sentence somebody wrote once: a hand-written
 * "Alerts, Cases and Hunt are translated" is a claim that goes stale the
 * first time a surface is added, in the direction nobody checks.
 *
 * The counts are the number of strings in the catalogue, **not** a fraction
 * of the console — those are different measurements and only one of them is
 * flattering. `scopeNote` says which, because "47 of 53" sitting alone next
 * to a language name reads as "89% of the product is in Arabic", and that
 * is wildly untrue.
 */

/** Console destinations, paired with the catalogue surface that covers them. */
function ScopeRow({ label, surface }: { label: string; surface: string }) {
  const { locale, t } = useLocale();
  const { total, translated } = surfaceCoverage(locale, surface);

  // Zero of zero is not full coverage. A surface the catalogue has never
  // heard of is "not translated", never 100% — the confident-zero defect
  // reads exactly as well with a percentage on top of it.
  const state = total === 0 ? 'absent' : translated === total ? 'covered' : 'fallback';

  const tone = {
    covered: 'border-green-500/30 bg-green-500/10 text-green-300',
    fallback: 'border-amber-500/30 bg-amber-500/10 text-amber-300',
    absent: 'border-gray-700 bg-gray-800/60 text-gray-400',
  }[state];

  const badge = {
    covered: t('language.covered'),
    fallback: t('language.fallback'),
    absent: t('language.absent'),
  }[state];

  return (
    <li className="flex items-center justify-between gap-3 py-1.5">
      <span className="text-sm text-gray-300">{label}</span>
      <span className="flex items-center gap-2">
        {total > 0 && (
          <span className="text-xs tabular-nums text-gray-500">
            {t('language.coverage', { translated, total })}
          </span>
        )}
        <span className={clsx('rounded-full border px-2 py-0.5 text-xs', tone)}>{badge}</span>
      </span>
    </li>
  );
}

export function LanguagePanel() {
  const { locale, setLocale, t } = useLocale();

  return (
    <div>
      <p className="text-sm font-medium text-gray-300">{t('settings.language')}</p>
      <p className="mt-1 text-xs text-gray-500">{t('language.description')}</p>

      <div className="mt-3 grid grid-cols-2 gap-3">
        {(Object.keys(LOCALES) as LocaleCode[]).map((code) => {
          const meta = LOCALES[code];
          const { total, translated } = localeCoverage(code);
          const active = locale === code;
          return (
            <button
              key={code}
              type="button"
              lang={code}
              onClick={() => setLocale(code)}
              aria-pressed={active}
              className={clsx(
                'rounded-xl border p-3 text-start transition-colors',
                active
                  ? 'border-blue-500/60 bg-blue-500/10'
                  : 'border-gray-800 bg-gray-950/40 hover:border-gray-700',
              )}
            >
              {/*
                The endonym, never a translation of it: somebody looking for
                their own language scans for the word they would write, and
                "Arabic" is not that word for the person who needs it.
              */}
              <span className="block text-sm font-medium text-gray-100">{meta.label}</span>
              <span className="mt-1 block text-xs text-gray-500">
                {code === BASE_LOCALE
                  ? t('language.covered')
                  : t('language.coverage', { translated, total })}
              </span>
            </button>
          );
        })}
      </div>

      <div className="mt-4 rounded-xl border border-gray-800 bg-gray-950/40 p-4">
        <p className="text-sm font-medium text-gray-300">{t('language.scopeTitle')}</p>
        <p className="mt-1 text-xs leading-relaxed text-gray-500">{t('language.scopeNote')}</p>
        {/*
          Written out one destination per line rather than mapped over a
          list, so each key is a literal the reader — and the gate — can
          see. `check_i18n_keys.py` credits a key only where it is named,
          and a `t(entry.key)` loop would satisfy nothing while looking
          like it covers everything.
        */}
        <ul className="mt-3 divide-y divide-gray-800/60">
          <ScopeRow label={t('nav.alerts')} surface="alerts" />
          <ScopeRow label={t('nav.cases')} surface="cases" />
          <ScopeRow label={t('nav.hunt')} surface="hunt" />
          <ScopeRow label={t('nav.settings')} surface="settings" />
          <ScopeRow label={t('nav.explore')} surface="explore" />
        </ul>
        <p className="mt-3 text-xs text-gray-500">{t('language.contribute')}</p>
      </div>
    </div>
  );
}
