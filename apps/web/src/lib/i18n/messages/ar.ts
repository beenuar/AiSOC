/**
 * Arabic — the pilot locale, chosen because it is right-to-left.
 *
 * Wave 2, Phase 9.3. A pilot in another left-to-right language would prove
 * the lookup works and nothing about the layout; RTL is where a console
 * breaks.
 *
 * This is a **deep partial**, and that is a deliberate, stated position
 * rather than an unfinished one. `settings.*` is left untranslated so the
 * fallback path is exercised by a real locale on a real surface — a fallback
 * that only ever runs in a test is a fallback nobody has seen. The gate
 * reports exactly which keys are missing, so the gap is a number an operator
 * can read rather than a surprise in production.
 */

import type { Messages } from './en';

/**
 * Same shape as the base catalogue, with plain strings at the leaves.
 *
 * `en` is declared `as const`, so a naive `DeepPartial<Messages>` would
 * require each translated value to be the *literal English string* — the
 * type error reads as "'حفظ' is not assignable to type 'Save'", which is
 * correct and useless. This maps string leaves to `string` while keeping the
 * key structure, so a misspelt or invented key is still a type error.
 */
type Translation<T> = { [K in keyof T]?: T[K] extends string ? string : Translation<T[K]> };

export const ar: Translation<Messages> = {
  common: {
    save: 'حفظ',
    cancel: 'إلغاء',
    retry: 'إعادة المحاولة',
    loading: 'جارٍ التحميل…',
    search: 'بحث',
    close: 'إغلاق',
    export: 'تصدير',
    unknown: 'غير معروف',
    notMeasured: 'غير مُقاس',
  },

  nav: {
    alerts: 'التنبيهات',
    cases: 'الحالات',
    hunt: 'التصيّد',
    explore: 'استكشاف',
    settings: 'الإعدادات',
  },

  alerts: {
    title: 'التنبيهات',
    empty: 'لا توجد تنبيهات',
    emptyHint: 'لم يطابق أي شيء قواعد الكشف في هذه الفترة.',
    loadFailed: 'تعذّر تحميل التنبيهات',
    loadFailedHint: 'تعذّرت قراءة قائمة التنبيهات، لذا فهي ليست قائمة فارغة.',
    severity: 'الخطورة',
    status: 'الحالة',
    assignee: 'المسؤول',
    firstSeen: 'أول ظهور',
    lastSeen: 'آخر ظهور',
    count: '{count} تنبيهات',
    countOne: 'تنبيه واحد',
  },

  severity: {
    critical: 'حرج',
    high: 'عالٍ',
    medium: 'متوسط',
    low: 'منخفض',
    info: 'معلومات',
  },

  cases: {
    title: 'الحالات',
    empty: 'لا توجد حالات',
    loadFailed: 'تعذّر تحميل الحالات',
    openedAt: 'فُتحت',
    closedAt: 'أُغلقت',
  },

  hunt: {
    title: 'التصيّد',
    ask: 'اسأل بلغة طبيعية',
    run: 'تشغيل الاستعلام',
    queryShown: 'الاستعلام الذي نُفِّذ',
    noStore: 'لم يتم الوصول إلى أي مخزن',
    unsupportedFilters: 'لم تُطبَّق هذه الأجزاء من سؤالك',
  },
};
