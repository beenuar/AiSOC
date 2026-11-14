/**
 * Render-blocking preamble that sets the document's language and reading
 * direction before first paint.
 *
 * The same reasoning as `themeScript.ts`, and a stronger case for it.
 * Getting the theme wrong for one frame is a flash of the wrong colour;
 * getting the direction wrong for one frame is the entire page laid out
 * left-to-right and then reflowed, which is the single most visible way a
 * right-to-left console announces that it was translated rather than built.
 *
 * It also keeps the server's markup and the client's agreeing. The root
 * layout ships `lang="en" dir="ltr"`, this script corrects both before React
 * hydrates, and `suppressHydrationWarning` on `<html>` covers the gap.
 *
 * Intentionally tiny, dependency-free and try/catch-wrapped: localStorage
 * throws in iOS private browsing, and rendering left-to-right English beats
 * crashing the page.
 */
export const LOCALE_STORAGE_KEY = 'aisoc-locale';

/**
 * Duplicated from `locales.ts` on purpose.
 *
 * This string is injected into a `<script>` that runs before any module
 * loads, so it cannot import. The parity is held by a test that reads
 * `LOCALES` and asserts every code and direction in it appears here — the
 * drift this repository keeps finding is the copy nobody checked, not the
 * copy itself.
 */
export const localeBootstrapScript = `
(function () {
  try {
    var directions = { en: 'ltr', ar: 'rtl' };
    var stored = window.localStorage.getItem('${LOCALE_STORAGE_KEY}');
    var locale = Object.prototype.hasOwnProperty.call(directions, stored) ? stored : 'en';
    var root = document.documentElement;
    root.setAttribute('lang', locale);
    root.setAttribute('dir', directions[locale]);
  } catch (_) {
    document.documentElement.setAttribute('lang', 'en');
    document.documentElement.setAttribute('dir', 'ltr');
  }
})();
`.trim();
