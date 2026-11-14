/**
 * Render-blocking preamble that resolves the active theme before first
 * paint. This is the only way to avoid a flash-of-wrong-theme — we cannot
 * wait for React hydration because the body has already been painted by
 * then.
 *
 * The script:
 *   1. reads `localStorage["aisoc-theme"]` ("light" | "dark" | "system"),
 *   2. resolves "system" against `prefers-color-scheme`, defaulting to
 *      "dark" when localStorage is empty (the historical default),
 *   3. writes the resolved theme to `<html data-theme="…">`,
 *   4. mirrors it to `<html style="color-scheme: …">` so UA chrome
 *      (scrollbars, native form controls) matches.
 *
 * Intentionally tiny + dependency-free + try/catch-wrapped: localStorage
 * can throw on iOS private browsing, and we'd rather render dark than
 * crash the page.
 */
export const THEME_STORAGE_KEY = 'aisoc-theme';

export const themeBootstrapScript = `
(function () {
  try {
    var stored = window.localStorage.getItem('${THEME_STORAGE_KEY}');
    var preference = stored === 'light' || stored === 'dark' || stored === 'system'
      ? stored
      : 'dark';
    var resolved;
    if (preference === 'system') {
      resolved = window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
    } else {
      resolved = preference;
    }
    var root = document.documentElement;
    root.setAttribute('data-theme', resolved);
    root.setAttribute('data-theme-preference', preference);
    root.style.colorScheme = resolved;
  } catch (_) {
    document.documentElement.setAttribute('data-theme', 'dark');
    document.documentElement.style.colorScheme = 'dark';
  }
})();
`.trim();
