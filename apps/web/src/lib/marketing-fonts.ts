import { VELVET_FONT_PRELOADS } from '@/fonts/preloads';

/**
 * VelvetEdge marketing fonts (T7.1).
 *
 * Applied only by the marketing surfaces — the root `app/page.tsx` landing
 * and the `(marketing)/layout.tsx` route group. Keeping the class name in
 * one shared module guarantees both consumers declare the same custom
 * properties and that the console chrome (which never imports this module)
 * stays on Inter / JetBrains Mono.
 *
 * The CSS variables this class declares resolve through the
 * `font-velvet-display` / `font-velvet-body` / `font-velvet-mono`
 * Tailwind utilities in `tailwind.config.ts`.
 *
 * The three faces used to come from `next/font/google`, which resolved them
 * over the network during `next build`. They are now vendored under
 * `apps/web/public/fonts` and declared in `src/fonts/fonts.css`, which
 * `scripts/generate_web_font_css.py` generates — same families, weights,
 * styles, unicode-ranges and fallback metrics, no build-time fetch.
 */

/**
 * Class that declares `--font-velvet-*`. Named the same as before so the two
 * call sites keep reading as "apply the marketing font variables here".
 */
export const velvetFontVariables = 'font-velvet-vars';

/**
 * Font files the marketing routes preload, reproducing the `<link rel="preload">`
 * tags `next/font/google` emitted for the two `preload: true` velvet faces.
 */
export { VELVET_FONT_PRELOADS };
