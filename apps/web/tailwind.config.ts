import type { Config } from 'tailwindcss';

/*
 * The `surface.*` and `fg.*` palettes below resolve at runtime via CSS
 * variables defined in `src/app/globals.css`. That layer is what powers
 * the WS-F1 light theme: when `<html data-theme="light">` is set, the
 * variables flip and any `bg-surface-card`, `text-fg-primary`, etc. class
 * automatically follows — no per-component branching required.
 *
 * `brand.*`, `severity.*`, and `status.*` are deliberately theme-agnostic
 * (a "high"-severity alert should look the same in both themes).
 *
 * Migration playbook for un-themed surfaces lives in
 * `apps/docs/docs/operations/theming.md`.
 */
const config: Config = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
    '../../packages/ui/src/**/*.{js,ts,jsx,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        // Primary brand — used for CTAs, links, and active state. Aligned with the
        // logo gradient (sky-400 → blue-700) so the marketing site and console feel
        // like one product.
        brand: {
          50: '#eff6ff',
          100: '#dbeafe',
          200: '#bfdbfe',
          300: '#93c5fd',
          400: '#60a5fa',
          500: '#3b82f6',
          600: '#2563eb',
          700: '#1d4ed8',
          800: '#1e40af',
          900: '#1e3a8a',
        },
        // Surface ramp — themeable. Resolves to dark hex values on
        // `[data-theme="dark"]` and slate-tinted whites on
        // `[data-theme="light"]`.
        surface: {
          base: 'var(--surface-base)',
          raised: 'var(--surface-raised)',
          card: 'var(--surface-card)',
          hover: 'var(--surface-hover)',
          subtle: 'var(--surface-subtle)',
          border: 'var(--surface-border)',
          divider: 'var(--surface-divider)',
        },
        // Foreground ramp — themeable. `fg-primary` is the highest-contrast
        // token, `fg-subtle` is the lowest. Use these instead of raw
        // `text-white` / `text-gray-*` on chrome so the text inverts in
        // light mode.
        fg: {
          primary: 'var(--fg-primary)',
          secondary: 'var(--fg-secondary)',
          muted: 'var(--fg-muted)',
          subtle: 'var(--fg-subtle)',
          inverse: 'var(--fg-inverse)',
        },
        // Severity scale shared by alerts, cases, dashboard, and detection rules.
        // Wired to the same hex values used in `getAlertSeverityColor()` so a
        // background-class swap stays consistent with text/badge colors.
        severity: {
          critical: '#ef4444',
          high: '#f97316',
          medium: '#eab308',
          low: '#3b82f6',
          info: '#22c55e',
        },
        // Connection / health status — used by LiveFeedPanel, connector cards, etc.
        status: {
          live: '#22c55e',
          warn: '#f59e0b',
          dead: '#ef4444',
          idle: '#64748b',
        },
        // Marketing-landing accents (T6.5). Strictly additive — these live in
        // a `landing.*` namespace so they cannot collide with the console
        // palette and only appear on `apps/web/src/components/landing/`
        // surfaces. Mirrors `docs/design/landing-page-design-tokens.md` §2.3.
        landing: {
          accent: {
            ember: '#f97316',
            violet: '#8b5cf6',
          },
        },
        // VelvetEdge jewel-tone palette (T7.1). Strictly additive — these
        // live in a `velvet.*` namespace so they cannot collide with the
        // console palette and only appear on `apps/web/src/components/landing/`
        // surfaces and the magicui primitives those landing sections consume.
        // The console keeps its `surface.*` / `fg.*` / `brand.*` chrome.
        //
        // Body text is rendered against `surface-base` (#0F0F14). Per the
        // VelvetEdge spec rule 10 (WCAG AA ≥4.5:1) we ship lighter accents
        // for any colored TEXT context: mint #34D399 instead of emerald
        // #064E3B (10.67:1 vs 2.11:1), #FB7185 instead of ruby #9F1239
        // (7.07:1 vs 1.91:1), and #60A5FA instead of sapphire #1E3A8A
        // (7.65:1 vs 2.18:1). The dark base shades stay available for
        // gradient stops, fills, and borders where they look gem-like.
        velvet: {
          emerald: '#064E3B',
          'emerald-light': '#065F46',
          'emerald-mint': '#34D399',
          ruby: '#9F1239',
          'ruby-light': '#BE123C',
          'ruby-soft': '#FB7185',
          sapphire: '#1E3A8A',
          'sapphire-soft': '#60A5FA',
          'sapphire-softer': '#93C5FD',
          'surface-base': '#0F0F14',
          'surface-raised': '#181820',
          'surface-sunken': '#0A0A0E',
          'surface-overlay': '#22222E',
          'content-primary': '#F0EDF5',
          'content-secondary': '#C8C2D6',
          'content-tertiary': '#8E879E',
          border: 'rgba(176, 171, 186, 0.12)',
          'border-strong': 'rgba(176, 171, 186, 0.28)',
          success: '#34D399',
          warning: '#FBBF24',
          error: '#FB7185',
          info: '#60A5FA',
        },
      },
      backgroundImage: {
        // Three brand-tinted gradients used by the landing page only. Resolve
        // to CSS variables defined in `globals.css` so a future light-mode
        // landing variant can flip the stops without touching components.
        'landing-grad-hero': 'var(--landing-grad-hero)',
        'landing-grad-pillars': 'var(--landing-grad-pillars)',
        'landing-grad-cta': 'var(--landing-grad-cta)',
        // VelvetEdge gradients (135deg per spec components rule 3).
        'velvet-emerald-cta': 'linear-gradient(135deg, #064E3B 0%, #065F46 100%)',
        'velvet-ruby-cta': 'linear-gradient(135deg, #9F1239 0%, #BE123C 100%)',
        'velvet-sapphire-soft': 'linear-gradient(135deg, #1E3A8A 0%, #1E40AF 100%)',
        'velvet-hero-grad':
          'radial-gradient(ellipse at top, rgba(6,78,59,0.35) 0%, rgba(15,15,20,0) 60%), linear-gradient(180deg, #0F0F14 0%, #0A0A0E 100%)',
        'velvet-pillars-grad':
          'linear-gradient(135deg, rgba(6,78,59,0.18) 0%, rgba(30,58,138,0.18) 100%)',
        'velvet-cta-grad':
          'radial-gradient(ellipse at center, rgba(159,18,57,0.28) 0%, rgba(15,15,20,0) 70%), linear-gradient(135deg, #0A0A0E 0%, #0F0F14 100%)',
      },
      boxShadow: {
        // VelvetEdge jewel-tone glows (spec §Elevation). One glow color per
        // element per spec rule 2; pair these with `motion-safe:` (or wrap in
        // a `prefers-reduced-motion` media query) so the glow does not render
        // when the user opted out — see globals.css `.velvet-glow-*` helpers.
        'glow-emerald-sm': '0 0 8px rgba(6, 78, 59, 0.30)',
        'glow-emerald-md': '0 0 20px rgba(6, 78, 59, 0.40)',
        'glow-emerald-lg': '0 0 36px rgba(52, 211, 153, 0.25)',
        'glow-ruby-sm': '0 0 8px rgba(159, 18, 57, 0.30)',
        'glow-ruby-md': '0 0 20px rgba(159, 18, 57, 0.40)',
        'glow-sapphire-sm': '0 0 8px rgba(30, 58, 138, 0.30)',
        'glow-sapphire-md': '0 0 20px rgba(30, 58, 138, 0.40)',
      },
      transitionTimingFunction: {
        // Easing tokens from `docs/design/landing-page-design-tokens.md` §7.1.
        'landing-out-expo': 'cubic-bezier(0.16, 1, 0.3, 1)',
        'landing-out-quart': 'cubic-bezier(0.25, 1, 0.5, 1)',
        'landing-in-out-quad': 'cubic-bezier(0.45, 0, 0.55, 1)',
      },
      fontFamily: {
        sans: ['var(--font-inter)', 'system-ui', 'sans-serif'],
        mono: ['var(--font-mono)', 'ui-monospace', 'monospace'],
        // VelvetEdge marketing typography — opt-in only. Console chrome keeps
        // Inter / JetBrains Mono. The `--font-velvet-*` variables are declared
        // by the `font-velvet-vars` class, which only the landing `page.tsx`
        // and `(marketing)/layout.tsx` apply, so console pages neither declare
        // them nor preload the faces. All five families are self-hosted from
        // `apps/web/public/fonts` — see `src/fonts/fonts.css`.
        'velvet-display': [
          'var(--font-velvet-display)',
          'ui-serif',
          'Georgia',
          'serif',
        ],
        'velvet-body': [
          'var(--font-velvet-body)',
          'system-ui',
          '-apple-system',
          'sans-serif',
        ],
        'velvet-mono': [
          'var(--font-velvet-mono)',
          'ui-monospace',
          'SFMono-Regular',
          'monospace',
        ],
      },
    },
  },
  plugins: [],
};

export default config;
