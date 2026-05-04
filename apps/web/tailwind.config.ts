import type { Config } from 'tailwindcss';

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
        // Surface ramp for the dark console. Avoid raw `gray-*` everywhere — these
        // names communicate intent (page bg, raised card, hover, divider).
        surface: {
          base: '#0a0d14',
          raised: '#11151f',
          card: '#141926',
          hover: '#1a2030',
          subtle: '#0d1119',
          border: 'rgba(148,163,184,0.12)',
          divider: 'rgba(148,163,184,0.08)',
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
      },
      fontFamily: {
        sans: ['var(--font-inter)', 'system-ui', 'sans-serif'],
        mono: ['var(--font-mono)', 'ui-monospace', 'monospace'],
      },
    },
  },
  plugins: [],
};

export default config;
