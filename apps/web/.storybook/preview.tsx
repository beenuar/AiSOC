/**
 * T3.8 — Storybook 9 preview config.
 *
 * Wraps every story in:
 *   1. The global stylesheet (Tailwind v4 + custom theme tokens from
 *      apps/web/src/app/globals.css).
 *   2. A theme decorator backed by @storybook/addon-themes so a reviewer
 *      can toggle between dark (default) and light to verify token
 *      coverage. The decorator sets data-theme on <html> exactly like
 *      ThemeProvider does in the running app.
 *   3. An axe-core / a11y configuration that flags AA violations by
 *      default; the addon UI surfaces them inline per story.
 */
import type { Preview, Decorator } from '@storybook/react-vite';
import { withThemeByDataAttribute } from '@storybook/addon-themes';
import React from 'react';

import '../src/app/globals.css';

const PageBackground: Decorator = (Story) => (
  <div className="min-h-screen bg-[var(--surface-base)] p-6 font-sans text-[var(--fg-primary)]">
    <Story />
  </div>
);

const preview: Preview = {
  parameters: {
    layout: 'padded',
    backgrounds: { disable: true },
    controls: {
      matchers: {
        color: /(background|color)$/i,
        date: /Date$/i,
      },
    },
    a11y: {
      element: '#storybook-root',
      config: {
        rules: [
          // Each rule below corresponds to a WCAG 2.1 AA criterion.
          { id: 'color-contrast', enabled: true },
          { id: 'label', enabled: true },
          { id: 'aria-valid-attr', enabled: true },
        ],
      },
    },
  },
  decorators: [
    withThemeByDataAttribute({
      themes: {
        dark: 'dark',
        light: 'light',
      },
      defaultTheme: 'dark',
      attributeName: 'data-theme',
    }),
    PageBackground,
  ],
};

export default preview;
