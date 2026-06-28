/**
 * T3.8 — Storybook 9 config for AiSOC console.
 *
 * We use the @storybook/react-vite framework instead of -nextjs because:
 *   1. Vite is dramatically faster for the design-system iteration loop
 *      (the marketing team uses Storybook screenshots in collateral).
 *   2. Most stories render pure UI primitives that never touch the
 *      Next.js router; the few that do are wrapped in a stub provider
 *      in preview.tsx instead.
 *   3. The Next.js / Vite mismatch is contained to the .storybook
 *      directory and never bleeds into the production Next build.
 *
 * Tailwind v4 is loaded via @tailwindcss/vite (registered in
 * viteFinal below) so utility classes work identically inside
 * Storybook and inside the running app.
 */
import type { StorybookConfig } from '@storybook/react-vite';
import { mergeConfig } from 'vite';

const config: StorybookConfig = {
  stories: [
    '../src/**/*.stories.@(ts|tsx|mdx)',
    '../stories/**/*.stories.@(ts|tsx|mdx)',
  ],
  addons: ['@storybook/addon-a11y', '@storybook/addon-themes'],
  framework: {
    name: '@storybook/react-vite',
    options: {},
  },
  // NOTE: We intentionally do NOT use `staticDirs: ['../public']` here,
  // AND we disable Vite's auto-detection of `apps/web/public/` in
  // `viteFinal` (`publicDir: false`). Storybook 9.1 + Node 22/24 hits a
  // `fs.cp` race in CI when copying nested directories — see
  // https://github.com/storybookjs/storybook/issues/16732 and the
  // underlying still-open Node issue
  // https://github.com/nodejs/node/issues/58947. The Vite build runs the
  // same code path: copying `public/` with overlapping subtrees races on
  // `mkdir` and fails with EEXIST on ubuntu-latest.
  //
  // None of our design-system stories actually reference `public/` assets;
  // the few app components that do (customer-logo MDX, etc.) live in the
  // Next app build path which serves `public/` natively. Disabling the
  // copy keeps the Storybook bundle hermetic and the CI build deterministic.
  typescript: {
    check: false,
    reactDocgen: 'react-docgen-typescript',
    reactDocgenTypescriptOptions: {
      shouldExtractLiteralValuesFromEnum: true,
      propFilter: (prop) => !prop.parent?.fileName.includes('node_modules'),
    },
  },
  async viteFinal(viteConfig) {
    // Use mergeConfig so we don't clobber what Storybook already wires
    // (the React plugin, JSX runtime, etc.).
    const { default: tailwindcss } = await import('@tailwindcss/vite');
    return mergeConfig(viteConfig, {
      plugins: [tailwindcss()],
      // Disable Vite's auto-copy of `apps/web/public/` into the Storybook
      // output. See the staticDirs comment above — this is what actually
      // fires the `fs.cp` EEXIST race in CI on Node 22/24.
      publicDir: false,
      resolve: {
        alias: [
          {
            // The app imports use the "@/" prefix configured by
            // tsconfig.json paths; we mirror that here so stories can
            // reuse components without rewriting imports.
            find: /^@\//,
            replacement: new URL('../src/', import.meta.url).pathname,
          },
          {
            // next/navigation is not available in the Vite-based
            // Storybook runtime. The shim below covers the surface the
            // console actually uses (useRouter().push / replace).
            find: 'next/navigation',
            replacement: new URL('./shims/next-navigation.ts', import.meta.url).pathname,
          },
          {
            // next/link is rendered as a plain <a> in stories so the
            // navigation contract doesn't matter — Storybook iframes
            // don't actually follow the link.
            find: 'next/link',
            replacement: new URL('./shims/next-link.tsx', import.meta.url).pathname,
          },
        ],
      },
    });
  },
};

export default config;
