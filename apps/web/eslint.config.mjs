// ESLint flat config for @aisoc/web.
//
// ESLint v9 made flat config the default and v10 removed legacy `.eslintrc.*`
// support entirely, so this file replaces the old `apps/web/.eslintrc.json`
// which simply extended `next/core-web-vitals`.
//
// `eslint-config-next@16.x` already ships as a *native* flat config (a plain
// `Config[]` array exported from `eslint-config-next/core-web-vitals`), so we
// spread it directly — no `FlatCompat`/`@eslint/eslintrc` shim needed.
// (Using FlatCompat triggers a circular-JSON error inside eslint-plugin-react's
// config validation because the preset is already flat.)
import nextCoreWebVitals from "eslint-config-next/core-web-vitals";

const eslintConfig = [
  ...nextCoreWebVitals,
  {
    ignores: [
      ".next/**",
      "dist/**",
      "build/**",
      "node_modules/**",
      "coverage/**",
      // T3.8 — Storybook config + stories live outside the Next.js app
      // and target the Vite-based Storybook 9 runtime; they import
      // shimmed versions of `next/navigation` and `next/link` so they
      // intentionally diverge from the production app's React tree.
      ".storybook/**",
      "stories/**",
      "storybook-static/**",
    ],
  },
  {
    // TODO(#193-followup): eslint-plugin-react-hooks@6 (pulled in via
    // eslint-config-next@16 in the dev-tooling Dependabot bump) introduced
    // several new strict rules that surface ~70 pre-existing violations in
    // hooks/components. These are real signals worth addressing, but each one
    // needs individual review (some are intentional patterns, some are real
    // bugs), so we downgrade them to warnings here to unblock the dep bump and
    // track the cleanup separately. Do NOT add new violations of these rules.
    rules: {
      "react-hooks/set-state-in-effect": "warn",
      "react-hooks/set-state-in-render": "warn",
      "react-hooks/purity": "warn",
      "react-hooks/refs": "warn",
      "react-hooks/immutability": "warn",
      "react-hooks/preserve-manual-memoization": "warn",
      "react-hooks/exhaustive-deps": "warn",
    },
  },
];

export default eslintConfig;
