# Theming (light & dark)

The AiSOC console ships dark-by-default and exposes a tri-state theme toggle in
the top bar (**dark → light → system → dark**). Users who pick **system** get
their OS-level `prefers-color-scheme` rendered, with live updates if they flip
their OS theme without reloading.

This page is for operators and contributors who want to know how the theme
system is wired together, why some surfaces deliberately don't flip, and how to
migrate a new component to the semantic palette.

## Overview

The theme story is intentionally minimal: one CSS-variable layer, one Tailwind
config, one `ThemeProvider`, one bootstrap script. There is no runtime CSS-in-JS
and no per-component theme branching.

| Layer | File | Purpose |
| --- | --- | --- |
| Tokens | `apps/web/src/app/globals.css` | Defines `--surface-*`, `--fg-*`, etc. for both `:root` / `[data-theme="dark"]` and `[data-theme="light"]`. |
| Tailwind | `apps/web/tailwind.config.ts` | Maps `bg-surface-*` / `text-fg-*` utilities onto the CSS variables so they flip automatically. |
| Provider | `apps/web/src/components/theme/ThemeProvider.tsx` | React context that owns the user's preference, persists it to `localStorage`, and listens to OS-level theme changes. |
| Bootstrap | `apps/web/src/components/theme/themeScript.ts` | Render-blocking inline script that resolves the theme **before first paint** to avoid FOUC. |
| Toggle | `apps/web/src/components/theme/ThemeToggle.tsx` | Tri-state button mounted in `TopBar`. |

## How it flips

1. The bootstrap script (rendered as the first child of `<body>`) reads
   `localStorage["aisoc-theme"]`, defaults to `dark`, resolves `system` against
   `prefers-color-scheme`, and writes `data-theme` + `color-scheme` onto the
   `<html>` element.
2. `<html data-theme="...">` switches which CSS-variable block is in scope.
3. Tailwind utilities like `bg-surface-card` are compiled to
   `background-color: var(--surface-card)`, so they automatically pick up the
   new value — no class swap required.
4. `ThemeProvider` (mounted in the root layout) keeps React state in sync with
   the DOM and provides `useTheme()` for components that need to render
   conditionally.

## Token reference

Use these tokens for chrome surfaces. Severity, status, and brand colours are
deliberately **theme-agnostic** so a *high-severity* alert looks the same in
both themes.

| Token | Purpose |
| --- | --- |
| `bg-surface-base` | Page background (App shell, marketing root). |
| `bg-surface-raised` | Topbar, sticky chrome. |
| `bg-surface-card` | Cards, panels, drawer bodies. |
| `bg-surface-hover` | Hover state on rows / list items. |
| `bg-surface-subtle` | Subtle inset surfaces (e.g. code blocks, JSON viewers). |
| `border-surface-border` | Container borders. |
| `border-surface-divider` | Separator lines inside cards. |
| `text-fg-primary` | Body / heading copy. |
| `text-fg-secondary` | Paragraph copy. |
| `text-fg-muted` | Captions, labels. |
| `text-fg-subtle` | Timestamps, helper text. |
| `text-fg-inverse` | Text on light buttons (rare). |

## Migrating a component

1. Replace `bg-gray-900` / `bg-gray-950` / `bg-[#…]` chrome backgrounds with
   `bg-surface-card` (or `bg-surface-raised` for sticky chrome).
2. Replace `text-white` / `text-gray-200` / `text-gray-300` with `text-fg-primary`
   or `text-fg-secondary`. Keep `text-white` only on coloured backgrounds
   (e.g. brand buttons, severity chips) where contrast is preserved.
3. Replace `border-gray-700` / `border-gray-800` with `border-surface-border`.
4. Leave `bg-brand-*`, `bg-severity-*`, `text-emerald-*`, etc. **as-is**.
   Brand and severity tokens are intentionally theme-locked.
5. Run `pnpm tsc --noEmit` and visually verify both themes via the toggle.

If a surface genuinely shouldn't flip (marketing hero with a fixed gradient,
in-canvas DAG visualisation tuned for dark mode), wrap it in a
`data-theme="dark"` (or `="light"`) boundary instead of migrating every
decorative class. The marketing landing in `apps/web/src/app/page.tsx` does
exactly this.

## Locked surfaces (today)

These surfaces are deliberately dark-only in v1 and require a follow-up to
become themable. Each one is wrapped in a `data-theme="dark"` boundary so the
toggle in the chrome doesn't make them look broken.

| Surface | Why dark-locked | Tracked under |
| --- | --- | --- |
| `/` marketing landing | Hero/Architecture/Features ride a fixed dark gradient. | WS-F1 follow-up |
| Playbook DAG canvas | `@xyflow/react` colors are tuned for dark mode. | WS-F1 follow-up |

## Why the bootstrap script is render-blocking

A pure-React theme provider has to wait for hydration before it can apply the
saved theme, which means the first frame is always rendered with the default.
Buyers in light mode would see a flash of dark before the React tree mounts —
exactly the failure mode WS-F1 was meant to eliminate. The synchronous inline
script runs *before* the browser paints, costs ~600 bytes after gzip, and is
wrapped in `try/catch` so iOS private-browsing `localStorage` failures fall
back to dark instead of crashing the page.

## Accessibility

Both palettes are tuned to meet **WCAG AA** for body copy and large text. The
WCAG AA audit (WS-F2) wires `axe-core` into the test suite to catch
regressions. See `axe-core` test files under `apps/web/src/test/a11y/`.
