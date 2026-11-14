# URL-backed console tabs

Date: 2026-11-11

## Problem and scope

At base `8a06f2eb51cd9f9386b840061070c92bf18c89f0`, the onboarding model
placement card links to `/settings?tab=deployment`, but Settings always
initializes its local tab to Profile. Case workspaces read `tab` only on
mount; subsequent URL changes and local tab selections can disagree.
The Responder manifest also publishes `tab=cases` and `tab=oncall` shortcuts,
while its index route redirects every request to the triage queue.

The fix covers these existing navigation contracts. Other tabbed screens
without published query-string links retain their current behavior.

## Reference and decision

| Reference | Fit and evidence | Decision |
| --- | --- | --- |
| Next.js 16.4.5, already locked by the console; MIT | `useSearchParams` reads the current router context. The App Router patches native History methods, restores the URL on history navigation, and updates that context. | Use the installed framework; add no routing dependency. |
| Existing CaseWorkspace query parsing | Validates known tabs, but stores the result in a one-time state initializer. | Share a small validated URL-tab hook with Settings instead of retaining two independent sources of truth. |
| Existing Responder child routes | Triage, cases and on-call already have their own pages. | Use those canonical paths for new shortcuts; retain a validated redirect for installed legacy shortcuts. |

The upstream implementation was read at the published `v16.4.5` tag:

- [navigation.ts](https://github.com/vercel/next.js/blob/v16.4.5/packages/next/src/client/components/navigation.ts):
  `useSearchParams`, blob `95e6d439a15bf6a14ebf01b02a46e9600636fe9f`.
- [app-router.tsx](https://github.com/vercel/next.js/blob/v16.4.5/packages/next/src/client/components/app-router.tsx):
  History integration, blob `19711d43a4a1ce2e5794d364ead9426049a7115b`.
- [License](https://github.com/vercel/next.js/blob/v16.4.5/license.md): MIT.

This uses framework APIs and references their behavior; it does not copy
upstream implementation code. A tab click adds a history entry without a
server navigation or scroll reset. It changes only `tab`, preserving other
query parameters and the fragment. Unknown or missing tabs render the
screen's default section. Selecting the already active section is a no-op.

## Verification boundary

Component regressions cover direct links, invalid parameters and updates
without remounting. Browser journey tests exercise the real Next.js router,
reload and history behavior, with backend responses isolated by the existing
network-fixture convention. Those tests establish frontend routing behavior;
they do not validate a live SOC backend, credential writes or model calls.
The defect should reproduce on the unmodified base and fail again when the
production fix is removed. Lint and type checks retain the repository's
existing configuration and dependency lockfile.
