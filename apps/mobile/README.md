# AiSOC Responder (native)

Approve or deny a containment from a phone.

## What this is, and what it is not

The responder console **already exists** as a PWA at `apps/web/src/app/(responder)/`
— nine routes, a service worker with per-route caching strategies, an
IndexedDB offline approval queue replayed via Background Sync, Web Push with
VAPID end to end, and passkey authentication. It works.

The roadmap called the mobile console "not started", which was true only in
the narrow sense that no React Native code existed. It was misleading about
the product: the capability shipped, as a PWA.

So this app is a **distribution channel**, not a new capability. It buys three
things the PWA cannot:

1. **Reliable iOS push.** Web Push on iOS requires the PWA to have been
   installed to the home screen and has been unreliable even then. For a
   product whose promise is "decide from your phone", a notification that
   sometimes does not arrive is the same as the feature not existing. This is
   the reason the app exists.
2. **App Store and Play presence**, which is how a SOC actually deploys
   software to analyst phones.
3. **Native biometrics** beyond what WebAuthn exposes.

## What has been verified, and what has not

Be clear about this, because the distinction matters for anyone picking the
app up:

| | |
|---|---|
| `src/lib/**` unit tests | **Run in CI.** Session handling, push registration, approval presentation. |
| `tsc --noEmit` | **Run in CI.** |
| Built for a device | **No.** No Expo build, no simulator, no store submission has been performed. |
| Push delivered to a real handset | **No.** APNs and FCM credentials are an account action, the same class of blocker as the npm and PyPI publish. |

The logic that could be tested without a device was written so that it could
be: storage, the device-token provider and the API client are all injected,
so `src/lib` runs under plain Node. The screens are deliberately thin over it.

## Why it is outside the pnpm workspace

`pnpm-workspace.yaml` excludes `apps/mobile`. React Native needs Metro rather
than Turbopack and brings its own Expo dependency tree; folding that into the
root lockfile adds roughly 3,700 lines and several hundred megabytes of
`node_modules` to **every** TypeScript CI job — the web build, Storybook, the
SDK tests — none of which can use any of it.

It installs and builds on its own, and it will ship through an app store
rather than through this repository's npm publish.

## Running it

```bash
cd apps/mobile
pnpm install
pnpm start          # then press i or a, or scan the QR code
```

Point it at your API by editing `expo.extra.apiBaseUrl` in `app.json`, or set
it per-environment with an `app.config.ts`. It defaults to
`http://localhost:8000`, which is what `make up` serves.

```bash
pnpm test           # src/lib unit tests
pnpm typecheck
```

## The SDK

The app uses `@aisoc/sdk`, which is React-Native-safe by construction: one
runtime dependency, no Node builtins, `fetch` and `URL` from the global scope.

v9.0 added the namespaces a responder needs — `approvals`, `push`, `onCall`,
`liveActions` — and fixed `AiSOCClientOptions.fetch`, which was documented and
never threaded through. That last one matters specifically here: React
Native's `fetch` is not the object the SDK module closed over at import time.

## Two deliberate behaviours

**Approving asks for biometrics; denying does not.** A phone picked up off a
desk should not be able to take a production host off the network. Denying is
the safe direction, and friction on it means an analyst trying to *stop* an
action has to fight the UI.

**The result is read back from the row, not from the button that was tapped.**
The API carries a decision through to the execution service and records
whether it ran. A screen that renders "Approved" for a dispatch that failed
tells an analyst the host is contained when it is not — which is the exact
failure v9.0 exists to remove. `outcomeOf()` in `src/lib/approvals.ts` is
where that lives, and it has a test named for it.
