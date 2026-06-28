# ADR-0004 — Live demo: replace the Cloudflare Tunnel with an always-on Fly.io deploy via the managed-mode pipeline

- **Status:** accepted
- **Date:** 2026-06-28
- **Decision-makers:** Beenu Arora (founder), AiSOC core team
- **Plan reference:** [AiSOC missing pieces plan](../../plans/aisoc-missing-pieces/aisoc_missing_pieces_plan.md) §5.4; [README.md](../../README.md) "Try it live" section.

## Context

`tryaisoc.com/dashboard` is the live product demo. Today it is served by a **Cloudflare Tunnel fronting a self-hosted instance on a maintainer's box**. The README is honest about this:

> "the demo at tryaisoc.com is a self-hosted instance fronted by a Cloudflare Tunnel — when it's reachable, the stack is running locally on a maintainer's box. It can therefore go offline at any time."

For a security product the demo going dark looks **worse** than no demo. Prospects who hit the CTA on the landing page and see a connection timeout assume the product itself is broken. Telemetry over the last two quarters shows the tunnel was down for ~6% of business hours (single laptop, single network, single maintainer's calendar).

We need to pick:

- **(a)** Invest in a real always-on deploy and keep the live-demo CTA on the landing page.
- **(b)** Remove the live-demo CTA and route to a hosted screencast (the 90-second video shipped in Phase 4.3).

The Phase 4.3 screencast already exists. The Phase 4.2 managed-mode pipeline already exists. So neither path is greenfield.

## Decision

We **invest in a real always-on Fly.io deploy that mirrors the managed-mode pipeline**, and keep the live-demo CTA on the landing page. The Cloudflare Tunnel is retired.

Concretely:

1. We provision a dedicated managed-mode tenant called **`demo`** on `tryaisoc.com/dashboard` using the auto-provision pipeline shipped in Phase 4.2. The tenant manifest lives at `infra/fly/managed/tenants/demo.yaml` and is owned by AiSOC core, not by Cyble customer-success.
2. The `demo` tenant gets its own Fly app stack (API + realtime + web), its own Fly Postgres, and its own Fly Redis — same shape as a real managed tenant. The only difference is the seed data: the tenant is seeded with a deterministic fixtures set (the same one the screencast records against) on every redeploy.
3. We add a **nightly GitHub Actions job** (`.github/workflows/demo-reseed.yml`) that runs `flyctl ssh console` against the demo tenant and reseeds it from `services/api/app/demo/seed.py`. The reseed is idempotent: deletes existing demo data, repopulates with the canonical scenario. This protects the demo from drifting into "every prospect sees a different broken state" after enough hands have poked at it.
4. **Both surfaces live side-by-side**: the landing CTA links to `/dashboard` (live), and the same section embeds the 90-second screencast as a fallback. If the deploy is ever down, the screencast still plays.
5. The README's "demo lives at" copy gets updated to drop the Cloudflare Tunnel disclaimer and replace it with the demo-tenant SLO ("we target 99.9% reachability on the demo dashboard; if it's not, the screencast below is the fallback").

## Consequences

### Code / infra changes that land alongside this ADR

- `infra/fly/managed/tenants/demo.yaml` (new) — tenant manifest for the always-on demo.
- `.github/workflows/demo-reseed.yml` (new) — nightly reseed.
- `services/api/app/demo/seed.py` (new) — deterministic fixture seeder (alerts, cases, playbook runs, hunt history).
- `apps/web/src/components/landing/Hero.tsx` — keep the `/dashboard` CTA, add an embedded screencast fallback.
- `README.md` — rewrite the "Try it live" callout per the SLO framing above.
- `apps/web/public/_redirects` — point `tryaisoc.com/signup` at `cyble.com/contact-us/` (already in place per workspace memory; no change).
- `docs/runbooks/demo-tenant-down.md` (new) — operator runbook for when the demo tenant goes red.

### Sales / marketing posture

- The landing CTA is "real product, live data, deterministic scenario". This is the strongest possible first-touch for a security product.
- Prospects who hit a slow point in the demo can still watch the screencast in-page; no dead-end UX.
- We are no longer apologising in the README for the demo going dark.

### Operational cost

- Fly Postgres + Redis for one demo tenant: ~$25/month at the smallest VM sizes.
- The reseed job: free (GitHub Actions Linux minutes are unlimited on this org for OSS workflows).
- Engineering time: the managed-mode pipeline already exists, so the marginal work is ~1 day to write the manifest, the seed script, and the reseed workflow.

### Roadmap

- A future "guided demo tour" overlay on the dashboard (à la Stripe's product walkthrough) is out of scope. The deterministic scenario plus the screencast is enough first-touch surface.

## Alternatives considered

1. **Remove the live-demo CTA, point only at the screencast.**
   - Rejected: for a security product, "real product you can click" is the strongest possible first-touch. Removing it gives up the headline differentiator.
2. **Keep the Cloudflare Tunnel and improve its uptime.**
   - Rejected: the failure mode is structural (single laptop, single network). No amount of tunnel-config polish fixes "the maintainer is asleep". The tunnel was a v0 expedient and has served its purpose.
3. **Deploy demo to Render / Vercel instead of Fly.io.**
   - Rejected: managed mode is already on Fly. Splitting the deploy target across two platforms doubles the operator surface for no win.
4. **Make the demo tenant on Fly but skip the nightly reseed (let demo data accumulate).**
   - Rejected: enough prospect interaction will eventually push the dashboard into states the screencast doesn't show. The deterministic reseed is the cheap way to keep the first-touch surface predictable.

## Open questions

- Should the demo tenant route to a synthetic `analyst@tryaisoc.com` SSO identity, or accept any GitHub login (read-only)? Default for v1: any GitHub login, read-only; surface the limitation in a banner.
- Reseed cadence: nightly is the default, but if we see prospects mid-demo lose data we may need to drop to weekly + add a "reset my session" button. Revisit after the first 30 days of telemetry.

## Supersedes / superseded by

- Supersedes: the Cloudflare-Tunnel demo arrangement described in README §"Try it live".
- Superseded by: none.
