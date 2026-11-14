# Six technical blog outlines

Each maps to a shipped phase and ends with a reproducible command a reader can
run. Keep them engineering-first; the CTA is "run this", not "book a demo".

---

## 1. "A verdict on every alert in 60 seconds, offline" (W1 — the CLI)

- The problem: time-to-value for a SOC tool is measured in days.
- The wedge: `npx aisoc triage --demo` — deterministic, zero-dep, <1s.
- How the verdict engine works: the additive weight stack, the four bands, the
  [0.05, 0.95] clamp, and why it's deliberately not a black box.
- Parity: how the TS port is pinned to the Python server via a test.
- The BYO-key LLM band, and why it's never proxied.
- **Run it:** `npx aisoc triage --demo`

## 2. "Publishing a redacted investigation replay" (W3 — the screenshot loop)

- Why analysts don't share their work: it leaks environment detail.
- The pre-publish redaction diff: what becomes `HOST_1` / `USER_2`, what stays
  (public IOCs, ATT&CK techniques) and why.
- The immutability guarantee (DB trigger) and the non-RLS public read.
- The OG image pipeline for unfurls.
- **Run it:** publish a demo run and open `/r/demo-lockbit` **on your own
  deployment** — replays are served by the instance that produced them, so on a
  local stack that is `http://localhost:3000/r/demo-lockbit`. There is no hosted
  public instance, so a `tryaisoc.com/r/demo-lockbit` link in the copy would 404.

## 3. "Grading your ATT&CK coverage in the browser" (W2 — the free tools)

- Coverage as a self-check, not an audit — and being honest about that.
- Parsing Sigma tags client-side; the prevalence-ranked catalog.
- The A–F grade and the "top uncovered" list as a shareable artifact.
- SEO as distribution: 30 programmatic format-pair pages.
- **Run it:** paste your rules into the coverage tool on your own deployment.
  Verify any `tryaisoc.com/tools/coverage` link returns 200 before it goes in
  the published copy.

## 4. "A GitHub Action that triages your own security alerts" (W4)

- Dependabot/CodeQL/secret-scanning noise, and prioritization by exploitability.
- Reusing the exact verdict engine (vendored, sync-gated) in CI.
- Idempotent PR comments + the weekly posture digest with an A–F grade.
- Why the deterministic floor matters in CI (no key, nothing leaves the runner).
- **Run it:** add `uses: beenuar/aisoc-action@v1` to a workflow.

## 5. "The SOC that attacks itself every night" (P2 — self-play purple team)

- From test-runner to continuous adversary: LLM-planned chains from Atomic Red
  Team + Caldera, scoped to a lab by a hard asset-tag guard (not a prompt).
- The closed loop: emit telemetry → defense responds → score detected/missed →
  auto-file eval-gated detection proposals for every miss.
- Publishing the weekly self-play scoreboard: turning our own defense
  improvement into a public time series.
- **Run it:** `pnpm aisoc:selfplay` (canned 5-stage campaign, ~3 min).

## 6. "Every install makes every other install smarter" (P1 — the mesh)

- The one network effect a closed vendor can't credibly copy: it needs your
  trust in the code.
- What's shared (hashed IOC sightings, verdict signatures) and what never is
  (entities, free text) — the k-anonymity threshold and per-instance signing.
- `mesh preview`: see exactly what would leave before enabling anything.
- The measured FP-suppression lift with mesh on vs. off, on the eval harness.
- **Run it:** `mesh preview` on your instance; read `docs/architecture/mesh.md`.

---

**Rule:** before publishing any post, verify its headline claim against
`apps/docs/docs/benchmark.md` and the claim-to-gate matrix. If a number isn't
gated, don't print it.
