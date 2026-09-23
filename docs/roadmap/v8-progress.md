# AiSOC v8 — progress tracker

**Last updated:** 2026-09-23
**Current release:** `v8.0.0` (2026-09-22) · **In progress:** `v8.1`

This tracker is the at-a-glance view of what has landed across the v8 line and
what is still open. It is deliberately short and dated. When it disagrees with
the tree, the tree wins — and the tracker is the thing to fix.

> **A note on this file's history.** It sat unchanged from 2026-06-27 through
> the v8.0 release, describing four wave-1 tasks as "in flight" months after
> they merged and naming a loose end that had already landed. `README.md`
> linked here for "v8.1 packaging work in flight" and a reader found a June
> snapshot with no packaging in it. A tracker that is not updated is worse than
> no tracker, because it is read as current.

---

## v8.0 — shipped 2026-09-22

Released as **close the loop**: connecting capabilities the codebase already
contained but never called. The recurring finding, which repeated a dozen
times, was *the mechanism exists, is unit-tested, and has no caller on the path
that needs it* — a passing test on an uncalled function is indistinguishable
from a working feature until someone traces the call graph.

Full inventory: `[8.0.0]` in [`CHANGELOG.md`](../../CHANGELOG.md).

## Post-v8.0 — the credibility floor and four pillars

Landed on `main` between the v8.0 tag and the v8.1 cut
([#696](https://github.com/beenuar/AiSOC/pull/696),
[#697](https://github.com/beenuar/AiSOC/pull/697),
[#707](https://github.com/beenuar/AiSOC/pull/707),
[#713](https://github.com/beenuar/AiSOC/pull/713),
[#715](https://github.com/beenuar/AiSOC/pull/715),
[#717](https://github.com/beenuar/AiSOC/pull/717)).

The floor came first because four docs described controls that did not exist.
Each was corrected **and then implemented**, so the claim could return
honestly. Then the four pillars: context graph (Neo4j schema v1.1 plus real
migration runners for all three non-Postgres stores), recursive investigation
(`run_with_tools` had zero production callers), the per-capability action
contract, and a SOC-agent benchmark a third party can run against their own
agent.

Claim-to-gate matrix: **102 rows — 93 GATED / 9 PARTIAL / 0 NO GATE**. Recount
with `python3 scripts/check_claim_gate_matrix.py`; do not quote a remembered
figure.

Of the twelve hardening phases, **Phase 4 is the only one unchecked, and
deliberately**: what remains is a funded provider key for the live-agent eval,
not code.

---

## v8.1 — in progress

### Wave-2 features (issue [#362](https://github.com/beenuar/AiSOC/issues/362))

Each item is audited against the tree before any code is written, because the
v8.0 lesson is that a capability is often already present and merely unwired.
Status is filled in from that audit rather than from the original ticket.

| T-ID | Item | Status |
|------|------|--------|
| T1.2 | Versioned config-snapshot writers (AWS / GitHub / Lacework / Okta) — Neo4j `:CONFIGURED_AS {ts}` edges so posture drift is queryable across time | see audit |
| T2.3 | `LLMInputContract` fail-closed validation across every sub-agent | see audit |
| T3.2 | Effective-permissions resolvers for Azure / GCP / Okta / Google Workspace | see audit |
| T3.3 | Attack-chain ranking + timeline UI hardening | see audit |
| T3.5 | Business-context rule engine | see audit |
| T3.6 | ChatOps coverage — Slack Block Kit approvals, Teams Adaptive Cards, signed email approval URLs | see audit |

### Release integrity

| Item | Status |
|------|--------|
| Changelog backfill for the post-v8.0 wave (#682–#719) | done |
| `RELEASES.md` brought up to v8.0.0 (it still announced v7.6.0) | done |
| `ROADMAP.md` — "v8.0 — Planned" section, stale matrix count | done |
| This tracker | done |
| Codespaces quickstart ([#716](https://github.com/beenuar/AiSOC/issues/716)) | open |
| Screencast + `hero.gif` assets | open |

---

## Not in v8.1: packaging

`release.yml` already builds, packs and would upload all eight packages on
every tag. The repository's only secret is `FLY_API_TOKEN` — there is no
`NPM_TOKEN` and no PyPI trusted publisher — so the upload steps skip with a
warning by design rather than reddening the release.

This is an account action, not an engineering task. Naming it against a release
that cannot perform it is the kind of claim the claim-to-gate matrix exists to
prevent, so packaging is named against **v8.2** and becomes a re-tag once the
credentials exist. Registry name state at the v8.1 cut: npm `aisoc`,
`@aisoc/sdk` and `@aisoc/mcp` are unclaimed; on PyPI `aisoc` is taken by an
unrelated project, so the Python side ships as `aisoc-sandbox`, and
`aisoc-sandbox`, `aisoc-cli`, `aisoc-sdk`, `aisoc-plugin-sdk` and
`aisoc-detections` are all free. One-time setup:
[`docs/operations/publishing.md`](../operations/publishing.md).

## Deferred by decision, not by omission

- **Mobile responder console (React Native).** Not started; no React Native
  code in the tree.
- **Plugin marketplace v3 (commercial plugins, revenue sharing).** Revenue
  sharing is a commercial decision rather than an engineering one, and the free
  packaging path is itself credential-blocked.

Both were labelled "deferred to v8.0" until that label went stale at the v8.0
tag. They are scope decisions, not gaps.
