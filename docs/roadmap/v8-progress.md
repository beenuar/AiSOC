# AiSOC v8 — progress tracker

**Last updated:** 2026-09-23
**Current release:** `v8.1.1` (2026-09-23) · **Next:** `v8.2` (packaging)

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

Claim-to-gate matrix: **108 rows — 99 GATED / 9 PARTIAL / 0 NO GATE**. Recount
with `python3 scripts/check_claim_gate_matrix.py`; do not quote a remembered
figure.

Of the twelve hardening phases, **Phase 4 is the only one unchecked, and
deliberately**: what remains is a funded provider key for the live-agent eval,
not code.

---

## v8.1 — shipped 2026-09-23

### Wave-2 features (issue [#362](https://github.com/beenuar/AiSOC/issues/362))

Each item is audited against the tree before any code is written, because the
v8.0 lesson is that a capability is often already present and merely unwired.
Status is filled in from that audit rather than from the original ticket.

The audit found the backlog **wrong in both directions**: two items were
already built, and four had the capability present with the path that feeds it
broken. That is the same shape v8.0 found a dozen times — the mechanism exists,
is tested, and has no caller on the path that needs it — so auditing against
the tree before writing code is now the first step of a wave rather than an
optional one.

| T-ID | Item | What the audit found | Done |
|------|------|----------------------|------|
| T1.2 | Versioned config-snapshot writers, Neo4j `:CONFIGURED_AS {ts}` | The Neo4j writer is fully built. The Go provider called a route nobody serves, and could not have called the real one (it has no vault), so snapshots silently never ran while reporting themselves enabled. `is_current` / `valid_from` / `valid_to` were declared and never written, so the documented O(1) lookup matched zero edges. | yes |
| T2.3 | `LLMInputContract` across every sub-agent | Real and fail-closed in `services/agents`, covering 15 of 16 call sites. `services/api` had **no contract at all** across seven endpoints, and the module described as living there did not exist. The no-bypass gate could not see a raw-HTTP LLM call. | yes |
| T3.2 | Effective-permissions resolvers (Azure / GCP / Okta / GWS) | **Already shipped** — all five exist, are registered and report `coverage: "full"`. The gap is the snapshot, not the resolver: no connector answers `__posture_snapshot__`, so four of five return 412. Docstrings still called them scaffolds. | audited; gap gated |
| T3.3 | Attack-chain ranking + timeline UI | Grouping (fusion, Redis) and weighted ranking (API, Postgres) both exist as independent implementations that never exchange data. `AttackChainPanel` and `AttackStory.tsx` are honest about empty states; `InvestigationTimeline.tsx` rendered a fabricated investigation with no demo gate. | partial — fabrication gated, the two implementations remain separate |
| T3.5 | Business-context rule engine | **Already shipped**, and the v8.0 Postgres fix is real. But the two evaluators disagreed on `not`, so one console-accepted rule silently discarded that tenant's entire rule set at triage, suppressions included. | yes |
| T3.6 | ChatOps coverage | Every piece existed; three had no caller. Slack Block Kit approvals worked only as a reply to the analyst's own slash command, the Teams card factory had zero senders, and the signed email link pointed at a route that did not exist. Worse: approvals **authorized nobody**. | partial — authorization and the email route fixed; proactive card push and a durable approval store remain |

### Release integrity

| Item | Status |
|------|--------|
| Changelog backfill for the post-v8.0 wave (#682–#719) | done |
| `RELEASES.md` brought up to v8.0.0 (it still announced v7.6.0) | done |
| `ROADMAP.md` — "v8.0 — Planned" section, stale matrix count | done |
| This tracker | done |
| Codespaces quickstart ([#716](https://github.com/beenuar/AiSOC/issues/716)) | done |
| arm64 service images (Apple Silicon could not pull any of them) | done |
| Screencast + `hero.gif` assets | moved to v8.2 — recording needs a stack to point a browser at, and the hosted OSS demo is down pending a billing action |

---

## v8.1.1 — shipped 2026-09-23

An adoption audit with no new capability, run against the whole repository:
installability, architecture comprehension, data provenance, pipeline
connectivity, and whether documented commands work. The headline finding is
that `./install.sh` started a compose file with **no ingest service, no fusion
service and Kafka disabled** — so the most-followed path into the project did
not run the project, and the console a reader saw had been populated by a seed
script.

| Item | Status |
|------|--------|
| `install.sh` runs `make up` (CORE) and then the golden pipeline | done |
| `tests/e2e/golden_pipeline/` + `golden-pipeline.yml`, verified to fail when broken | done |
| `scripts/doctor.sh` / `make doctor` | done |
| `/livez` + `/readyz` on `services/ingest`, dialling Kafka | done |
| CORE as the default profile; ClickHouse / Neo4j / Qdrant / OpenSearch / enrichment / connectors to `full` | done |
| Five fabricated-data surfaces gated behind demo mode; `seed_demo.py` refuses outside development | done |
| `054_alert_provenance.sql` — `is_synthetic` on `alerts` | done |
| `scripts/project_stats.py --check` — README figures derived from the tree | done |
| `docs/audit/REPOSITORY_REALITY.md` | done |
| `docs/architecture/README.md` rewritten around one event's journey | done |
| `docs/testing/CLEAN_INSTALL.md` | done |
| README rewritten for adoption | done |
| Consolidated `Makefile` | done |
| The three packages that could not be built at the v8.1.0 tag | done |
| CrowdStrike has no normalizer profile and uses the generic one | open — recorded in the reality audit |
| OpenSearch is started by `full` and read by nothing | open — recorded, not drawn into a diagram |

---

## Not in v8.1 either: packaging

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

## Deferred by decision — both taken up in v9.0

- **Mobile responder console.** Recorded here as "not started; no React Native
  code in the tree", which was true about React Native and misleading about the
  product: the responder console already existed as a **PWA** under
  `apps/web/src/app/(responder)/`, complete with a service worker, an offline
  approval queue and Web Push. `apps/mobile` shipped in v9.0 as a distribution
  channel on top of it. Its unit tests and type-check run in CI; no device
  build has been performed.
- **Plugin marketplace v3 (commercial plugins, revenue sharing).** Taken up in
  v9.0. The signing and OCI foundations were real; publisher identity was a
  stub returning `None`, so a submitted plugin was never rejected for a bad
  signature, and there was no commerce code of any kind in the repository.

Both were labelled "deferred to v8.0" until that label went stale at the v8.0
tag.
