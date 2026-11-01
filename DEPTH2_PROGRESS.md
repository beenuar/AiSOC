# AiSOC depth plan, wave 2: progress

Mirrors `plans/aisoc_depth_wave2.plan.md`, which is locked and is the source of
truth. This file is the mutable half. The only permitted edit to the plan file
is flipping a todo's `status` in its front matter; every deviation is recorded
here.

Legend: `[ ]` not started, `[~]` in progress, `[x]` done, `[!]` blocked (with
exactly what is needed).

An item is `[x]` only when all three of these are recorded against it: the test
or gate that failed on the pre-change tree for the stated reason, the change,
and the negative control showing that reverting it fails again.

- **Base commit:** `152c6d5f` (`origin/main`, v21.0.0).
- **Plan captured at:** `152c6d5`. Figures in the plan body are hints at that
  commit; Phase 0.2 below re-derives each one and the tree wins.
- **Predecessor:** `DEPTH_PROGRESS.md` tracks the first depth plan. Items that
  plan left open are carried here (see "Hand-over" below) and are never ticked
  in both files.

## Hand-over from the first depth plan

Recorded once, at kickoff, as the plan's precondition requires. These items
move from `plans/aisoc_depth_plan.plan.md` to this plan and are tracked here
from now on; `DEPTH_PROGRESS.md` gains a cross-reference rather than a tick.

| First depth plan item | Carried to | Note at hand-over |
|---|---|---|
| 0.3 `make up-full` baseline | wave 2 Phase 0.3 | `DEPTH_PROGRESS.md` D2 records why it was not captured there |
| 2.6 effective permissions | wave 2 Phase 1.1 | wave 2 adds usage overlay, computed tags, AWS semantics |
| 3.6 content depth | wave 2 Phase 2.1 | wave 2 adds the scenario families |
| 3.7 detection engineering agent | wave 2 Phase 2.5 | unchanged scope |
| 4.4 cloud-hardware run | wave 2 Phase 8.4 | maintainer-blocked at hand-over |
| 4.5 managed-cluster run | wave 2 Phase 8.4 | maintainer-blocked at hand-over |
| 5.5 verb breadth | wave 2 Phase 6.1 | wave 2 raises the floor to 150 arms |
| 5.6 plain-language playbooks | wave 2 Phase 6.2 | wave 2 adds the bounded model step |
| 6.3–6.6 AI estate | wave 2 Phases 7.1, 7.3, 7.4, 7.5 | wave 2 adds hosted agents and repo skills (7.2) |
| 8.1 sub-item 4.5 operator pages | wave 2 Phase 9.5 | unchanged scope |
| 8.1 sub-item 4.6 internationalisation | wave 2 Phase 9.3 | unchanged scope |
| 9.4 Teams half | wave 2 Phase 9.4 | maintainer-blocked at hand-over |
| 9.6 remainder (device evidence) | wave 2 Phase 9.2 | maintainer-blocked at hand-over |
| Phase 10 close | wave 2 Phase 10 | wave 2's Phase 10 closes both |

## Migration and ADR numbers claimed

Claim a number here, push the claim, then write the file. Two lanes once
claimed the same migration number simultaneously and one had to renumber.

| Number | Kind | Lane / item | Claimed | File |
|---|---|---|---|---|
| 0015 | ADR | Wave 0 / Phase 0.4 | 2026-11-01 | `docs/decisions/0015-siem-replacement-scope.md` |
| 146 | migration | Lane E / 7.1 | 2026-11-01 | AI provider coverage + chat compliance (labels and bounded snippet only) |
| 147 | migration | Lane E / 7.2 | 2026-11-01 | hosted agents and repository AI artefacts as asset kinds |
| 148 | migration | Lane E / 7.3 | 2026-11-01 | agent identities and per-agent baselines |
| 149 | migration | Lane E / 7.3 | 2026-11-01 | reserved: agent baseline observations |
| 150 | migration | Lane E / 7.4 | 2026-11-01 | reserved: AI rule-pack supporting state |
| 0021 | ADR | Lane E / 7.1 | 2026-11-01 | AI-chat compliance-log minimisation |

Highest at kickoff: migration `123`, ADR `0014`. Lane E holds the exclusive
block migrations `146`–`150` and ADR `0021`.

## Phase 0: Kickoff

- [x] **0.1** This file exists, modelled on `DEPTH_PROGRESS.md`, with the
      hand-over recorded above.
- [x] **0.2** Every figure re-derived against the base commit. See below.
- [x] **0.3** Baseline artefacts committed under
      `docs/audit/depth2-baseline/` with hardware, date and commit.
- [x] **0.4** ADR-0015 (SIEM-replacement scope) written as **proposed**:
      AiSOC federates to the SIEM rather than replacing it, so the README's
      "Not a drop-in SIEM replacement" is now a decided position with its
      cost argument recorded. Nothing is built from it in this plan.

### 0.2 Re-derived figures

Measured on `152c6d5f` (the base commit) on 2026-11-01, Apple M-series
(arm64, macOS), from the generators the plan names. Captured values are the
plan body's; measured values are this tree's. The tree wins.

| Figure | Captured | Measured | Source | Verdict |
|---|---|---|---|---|
| Executable detections | 2,530 | **2,530** | `scripts/project_stats.py` | matches |
| Detection rules on disk | 7,015 | **7,015** | `scripts/project_stats.py` | matches |
| Threat-and-anomaly family | 24 | **24** | `scripts/project_stats.py` | matches |
| Windowed rules | 76 | **76** | `services/fusion/app/data/windowed_ruleset.json` | matches |
| Longest window | 86,400 s | **86,400 s** | same file | matches |
| Registered connectors | 87 | **87** | `scripts/generate_connector_count.py --check` | matches |
| Connector type ids | 98 | **98** | `packages/types/src/generated/connector-types.json` (`members`) | matches |
| Executor arms (strict) | 89 | **89** | `capability = "..."` declarations under `services/actions/app/live_actions/` | matches |
| Distinct verbs | 39 | **39** | same, deduplicated | matches |
| Executor arms (loose grep) | 111 | **111** | same pattern without the line anchor, counting `reverse_capability` | matches — and is still not the figure |
| Claim-to-gate matrix | 334 / 329 / 5 | **334 / 329 / 5** | `scripts/check_claim_gate_matrix.py` | matches |
| Verdict best balanced accuracy | 0.357 | **0.357** (`llama3.1:8b-instruct-q4_K_M`) | `apps/docs/docs/benchmark.md` | matches |
| Constant-answer floor | 0.250 | **0.250** | same | matches |
| Hosted model rows | not measured | **not measured** | same | matches |
| Auto-close precision range | 0.091–0.571 | **0.091–0.571** | same | matches |
| Alert reduction (production key) | 33.3 % | **33.3 %** | same | matches |
| Alert reduction (detection-shaped) | 24.5 % | **24.5 %** | same | matches |
| Highest migration | 123 | **123** | `services/api/migrations/` | matches |
| Highest ADR | 0014 | **0014** | `docs/decisions/` | matches |
| Cloud/identity/SaaS/code conditions | ~358 | **344** by the method below | compiled rulesets | **moved — see D1** |

Every figure the plan named reproduces exactly except the last, which the plan
itself flagged as approximate ("about 358 ... record why it moved").

### D1 — The cloud/identity/SaaS/code condition count has no formal rule yet

The first depth plan's 3.6 counts "executable cloud, identity, SaaS and code
conditions (native rules, windowed rules and threat-and-anomaly conditions
together)", by `log_source` product. No script in the tree implements that
sentence, so every published value of it — 461 at the first plan's capture,
395 at its re-derivation, "about 358" in this plan — was counted by hand with
a slightly different product set. That is the defect this plan's Phase 2.1
fixes by requiring a `make stats` line held by a `--check` gate.

Measured here, stating the method so the next reader can reproduce it: native
compiled rules whose `product` falls in the cloud (`aws`, `gcp`, `azure`,
`kubernetes`, `docker`, `cloudflare`), identity (`okta`, `identity`,
`active-directory`, `entra`, `auth0`, `jumpcloud`, `ping`, `onelogin`, `duo`),
SaaS (`google-workspace`, `m365`, `slack`, `salesforce`, `snowflake`, `box`,
`dropbox`, `1password`, `atlassian`, `jira`, `confluence`, `zoom`,
`servicenow`, `notion`, `hubspot`) and code (`github`, `gitlab`, `bitbucket`,
`npm`, `pypi`) sets: **344**.

Top contributors: `aws` 73, `azure` 46, `kubernetes` 37, `gcp` 35, `okta` 33,
`identity` 33, `active-directory` 17, `google-workspace` 10, `docker` 9,
`m365` 8, `github` 7, `slack` 7.

Windowed rules contribute **0** to that figure, and the reason is a finding in
itself: `windowed_ruleset.json` entries carry `category` but **no `product`
field at all**, so a product-keyed count cannot see them and a category-keyed
count would be counting a different thing. Phase 2.1's gate has to decide this
explicitly — either windowed rules gain a product, or the published figure
says "native only" — and whichever it picks, the number moves again. Recorded
here so that move reads as a definition being fixed rather than as content
disappearing.

The gap between 344 and "about 358" is therefore a difference of product sets,
not of content: nothing was removed from the tree between the plan's capture
commit and this one (they are the same commit, `152c6d5`).

### 0.3 Baseline artefacts

Committed under `docs/audit/depth2-baseline/` with hardware, date and commit
on each. These are the "before" for every later delta.

| Artefact | Status |
|---|---|
| Re-derived figures | captured (the table above) |
| Executor arm count | captured (89 strict / 39 verbs / 111 loose) |
| Cloud/identity/SaaS/code conditions | captured (344, method recorded in D1) |
| Verdict scorecard | the published matrix is the baseline; re-running it needs a local model pulled (see below) |
| Alert-reduction suite | captured |
| `make up` + `make smoke` | captured |
| `make up-full` | captured — closes the first depth plan's D2 |

## Deviations

Recorded as they are found. D1 is above.

### D2 — `make up-full` failed its first run on a port bind, and what that does and does not prove

The baseline host had nine unrelated containers running from other projects,
one of them `lodestone-postgres-1` published on `0.0.0.0:5432`. That is the
exact condition the port resolver was built for, and it is a more honest
baseline host than a clean one.

What happened, in order:

1. `make up` succeeded. CORE came up, an administrator was created, and
   `make smoke` passed 10 of 10 stages. No `docker-compose.ports.yml` was
   written during this run.
2. `make up-full` recreated `postgres` (the `full` profile changes its
   environment) and the recreate failed:
   `Bind for 0.0.0.0:5432 failed: port is already allocated`.
3. Running `python3 scripts/resolve_port_conflicts.py` by hand detected the
   conflict immediately and wrote the overlay:
   `postgres 5432 → 15432 (5432 is held by container lodestone-postgres-1)`.
4. `make up-full` then succeeded: 22 AiSOC containers, postgres published on
   15432.

Both `up` and `up-full` declare `_ports` as a prerequisite, and `COMPOSE` is
a recursively-expanded variable whose `$(shell test -f ...)` re-runs on every
reference, so the overlay is picked up by both targets once it exists. The
unexplained step is (1): the resolver ran as a prerequisite of `make up` and
did not write an overlay, while the same script three minutes later did.

**What this does not prove.** Step 1 ran against a tree where an earlier
backgrounded `make up` had been killed mid-pull, so the container and
network state at that moment is not reconstructable, and the two obvious
hypotheses — a probe that reads a held port as free (the `SO_REUSEADDR`
class, recorded as fixed) versus a resolver that correctly saw AiSOC's own
already-running postgres — cannot be separated from this evidence. A grep is
not a reproduction and neither is a sequence I cannot replay.

**Carried as a follow-up, not claimed as a defect:** reproduce on a clean
host by starting a foreign Postgres on 5432 first, then `make up` from a tree
with no overlay present, and record whether the overlay is written. If it is
not, that is a real first-run defect for the most common conflict there is
and belongs in its own fix with a negative control. Until that run exists,
this is an observation with its evidence attached.

## Phase 7: AI agent security (Lane E)

- [x] **7.1** Provider coverage (depth 6.3) plus enterprise AI-chat
      compliance logs stored as labels and bounded snippets only.
      [#1585](https://github.com/beenuar/AiSOC/pull/1585).
- [ ] **7.2** Hosted agents and repository AI artefacts as new asset kinds.
- [ ] **7.3** Agent identity and per-agent baselines (depth 6.4 / parity 6.7).
- [ ] **7.4** AI rule pack (depth 6.5 plus this plan's additions).

## Item log

One entry per item as it lands: what failed before, the change, the negative
control, and the measurement delta.

### 7.1 — Provider coverage and AI-chat compliance logs

Landed early because Lane D's 7.5 depends on the provider work.

**What already existed, and was therefore not rebuilt.** Verified before
writing anything: the AI estate inventory (`services/api/app/services/
ai_inventory.py`, one `score_risk`, six asset kinds, tri-state `sanctioned`),
migration 110 and its RLS, the fusion recorder with its three discovery
sources, endpoint discovery, the `ai_gateway` connector, the two OCSF 6003
webhook templates, `packages/aisoc-ai-sdk`, the AI estate console page, and
**sixteen** executable AI rules — eight `llm-*` on the OpenAI/Anthropic
control plane (`det-application-071`…`078`) and eight `ai-*` on runtime and
guardrail findings (`079`…`086`). None of that was touched.

**Reproduced gap A.** `LlmUsageConnector` accepted `openai` and `anthropic`
and nothing else. Six of seven tests in
`services/connectors/tests/connectors/test_llm_usage_provider_coverage.py`
fail on the base commit; four of them drive the real HTTP path against a
mock server and get a `ValueError` from the constructor.

**Reproduced gap B**, found while wiring A and the more interesting one.
`test_ai_asset_recorder.py` writes `finding.evidence.scopes` into a
hand-built OCSF event and asserts the recorder reads
`finding.evidence.scopes`. Both halves are the test's own invention: no
connector produces that path and ingest does not synthesise it, so the
assertion held whether or not the production path worked. Driven through the
shape ingest really produces — the connector's dict as a JSON string under
`raw_data` — an Entra consent grant reached the inventory with **no scopes at
all**, so an AI notetaker consented into every mailbox scored identically to
one granted nothing.

**Reproduced gap C.** No table anywhere held AI-chat compliance data; the
migration sweep for one returned nothing.

**What shipped.** Four more providers on the existing connector
(`google_gemini`, `github_copilot`, `microsoft_copilot`, `entra_consent`),
each against the vendor's current public reference, every URL fetched and
200 before committing. `_from_provider_audit` now reads through
`_connector_fields`, so scopes reach the one existing `score_risk`; an OAuth
grant is keyed on the application rather than the audit record. Migration
146 with five RLS'd tables, ADR-0021, a classifier, a client, three API
routes and a console panel.

**Wiring proof.** One `score_risk` path, unchanged — the new providers feed
the existing `oauth_grant` and `provider_key` kinds and add no second
scorer. Minimisation is schema-enforced (no column can hold a message;
`VARCHAR(280)`; CHECK-constrained label vocabulary; no client method returns
text) rather than promised in prose. Erasure and retention come from the
`tenant_id` column name that `discover_tenant_tables` selects on, asserted
per table.

**Negative controls.** (1) Reverting only the `fields.get("scopes")` read
fails both recorder tests again with `KeyError: 'scopes'`. (2) Adding a
`transcript` `Text` column to `AiChatContentLabel` and changing nothing else
fails the forbidden-column and unbounded-TEXT sweeps.

**Measurement delta.** No change to the executable-detection figure: this
item adds no rules. Rules reading these feeds are 7.4.

**Deviation D3 — one provider, not several, for the compliance half.** The
plan says "where a provider offers a compliance API". Exactly one does with
a complete public reference: Anthropic's, at
`platform.claude.com/docs/en/manage-claude/compliance-*`, whose pages were
fetched and returned 200. OpenAI's equivalent is behind a Cloudflare
challenge that answers 403 to every non-browser request, including its
ordinary audit-log reference, so no honest mock can be written from it. The
`provider` column is a CHECK constraint with one value today; adding a
second is a one-line migration. **Blocked, with exactly what is needed:** a
reachable public reference for the OpenAI Compliance API, or a recorded
payload from a customer tenant.
