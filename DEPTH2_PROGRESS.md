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
| 0018 | ADR | Lane B / 1.6 | 2026-11-01 | `docs/decisions/0018-ip-class-dataset-provenance.md` |
| 130 | migration | Lane B / 1.6 | 2026-11-01 | `services/api/migrations/130_alert_ip_class.sql` |
| 131 | migration | Lane B / 1.3 | 2026-11-01 | `services/api/migrations/131_workforce_context.sql` |
| 132 | migration | Lane B / 8.3 | 2026-11-01 | `services/api/migrations/132_tenant_enrichment_providers.sql` |
| 133 | migration | Lane B / 8.1 | 2026-11-01 | `services/api/migrations/133_cloud_security_findings.sql` |

Lane B holds an exclusive pre-allocated block: migrations `130`-`137` and ADR
`0018`. Numbers `134`-`137` are reserved and unused unless an item below
claims one here first.

Highest at kickoff: migration `123`, ADR `0014`. Next free outside Lane B's
block: migration `124`, ADR `0016`.

Highest at kickoff: migration `123`, ADR `0014`. Next free: migration `124`,
ADR `0016`.

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
- [x] **7.2** Hosted agents and repository AI artefacts as new asset kinds.
      [#1585](https://github.com/beenuar/AiSOC/pull/1585).
- [!] **7.3** Agent identity and per-agent baselines (depth 6.4 / parity 6.7)
      — not delivered; reproduced gap and what is needed recorded below.
- [~] **7.4** AI rule pack — four of the listed targets shipped and replayed
      ([#1585](https://github.com/beenuar/AiSOC/pull/1585)); the rest need a
      producer or 7.3's baselines, each recorded below.
### D3 - Three of the five anonymizer classes have no redistributable source

Item 1.6 names five classes and anticipates that one of them (residential
proxies) may have no redistributable source. Measured, **three** do not.

The widely cited community list of VPN and datacentre ranges was the obvious
candidate and was refused on the licence, not on the data: its repository
carries no licence file at all. Recorded as a command rather than as a claim,
because this is the kind of statement that goes stale:

    $ curl -s -o /dev/null -w "%{http_code}" \
        https://raw.githubusercontent.com/X4BNet/lists_vpn/main/LICENSE
    404

An MIT-licensed repository cannot redistribute data whose terms nobody can
read. Commercial anonymizer feeds exist and are licensed per deployment,
which makes them a per-tenant credential rather than something to commit.

So `vpn`, `public_proxy` and `residential_proxy` ship with zero records and
are tenant-supplied only; `tor_exit` and `hosting_provider` ship populated.
The docs page says this in a table and in prose, the ADR records the
alternatives, and the claim-matrix row leads with it.

### D4 - Tenant-supplied class lists are designed and not built

The fallback the plan names for an uncovered class is a tenant-supplied
list. It is **not implemented**, and three classes are therefore unavailable
rather than empty-by-choice. Said plainly in
`apps/docs/docs/operations/ip-classification.md` under "What is not here
yet" rather than implied to exist.

The design, recorded so the next lane does not re-derive it:

* the stamper is in Go at ingest and has no per-tenant database access, so
  the per-tenant layer belongs in fusion, where the tenant is known;
* `services/fusion/app/services/tenant_overlay.py` is the extension point.
  It already loads per-tenant rows from Postgres with hot reload and already
  exposes exactly this shape in `derived_allowlist_fields(event)` and
  `derived_identity_fields(event)`: per-tenant derived fields applied at
  match time;
* it needs a tenant-scoped table (CIDR, class, author, reason) with RLS, a
  third source in `TenantOverlay._fetch` (whose signature is a 2-tuple
  today and would become a 3-tuple), an `ip_class` applied only where the
  global dataset had no answer, and an API route plus a settings surface so
  something writes the table. A table fusion reads and nothing writes is the
  same defect as a table the console writes and nothing reads.

Not done because landing 1.6 and 1.3 unblocks Lane C, and a half-wired
per-tenant path would have been worse than an honest gap. Nothing shipped
depends on it; the three classes simply carry no records.

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

### 7.2 — Hosted agents and repository AI artefacts

**What already existed, and was therefore not rebuilt.** The whole asset
table, the one `score_risk`, the tri-state `sanctioned`, the console page and
its "not learned" rendering, and the recorder's three discovery sources. 7.2
widened two constraints and added two producers; it changed no scoring.

**Reproduced gap.** `.laneE/repro_7x.py` against the base commit:
`AI_ASSET_KINDS` held six values, `hosted_agent present: False`,
`repo artefact kind present: False`. Migration 110's CHECK constraint rejected
a seventh kind deliberately, so this is that refusal answered by a reviewed
migration rather than by dropping the constraint.

**What shipped.** Migration 147 (two kinds, two discovery sources, a
repository expression index), `ai_repo_scan.py`, `hosted_agents.py`, the
generated `_vendor/ai_instruction_rules.py` with its sync gate wired into
`ci.yml`, and the console's kind list and source-limitation copy.

**Wiring proof — the single scorer.** `score_risk` gained three signals
(`unvetted_mcp_server`, `instruction_injection`, `unpinned_skill_source`) and
both producers emit `attributes` keyed to what it already reads (`tools`,
`mcp_servers`, `skills`), so neither needs a special case and no second
scorer exists. `DEVICELESS_KINDS` is shared between the model and the scorer
so the four kinds with no device are not charged for lacking one.

**Wiring proof — the injection channel.** Repository instruction text and a
hosted agent's system prompt both pass `scan_instruction_text` at capture.
The patterns are generated from the agents guard's own `_RULES` table, so the
scanner and the triage guard cannot disagree about the same text; only
pattern *names* are stored, never the matching span. Proven in both
directions: a hostile instruction file is flagged and scores higher, an
ordinary one is flagged by nothing and scores exactly 0 with an empty reason
list.

**Negative controls.** Clean twins on every signal (clean instruction file,
clean hosted agent, vetted MCP server, every deviceless kind) each score 0
with no reasons, so every delta is attributable to one field. The vendored
rule table's `--check` fails against a stale copy, and the generator fails if
an excluded rule name leaves the guard.

**Two defects found while building it, both recorded rather than quietly
fixed.** `path.lstrip("./")` strips the leading dot of a dotfolder, which
would have turned most of the scan off silently — caught because the
classification test enumerates real paths instead of two examples. And a
committed JWT-shaped literal in the 7.1 test, which the repository's secret
scan correctly refused.

**Measurement delta.** No change to the executable-detection figure.

### D4 — One hosted-agent provider, for the same reason as D3

`GET /v1/agents` is the one provider hosted-agent list with a complete public
reference. The GitHub Copilot coding agent is reachable only through its
audit events (`copilot.swe_agent_*`), which 7.1 now ingests but which are
events rather than an inventory; `docs.github.com/en/rest/copilot/copilot-agents`
is a 404. **Blocked, with exactly what is needed:** a published REST reference
for a second provider's hosted-agent list, or a recorded response from one.

### 7.4 — AI rule pack (PARTIAL, four of the listed targets)

**What already existed.** Sixteen executable AI rules: eight `llm-*` on the
OpenAI/Anthropic control plane and eight `ai-*` on runtime and guardrail
findings. Not rebuilt.

**Reproduced gap.** `.laneE/repro_7x.py` showed no rule anywhere clausing on
a Copilot audit action, a consent scope or an assistant's resource-access
volume, because until 7.1 no connector emitted any of them.

**What shipped.** Four rules on the feeds 7.1 added:
`llm-copilot-content-exclusion-changed` (critical),
`llm-copilot-agent-mcp-config-changed` (high),
`llm-ai-app-granted-write-scope` (high),
`llm-copilot-bulk-resource-access` (medium).

**Replay proof.** `services/fusion/tests/test_ai_rule_pack_replay.py` drives
the real `DetectionEngine` over the real compiled ruleset against fixtures
that are the committed output of `LlmUsageConnector.normalize()` — not
synthesized from the rules. Each negative twin differs in exactly one
decisive field, and a test asserts that property on the fixtures rather than
trusting it.

**Negative control.** Rewriting one rule's clause to the unprefixed vendor
action — the exact shape of the measured GitHub failure where 1 of 12 rules
fired on real output — and re-exporting fails that rule's positive replay
while the other three stay green.

**Measurement delta.** Executable detections **2,530 → 2,534**; on disk
7,015 → 7,019. Re-derived with `python3 scripts/project_stats.py` and
propagated by the generators to the README, `ROADMAP.md`, the truth table,
`corpus-stats.json`, both marketplace indexes and the packaged API copy. No
figure was hand-typed; `test_readme_figures_gate.py` passes (23).

**Not delivered, and why — the remaining targets each need a producer that
does not exist yet.** Recorded rather than shipped as rules clausing on
fields nothing emits, which is the failure this plan's replay rule exists to
prevent:

| Target | What is missing |
|---|---|
| Provider key used from a new ASN | No provider audit log read here carries a source IP, so there is no address to resolve to an ASN. Needs 1.6's anonymiser/ASN dataset plus a provider feed that emits the IP. |
| Agent invoking a *new* high-risk tool | "New" is a per-agent baseline, which is 7.3 and is not built. The stateless engine can see the tool, not its novelty. |
| Rise in guardrail violations | A rate over a window per agent; same dependency on 7.3. |
| Token-spend anomalies per key and per agent | `cost_telemetry.py` records per-call cost and the dashboard aggregates it, but neither writes a per-agent baseline the engine can read. Wiring a second meter was explicitly refused. |
| Secrets or personal data labelled in AI chats | The labels exist (7.1, migration 146) but live in Postgres, not on the event stream the engine evaluates. Needs a promoter from `aisoc_ai_chat_content_labels` to an event, which is a design decision rather than a rule. |
| Agent process reading browser cookie or credential stores | Endpoint discovery sees AI processes; nothing emits a file-access event scoped to cookie or credential stores. Needs an osquery/EDR producer. |

### 7.3 — Agent identity and baselines: NOT DELIVERED

**Reproduced gap, recorded for whoever picks it up.** Two halves, both open:

- *Agent identity.* No module in the tree defines an identity for AiSOC's own
  agents: `grep -rln "agent_identity\|AgentIdentity\|agent_principal"` across
  `services/` returns nothing. Parity 6.7 asks for short-lived credentials and
  least-privilege tool scopes visible in the audit log.
- *Per-agent baselines.* `services/fusion/app/services/baselines.py` defines
  **zero** `baseline_*` functions; the only AI-adjacent signal is
  `baseline_oauth_app_volume_z`, emitted inside `BaselineStore` and keyed on
  the OAuth application, not on an agent. Nothing keys a baseline on an agent
  identity, and `cost_telemetry.py` has no baseline writer at all.

**Why it is not started rather than half-built.** It is the dependency under
four of 7.4's six remaining targets, so a partial version would have produced
rules that cannot fire — and 7.5 (Lane D) depends on 7.1, which landed first
as instructed. Starting a per-agent baseline store without the agent identity
half would key it on whatever field happened to be present, which is how
`baseline_oauth_app_volume_z` came to be the only one.

**What is needed:** the full item, in order — agent identities with
short-lived credentials and least-privilege tool scopes first, then baselines
keyed on them (tools, resources, volume, token spend, hours) reading the
existing `cost_telemetry.py` rather than a second meter.
### 1.6 Anonymizer and hosting classes at ingest - Lane B

**Reproduced.** A Go test driving the real `Normalize` entry point, not the
classifier in isolation, so that a classifier package with passing unit
tests and no caller could not satisfy it. On the pre-change tree:

    internal/normalizer/ipclass_stamp_test.go:68:20:
      act.Location.IPClass undefined (type activity.Location has no field)

Nothing in the tree classified an address, and no dataset existed to
classify from.

**Shipped.**

| Piece | Where |
|---|---|
| Downloader | `scripts/fetch_ip_class_dataset.py` |
| Pinned snapshot | `services/ingest/internal/activity/ipclass/data/` (21,726 records) |
| Go classifier | `services/ingest/internal/activity/ipclass/ipclass.go`, embedded |
| Production caller | `activity.Project` -> `stampIPClass`, so every caller gets it |
| Python loader | `scripts/ip_class_dataset.py`, vendored to `services/fusion/app/services/ip_class.py` |
| Live -> matcher | `DetectionEngine._with_activity_location` lifts the nested stamp flat |
| Replay -> matcher | `ip_class_fields` in both copies of the derived-field lockstep |
| Lake | 3 columns, `001_init.sql` and lake migration `005_ip_class` in lockstep |
| Alert | migration `130`, fusion `RawAlert`, promoter, `_INSERT_SQL`, API `AlertResponse` |
| Console | `SourceAddressClassSection` on the investigation rail |
| Gate | `scripts/check_ip_class_dataset.py`, wired in `ci.yml` twice |
| Decision | ADR `0018` |
| Docs | `apps/docs/docs/operations/ip-classification.md`, in the sidebar |

**Negative control.** Removing the single `stampIPClass(&act.Location)` call
from `Project`, leaving the fields and the dataset in place:

    --- FAIL: TestNormalizeStampsAnonymizerClass/tor_exit_relay
        ip 2.56.10.36: ip_class = "", want "tor_exit"
    --- FAIL: TestNormalizeStampsAnonymizerClass/cloud_hosting_range
        ip 1.178.1.0: ip_class = "", want "hosting_provider"

Restored, the suite passes again.

**Numbers, from the generators.**

| Figure | Value | Source |
|---|---|---|
| Dataset records | 21,726 | `check_ip_class_dataset.py` |
| `tor_exit` records | 1,228 | same |
| `hosting_provider` records | 20,498 | same |
| Sources | 8 | same |
| Classes shipped | 2 of 5 | same (see D3) |
| Go/Python parity sample | 400 addresses, 0 disagreements | same |
| Claim matrix | 334/329/5 -> **335/330/5** | `check_claim_gate_matrix.py` |

**Scorecard and reduction suite.** Not re-run: this item adds a field that no
shipped rule matches on yet (Lane C's 2.1 is what will), changes no
correlation key, no confidence input and no priority input, and the fusion
suite's 1,065 tests pass unchanged. Recorded as a deliberate judgement
rather than an omission; Lane C's first rule reading `ip_class` is the PR
that has to carry the delta.

**Deviations:** D3 (three classes have no redistributable source), D4
(tenant-supplied lists designed, not built).


### 7.3 — Agent identity and per-agent baselines (depth 6.4 / parity 6.7)

[#1601](https://github.com/beenuar/AiSOC/pull/1601), base `main`.

**Reproduced gap.** `docs/audit/depth2-baseline/lane-e-phase73-reproduction.py`,
runnable from a bare checkout: no module under `services/agents` defines an
agent identity; `ToolRegistry.execute` takes no caller, declares no scope and
writes no audit row; `baselines.py` declares seven derived fields and none is
keyed on an AI agent.

**Half A.** Short-lived identity per run, least-privilege tool scope enforced
at `ToolRegistry.execute` — the one chokepoint every tool call passes
through, because a check an agent performs on itself is one a steered agent
can be talked out of. Identity is required, not optional. Nothing in the
scope table changes an estate; a test forbids it.

**Half B — one mechanism, built for Lane A.** `SUB_PRINCIPAL_FIELDS` replaces
the hardcoded OAuth-app block, with the dict key as the field prefix so
`baseline_oauth_app_volume_z` keeps its published name. Lane A's 1.4 adds
`token` and `service_account` as one entry each. Eight new derived fields.

**Negative controls.** Making identity optional fails one named test;
removing the `agent` entry fails eight baseline tests.

### 7.4 — four more targets shipped, two still blocked

Executable detections **2,530 → 2,534** on `main`'s base (and 2,534 again on
the landing branch, which carries the other four — the two PRs touch
different rules and the figure is regenerated in each).

Shipped and replayed through the real connector, the real `BaselineStore`
and the real engine: `ai-agent-new-high-risk-tool`,
`ai-agent-guardrail-violation-rate`, `ai-agent-token-spend-anomaly`,
`ai-gateway-key-spend-anomaly`.

### D5 — The 7.1 labels reach the engine as events, not as a query

Decided explicitly, as the brief requires, and **not yet implemented**.

The chat-content labels from 7.1 live in `aisoc_ai_chat_content_labels` in
Postgres; the detection engine evaluates a stream. Two options:

*The rule reads it where it lives* — refused. The engine is stateless and
evaluates per event with no database handle; giving it one would mean a
Postgres round trip per event on the hot path, and the one place that
pattern exists (the tenant tuning overlay) is a per-tenant cache loaded
once, not a per-event read.

*The label reaches the stream* — chosen. The collector emits one OCSF event
per newly labelled conversation, through the same ingest path a connector
uses, carrying the labels, the shape names and the bounded snippet it
already stores. A rule then clauses on `labels_has_any` exactly as every
other rule clauses on connector fields, with no new mechanism and no new
hot-path cost.

**What it needs:** the API service has no ingest client — `IngestClient`
lives in `services/connectors` — so this is either a small vendored client
in the API or a move of the collector into the connectors service. That is
a structural decision touching another lane's tree, which is why it is
recorded here rather than guessed at. Nothing is shipped clausing on
`labels` until it exists.

### D6 — The enrichment-decision gate judges reachability globally

Found while landing 7.1: `scripts/check_enrichment_decisions.py` asks
whether a retired rule's fields are resolvable against the **union of every
connector's** namespace. Promoting a field called `scopes` on Entra consent
events therefore made `ident-github-pat-classic-created-with-broad-scopes`
look reachable, and the gate demanded it be un-retired — while GitHub's
audit log still does not carry a created classic PAT's scopes, so the rule
could not fire.

Worked around correctly by renaming the field to `granted_scopes`, which is
more precise anyway. **The gate weakness is not fixed:** a rule's
reachability should be judged against the fields its own `log_source`
emits. Left recorded rather than changed, because it is a shared gate
several lanes depend on and a scoping change belongs with its owner.

### D7 — Lane A's Phase 1.4 had not landed when 7.3 was built

`origin/main` was fetched before starting and again before committing;
`baselines.py` on `main` still had no sub-principal mechanism. 7.3 therefore
built the shared one rather than waiting. It is additive — a dict entry per
kind, plus one name appended to `PRINCIPAL_FIELDS` — so if 1.4 lands first
the two combine rather than conflict. If both touch the file, combine; never
take one side.
