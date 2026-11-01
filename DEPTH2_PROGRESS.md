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
| 159 | migration | Lane C / 2.4 | 2026-11-01 | `services/api/migrations/159_api_endpoint_profiles.sql` |
| 160 | migration | Lane C / 2.5 | 2026-11-01 | reserved — detection coverage gaps, if the existing proposal tables do not carry them |
| 161 | migration | Lane C / 2.3 | 2026-11-01 | reserved — weak-signal accumulation, if the Redis baseline store cannot hold it |
| 0023 | ADR | Lane C / 2.2 | 2026-11-01 | `docs/decisions/0023-long-horizon-identity-aggregates.md` |

Lane B holds an exclusive pre-allocated block: migrations `130`-`137` and ADR
`0018`. Numbers `134`-`137` are reserved and unused unless an item below
claims one here first.

Lane C holds migrations `159`-`161` and ADR `0023`. Numbers `142`-`158` are
Lane D, Lane E and Lane F blocks; Lane C starts above all of them so a lane
that has not yet pushed its claim cannot collide.

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


### Phase 2 Detection depth — Lane C

**Status.** 2.1 partial (the content target is not met and the gate says so),
2.2, 2.3, 2.4 and 2.5 shipped. Five pull-request-sized commits on
`depth2/lane-c-detection`.

#### 2.1 Content depth — PARTIAL, 569 of 800

**Reproduced first.** The depth plan's own counting rule (products grouped
into cloud / identity / SaaS / code) measured **443** on the base commit
`4bb84f0`, against the plan's note of "about 358". The difference is the
grouping, not the tree: the first depth plan grouped `log_source` values out
of `marketplace/index.json`, which carries no `log_source` for the 1,770
imported rules. The grouping is now pinned in code in
`scripts/project_stats.py::SCENARIO_GROUPS` so the figure stops being
re-derivable two ways, and every product outside the four groups is printed
as `other` rather than dropped, so the breakdown and the headline reconcile.

**Measured: 443 → 569.** `make stats` publishes it, `--check` ratchets it at
the floor and prints the 231-rule shortfall against 800 on every run. The
gate does **not** assert 800; a gate asserting a number the tree does not
have is simply red, and the claim-matrix row is PARTIAL with the
return-to-GATED condition stated.

**Why the target was not reached.** Closing it needs roughly 380 more rules
concentrated in GCP (+81), Azure including Entra (+76), Kubernetes (+23),
GitHub and GitLab (+29) and the SaaS sources at their 20-rule minimums. The
rules shipped here were held to the standard the plan sets — every one
replayed through its real connector and the real engine and observed to fire
— and that standard, not the authoring, is the cost. Writing the remainder
without it would have raised the number and lowered what it means.

**What shipped.** 86 executable rules in six declared families:
`workspace-takeover` (21), `third-party-access` (24), `saas-data-movement`
(24), `saas-authentication-abuse` (10), `apps-script-impersonation` (4),
`long-horizon-identity` (4, from 2.2) and `api-behaviour` (3, from 2.4). The
family is declared on the spec and travels into the artefact the engine
loads, so the console and `make stats` read one string rather than guessing
from a slug.

**The enabling work was connector-side, and it is the finding of this item.**
Seven connectors were dropping the fields their own rules would need,
because the engine flattens `raw_event` exactly one level and the vendors
nest two or three deep: Slack's signing-in address is `context.ip_address`
and an app's scopes are `entity.app.scopes`; Workspace puts the OAuth scopes
a consent granted and the visibility a share opened inside
`events[].parameters`, and `events` is a *list*; a Cloud Audit method is
`protoPayload.methodName`. `scripts/check_connector_field_lift.py` pins 36
lifted fields and, run against a detached worktree at the pre-fix commit,
exits 1 naming **35 of the 36**.

**Refused, with reasons.**

| Refused | Reason |
|---|---|
| The plan's "recovery email or phone changed, then the password, within minutes" as a single rule | A sequence, and the windowed engine counts without ordering. 24 rules were already refused on that ground. Routed to 2.3, where the pair accumulates and the finding lists both halves in arrival order |
| Zoom's 20-rule minimum | No Zoom connector exists in the tree. The plan lists Zoom among "SaaS sources with a connector"; the tree disagrees and the tree wins |
| ServiceNow's 20-rule minimum | The connector reads the `incident` table only. Platform-audit detections (`sys_audit`, role grants, ACL changes) have no source until the connector collects them |
| Workspace app-specific-password, mailbox-delegation and recovery-change *admin* variants | Could not confirm the activity names against Google's reference. `scripts/vendor_event_vocabulary.py` would have rejected them, which is the gate working |

**Not vacuous, proven twice.** Reverting one connector lift reds 15 Slack
rules in `check_scenario_family_alignment.py`; an invented action name
(`slack.app_install` for `slack.app_installed`) is rejected by the
vocabulary arm, which is the `deploy_key.create` defect class.

**A defect found on the way.** Allocating ids for the new rules collided
with **44 orphan YAML files** left by an earlier generation run — ids no
spec owns, which `generate_detections.py` has never deleted. Harmless until
the lock reissues the number, and then not: `detection_truth_table.py`
classifies a file as executable by asking whether its id is in the engine's
set, so two files sharing one id are counted twice. Four collided
immediately and the truth table published **2,617 against an engine loading
2,613**. Deleted, with `scripts/check_detection_yaml_orphans.py` refusing
both an unowned id and a duplicated one.

**Counts moved together:** executable 2,530 → **2,620**; on disk 7,015 →
**7,061**. README, `REPOSITORY_REALITY.md`, the claim matrix, `llms.txt`,
`llms-full.txt`, the truth table, corpus stats and the marketplace index.
Unreachable rules unchanged at the floor of **2**.

#### 2.2 Long-horizon identity attacks — shipped

`services/fusion/app/services/long_horizon_identity.py` accumulates distinct
source ASNs, countries and IPs per account per day over 30 days, on the
baseline store rather than the windowed engine exactly as the plan requires.
The discriminator is the shape, not the count: an attack widens the set of
networks that *fail* while the succeeding set stays small, a traveller
widens both. Folded into the namespace by `evaluate_async`; four rules read
it. Absent-not-zero throughout — an account with fewer than three active
days publishes no key, and the ratio is *undefined* rather than enormous
when no success was observed, so a dormant account cannot fire it.

**Thresholds are a rationale, not a measurement, and say so.**
`scripts/derive_long_horizon_thresholds.py` surveyed 502 events across both
telemetry corpora and found **0** carrying an account, a source network and
an outcome together, so it refuses to publish a derived number and writes
`measured: false` with the return-to-measured condition.

#### 2.3 Weak-signal aggregation — shipped

`services/fusion/app/services/weak_signals.py`. Eleven signal kinds
accumulate per session and per principal inside an hour; past a strength
threshold they become one finding listing every contributor and its weight.
The plan's invariant — one geography or ASN change alone is never a finding
— is a property of the weight table asserted by a test over *every* weight,
so a future signal added above the threshold fails rather than ships.
`MIN_DISTINCT_KINDS` stops one noisy integration repeating its way past it,
and strength counts each kind once plus a small increment for repeats so
forty copies of one risk event cannot outscore a four-kind sequence.
Severity is the strongest contributor on the five-tier ladder; confidence is
a separate 0–100.

**The threshold is a rationale, not a calibration.**
`scripts/calibrate_weak_signals.py` loads all 72 balanced corpus items (36
malicious, 36 benign) and refuses to publish a sweep: the corpus carries
vendor alert *evidence* while every signal here is produced by fusion's
enrichment, so all 72 score 0.0. Publishing `recall 0.0000` would have
stated "the aggregator detects nothing" having measured "this corpus carries
none of its inputs". See D5.

#### 2.4 API behaviour — shipped

`services/fusion/app/services/api_behaviour.py` templates request paths,
learns parameter names, coarse value types and status codes per template,
and raises unknown-parameter, type-change and identifier-enumeration
signals. Off by default per tenant, checked before any store call. Three
rules read it. Templating is conservative in both directions and a test pins
both: identifiers are replaced, words are not, however unusual they look.

#### 2.5 Detection engineering agent — shipped as the missing half

The governed flow already existed end to end (propose, evaluate, backtest,
decide with a separate approver, promote). What it never had was a reason to
start. `services/api/app/services/detection_coverage_gaps.py` ranks gaps
against the connectors **this tenant** has enabled, joining two things the
tree already knew and nothing had joined. Exposed read-only at
`GET /api/v1/detection-proposals/coverage-gaps`.

It deliberately does not write a proposal: ranking a gap and drafting a rule
are different authorities, and the drafting path's separate-approver
requirement would be meaningless if the ranker could reach past it. A test
proves the compiled corpus is readable *from the API service* — a zero there
would report every connected source as uncovered, which is the most alarming
possible way to be broken.

### D5 — two thresholds this phase publishes are rationales, not measurements

Both derivation scripts refuse rather than publish a number. 2.2's has no
corpus carrying an account, a source network and an outcome together; 2.3's
has a balanced corpus of the right size whose items carry vendor alert
evidence rather than enriched events, so every one scores zero on a
mechanism that reads fusion's enrichment output.

The shape is worth recording because the second is the more dangerous: the
sweep *runs*, over 72 correctly-labelled items, and produces `recall
0.0000` at every threshold. Published, a reader concludes the aggregator was
graded and failed. Both artefacts carry `measured: false`, the reason, and
the condition that returns them to measured.

### D6 — the depth plan's SaaS minimums name two sources the tree cannot feed

Depth 3.6 lists Zoom among "every SaaS source with a connector"; there is no
Zoom connector. ServiceNow has one, but it reads the `incident` table only,
so the platform-audit events a detection would clause on are not collected.
Both minimums are refused rather than met with rules nothing can feed, and
both are named in the 2.1 refusal table above.

### Phase 2 second pass — closing 3.6, and the orphan disposition confirmed

#### 2.1 closed: 569 → 907 cloud/identity/SaaS/code conditions

The first pass named the blocker as authoring effort rather than
impossibility. It was, and the effort closed it. **338 new executable rules**
across GCP, Entra, Kubernetes, AWS, GitHub, GitLab, M365, Okta, Atlassian,
Box, Dropbox, 1Password, Salesforce and Snowflake, every one replayed
through its real connector and the real engine and watched to fire.

| Group | Before | After |
|---|---|---|
| cloud | 301 | **494** |
| identity | 138 | **152** |
| saas | 119 | **208** |
| code | 11 | **53** |
| **total** | **569** | **907** |

Per-source minimums, all met: aws 120/120, gcp 121/120, azure 151/150,
kubernetes 63/60, okta 63/60, github+gitlab 51/40, and every SaaS source
with a connector at or above 20.

`make stats --check` now **asserts** the 800 target as well as ratcheting
the measured floor at 907. The shortfall line still prints every run — that
property is what made the earlier PARTIAL honest, and a reader needs the
headroom. The matrix row moved PARTIAL → GATED by reaching the target, not
by relabelling.

**Proof, not assertion.** `check_scenario_family_alignment.py` covers **421
rules across 16 products**, up from 83 across 8. Each spec in
`detection_specs_part6_coverage.py` carries the vendor envelope that proves
it, written in the vendor's own nesting — a rule clausing on `new_value` is
proven by a payload carrying it three levels down inside
`targetResources[0].modifiedProperties[0].newValue`, which a clause-derived
sample would never have. Keeping proof and rule adjacent means a rule edited
without its proof fails immediately.

**Four more connector lifts**, same class as the first seven: Entra puts the
account a role was granted to inside `targetResources` with the role itself
nested again; M365 puts the address an inbox rule forwards to inside
`Parameters`; GitLab's `details` dict held the object acted on and its
`event_type` carries spaces; Confluence's `event_type` carries the audit
category, grouping every permission change in the site under one value.
`check_connector_field_lift.py` now pins **61 fields across 10 connectors**
and, against a detached worktree at `origin/main`, exits 1 naming **59 of
the 61**.

**The CloudTrail proof is worth recording.** The connector reads the
*LookupEvents* envelope, taking `EventName` from the envelope and everything
else out of `CloudTrailEvent`, a JSON string. A sample shaped like a raw
CloudTrail record normalises with `event_name` empty and every identity
field `None`. That was the first attempt at the AWS proof, and the replay is
what caught it — a clause-derived fixture would have passed.

**Refused in this round.**

| Refused | Reason |
|---|---|
| `aws-config-recorder-stopped`, `aws-guardduty-detector-deleted` | Both conditions already have a rule in the cloud corpus. Dropped rather than renamed: a second rule for one condition is noise, and renaming to dodge a collision is how a corpus grows duplicates |
| Zoom, ServiceNow, four Workspace admin variants | The first pass's refusals, unchanged. Zoom has no connector; ServiceNow's reads the `incident` table only; the four Workspace activity names could not be confirmed against Google's reference and the vocabulary gate would reject them |
| A vocabulary arm over the pre-existing AWS corpus | `AWS_EVENTS` transcribes only the names this pass introduced. Applying a partial transcription to the older AWS rules would report every one of them as unknown, so the arm is scoped to the specs the gate walks and the limit is stated in the module rather than left for a reader to infer |

#### The 44 orphan YAML files: disposition confirmed, and a second defect in the same class

The files were **deleted in the first pass**, not merely diagnosed. Evidence:

* 60 deletions under `detections/` in commit `91baf368d` (44 rule files plus
  their directory companions);
* `check_detection_yaml_orphans.py` reports **OK — 7,403 rule files, every
  id owned by one file**;
* the truth table and the engine agree at **2,962**, where they read 2,617
  against 2,613 before the cleanup;
* the gate is wired into `validate-detections.yml`, which it was not when
  the first pass's claim-matrix rows named `ci.yml :: python-lint`. That was
  a false gate reference and `check_gate_coverage.py` found it, along with
  two more scripts of mine nothing invoked.

The second pass found a **second defect in the same class**: a slug used
twice in one category writes **one** YAML and exports **two** engine rules,
so the published total exceeds the file count by the number of collisions.
It surfaced on this branch's own AWS batch. The gate now refuses all three
shapes — an unowned `det-*` id, a duplicated id, and a duplicated
`(category, slug)`.

A **third** shape appeared at merge time and is not a gate failure but a
lane-coordination one: `detections/rule-ids.lock.json` is first-come across
lanes exactly like a migration number, and Lane E and this lane both
allocated `det-application-087` through `090`. The JSON merge kept both
keys. Lane E landed on `main` first, so its ids stand and this lane's four
were released and re-allocated — an id that has shipped must never move.

### D7 — a gate nothing runs is a claim, and three of mine were

The first pass's claim-matrix rows named `ci.yml :: python-lint` as the gate
for `check_scenario_family_alignment`, `check_connector_field_lift`,
`check_detection_yaml_orphans` and `project_stats --check`. None of the four
ran in any workflow. `check_gate_coverage.py` found them and two more I had
not thought of as gates at all — `calibrate_weak_signals` and
`derive_long_horizon_thresholds` both have `--check` modes, which is what
makes them gates. All six are wired into `validate-detections.yml` and the
matrix rows name the workflow that actually runs them.
