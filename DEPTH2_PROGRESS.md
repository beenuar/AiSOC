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

### 8.1 CNAPP depth - Lane B

Migration `133` is this item's, from Lane B's pre-allocated block; the claim
above already names `133_cloud_security_findings.sql` and this item keeps that
filename. Re-derived against `origin/main` immediately before writing:
`130` is the highest on `main`, and `124`, `125`, `128`, `131`, `142`, `143`,
`146` and `147` are taken on pushed lane branches. `133` is free everywhere.

**Inventory first, because several "missing" capabilities in this repository
turned out to be built and unwired.** Measured on `4bb84f0fd`, in a worktree,
with `rg` run inside it:

| Piece | State on `main` |
|---|---|
| `services/api/app/services/cspm.py` | Real. Pure functions, five resource types, severity plus control refs. **Stateless** |
| `POST /posture/scan` | Evaluates a snapshot supplied in the request body and persists nothing |
| `posture_findings` (migration `017`) | Table, RLS, six indices, one of them `(tenant_id, resource_id)` |
| Writers of `posture_findings` | **One**: `POST /posture/findings`, which a human calls by hand. No collector, no scheduler, no connector |
| Writers of `posture_scan_runs` | **None anywhere in the tree.** `GET /posture/scans` reads a table nothing writes |
| `GET /posture/summary` | Counts that table, so on every deployment it answers eight confident zeros |
| Console cloud-posture page | **Does not exist.** `AlertPosturePanel` is the alert backlog; the other `/posture` hits in `apps/web` are autonomy posture |
| `wiz.py` | Issues only, exactly as the plan says. `raw_event` envelope correct, five-tier map correct |
| `orca`, `prisma_cloud`, `lacework`, `sysdig` | One aggregated feed each; `lacework` also reads compliance evaluations. All alert-shaped |
| Ingest profiles | None of the five has a `connectorProfiles` entry; all five resolve through the canonical `raw_event` envelope, which defaults to class 2001, so their issues **are** promoted. `check_connector_profiles.py` is green and stays green |
| `plugins/wiz/plugin.yaml` | **Absent.** The only one of the five cloud-security connectors with no manifest (63 of 87 connectors have one) |
| `Capability.PULL_VULNERABILITIES` + `fetch_vulnerability_findings()` | **Built and working.** The scheduler calls it and `app/vulnerabilities.py` materialises into `asset_vulnerabilities` under the polled tenant. Implemented by the host-IDS and the vulnerability-scanner connector only |
| `incident_context.py` (the five triage dimensions) | 100% Neo4j, so `full` only. On CORE every dimension answers "graph unavailable" |
| `context/identity.py` | The CORE-native precedent: an internal API route behind a service token, `render_for_prompt`, `basis`, cached, never raises |

**What 8.1 therefore adds, and what it deliberately does not.** It does not
add a second posture store, a second scanner or a second scoring path. It
gives `posture_findings` its first production writer, extends Wiz to the three
finding classes its API actually offers, and makes the result reach a verdict
on CORE through the `identity.py` pattern rather than through the graph.

**Reproduced.** Not by grep. Three measurements on the pre-change tree:

1. `rg` over the whole tree for writers of `posture_findings` returns one
   non-test site, `posture.py:149`, inside `ingest_finding` — a route behind
   `settings:write`. For `posture_scan_runs`, zero.
2. `GET /posture/summary` is `sum(1 for f in findings if ...)` over that
   table with no discriminator, so on any deployment that has not POSTed a
   finding by hand it returns eight zeros. Pinned by
   `test_a_tenant_that_has_never_collected_gets_nulls_and_a_false_flag`,
   which fails against the pre-change handler.
3. `get_incident_context` imports `app.db.neo4j.get_session` and every one of
   its five dimensions is Cypher, so on CORE the whole bundle answers
   `graph unavailable`. That is why the new read is Postgres.

**Shipped.**

| Piece | Where |
|---|---|
| Vendor reads | `wiz.py`: `vulnerabilityFindings`, `configurationFindings`, `detections`, each opt-in |
| Vulnerability destination | the existing `fetch_vulnerability_findings` hook -> `asset_vulnerabilities`. No new store |
| Posture destination | `services/connectors/app/cloud_security.py` -> `posture_findings`, written in the connectors service for the reason `vulnerabilities.py` records |
| Scheduler hook | `_sync_cloud_security_findings`, its own `try`, a failure costs the poll nothing |
| Schema | migration `133`: `source`, `finding_class` + CHECK, `external_id`, `resource_keys` + GIN, `last_seen_at`, a partial unique index, and two columns on `posture_scan_runs` |
| Honest summary | `collected` + null counts; a run row is written even for a poll that found nothing |
| Internal read | `GET /posture/resource-findings`, service-token only, conditional exemption in `check_route_tenant_scope` |
| Triage context | `services/agents/app/context/cloud_posture.py`, modelled on `context/identity.py` |
| Replay freeze | a fourth `CUTOFF` source; cut on the vendor's own `first_detected_at`, which is stronger than directory context's import stamp |
| Injection scan | a sixth channel in `_scannable_fields` |
| Manifest + docs | `plugins/wiz/plugin.yaml` (the only one of the five that had none), `connectors/wiz.md`, `connectors/cloud-security-depth.md` |

**Negative controls, measured.**

    # re-poll resets the exposure clock
    FAILED test_a_repoll_touches_one_row_and_does_not_restart_the_exposure_clock
      assert datetime(2026, 11, 1, ...) == datetime(2026, 10, 20, 9, 0, ...)

    # match lookup drops its tenant predicate
    FAILED test_a_second_tenants_poll_leaves_the_first_alone
      assert 0 == 1

    # the vendor's default type filter is left in place
    FAILED test_wiz_detections_request_both_types
      KeyError: 'type'

    # the service-token check is deleted but the allowlist entry kept
    check_route_tenant_scope FAIL: 1 route(s) take a tenant identifier with
      no auth dependency

**A defect this work introduced and its own test caught.** The first renderer
passed each field through `sanitize_text`, which deliberately keeps single
newlines — correct for a runbook body, wrong for a one-line list item, where
an attacker-chosen resource name could start its own line and read as a new
section of the prompt. `_one_line` flattens every field;
`test_a_resource_name_cannot_smuggle_an_instruction_into_the_prompt` failed
against the first version.

**Refused, with the reason recorded.** The plan names four finding classes
and Wiz offers three. No public reference documents a top-level secrets
query: the official Elastic integration ships six Wiz data streams and none
is secrets, and third-party query inventories list only issues,
configuration findings and vulnerability findings. Writing a
`secretFindings` query from the product's marketing surface would be
inventing an endpoint, so secrets are not collected and the docs say why.
They reach AiSOC as `issues` where Wiz raises them as such. This is the
maintainer-blocked item the plan already anticipated ("recorded payloads for
the CNAPP vendor's newer APIs, where public references are not enough to
build the mock").

**Also refused: auto-resolving a finding that stopped being returned.** A
poll asks for a time window, so absence means "not updated in this window"
far more often than "remediated", and writing `resolved` from it would
retire a live misconfiguration on a quiet afternoon.

**Numbers.**

| Figure | Value | Source |
|---|---|---|
| Live writer cases | 8, real Postgres as `aisoc_app` (NOBYPASSRLS) | `test_cloud_security_findings_live.py` |
| Connector cases | 12, three asserted on the request | `test_wiz_cnapp_depth.py` |
| Agents context cases | 16 | `test_cloud_posture_context.py` |
| API surface cases | 12 | `test_posture_triage_context.py` |
| Registered connectors | 87 -> **87** (none added) | `generate_connector_count.py --check` |
| Plugin manifests | 80 -> **81** | `pnpm marketplace:sync` |
| Marketplace items | 7,183 -> **7,184** | same |
| Claim matrix | 335/330/5 -> **338/333/5** | `check_claim_gate_matrix.py` |
| Service suites | agents 2,212 · connectors 1,243 · api 5,034, all green | each service's own locked venv |

**Scorecard and reduction suite.** Not re-run, recorded as a judgement. This
item adds a prompt block that is empty on every tenant in the corpus: the
verdict corpus carries no cloud-posture findings and no CNAPP connector, so
`render_for_prompt` returns `""` for all 72 items and the model input is
byte-identical. It changes no correlation key, no confidence input and no
priority input. The PR that seeds posture findings into the corpus is the one
that has to carry the delta.

### 8.4 Scale and deployment evidence - Lane B (audit)

Audited rather than re-implemented, since a sibling lane reported it done.
Four of the five things worth checking were already right, and saying so is
the point of the audit.

| Property | State on `main` | Verdict |
|---|---|---|
| 4.4 cloud-hardware run | Absent, with its own page section, the exact command, and "an account and an instance, not code" as what is needed | already honest |
| End-to-end floor and ceiling | 11 events/s and 21,000 ms, stated as 7.3x and 19.2x from the published figures, held by `test_perf_gate_is_related_to_the_claims.py` | already bound |
| Harness refuses to grade | `load_harness.py` turns an unmeasured stage into a failure ("throughput was not measured, so the floor cannot be met"), not a pass | already correct |
| An unknown probe reads as unknown | The `kind` run records absent `kubectl top` data as absence rather than zero; `/scale-hint` publishes `lag_measured: false` and the page says a scaler must treat it as no signal | already correct |
| **In-process floor** | `--assert-floor 1000` against a figure published nowhere, under a comment claiming ">200x below the measured number" | **the real gap** |
| **4.5 managed-cluster run** | Absent, but only implicitly — the page carried a Kubernetes table (`kind`) and no sentence saying a managed run is a separate missing thing | **understated** |

The in-process floor is the one that mattered, because `end-to-end` is
`if: schedule || workflow_dispatch`: on a pull request it was the only
throughput assertion running at all. Measured at **140,692 events/s** (Apple
M5 Max, 18 cores, 2026-11-01, commit `4e6c79305`), published on the
performance page, floor moved `1000` -> `7000`, a stated **20.1x**. Controls:
reverting the floor fails at 140.7x against a 25x ceiling; deleting the
published section fails with the reason rather than passing over an absent
claim.

Both runs stay **blocked**, now stated separately and each with exactly what
is needed: a cloud account and a named instance type for 4.4, and a managed
Kubernetes cluster plus a kubeconfig for 4.5. Neither is blocked on code —
the harness records hardware, load shape and commit into every result file,
and `helm.yml` already installs all of CORE on `kind` on every pull request.

**An observation recorded rather than acted on.** `context/identity.py`'s
renderer has the same newline exposure the posture renderer had, through a
directory display name. It is a lower trust tier (first-party import, and
the module says so) and it is Lane A's surface, so it is reported here rather
than edited mid-flight.

