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

### D5 - Workday and Kandji are blocked; three of the six named sources are built

Item 1.3 names six connectors. Three are built against public references
verified on 2026-11-01 and cited by URL in each module: BambooHR, Rippling
and Microsoft Intune. Three are not, for different reasons.

**Workday.** `community.workday.com/sites/default/files/file-hosting/restapi/`
answers 200, but the Staffing REST surface a tenant actually exposes is
per-tenant and the report-as-a-service shape most deployments use is defined
by the customer's own report definition, not by a fixed schema. There is no
public response document from which an honest mock payload can be written.
**Needed:** a Workday sandbox tenant, or one recorded (redacted) response
from `Get_Workers` or from a customer's staffing RaaS report.

**Kandji.** `api-docs.kandji.io` answers 200 and the landing page documents
the base URL, the token header, the rate limit and the response codes. The
device-list response's field names are rendered client-side and could not be
extracted. **Needed:** one recorded (redacted) `GET /api/v1/devices`
response, or the field list from the vendor's device-detail page.

**Jamf Pro.** `developer.jamf.com/jamf-pro/reference/get_v1-computers-inventory`
answers 200 and the field names *are* verified -- `general.name`,
`operatingSystem.version`, `operatingSystem.fileVault2Status`,
`diskEncryption.fileVault2Enabled`, `userAndLocation.username`,
`userAndLocation.email`, `security.firewallEnabled` -- so unlike the other
two this one is **not blocked on the vendor**. It is not built in this pass
for time, and `plugins/jamf-mdm` stays a manifest without a connector class.
The promotion is a known quantity: one module in the shape of
`microsoft_intune.py` reading `GET /v1/computers-inventory` with
`section=GENERAL&section=OPERATING_SYSTEM&section=DISK_ENCRYPTION&section=USER_AND_LOCATION&section=SECURITY`.

Recorded rather than built against an invented shape, which is the plan's own
rule for exactly these vendors.

### D6 - HR and MDM connectors get no ingest profile, deliberately

The wiring rule says every connector needs a `connectorProfiles` entry in
`services/ingest/internal/normalizer/normalizer.go`, because a connector
without one hits the lenient fallback at `class_uid: 4001` with an empty
severity map and its events are archived and never promoted.

These three emit no events at all. `fetch_alerts` returns `[]` on each by
design: an HR system reports slowly-changing state, not security events, and
pushing it through ingest would make "is this person leaving" a lake search
rather than a lookup. A profile would be an entry nothing can reach.

Checked rather than assumed: `go test ./internal/normalizer/` passes, and the
only cross-check between the connector registry and the profile map is
`TestConnectorTypeCanonicalTargetsAreDeclaredAndUnshadowed`, which asserts
that every *alias target* is declared -- not that every connector has a
profile. The context path is the scheduler's `_sync_workforce_context`, and
the test asserting the scheduler calls it is the equivalent control.

## Item log

One entry per item as it lands: what failed before, the change, the negative
control, and the measurement delta.

### 1.3 HR and device context - Lane B

**Reproduced.** On the current tree:

    ModuleNotFoundError: No module named 'app.connectors.bamboohr'

and the state behind it, measured rather than asserted: 88 connectors in
`_CONNECTOR_CLASSES`, none HR and none MDM; `import_context` with exactly
one production caller, the manual POST at
`services/api/app/api/v1/endpoints/graph.py:725`.

**Shipped.**

| Piece | Where |
|---|---|
| HR connectors | `bamboohr`, `rippling` |
| MDM connector | `microsoft_intune` |
| Capabilities | `PULL_WORKFORCE`, `PULL_DEVICE_INVENTORY` |
| Context store | `services/connectors/app/workforce.py`, migration `131` |
| Scheduler caller | `ConnectorScheduler._sync_workforce_context`, on every poll |
| CORE read | `services/api/app/services/workforce_context.py`, merged into `/graph/identity-context` |
| Triage derivations | `derive_employment_facts` and `_render_device_line` in `services/agents/app/context/identity.py` |
| Citations | `identity.basis` names departed, departing, contractor and device counts |
| Marketplace | three `plugins/<id>/plugin.yaml`, index regenerated |
| Docs | three pages generated, all three in the sidebar |
| Count | regenerated, not edited: 87 -> **90** |

**Negative control.** Removing the `_sync_workforce_context` call from
`_poll_one` fails `test_the_scheduler_calls_a_workforce_sync_on_every_poll`
with the reason stated: the connector would be registered, configured,
polled and silently ignored. Removing each derived fact from
`render_for_prompt` fails its paired prompt assertion, and removing it from
`basis` fails its paired citation assertion, which is why both halves are
asserted for all four facts.

**Numbers, from the generators.**

| Figure | Value | Source |
|---|---|---|
| Registered connectors | 87 -> **90** | `generate_connector_count.py --check` |
| Connector docs | 90 documented, 41 generated / 49 hand-written | `generate_connector_docs.py --check` |
| Marketplace plugins | 80 -> **83** | `build_marketplace.py` |
| Claim matrix | 335/330/5 -> **336/331/5** | `check_claim_gate_matrix.py` |

**One trap avoided and worth recording.** `generate_connector_docs._slug`
writes the hyphenated filename for a connector with no existing page, so
`microsoft_intune` documents at `/docs/connectors/microsoft-intune`. The
connector's `docs_url` was written with the underscore first and would have
404'd; corrected before commit and verified against the generated sidebar
entry.

**Deviations:** D5 (Workday and Kandji blocked, Jamf deferred with its shape
recorded), D6 (no ingest profile, with the reason and the check).

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

