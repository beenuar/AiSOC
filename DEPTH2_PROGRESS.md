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

## Lane B status (sources: 1.3, 1.6, 8.1 to 8.4)

| Item | State | Where |
|---|---|---|
| 1.6 Anonymizer and hosting classes at ingest | **done and MERGED** 2026-11-01 | PR #1586 |
| 1.3 HR and device context | **done for three of six connectors**, in review | PR #1589 |
| 8.1 CNAPP depth | **blocked** on unreachable Wiz docs; depth check recorded, two findings in it | item log |
| 8.2 NDR connectors | **ExtraHop done**, in review; Corelight blocked (D8) | PR #1591 |
| 8.3 Enrichment per tenant, cited | **rate limiting shipped**; provider gate built and held for its caller | item log + `depth2/lane-b-enrichment-tenant` |
| 8.4 Scale and deployment evidence | **blocked, recorded with exactly what is needed** | item log |

Every row above has its reproduction recorded in the item log as a command
or a failing test, including the ones that were not built: a gap nobody
reproduced is a rumour, and the three not-started items are written up so
the next lane starts from evidence rather than from the plan's prose.

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

### D6 - HR and MDM connectors get no ingest profile, and the first evidence for that was the wrong test

**Corrected after CI.** The conclusion held; the evidence did not, which is
the half worth recording.

These three connectors publish no events at all. `fetch_alerts` returns an
empty list on each by design: an HR system reports slowly-changing state,
not security events, and their output is context the scheduler writes to
`workforce_members` and `workforce_devices`, never to ingest. A
`connectorProfiles` entry would be an entry nothing can reach.

What was wrong was the check behind it. The original entry said `go test
./internal/normalizer/` passed and cited
`TestConnectorTypeCanonicalTargetsAreDeclaredAndUnshadowed`, which asserts
that every *alias target* is declared and asks nothing about a connector
having a profile. The test that does ask is
`TestEveryDeclaredConnectorHasAnOCSFDecision`, and it failed in CI:

    connector "bamboohr" has no entry in connectorOCSFClass: its events
    take the 2001 default, which is always promoted, and nothing records
    that as a decision

`connectorOCSFClass` exists precisely to separate "decided to take the
generic path" from "nobody looked", and a connector with no entry reads as
the second. All three now carry a `genericReason` naming what they are.

The lesson is the one this programme keeps paying for: a local suite
passing is not evidence that the specific question was asked. The original
entry named a test by title and did not read what it asserted.

### D8 - Corelight is blocked on documentation nobody can read

Item 8.2 names two NDR connectors. ExtraHop RevealX 360 is built; Corelight
is not, and the reason is outside the repository.

Measured 2026-11-01:

    $ curl -sL -o /dev/null -w "%{http_code}" https://docs.corelight.com/
    401

There is no public API reference, so there is no document from which an
honest mock payload can be written, and the plan's own rule for exactly
this case is to record it rather than invent one.

**Needed, specifically:** a Corelight documentation account, **or** one
recorded (redacted) detection payload together with the endpoint path and
the authentication shape the sensor expects.

One thing that must not be mistaken for closing it. Corelight's **Zeek
output** is open, and `services/connectors/app/connectors/zeek_suricata.py`
already ingests it. That is a different thing from the sensor's own
detection API: Zeek logs are network telemetry, and a Corelight detection
has passed Corelight's correlation. Shipping the first while the item asks
for the second, and calling the item done, would be the kind of
substitution this plan exists to catch.

### D7 - Zero check runs was a conflicted PR, not a saturated pool, and the two look identical from outside

**Corrected.** This entry first recorded the wrong cause, and the
correction is worth more to the next lane than the original observation
was.

What was true: the head commit of each Lane B branch returned
`total_count: 0` check runs. What was wrong: attributing that to the shared
runner pool because 19 runs were queued and 18 in progress at the same
moment. The pool had in fact drained to a single queued run.

**The real cause.** Wave 0 was squash-merged into `main`, so `main` and the
Lane B base `depth2/wave0-kickoff` each carried `DEPTH2_PROGRESS.md` and
`plans/aisoc_depth_wave2.plan.md` by different histories - an add/add
conflict. Both pull requests were therefore `mergeStateStatus: DIRTY`, and
**GitHub cannot compute a merge ref for a conflicted pull request, so it
creates no check runs at all**. Zero runs was the conflict, not the queue.

**The one call that tells the two apart**, which is the durable half of
this entry:

```bash
gh pr view <n> --repo beenuar/AiSOC --json mergeStateStatus -q .mergeStateStatus
```

* `DIRTY` - the merge ref cannot be computed. **Nothing can be graded**,
  and no amount of waiting or re-pushing will change that. Merge the base
  in and the runs appear.
* `BLOCKED` or `UNSTABLE` with `total_count: 0` - the pull request is
  gradeable and the runs have genuinely not started. That is the pool.

A queue snapshot alone cannot distinguish them, because a busy queue is the
ordinary state of this repository and is true at the same moment either way.
Checking the queue first is what produced the wrong answer here.

**Standing rule for this lane from now on:** after any push, read
`mergeStateStatus` before concluding anything about the pool.

Resolved by merging `origin/main` into both branches, keeping both sides of
the tracker. Measured immediately afterwards: 108 check runs on
`depth2/lane-b-sources` and 109 on `depth2/lane-b-workforce`, against zero
before.

## Item log

One entry per item as it lands: what failed before, the change, the negative
control, and the measurement delta.

### 8.2 NDR connectors - Lane B - ExtraHop shipped, Corelight blocked

**Reproduced, in the two places this item can be wired wrong.** The
connector half:

    ModuleNotFoundError: No module named 'app.connectors.extrahop'

The ingest half, which is the one that fails quietly:

    extrahop_profile_test.go:22: extrahop has no connectorProfiles entry;
      its detections would fall to the lenient 4001 fallback and never
      promote

and the normalizer saying so itself in the same run:

    {"level":"warn","connector_type":"extrahop",
     "message":"Using generic profile for unknown connector"}

**Shipped.** All seven registration surfaces plus the ingest profile:

| Surface | Where |
|---|---|
| Registry class | `ExtraHopConnector` in `_CONNECTOR_CLASSES` |
| `schema()` with `secret=True` | `client_secret` only; asserted by test |
| Marketplace manifest | `plugins/extrahop/plugin.yaml`, index regenerated |
| Docs page | `apps/docs/docs/connectors/extrahop.md`, sidebar entry `connectors/extrahop` |
| Count gate | regenerated, not edited: 90 -> **91** |
| Scheduler polling | `test_scheduler.py` asserts a non-null `next_run_time` |
| Severity ladder | three bands, no invented `critical` |
| **Ingest profile** | `connectorProfiles["extrahop"]`, class 2001 / category 2 |
| Read verbs | `lookup_network_flows`, `lookup_network_device` |

**The severity decision, because a reviewer will ask why this connector
never emits critical.** ExtraHop publishes three risk bands and no fourth.
From the vendor's own detections page, verbatim: the icon is "color coded
by severity as red (80-99), orange (31-79), or yellow (1-30)". The same
page draws the contrast itself, because CrowdStrike detections in the same
view use red for *Critical* while ExtraHop's red is just 80-99.

So 80-99 maps to `high` and stops. Promoting it would assert a tier the
vendor does not publish, which is the mirror of collapsing a vendor's real
`critical` into `high`. Promotion does not depend on it: class 2001 is
category 2 and promotes unconditionally.

**Negative control.** Removing the `connectorProfiles["extrahop"]` entry
fails all three Go tests and the normalizer logs `Using generic profile for
unknown connector`. Restored, they pass.

**Numbers, from the generators.**

| Figure | Value | Source |
|---|---|---|
| Registered connectors | 90 -> **91** | `generate_connector_count.py --check` |
| Conformance matrix | 91/91 | `connector_conformance.py` |
| Marketplace plugins | 83 -> **84** | `build_marketplace.py` |
| Executor arms | 97 -> **99** | `check_action_contract.py` |
| Claim matrix | 336/331/5 -> **337/332/5** | `check_claim_gate_matrix.py` |

**A real defect the contract gate caught, from the previous item.**
`check_action_contract.py` compares the connectors `Capability` enum
against `KNOWN_CAPABILITIES` in the actions service in both directions, and
reported that `pull_workforce` and `pull_device_inventory` -- added by 1.3
-- were missing from the mirror. Fixed here rather than left, because the
gate is right: the two sets are mirrors and a one-way addition is drift.

**No live suite was added**, and that is a decision rather than an
omission. There is no containerised ExtraHop to stand up, so a job in
`integration.yml` would have nothing to drive; the tests run in the
ordinary `ci.yml` jobs against a mock transport and recorded vendor shapes.
What that does not prove is stated in the claim-matrix row: no live tenant
has been exercised.

**Deviation:** D8 (Corelight blocked on 401 documentation).

### 8.1 CNAPP depth - Lane B - **BLOCKED on vendor documentation**, with the depth check recorded

**Reproduced.** `services/connectors/app/connectors/wiz.py` declares exactly
one GraphQL operation, `query IssuesTable`. No vulnerability query, no
configuration-finding query, no secrets query, no runtime-detection query.

**Blocked, and this is not a scoping choice.** The item asks for queries
the vendor's current public reference must support an honest mock for.
Measured 2026-11-01, repeatedly and with a browser user agent, with a
twenty-second pause between attempts:

    429  https://docs.wiz.io/
    429  https://win.wiz.io/reference/wiz-api
    429  https://docs.wiz.io/wiz-docs/docs/welcome
    000  https://integrate.wiz.io/

Every attempt was rate-limited or unreachable, so the GraphQL schema for
vulnerabilities, configuration findings, secrets and runtime detections
could not be read. The one query already in the tree predates this work and
is not evidence about the others.

Writing those four queries from memory or by pattern-matching the issues
query would be inventing a payload shape, which the plan names as the thing
to refuse. **Needed:** the Wiz API reference reachable, or the GraphQL
schema document (`wizQueryTable` / `vulnerabilityFindings` /
`configurationFindings` / `secrets` / `threatDetections` field definitions),
or one recorded (redacted) response per query type.

**The depth check for the other four, as the item asks.** What each
connector reads today is established from the code and is exact. What each
API offers is marked unverified where the vendor's reference could not be
reached, rather than asserted from recollection.

| Connector | Reads today (verified from the tree) | Vendor reference | Verdict |
|---|---|---|---|
| `wiz` | one GraphQL operation, `IssuesTable` | `docs.wiz.io` **429**, `integrate.wiz.io` **000** | depth unverifiable; blocked |
| `orca` | `GET /api/alerts` (plus `/api/user/session` for auth) | `api-docs.orcasecurity.io` **000** | alerts only; depth unverifiable |
| `prisma_cloud` | `POST /alert/v1/alert` (plus `/login`) | `pan.dev/prisma-cloud/api/cspm/` **200**, overview only: the page describes authorisation and request shape and enumerates no endpoint groups | alerts only; depth needs the endpoint index, not the overview |
| `lacework` | `GET /api/v2/Alerts` **and** `POST /api/v2/Configs/ComplianceEvaluations/search` | `docs.lacework.net` **000** | **already deeper than issues**: it reads compliance evaluations as well as alerts, which is the configuration-findings half of this item |
| `sysdig` | `GET /api/v1/secureEvents` | `docs.sysdig.com/en/sysdig-secure/` **200** | runtime events only |

Two things in that table are worth more than the blocked verdict.

`lacework` already reads compliance evaluations, so the plan's premise that
every cloud-security connector reads issues only is **wrong for one of the
five**. That is the "do not build what exists" rule paying for itself: the
depth check was supposed to be a formality and found a connector a third of
the way through this item already.

`sysdig` reads `secureEvents`, which is Sysdig's **runtime** detection
stream rather than a posture issue list. So the runtime-detections half of
this item is partly covered there too, by a connector nobody counted.

**Not started, and distinct from the blocked half:** findings as *triage
context* keyed on the resource an alert touched, rather than as alerts. That
needs no new vendor read -- it can be built over what these five already
ingest -- and it is the half of 8.1 that is not blocked on anything. It is
the first thing the next pass should take.

### 8.3 Enrichment per tenant, cited - Lane B - rate limiting shipped, the rest split and in flight

**Reproduced, and the gap is wider than the plan's wording.** Measured on
this tree:

  * `grep -c tenant` over `internal/enricher/enricher.go` and
    `internal/config/config.go` returns **0** and **0**. There is no tenant
    dimension anywhere in this service, so per-tenant opt-in is absent
    rather than partial. Keys are per deployment, which means a deployment
    holding a VirusTotal key sends **every** tenant's indicators to
    VirusTotal whether that tenant agreed or not. An indicator is the
    customer's own address, domain or file hash, so that is a disclosure
    nobody consented to.
  * `RATE_LIMIT_RPS` and `RATE_LIMIT_BURST` are parsed at `config.go:59-60`,
    assigned to struct fields at `92-93`, and **read by nothing else**.
  * No reference to the credential vault anywhere under
    `services/enrichment/`.
  * `URLSCAN_API_KEY` is a config field with no client.
  * No enrichment result is cited in the ledger.

**Shipped in the NDR pull request**, because it is complete, wired and
regresses nothing:

  * a per-tenant token-bucket limiter applied in the real handler, on both
    `/enrich` and `/enrich/bulk`, with one token per *item* on the bulk path
    so a hundred-indicator call cannot be the way around the limit;
  * a tenant-scoped cache key, because two tenants legitimately enable
    different providers and a shared key would serve tenant A's verdict from
    a provider tenant B switched off straight to tenant B;
  * six tests, every grant with a partner refusal, driven through the real
    handler with the real `Enricher` rather than a nil one, so the granted
    path is exercised too.

**Held back deliberately, on `depth2/lane-b-enrichment-tenant`:** the
default-deny provider gate. It is built, tested and negative-controlled
(`TenantPolicy`, `runFanOutForTenant`, and an AST wiring test that fails
naming the call site when any fan-out bypasses the gate).

It is not in the pull request because **threading a default-deny gate into
`Enrich` while no caller sends a policy would stop enrichment on every
deployment.** That is a regression, and shipping it to satisfy an item
would be the exact substitution this plan exists to catch. It lands with
the caller.

**Remaining scope, so the next pass starts from a decision rather than a
survey:**

| Piece | What it needs |
|---|---|
| Per-tenant provider table | Migration (Lane B block has `132`-`137` free), RLS, and a row seeded per existing tenant from the deployment's current providers, mirroring migration 122's treatment of closure policy: new tenants default-deny, existing ones keep what they had |
| Tenant's own key in the vault | The API owns the vault write path and this is a Go service, so either it learns a vendored read-path `decrypt_dict` (the pattern `services/connectors` already uses) or the fan-out moves behind an API route that resolves credentials first. **This is the design decision to make first**; everything else follows from it |
| Console settings surface | API routes plus a settings panel. A table nothing writes is the same defect as a console nothing reads |
| Caller wiring | `services/fusion/app/services/alert_enricher.py` resolves the tenant's policy and sends it; the held-back gate then binds in production |
| Ledger citations | Every enrichment result triage uses, with provider and time |
| URLScan client | The config key exists and no client does |
| Breached-credential source | One source, off by default per tenant |
| Docs | Say plainly that enrichment needs the `full` profile |

### 8.4 Scale and deployment evidence - Lane B - **BLOCKED**, which is the correct outcome

The plan's own text allows for this: "published with hardware, date and
commit, **or recorded as blocked with exactly what is needed**". Both halves
are blocked on hardware nobody here has, and neither is blocked on code.

**4.4, the cloud-hardware run.** Already stated honestly on
`apps/docs/docs/operations/performance.md` under "No cloud-hardware run
exists yet, and that is a gap", re-read on 2026-11-01 and still accurate.
Every figure on that page comes from an 18-core Apple-silicon laptop, a
6-CPU Linux VM on it, or a kind cluster on the same machine. The target is
a sustained 5,000 events/s through detection at p95 under 2 s on one
documented instance size.

**Needed:** a cloud account and one named instance type. Nothing else. The
harness already records the hardware fingerprint, the load shape and the
commit into every result file, and `scripts/check_perf_results.py` already
refuses a result that drops any of them. The command that produces the row
is published on that page and is reproduced here so this entry stands alone:

```bash
python3 scripts/perf/load_harness.py \
    --target compose --events 500000 --workers 32 --batch 100 \
    --alert-every 100 --target-eps 5000 --drain-timeout 1800 \
    --assert-benign-alert-rate-max 0.001 \
    --out docs/perf/results/<date>-<instance-type>-realistic-mix.json
```

**4.5, the managed-cluster run.** The only cluster evidence in the tree is
the three-node **kind** run of 2026-09-27, and the page already says what
that does and does not prove: "kind nodes are containers on the same
kernel, so this is not two machines' worth of anything". A kind run is not
a managed-cluster run and must not be published as one.

**Needed:** a managed Kubernetes cluster (EKS, GKE or AKS) with at least
three worker nodes and a load balancer, plus permission to install the
chart into it. The first depth plan recorded the same requirement as
maintainer action M3; this entry carries it forward rather than restating
it as new.

**What was deliberately not done:** no figure was produced by extrapolation
from the laptop runs. A laptop VM's disk, network and CPU scheduling are not
an instance type's, and a number derived that way becomes a promise nobody
can keep. "Not measured" with the exact requirement is the honest record,
and it is the record this item asks for.

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

