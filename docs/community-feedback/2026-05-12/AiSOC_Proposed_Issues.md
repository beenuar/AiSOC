# AiSOC Proposed Issues — 2026-05-12

This file holds 23 implementation tickets distilled from the
[community feedback synthesis](./AiSOC_Community_Feedback_Synthesis.md)
and slotted into the [Now / Next / Later roadmap](./AiSOC_ROADMAP.md).

Each ticket is a faithful issue draft. When opening on GitHub:

- **Title format:** `[F<id>] <area>: <change>` (e.g. `[F001] connectors: add Wazuh ingest`).
- **Labels:** the `area:*` and `priority:*` labels listed inline.
- **Body:** copy from the ticket below; the file references have been
  reconciled against `main` as of v7.1.0 planning.

> **Path-correction note:** The original draft set assumed several files
> from the v7.0.x PR1–PR6 endpoint-telemetry wave were on `main`. They
> are not — see the [reconciliation notice in `CHANGELOG.md`](../../../CHANGELOG.md)
> under `[7.0.x]`. Tickets below have been rewritten to build fresh on
> `main` rather than depend on the unmerged
> `feat/pr6-osquery-extensions` primitives.

---

## Issue #1 — `[F001]` connectors: Wazuh ingest connector

**Labels:** `area:connectors`, `area:detections`, `priority:high`, `good-first-issue:no`
**Bucket:** Now (≤30 days)
**Effort:** L

### Problem

OSS-leaning adopters cannot deploy AiSOC end-to-end without first paying
for a commercial EDR. Wazuh is the dominant OSS endpoint stack and is
absent from the connector matrix.

### Acceptance criteria

- New connector class at `services/connectors/app/connectors/wazuh.py`
  subclassing `BaseConnector`, declaring a `schema()` returning a
  `ConnectorSchema(category="edr", ...)` per the conventions in
  [`AGENTS.md`](../../../AGENTS.md).
- Registered in `_CONNECTOR_CLASSES` in
  `services/connectors/app/connectors/__init__.py`.
- Subscribes to a Wazuh manager's `archives.json` socket *or* polls the
  Wazuh REST API (configurable via the connector schema).
- Normalizes events to OCSF in the connector's `normalize()` method,
  collapsing Wazuh's severity ladder into AiSOC's
  `info | low | medium | high`.
- Ships with detection content for the top-5 Wazuh-native rule families
  under `detections/endpoint/wazuh/`.
- Marketplace manifest at `plugins/wazuh/plugin.yaml`; rerun
  `pnpm marketplace:sync`.
- Connector setup walkthrough at `apps/docs/docs/connectors/wazuh.md`,
  added to `apps/docs/sidebars.ts` under the `Connectors` category.
- Eval gate: ≥0.9 precision on the synthetic Wazuh corpus that ships in
  this PR.

### Out of scope

- Wazuh **active-response** wiring — that lands in Issue #8 as a
  `live_action` implementation.

---

## Issue #2 — `[F001]` connectors+agents: `aisoc-host-agent` skeleton

**Labels:** `area:connectors`, `area:agents`, `priority:high`
**Bucket:** Now
**Effort:** L

### Problem

OSS-leaning adopters want a first-party lightweight host agent rather
than installing two third-party tools (Wazuh + osquery).

### Acceptance criteria

- New Go module at `services/aisoc-host-agent/` (matching the existing
  Go service layout under `services/`).
- Emits OCSF-shaped JSON events to `services/ingest /v1/ingest/batch`
  with the `X-Tenant-ID` header per `AGENTS.md`.
- Ingest handler accepts the new event source and tags it
  `source.product = "aisoc-host-agent"`.
- Plugin manifest at `plugins/aisoc-host-agent/plugin.yaml`.
- Setup doc at `apps/docs/docs/connectors/aisoc-host-agent.md`.
- Skeleton-only: process listing + file-event watcher + outbound HTTPS
  with a static bearer token. **No** persistence, no live-response, no
  auto-update — those are Next-bucket follow-ups.

### Out of scope

- Production hardening (auto-update, mTLS, signed binaries) — separate
  Next-bucket ticket.

---

## Issue #3 — `[F004]` detections+connectors: audit.d profile + endpoint rules

**Labels:** `area:detections`, `area:connectors`, `priority:high`
**Bucket:** Now
**Effort:** M

### Problem

Linux-heavy fleets are second-class. The detection content assumes
Windows/mac event sources.

### Acceptance criteria

- New connector at `services/connectors/app/connectors/auditd.py`
  parsing the audit.d ruleset emitted by a sidecar shipper (Vector,
  Filebeat, or the new `aisoc-host-agent` once #2 lands).
- 8 detection rules under `detections/endpoint/linux/auditd/`:
  - 2 privilege-escalation (sudo abuse, setuid drop)
  - 2 persistence (cron, systemd unit creation)
  - 2 defense-evasion (auditd rule tampering, log truncation)
  - 2 credential-access (`/etc/shadow` read, ssh-key read)
- Registered, eval-gated (≥0.9 precision on synthetic corpus),
  documented at `apps/docs/docs/connectors/auditd.md`.

---

## Issue #4 — `[F002][F015]` detections+ci: quarantine sweep + CI gate

**Labels:** `area:detections`, `area:ci`, `priority:high`
**Bucket:** Now
**Effort:** L (larger than its draft suggested — every YAML rule is in scope)

### Problem

Out-of-the-box detection content fires too often on baseline noise. The
eval harness catches aggregate regressions but does not surface or block
individual high-FP rules.

### Acceptance criteria

- Audit every YAML rule under `detections/` against the synthetic FP
  corpus.
- Move rules with FP-rate > threshold (initial threshold: 0.30) to
  `detections/_quarantine/` with a `README.md` index entry per rule
  documenting *why* it's quarantined and the link to the eval run.
- Add `.github/workflows/quarantine-guard.yml` that fails CI if any
  quarantined rule slug is referenced from `marketplace/`,
  `plugins/`, `services/agents/app/playbook/`, or any other detection
  pack manifest.
- Update `detections/README.md` with the quarantine policy.

### Sequencing

Land **before** Issue #5; #5's per-rule gate assumes the noisy floor
has been swept first.

---

## Issue #5 — `[F015]` ci+evals: per-rule false-positive gate

**Labels:** `area:ci`, `area:detections`, `priority:high`
**Bucket:** Now
**Effort:** M

### Problem

Authors land changes that silently regress an unrelated rule's FP rate.

### Acceptance criteria

- Extend `scripts/run_evals.py` (and the corresponding
  `services/agents/tests/eval_data/` fixtures) to compute and emit a
  per-rule FP score against the synthetic corpus.
- New eval gate: fail the eval suite if any rule regresses ≥10% in FP
  rate from its baseline (baseline file: `scripts/eval_baselines/fp_per_rule.json`).
- Update the PR template / `AGENTS.md` eval-gate section to mention the
  new gate.

---

## Issue #6 — `[F003]` api+web: `POST /alerts/{id}/explain`

**Labels:** `area:api`, `area:web`, `priority:high`
**Bucket:** Now
**Effort:** M

### Problem

Triagers reconstruct "why did this fire" by hand from the raw event
payload + rule YAML. Should be one click.

### Acceptance criteria

- New endpoint `POST /alerts/{id}/explain` in `services/api/app/api/v1/endpoints/`.
- Returns a structured payload: `rule_lineage`, `contributing_events`,
  `mitre_techniques`, `historical_fp_rate`, `suggested_actions`.
- Backed by a new service `services/api/app/services/alert_explain.py`
  that re-uses the existing LLM cost-tracker (`cost_dashboard.py`)
  for per-tenant budgeting and BYOK keys
  (`TenantLlmCredential`).
- UI button on the alert detail page in
  `apps/web/src/app/(admin)/alerts/` that opens a side panel rendering
  the structured explanation.
- Rate-limited per-tenant per the WS-D1 hardening in v1.0.

---

## Issue #7 — `[F002][F006]` docs: alert-reduction benchmark page

**Labels:** `area:docs`, `area:detections`, `priority:medium`
**Bucket:** Now
**Effort:** S

### Problem

There is no published baseline for noise reduction.

### Acceptance criteria

- Extend `apps/docs/docs/benchmark.md` with an `alert_reduction` axis.
- Label clearly that this axis is a **substrate self-consistency gate**,
  not an agent-accuracy claim — match the existing v1.4 eval doc
  conventions in `AGENTS.md`.
- Publish the baseline numbers from the synthetic 200-incident corpus.

---

## Issue #8 — `[F007]` agents+playbook: generic `live_action` interface

**Labels:** `area:agents`, `area:playbook`, `priority:high`
**Bucket:** Now
**Effort:** L

### Problem

Operators with mixed fleets branch on connector type inside playbooks
to invoke the right vendor's response primitive. Should be one
playbook step.

### Acceptance criteria

- New abstract base at
  `services/agents/app/playbook/steps/live_action_base.py` (the
  `services/agents/app/playbook/steps/` directory does not exist on
  `main` and must be created — verified 2026-05-12).
- Three concrete implementations:
  - `live_action_wazuh.py` (active-response)
  - `live_action_fleetdm.py` (live-query)
  - `live_action_crowdstrike.py` (RTR — stub returning
    `not_implemented` with a clear error if RTR creds are absent)
- Playbook DSL gains a `live_action` step type that dispatches to the
  right impl based on the target host's connector source.
- Eval gate: per-vendor smoke test in `services/agents/tests/`.

### Reconciliation note

Earlier draft sequencing assumed the v7.0.x `osquery_live_query`
primitive on `main`. It isn't — it lives on
`feat/pr6-osquery-extensions` and is unmerged. This ticket builds the
generic interface fresh on `main` without depending on that branch.

---

## Issue #9 — `[F011]` docs: endpoint decision-matrix

**Labels:** `area:docs`, `priority:medium`
**Bucket:** Now
**Effort:** S

### Problem

Adopters can't pick an endpoint stack without reading the source.

### Acceptance criteria

- New page `apps/docs/docs/operations/endpoint-stack-decision.md`.
- Comparison table: OSS (Wazuh, audit.d, `aisoc-host-agent`) vs.
  commercial (CrowdStrike, SentinelOne, Defender) on coverage, cost,
  operational effort, live-action support.
- Adoption guidance for the 3 most common shapes (homelab, mid-market,
  MSSP-multi-tenant).
- Linked from `apps/docs/sidebars.ts` and from the new connector docs
  in #1, #2, #3.

---

## Issue #10 — `[F008]` docs+contrib: `HELLO_CONNECTOR.md`

**Labels:** `area:docs`, `area:dx`, `priority:high`, `good-first-issue:helps-create`
**Bucket:** Now
**Effort:** S

### Problem

First-contributor ramp is 2–4 hours.

### Acceptance criteria

- New top-level `HELLO_CONNECTOR.md` walkthrough.
- Runnable example connector at
  `services/connectors/app/connectors/_examples/hello_httpbin.py` that
  polls `https://httpbin.org/uuid` and ingests one event per minute.
  Marked clearly as an example (skipped from registration unless
  `AISOC_ENABLE_EXAMPLE_CONNECTORS=1`).
- Smoke test at
  `services/connectors/tests/connectors/test_hello_httpbin.py` that
  asserts the example normalizes and ingests one event end-to-end with
  the scheduler disabled (`AISOC_CONNECTORS_DISABLE_SCHEDULER=1`).
- Target: ≤30 minutes from `git clone` to "I see my event in the UI",
  measured against a fresh contributor before merge.

---

## Issue #11 — `[F008][F022]` docs+contrib: `HELLO_HUNT.md` + `HELLO_PLUGIN.md`

**Labels:** `area:docs`, `area:dx`, `priority:medium`
**Bucket:** Now
**Effort:** S

### Acceptance criteria

- `HELLO_HUNT.md` walks an analyst from "what's a hunt" through writing
  one Sigma rule and grading it against the synthetic corpus.
- `HELLO_PLUGIN.md` walks a plugin author from `pnpm marketplace:sync`
  through publishing a no-op plugin and seeing it appear in the
  marketplace UI.
- Both link to #10 as the prerequisite.

---

## Issue #12 — `[F012]` cli+dx: `aisoc-cli plugin new`

**Labels:** `area:dx`, `area:cli`, `priority:medium`
**Bucket:** Now
**Effort:** M

### Acceptance criteria

- New subcommand `aisoc-cli plugin new <type> <name>` where `<type>`
  is one of `connector | detection-pack | playbook`.
- Templates at `plugins/templates/connector/`,
  `plugins/templates/detection-pack/`,
  `plugins/templates/playbook/`.
- Each template ships with a working hello-world implementation,
  passing tests, and a `plugin.yaml` skeleton.
- Documented in `HELLO_PLUGIN.md` (#11).

---

## Issue #13 — `[F013]` security+api: MSSP RBAC on actor profiles

**Labels:** `area:security`, `area:api`, `priority:critical`
**Bucket:** Now (schedule first)
**Effort:** S

### Problem

P0: tenant-scoped tokens currently return cross-tenant rows from the
threat-actor profile read endpoint.

### Acceptance criteria

- Audit `services/api/app/api/v1/endpoints/threat_intel.py` and any
  other tenant-scoped read surface (use `git grep` for
  `tenant_id` and review every `select(...)` that lacks a
  `where(model.tenant_id == ...)` clause).
- Enforce tenant-scoped filters on every `list` and `get` operation.
- Regression tests asserting tenant A cannot read tenant B's actor
  profiles, alerts, cases, playbooks, plugin configs, or BYOK
  credentials.
- Add a periodic CI job
  (`.github/workflows/cross-tenant-rbac.yml`) that re-runs the
  regression suite nightly against `main`.

---

## Issue #14 — `[F014]` infra: `terraform-aws-aisoc` module shape

**Labels:** `area:infra`, `area:deployment`, `priority:high`
**Bucket:** Now
**Effort:** L

### Acceptance criteria

- New module at `infra/terraform/modules/aws-aisoc/`.
- Variant: VPC + ECS Fargate + RDS Postgres + ElastiCache Redis +
  Secrets Manager.
- Outputs: API URL, web URL, Postgres connection string (sensitive),
  Redis URL.
- README with a 5-step quickstart.
- Multi-AZ, KMS-CMK, and PrivateLink variants are flagged as
  Next-bucket polish.

---

## Issue #15 — `[F014]` infra: `terraform-gcp-aisoc` skeleton

**Labels:** `area:infra`, `area:deployment`, `priority:medium`
**Bucket:** Now
**Effort:** M

### Acceptance criteria

- Same module shape as #14, GKE + Cloud SQL + Memorystore + Secret
  Manager.
- Skeleton-only; production hardening is a Next-bucket follow-up.

---

## Issue #16 — `[F009]` api: NL-to-query translator + 50-pair eval

**Labels:** `area:api`, `area:agents`, `priority:medium`
**Bucket:** Now
**Effort:** M

### Acceptance criteria

- New service at `services/api/app/services/nl_query.py` that takes a
  natural-language prompt and returns the internal query DSL.
- Re-uses the existing LLM cost-tracker + BYOK pattern.
- 50-pair eval suite at
  `services/api/tests/eval_data/nl_query_pairs.json`.
- Eval gate: ≥0.85 exact-match accuracy.
- Endpoint `POST /search/translate` exposes the translator; UI
  integration is a separate Next-bucket ticket.

---

## Issue #17 — `[F010]` docs: notifications surface

**Labels:** `area:docs`, `priority:medium`
**Bucket:** Next
**Effort:** S

### Acceptance criteria

- Document the existing notification abstraction (Slack, email,
  PagerDuty, webhooks) at
  `apps/docs/docs/operations/notifications.md`.
- Missing-channel matrix listing what's wired up vs. what's planned.

---

## Issue #18 — `[F006]` docs+evals: red-team coverage widget

**Labels:** `area:docs`, `area:evals`, `priority:medium`
**Bucket:** Next
**Effort:** M

### Acceptance criteria

- New widget on `apps/docs/docs/benchmark.md` rendering a
  MITRE ATT&CK technique-coverage heatmap from the synthetic adversary
  emulation runs.
- Source data emitted by the eval harness as
  `services/agents/tests/eval_data/mitre_coverage.json`.

---

## Issue #19 — `[F010]` api: TI briefings service

**Labels:** `area:api`, `area:ti`, `priority:medium`
**Bucket:** Next
**Effort:** M

### Acceptance criteria

- New module `services/api/app/services/ti_briefings.py`.
- Generates a weekly markdown briefing per tenant from ingested feeds +
  recent alerts + recent cases.
- Exposed via `GET /tenants/{id}/briefings/weekly` and
  delivered via the existing notification surface (#17).
- **No new microservice** — extends `services/api`.

---

## Issue #20 — `[F010]` threatintel: MISP push

**Labels:** `area:threatintel`, `priority:medium`
**Bucket:** Next
**Effort:** S

### Acceptance criteria

- Extend `services/threatintel/app/exporters/stix_taxii.py` (or the
  exporter module nearest to it on `main`) with a MISP push target.
- Re-uses the credential vault pattern (`CredentialVault`,
  `vault:v1:<base64>`).
- Configurable per-tenant via the existing connector schema.

---

## Issue #21 — `[F017]` api: auto post-mortem endpoint

**Labels:** `area:api`, `priority:medium`
**Bucket:** Next
**Effort:** M

### Acceptance criteria

- New endpoint `POST /cases/{id}/postmortem` in
  `services/api/app/api/v1/endpoints/`.
- Drafts a markdown post-mortem from the case timeline (events, agent
  actions, human notes).
- Re-uses the LLM cost-tracker + BYOK pattern.
- Saved as a case artifact and attached to the case timeline.

---

## Issue #22 — `[F018]` web+ci: Playwright time-to-task suite

**Labels:** `area:web`, `area:ci`, `priority:medium`
**Bucket:** Next
**Effort:** M

### Acceptance criteria

- New Playwright suite at `apps/web/tests/e2e/time_to_task/`.
- Measures p50 / p95 wall-clock for: triage-an-alert, open-a-case,
  run-a-playbook, write-a-detection.
- Baseline file at `apps/web/tests/e2e/time_to_task/baselines.json`.
- CI fails on >25% regression on any task.

---

## Issue #23 — `[F023]` docs: plugin lifecycle

**Labels:** `area:docs`, `area:plugins`, `priority:low`
**Bucket:** Next
**Effort:** S

### Acceptance criteria

- New page `apps/docs/docs/plugins/lifecycle.md`.
- Sections: version pinning, deprecation, signing, marketplace
  publishing, marketplace de-listing.
- Cross-link from `HELLO_PLUGIN.md` (#11) and the existing plugin SDK
  docs.

---

## Cross-references

- [Strategic roadmap](./AiSOC_ROADMAP.md)
- [Feedback synthesis](./AiSOC_Community_Feedback_Synthesis.md)
- [Contributor invariants & eval gates](../../../AGENTS.md)
- [v7.0.x reconciliation](../../../CHANGELOG.md)
