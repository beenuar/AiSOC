# AiSOC Roadmap (Now / Next / Later) — 2026-05-12

> **Source of truth for active prioritization.** See
> [`README.md`](./README.md) for how this doc relates to `/ROADMAP.md` and
> `/CHANGELOG.md`.

This roadmap is organized into three rolling buckets — **Now** (≤30 days),
**Next** (30–90 days), and **Later** (90+ days) — with each item tagged by
its originating feedback theme (`Fxxx`) from
[`AiSOC_Community_Feedback_Synthesis.md`](./AiSOC_Community_Feedback_Synthesis.md).
Implementation tickets live in
[`AiSOC_Proposed_Issues.md`](./AiSOC_Proposed_Issues.md).

---

## North-Star Themes (carry across all buckets)

1. **OSS-first telemetry coverage.** Every commercial connector (CrowdStrike,
   SentinelOne, Defender, etc.) ships alongside an OSS-native equivalent
   (Wazuh, `aisoc-host-agent`, audit.d, osquery). Closes the "I cannot adopt
   this without a paid EDR" objection raised across `F001`, `F004`, `F011`.
2. **Reasoning quality > connector count.** A new connector earns its keep
   only if it ships with detection content + an eval-gated baseline. False
   positive tuning, "Explain this alert" affordances, and alert-reduction
   benchmarks (`F002`, `F003`, `F015`) are first-class deliverables, not
   afterthoughts.
3. **Contributor on-ramp under 30 minutes.** A new contributor should land
   their first connector, hunt, or plugin within half an hour using
   `HELLO_*.md` walkthroughs and the `aisoc-cli plugin new` scaffolder
   (`F008`, `F012`, `F022`).
4. **Multi-tenant safety as a hard invariant.** Cross-tenant data exposure
   bugs (`F013`, `F019`) are P0; every new endpoint that touches
   tenant-scoped data needs an RBAC regression test before merge.
5. **Deployment leverage.** Published Terraform modules for AWS and GCP
   (`F014`) replace handcrafted `docker-compose` adoption flows for
   production deployments.

---

## Now — ≤30 days (v7.1.x train)

The Now bucket runs in parallel with the v7.1.0 cloud-security wave already
in flight. Items are sized so that landing them does not block v7.1.0; where
sequencing matters it is called out inline.

### Telemetry coverage gap-fill (`F001`, `F004`, `F011`)

- **#1 — Wazuh ingest connector** (`area:connectors`, `priority:high`).
  Subscribes to a Wazuh manager's `archives.json` socket / API, normalizes
  to OCSF, ships with detection content for the top-5 Wazuh-native rules.
  Eval gate: ≥0.9 detection precision on synthetic Wazuh corpus.
- **#2 — `aisoc-host-agent` skeleton** (`area:connectors`,
  `area:agents`). Lightweight Go agent emitting OCSF-compatible host
  telemetry to `services/ingest /v1/ingest/batch`. Skeleton + ingest handler
  + plugin manifest only — production hardening is a Next-bucket follow-up.
- **#3 — auditd profile + endpoint detection rules** (`area:detections`,
  `area:connectors`). Reuses the existing `services/connectors`
  registry-based discovery; ships with 8 baseline detections covering
  privilege escalation, persistence, defense evasion.

### Reasoning-quality + alert-noise floor (`F002`, `F003`, `F015`)

- **#4 — Quarantine sweep + CI gate** (`area:detections`, `area:ci`). Audit
  every YAML rule under `detections/` for FP rate against the synthetic
  corpus; quarantine rules above the threshold into `detections/_quarantine/`
  with a README index, add a CI workflow that fails if a quarantined rule
  is referenced from `marketplace/` or playbooks.
- **#5 — Per-rule false-positive eval gate**. Extend `scripts/run_evals.py`
  to surface a per-rule FP score and fail the eval suite if any rule
  regresses ≥10% from its baseline.
- **#6 — `POST /alerts/{id}/explain`** (`area:api`, `area:web`). Endpoint
  in `services/api` that returns a structured explanation (rule lineage,
  contributing events, MITRE mapping, suggested triage actions) plus a UI
  button on the alert detail page. Re-uses the LLM cost-tracker for
  per-tenant budgeting.
- **#7 — Alert-reduction benchmark page** in `apps/docs/docs/benchmark.md`.
  Adds an `alert_reduction` axis aligned with the existing v1.4 eval
  conventions (substrate self-consistency gate, not an agent-accuracy claim
  — labeled as such on the page).

### Live-action surface unification (`F007`)

- **#8 — Generic `live_action` playbook step interface** (`area:agents`,
  `area:playbook`). Build the abstract base + 3 vendor implementations
  (Wazuh active-response, FleetDM live-query, CrowdStrike RTR stub). Lives
  at `services/agents/app/playbook/steps/live_action_base.py` (new
  directory). Depends on Stage 0.1 reconciliation in `CHANGELOG.md` so we
  do not assume the unmerged `feat/pr6-osquery-extensions` primitives are
  on `main`.
- **#9 — Endpoint decision-matrix docs**. New page under
  `apps/docs/docs/operations/` comparing OSS (Wazuh + audit.d +
  host-agent) vs. commercial (CrowdStrike, SentinelOne, Defender) coverage,
  with adoption guidance.

### Contributor on-ramp (`F008`, `F012`, `F022`)

- **#10 — `HELLO_CONNECTOR.md`** + a runnable `httpbin.org` example
  connector + smoke test. Every step copy-pasteable. Target: 30 min from
  `git clone` to ingested event.
- **#11 — `HELLO_HUNT.md` + `HELLO_PLUGIN.md`** completing the trio.
- **#12 — `aisoc-cli plugin new`** scaffolder + `plugins/templates/` with
  three starters (connector, detection pack, playbook).

### Multi-tenant safety (`F013`)

- **#13 — MSSP RBAC enforcement on actor profiles**. Audit
  `services/api/app/api/v1/endpoints/threat_intel.py` (and any other
  cross-tenant readable surface), enforce tenant-scoped filters on every
  list/get, add regression tests that assert tenant A cannot read tenant
  B's actor profiles.

### Deployment leverage (`F014`)

- **#14 — `terraform-aws-aisoc` module shape**. Establish the module
  layout and ship a working VPC + ECS Fargate + RDS variant; mark advanced
  variants (multi-AZ, KMS-CMK, private link) as Next-bucket polish.
- **#15 — `terraform-gcp-aisoc` skeleton**. Same shape, GKE + Cloud SQL.
  Skeleton-only in Now; productionization in Next.

### Search & query UX (`F009`)

- **#16 — NL-to-query translator + 50-pair eval**. Adds an LLM-backed
  translator from natural-language prompts to the internal query DSL,
  gated on a 50-pair eval suite (target ≥0.85 accuracy). Lives in
  `services/api/app/services/nl_query.py`.

**Now-bucket capacity note.** The honest estimate for items #1–#16, run in
parallel with v7.1.0, is closer to 6–8 weeks than 30 days for a small team.
The doc is intentionally aspirational; if a 30-day train is required,
ship the bolded high-priority items (#1, #4, #5, #8, #13) first and let
the rest slip into the v7.1.x patch line.

---

## Next — 30–90 days (v7.2.x → v7.3.x)

### Eval-harness depth (`F006`)

- **#17 — Notifications surface docs**. Document the existing notification
  abstraction (Slack, email, PagerDuty) and add a missing-channel matrix.
- **#18 — Red-team coverage widget on benchmark page**. Surfaces MITRE
  ATT&CK technique coverage from the synthetic adversary emulation runs as
  a heatmap on the benchmark page.

### Threat-intel surface (`F010`, `F016`)

- **#19 — TI briefings service**. New module
  `services/api/app/services/ti_briefings.py` that generates weekly
  AI-drafted briefings per tenant from ingested feeds + recent alerts.
  No new microservice — extend the existing API service to keep the
  deployment surface flat.
- **#20 — MISP push** as an extension to the existing
  `services/threatintel/app/exporters/stix_taxii.py`. Reuses the credential
  vault pattern.

### Investigation surface (`F017`)

- **#21 — Auto post-mortem endpoint**. `POST /cases/{id}/postmortem`
  drafts a markdown post-mortem from the case timeline (events, agent
  actions, human notes) using the same LLM cost-tracker as #6.

### UX time-to-task (`F018`)

- **#22 — Playwright time-to-task tests**. Add a Playwright suite in
  `apps/web/tests/e2e/` measuring p50/p95 time for: triage-an-alert,
  open-a-case, run-a-playbook. Establish baselines and fail CI on >25%
  regressions.

### Plugin lifecycle (`F023`)

- **#23 — Plugin lifecycle docs**. Document version pinning, deprecation,
  signing, and the marketplace publishing flow end-to-end.

---

## Later — 90+ days

These items are deliberately under-specified. They graduate to Next when
the upstream prerequisites land or community pull justifies the
re-prioritization.

- **Threat actor attribution v1** — graduate the v0 engine
  (`services/threatintel/`, currently PR #43) into a first-class surface
  with confidence scoring, evidence chains, and a UI. (`F016`)
- **Hosted SaaS option for evaluation tenants.** Strictly opt-in,
  air-gap-compatible defaults preserved. (`F014`)
- **Cross-tenant federated detection sharing.** Opt-in detection pack
  authoring with cryptographic provenance, building on the threat-intel
  exporter pattern. (`F010`)
- **Mobile-first triage app**. Read-only first; write surfaces only after
  the time-to-task tests (#22) demonstrate the desktop flow is stable.
  (`F018`)
- **AI-assisted detection authoring.** Extend the explain-alert primitive
  (#6) into a "draft a Sigma rule from this incident" flow. Requires the
  per-rule FP gate (#5) to be load-bearing first. (`F003`)
- **Case-management integrations.** Native Jira / ServiceNow connectors
  beyond the existing notification webhook. Schedule once #17 lands.
  (`F017`)

---

## Sequencing & risk notes

- **Now-bucket parallelism.** Items #1–#3, #4–#7, #10–#12, #14–#15 are
  largely independent and can run concurrently. #8 has a Stage-0
  reconciliation prerequisite. #13 is a P0 security item — schedule it
  first if security tester time is available.
- **CI baseline.** `PR_TRIAGE.md` lists 31 open Dependabot PRs and 4
  failing CI checks on `main`. Assume some Now-bucket items will require
  fixing CI plumbing before their own tests can run cleanly. Budget 1–2
  days for that across the train.
- **v7.1.0 conflict surface.** The cloud-security wave touches
  `services/connectors/` and `apps/web/src/app/(admin)/alerts/`. Now-bucket
  items #1–#3 and #6 land in the same files; coordinate via PR ordering
  to avoid merge thrash.
- **Eval-harness load.** #4, #5, #6, #16, #18, #21 all add to the eval
  surface. Watch the harness wall-clock; if it crosses 15 min on CI we
  should shard before #18 lands.

---

## Cross-references

- **Stable feedback IDs:** [`AiSOC_Community_Feedback_Synthesis.md`](./AiSOC_Community_Feedback_Synthesis.md)
- **Implementation tickets:** [`AiSOC_Proposed_Issues.md`](./AiSOC_Proposed_Issues.md)
- **Historical roadmap:** [`/ROADMAP.md`](../../../ROADMAP.md)
- **Active progress tracker:** [`/PROGRESS.md`](../../../PROGRESS.md)
- **Contributor invariants & eval gates:** [`/AGENTS.md`](../../../AGENTS.md)
