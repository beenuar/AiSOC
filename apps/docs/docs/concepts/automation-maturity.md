---
sidebar_position: 6
title: L0–L4 Automation Maturity
description: The five-tier model AiSOC uses to gate autonomous response, from analyst-only (L0) through closed-loop autonomous (L4).
---

# L0–L4 Automation Maturity

Every SOC sits on a spectrum between "humans do everything" and "agents do
everything, humans review at audit time." AiSOC formalises that spectrum into
five tiers — **L0 through L4** — and ships the tier as a first-class,
per-tenant configuration. The tier you operate at is not a marketing claim; it
is a row in `remediation_maturity`, a gate that fires on every action, and an
audit-log decision in `remediation_gate_log`.

This page is the canonical reference for the model. For a longer,
narrative-style treatment with worked examples, migration playbooks, and
references to industry frameworks, read the
[**L0–L4 Automation Maturity white paper**](https://tryaisoc.com/papers/l0-l4-automation-maturity.pdf).

## Why a tier model

The honest reason: **trust is earned per-action-class, not per-product.** A
SOC will happily accept an agent that posts a Slack alert to a channel, while
the same SOC will refuse, with cause, to give that agent the ability to
disable a CEO's account at 2 a.m. on a Sunday. Treating "automation" as a
single switch hides that nuance and pushes teams to either over-claim
("we're autonomous") or under-deliver ("everything goes to the queue").

The L0–L4 model gives operators a single dial to turn, with predictable,
auditable consequences at each click. It also gives auditors a precise answer
to the question, "what is allowed to run without a human in the loop?"

## The five tiers

The implementation lives in
[`services/actions/app/services/maturity.py`](https://github.com/beenuar/AiSOC/tree/main/services/actions/app/services/maturity.py),
gated by `evaluate_gate()` against the action's blast radius. Blast radii are
defined in
[`services/actions/app/models/action.py`](https://github.com/beenuar/AiSOC/tree/main/services/actions/app/models/action.py)
as `MINIMAL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.

| Tier | Name | Auto-executed blast radius | Everything else | Default for | Honest MTTR target |
|------|------|----------------------------|-----------------|-------------|---------------------|
| **L0** | Observe | _nothing_ — agents are advisory | All actions queued for approval | New tenants, regulated workloads first 30 days | Human-bound (hours) |
| **L1** | Notify | `MINIMAL` (Slack, ticket, ChatOps verify) | Queued for approval | Tenants in week 2–4 of onboarding | < 30 min for triage notify |
| **L2** | Contain | `MINIMAL` + `LOW` (quarantine file, IOC blocklist, AV scan) | Queued for approval | Most production AiSOC tenants today | < 10 min for low-risk containment |
| **L3** | Remediate | `MINIMAL` + `LOW` + `MEDIUM` (block IP/domain, kill process, reset password, run playbook) | Queued for approval | Mature tenants with strong rollback discipline | < 5 min for medium-risk remediation |
| **L4** | Automate | All radii up to and including `HIGH` (isolate host, disable user, suspend session) — **only if a whitelist entry matches** | Queued for approval | Closed-loop scenarios on pre-approved action+target pairs | < 2 min for whitelisted closed loops |

### L0 — Observe (analyst-only, agents advisory)

The agent stack runs in full read-and-reason mode: it triages, enriches,
correlates, drafts case notes, suggests playbooks, and flags suspicious
behaviour — but it does not execute. Every action a playbook or human
operator requests is routed to the approval queue. The agent's role is
**recommendation, not response.**

Entry criteria:

- A working AiSOC tenant with at least one connector emitting alerts.
- No special trust signals required.

Auto-executed:

- Nothing.

Gated:

- Every action, regardless of blast radius.

Honest performance:

- MTTR is bounded by human review latency. The agent will never reduce
  median time-to-respond below the time it takes an analyst to read an alert
  and click approve.

FP tolerance:

- Very high. Because no autonomous action fires, false positives carry only
  the cost of analyst attention.

### L1 — Notify (agent owns the notifications)

The agent is allowed to take actions whose only side effect is information
movement: posting to Slack, opening tickets, sending a ChatOps "was this
you?" verification prompt, kicking off a SIEM search. None of these mutate
infrastructure. They mutate _attention._

Entry criteria:

- Tenant has wired at least one notification connector (Slack, Teams,
  PagerDuty, or an ITSM connector for ticket creation).
- Operator has reviewed the list of `MINIMAL` actions in
  `ACTION_BLAST_RADIUS` and explicitly opted into L1.

Auto-executed:

- `notify_slack`, `create_ticket`, `chatops_verify`, `search_siem`.

Gated:

- Everything `LOW` and above.

Honest performance:

- Time-to-notify drops from minutes to seconds. Time-to-contain is still
  human-bound.

FP tolerance:

- Medium-high. A wrong Slack post or wrong ticket is recoverable and
  embarrassing, not destructive.

### L2 — Contain (low-blast-radius autonomous, the AiSOC default for production)

The agent is allowed to take reversible, single-resource actions: quarantine
a file, capture forensics, add an IOC to a blocklist, run an AV scan. These
have observable, undoable consequences on a small scope.

Entry criteria:

- Tenant has been at L1 for at least a deployment cycle (or has executed
  enough actions through approval that the operator has a sample of
  agent-suggested decisions to grade).
- Operator has reviewed and accepts the rollback semantics in
  `services/actions/app/executors/`.

Auto-executed:

- Everything at L1 plus: `quarantine_file`, `capture_forensics`,
  `add_ioc_to_blocklist`, `run_av_scan`, `create_notable_event`.

Gated:

- Everything `MEDIUM` and above.

Honest performance:

- MTTR for low-blast-radius containment drops to single-digit minutes.
  AiSOC's published benchmark on synthetic incidents measures this as
  the most common autonomous path in production tenants today.

FP tolerance:

- Medium. A wrongly-quarantined file or a wrongly-blocked IOC is
  recoverable from the gate log and rollback metadata, but it costs time.

**This is where most AiSOC tenants operate in practice as of v8.0.** If a
prospect asks "where is AiSOC autonomous today," the honest answer is "L2
for the median tenant, L3 on selected action classes for mature tenants."
Anyone marketing a higher number is either running a narrow demo or is
counting recommendations as actions.

### L3 — Remediate (medium-blast-radius autonomous, audited after-the-fact)

The agent is allowed to take medium-blast-radius actions: block an IP at the
firewall, block a domain at DNS, kill a process, reset a password, run a
playbook. These affect a single resource but the affected resource is more
visible — a real human's password gets reset, a service's outbound traffic
is interrupted.

Entry criteria:

- Tenant must have a tested rollback story for each MEDIUM action class.
  AiSOC's executor framework records `rollback_data` on every action, but
  the actual rollback is a connector-side capability and varies by vendor.
- Operator has reviewed the gate log for at least one full alert cycle at
  L2 and is satisfied with the false-positive rate.
- ITSM integration is live so post-hoc review is a single click.

Auto-executed:

- Everything at L2 plus: `block_ip`, `block_domain`, `kill_process`,
  `reset_password`, `force_mfa`, `run_playbook`, `allow_ip`, `block_ioc`,
  `sync_detection_rule`, `update_watcher`.

Gated:

- Everything `HIGH` and above.

Honest performance:

- MTTR for medium-blast-radius response drops to under five minutes on
  well-instrumented connectors. Analyst reviews are now retrospective: the
  question becomes "was the agent right?" not "should the agent act?"

FP tolerance:

- Low-medium. A wrongful password reset or DNS block can interrupt real
  work. Rollback is supported but not free.

### L4 — Automate (HIGH-blast-radius autonomous, whitelist-gated)

The agent is allowed to take the most consequential actions: isolate a host
from the network, disable a user account, suspend an active session, run a
remote-execution script. These can interrupt a real human's day, take a
production service offline, or shut down a CEO's email mid-keynote.

Because the cost of a false positive at this radius is severe, **L4 does
not unlock blanket HIGH-radius autonomy.** Instead, L4 requires a
per-tenant whitelist entry in `remediation_whitelist` that matches the
action type and (optionally) a target prefix.

The whitelist is the operator's way of saying:

> "For these specific action types, applied to these specific target
> patterns, I have pre-approved autonomous execution. For everything else
> at HIGH radius, queue it like you would at L3."

Entry criteria:

- Tenant has been at L3 for an extended period with a satisfactory gate log.
- Operator has at least one closed-loop scenario where the action+target
  combination is provably safe (for example: "isolate host" on workstations
  in `host_tag=quarantine-eligible`).
- Operator has constructed the whitelist with explicit constraints
  (target prefixes, expiry times) and ChatOps notification on every fire.

Auto-executed:

- Everything at L3 plus, _for whitelisted (action, target) combinations
  only:_ `isolate_host`, `disable_user`, `suspend_session`, `run_script`.

Gated:

- Any HIGH-radius action not matching a whitelist entry. Any
  `CRITICAL`-radius action regardless of tier.

Honest performance:

- MTTR for the whitelisted closed loops can drop below two minutes
  end-to-end. The agent owns the response; the human reviews at audit time.

FP tolerance:

- Very low for whitelisted actions. The whitelist is the operator's
  contract that they have de-risked this specific combination, with a
  rollback story and a notification path.

## How the gate evaluates

For every action a playbook, agent, or human submits, `evaluate_gate()` runs
the following decision tree:

1. **Per-action override.** If the tenant's `action_overrides` JSON has
   `{ "block": true }` for this action type, the decision is `blocked` and
   the gate stops. If it has `{ "force_auto": true }`, the decision is
   `auto` regardless of tier (this is a deliberate operator bypass and is
   logged with `force_auto_override` in `overrides_applied`).
2. **L4 whitelist (HIGH radius only).** If the action is HIGH-radius and
   the tier is L4, the gate consults `remediation_whitelist` for a matching
   action type and target prefix. No match → `queued_approval`.
3. **Standard tier gate.** The action's blast radius is compared against
   the tier's allow-set. In-set → `auto`. Out-of-set → `queued_approval`.

Every decision — `auto`, `queued_approval`, or `blocked` — is written to
`remediation_gate_log` with the tier, blast radius, rationale, and actor.
This log is the source of truth for tier-graduation discussions.

## How to assess your own SOC's level

These are the questions AiSOC's onboarding flow asks (and that you can ask
yourself before flipping the dial):

1. **Notification readiness.** Is at least one notification connector
   configured? Are analysts paying attention to it? If not, **stay at L0.**
2. **Triage volume.** Is the alert-to-incident ratio under control? AiSOC's
   public benchmark gates at 50:1; if your tenant is over that, autonomous
   action will amplify noise, not reduce it. **Stay at L1.**
3. **Rollback discipline.** For each LOW-radius action you intend to enable,
   do you have a documented rollback? Has it been tested? If no, **stay
   at L1.**
4. **Gate log review cadence.** Do you have a person (or a scheduled job)
   that reviews the gate log for the last 24 hours every morning? If no,
   **stay at L2 at the absolute most.**
5. **Whitelist hygiene.** For L4, do you have at least one specific
   (action, target) combination with constraints, expiry, and a
   notification path? If no, **stay at L3.**

Most tenants land at L2 within their first deployment cycle and stay there
until they have multiple weeks of clean gate logs. The path to L3 is
gradual, action-class by action-class, via `force_auto` overrides on
specific action types rather than a global tier bump.

## Migration paths

The plan is to move tiers gradually and reversibly:

```
L0 → L1: enable notification connectors, opt into L1.
L1 → L2: run at L1 for one deployment cycle, review gate log, opt into L2.
L2 → L3: prove rollback for each MEDIUM action, opt into L3.
L3 → L4: define a whitelist for a single (action, target) combination
         with expiry, ChatOps notifications, and post-hoc review.
```

The dial moves both ways. If a tenant ships a L3 → L2 rollback because of an
operational change (new auditor, new compliance scope, recent incident), the
tier drops with no code change: a single `PUT /api/v1/remediation/config`
call writes the new tier and `evaluate_gate()` picks it up on the next
action.

## What lives outside the tier

A few things deliberately don't sit inside the L0–L4 dial:

- **`CRITICAL`-blast-radius actions.** AiSOC currently has no action type
  marked CRITICAL in `ACTION_BLAST_RADIUS`; the level exists in the enum so
  future actions (e.g. bulk credential rotation, regional traffic
  blackholing) can land in a tier that requires a separate explicit
  approval flow even at L4.
- **Human-initiated actions.** When an analyst clicks "Isolate host" from
  the case view, the gate still runs, but the rationale records the human
  as the actor. The tier model is about _autonomous_ execution; human-in-
  the-loop never bypasses the audit log.
- **`force_auto` overrides.** These are a deliberate operator escape hatch.
  They're logged and visible in the gate log, but they sit outside the
  tier-graduation flow because they're tenant-specific commitments.

## References

- The model is influenced by — but not aligned to — the
  [MITRE D3FEND](https://d3fend.mitre.org/) defensive technique catalog,
  particularly the `D3-* / Eviction / Restore` branches that map naturally
  to AiSOC's blast-radius classes.
- For interoperable playbook formats, AiSOC's playbook engine is
  format-compatible with [OASIS CACAO](https://www.oasis-open.org/standard/cacao/)
  v2.0 (Collaborative Automated Course of Action Operations); the L0–L4 gate
  evaluates the same actions a CACAO playbook would.
- Industry framings of autonomy gradient parallel the
  [SAE J3016](https://www.sae.org/standards/content/j3016_202104/) levels-of-
  driving-automation taxonomy from automotive. The analogy is loose — SOC
  actions are reversible in ways driving is not — but the framing of
  "who is responsible at each tier" is portable.

## Where AiSOC sits today

As of v8.0, the majority of production AiSOC tenants operate at **L2** with
a small set of L3 overrides for specific action types where the rollback
story is mature. A small number of pilot tenants are running L4-whitelisted
closed loops for `isolate_host` on quarantine-tagged hosts.

The white paper companion to this page —
[`l0-l4-automation-maturity.pdf`](https://tryaisoc.com/papers/l0-l4-automation-maturity.pdf) —
goes deeper on:

- The case for an explicit maturity model (vs. opaque "automation level"
  marketing claims).
- Worked-example walkthroughs at each tier.
- An honest discussion of where the industry's autonomy claims diverge
  from production reality.
- Open questions for the next 12–24 months.
