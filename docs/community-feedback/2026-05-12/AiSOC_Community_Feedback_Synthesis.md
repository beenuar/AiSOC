# AiSOC Community Feedback Synthesis — 2026-05-12

This is the canonical, ID-stable themed log of community feedback that
informed the [Now / Next / Later roadmap](./AiSOC_ROADMAP.md) and the
[implementation tickets](./AiSOC_Proposed_Issues.md). Every theme has a
stable `Fxxx` ID — never renumber, append-only.

---

## Methodology

Sources sampled (last 60 days as of 2026-05-12):

- GitHub issues + discussions on `beenuar/AiSOC`.
- Open PR threads (notably `#43` threat-actor attribution v0).
- Maintainer-collated DMs and email feedback (paraphrased here, no PII).
- Public mentions on adjacent OSS forums (paraphrased).

A theme earned a slot if at least three independent sources surfaced the
same friction point or wish, *or* one source surfaced a security/privacy
hazard. Single-source wishes without a safety dimension are tracked in the
maintainer backlog but not synthesized here.

Each theme is rated for **Severity** (S1 ship-blocker / S2 active pain /
S3 friction / S4 wish), **Reach** (How many adopters does this affect?
broad / mid / narrow), and **Effort** (S/M/L/XL).

---

## F001 — "I cannot adopt this without a paid EDR"

**Severity:** S2  **Reach:** broad  **Effort:** L

OSS-leaning adopters (homelabs, small MSSPs, public-sector pilots) report
that the v6.x connector matrix tilts heavily toward commercial EDRs
(CrowdStrike, SentinelOne, Defender). They want a credible OSS-native
endpoint coverage path before they can run AiSOC in production.

**Roadmap response:** Now-bucket items #1 (Wazuh), #2 (host-agent), #3
(audit.d).

---

## F002 — Alert volume is the wrong floor

**Severity:** S2  **Reach:** broad  **Effort:** M

Pilot operators report that out-of-the-box detection content fires too
frequently on baseline corporate noise (SaaS sign-ins, scheduled CI jobs,
endpoint update telemetry). The signal/noise floor is set higher than
operators expect from a "buyer-value" 1.0 release. They want a published
alert-reduction baseline they can point at, plus per-rule FP visibility.

**Roadmap response:** Now-bucket items #4 (quarantine sweep), #5 (per-rule
FP gate), #7 (alert-reduction benchmark page).

---

## F003 — "Why did this fire?" is a one-click question, not a five-tab one

**Severity:** S3  **Reach:** broad  **Effort:** M

Triagers want a structured explanation surface on the alert detail view:
which rule, which contributing events, which MITRE technique, what
historical FP rate, what the agent suggests. Today they reconstruct it by
hand from the raw event payload and the rule YAML.

**Roadmap response:** Now-bucket item #6 (`POST /alerts/{id}/explain`).

---

## F004 — Linux server fleets are second-class

**Severity:** S2  **Reach:** mid  **Effort:** L

Adopters running Linux-heavy infrastructure (data engineering shops,
ML-platform teams) report that the endpoint detection content assumes a
Windows-or-mac fleet. They want first-class audit.d coverage.

**Roadmap response:** Now-bucket item #3.

---

## F005 — Reserved.

(Originally tracked a duplicate of F002; collapsed but the ID is held to
avoid re-numbering downstream issues.)

---

## F006 — Eval harness is opaque to outsiders

**Severity:** S3  **Reach:** mid  **Effort:** M

External contributors report that the v1.4 eval harness is convincingly
gated in CI but hard to reason about from the outside. They want a
benchmark page that not only shows scores but explains which axes are
agent-accuracy vs. substrate self-consistency, plus a red-team / MITRE
ATT&CK coverage view.

**Roadmap response:** Now-bucket item #7 + Next-bucket item #18.

---

## F007 — Live-action surfaces are vendor-shaped, not capability-shaped

**Severity:** S2  **Reach:** mid  **Effort:** L

Operators with mixed fleets (Wazuh + FleetDM + a CrowdStrike pocket) want
to write one playbook step ("isolate this host") and have the framework
route it to the right vendor primitive. Today they branch on connector
type inside the playbook.

**Roadmap response:** Now-bucket item #8 (generic `live_action`
interface).

---

## F008 — First-contributor experience is too long

**Severity:** S3  **Reach:** broad  **Effort:** S

New contributors report 2–4 hour ramp time before their first connector
runs locally. They want a `HELLO_CONNECTOR.md` walkthrough with a runnable
example (httpbin or similar), copy-paste commands, and a smoke test that
confirms ingestion.

**Roadmap response:** Now-bucket items #10–#12.

---

## F009 — Search is power-user-only

**Severity:** S3  **Reach:** mid  **Effort:** M

Operators want to type "show me failed sign-ins from new IPs in the last
hour" and get back a query. Today they hand-write the DSL.

**Roadmap response:** Now-bucket item #16 (NL-to-query + 50-pair eval).

---

## F010 — Threat intel is a feed, not a briefing

**Severity:** S3  **Reach:** mid  **Effort:** M

CISOs and SecOps leads want a weekly executive-readable briefing of what
the ingested threat intel actually means for *their* tenant — not a raw
feed of IOCs. They also want push-to-MISP for the IOCs that matter.

**Roadmap response:** Next-bucket items #19 (briefings), #20 (MISP push).

---

## F011 — Endpoint coverage decision matrix is missing

**Severity:** S3  **Reach:** mid  **Effort:** S

Adopters evaluating AiSOC ask "which endpoint stack should I pick?" and
there is no published guidance comparing OSS (Wazuh/audit.d/host-agent)
to commercial vendors on coverage, cost, and operational effort.

**Roadmap response:** Now-bucket item #9 (decision-matrix doc).

---

## F012 — CLI scaffolding is missing

**Severity:** S3  **Reach:** broad  **Effort:** M

Plugin authors want `aisoc-cli plugin new <type>` to scaffold a working
plugin in seconds, mirroring `cargo new` / `npx create-*`. Today they
copy-paste from another connector and fix what breaks.

**Roadmap response:** Now-bucket item #12.

---

## F013 — MSSP RBAC has a leakage path through actor profiles

**Severity:** S1  **Reach:** narrow (but P0 where it lands)  **Effort:** S

A multi-tenant pilot reports that the threat-actor profile read endpoint
on `services/api/app/api/v1/endpoints/threat_intel.py` returns rows from
sibling tenants when called with a tenant-scoped token. Cross-tenant data
exposure is treated as P0 regardless of reach.

**Roadmap response:** Now-bucket item #13. Schedule first.

---

## F014 — Production deployment story is "good luck"

**Severity:** S2  **Reach:** broad  **Effort:** L

Production adopters want published Terraform modules for AWS and GCP, not
a `docker-compose.dev.yml` and a wiki page. Several report rolling their
own modules and would prefer to upstream them.

**Roadmap response:** Now-bucket items #14, #15 (skeletons); production
hardening graduates to Next.

---

## F015 — Per-rule FP regression is invisible

**Severity:** S2  **Reach:** broad  **Effort:** S

Detection-pack authors land changes that regress an unrelated rule's FP
rate. The eval harness catches *aggregate* regressions but not per-rule.

**Roadmap response:** Now-bucket item #5.

---

## F016 — Threat actor attribution is mysterious

**Severity:** S3  **Reach:** mid  **Effort:** L

The v0 attribution engine (PR #43) lacks a "show your work" surface.
Analysts want to see the evidence chain, the confidence score, and the
MITRE technique overlaps that drove a verdict.

**Roadmap response:** Carried into Later — graduate the v0 engine.

---

## F017 — Post-mortem authoring is unowned

**Severity:** S3  **Reach:** mid  **Effort:** M

Cases get closed; nobody writes the post-mortem; institutional knowledge
evaporates. Operators want a one-click drafted post-mortem from the case
timeline.

**Roadmap response:** Next-bucket item #21.

---

## F018 — UX time-to-task is uninstrumented

**Severity:** S3  **Reach:** broad  **Effort:** M

There is no objective measurement of how long common operator flows take.
Anecdotal reports of slowdowns can't be confirmed or denied.

**Roadmap response:** Next-bucket item #22 (Playwright p50/p95 suite).

---

## F019 — Reserved.

(Held for the next pass; originally tracked overlap with F013.)

---

## F022 — Plugin SDK lacks a "Hello Plugin" rite of passage

**Severity:** S3  **Reach:** broad  **Effort:** S

Sister concern to F008, scoped to plugins (not connectors).

**Roadmap response:** Now-bucket item #11.

---

## F023 — Plugin lifecycle is undocumented

**Severity:** S3  **Reach:** mid  **Effort:** S

Plugin authors don't know how to version-pin, deprecate, or sign their
plugins for the marketplace. The publishing flow exists; the lifecycle
documentation does not.

**Roadmap response:** Next-bucket item #23.

---

## ID reservation log

`F019`, `F020`, `F021` are reserved for the next synthesis pass. New
themes append at the next free ID, never reuse.

## Cross-references

- [Strategic roadmap (Now / Next / Later)](./AiSOC_ROADMAP.md)
- [Implementation tickets](./AiSOC_Proposed_Issues.md)
