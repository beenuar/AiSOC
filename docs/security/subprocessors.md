# Sub-processors

> **Status: incomplete, deliberately.** There is no verified sub-processor
> list for the hosted service in this repository, and this page does not
> invent one. What follows is (1) the answer for self-hosted deployments,
> which is complete and checkable, and (2) a clearly-marked placeholder for
> the hosted service, with exactly what is missing and who can supply it.

## Self-hosted: there are none, by construction

If you run AiSOC yourself, **the project processes none of your data and
operates no infrastructure in the path**. There is no phone-home, no telemetry
to the AiSOC project, and no model-improvement callback. That is enforced by
three independent controls rather than asserted —
[`scripts/check_default_egress.py`](../../scripts/check_default_egress.py),
`tests/test_no_default_egress.py` and
[`container-egress.yml`](../../.github/workflows/container-egress.yml) — and
the detail is in [data handling](data-handling.md#what-never-leaves-in-every-mode).

The processors in a self-hosted deployment are therefore **the ones you
choose**:

| You choose | It receives | Your control |
|---|---|---|
| Your cloud or hardware | Everything | Yours entirely |
| Each vendor you connect | API calls from the connector you configured, under the credential you issued | [Least-privilege scopes](connector-least-privilege.md) |
| A model provider, **only if you configure one** | Pseudonymized evidence, or raw if you turn pseudonymization off | [Per-mode egress](data-handling.md#egress-per-mode) |
| Each threat-intel feed you enable | A request. The only default is the public CISA KEV catalog, which receives nothing from you | Disable it |

A contract with any of those is between you and them. The project is not a
party to it and cannot be.

## Hosted service: what this repository cannot establish

The maintainers operate a managed offering. A sub-processor list for it is a
legal artefact describing the processing arrangements actually in force, and
**it cannot be derived from source code.** This page will not guess at one.

### What the repository does say, and why that is not an answer

Two documents describe hosted infrastructure:

- [`apps/docs/docs/operations/managed-instance.md`](../../apps/docs/docs/operations/managed-instance.md)
  describes an invite-only managed beta, naming Fly.io for compute, Fly
  managed Postgres, Fly managed Redis, and Cloudflare for TLS termination.
- [`docs/managed-mode.md`](../managed-mode.md) describes the
  provision-from-`main` pipeline, and the machinery is still in the tree at
  `infra/fly/managed/` and
  [`managed-auto-provision.yml`](../../.github/workflows/managed-auto-provision.yml).

Three reasons that is documentation and not a sub-processor list:

1. **A deployment description is not a processing agreement.** A
   sub-processor list states who processes personal data, for what purpose, in
   which jurisdiction, and under which contract. None of that is in a compose
   file or a Terraform module.
2. **It cannot be verified as current from here.** Infrastructure changes
   without a commit, and a hosting arrangement that moved would leave these
   pages reading exactly as they do now. A reader has no way to tell a current
   page from a stale one, and neither does this one.
3. **The list is certainly longer than the hosting vendor.** Payment
   processing, transactional email, error tracking, analytics and support
   tooling are all plausible, each is a real sub-processor if present, and
   **naming any of them without confirmation would be the fabrication this
   page exists to avoid.**

### The gap, stated

[ADR-0002](../decisions/0002-compliance-claims.md) committed to publishing a
GDPR posture at `docs/compliance/gdpr.md` — controller/processor mapping, a
DPA template, a data-subject-request workflow and **a sub-processor list** —
"alongside this ADR".

**Neither `docs/compliance/gdpr.md` nor `docs/compliance/README.md` exists in
the tree.** The single occurrence of the word "sub-processor" anywhere in this
repository is the ADR line promising the list. That is recorded here as an
open commitment rather than quietly dropped, which is the whole point of
checking an ADR's deliverables against the tree.

### What has to happen, and by whom

This is a maintainer action, not a code change. Completing it needs:

- [ ] The current hosting, database and cache providers for the managed
      service, confirmed rather than inferred from `infra/`.
- [ ] Every other vendor that touches customer data in that path — payments,
      email, error tracking, analytics, support.
- [ ] For each: purpose, data categories, processing location, and the DPA or
      standard contractual clauses in force.
- [ ] A change-notification commitment, since a sub-processor list without one
      is a snapshot rather than a control.
- [ ] The GDPR posture document ADR-0002 committed to, of which this list is
      one section.

Until those are supplied, **a prospective customer of the hosted service
should ask for the list directly and not infer it from this repository.**
Self-hosting removes the question entirely, which is the honest
recommendation while this page is in the state it is in.

## Models are the sub-processor people forget

Worth separating out, because it is the one most often missed in an AI
product's diligence.

**On the default self-hosted install there is no model sub-processor at all.**
`make up` ships `llama3.2:3b-instruct-q4_K_M` and runs it in your own stack —
no account, no key, no GPU. Triage produces a real verdict from a real model
with real token counts.

A hosted model provider becomes a sub-processor only when **you** configure
one, and then it is your contract. What it receives in that case is
pseudonymized at the contract layer unless you turn that off; the mechanism,
the token scheme and the deliberate exception for public threat indicators are
in [data handling](data-handling.md#self-hosted-with-a-hosted-model).
