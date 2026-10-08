# Security questionnaire

Standard control questions, answered for the **software**. Where the answer
depends on how an operator deployed it, that is said. Where the answer is no,
it says no — a questionnaire with no gaps in it has not been filled in
honestly, and [the gap list](#the-gap-list) at the end collects every one.

Every "yes" names the file or the CI job behind it. A reviewer who wants to
check rather than read should start with
[the verification commands](README.md#verifying-any-of-this-yourself).

---

## Governance and assurance

**Do you hold SOC 2, ISO 27001 or equivalent certification?**
**No.** No third-party audit has been commissioned.
[ADR-0002](../decisions/0002-compliance-claims.md) records the decision, the
trigger condition (a Type I audit in the first quarter with both a revenue
threshold and an enterprise design partner for whom it is
procurement-blocking) and the sequencing. Marketing surfaces say "controls
aligned to" rather than naming a framework unqualified.

**That convention is a convention, not a gate.** ADR-0002 states that
`scripts/audit_compliance_claims.py` "already exists" and fails the build on
an unqualified framework name. **It does not exist, and no workflow references
it** — a finding
[`docs/audit/REALITY_REPORT.md`](../audit/REALITY_REPORT.md) already records
under "Referenced-but-missing CI guard". Listed [below](#the-gap-list).

**Has a penetration test been performed?**
**No external test has been commissioned.** What exists instead is a public
advisory history — 16 advisories published, from both external reports and
internal audits, each with its fix and a regression guard. Private
vulnerability reporting is enabled; the process and response windows are in
[`SECURITY.md`](../../SECURITY.md).

**Do you have a documented secure development lifecycle?**
Yes, and it is unusually literal here: every published product claim maps to a
CI job in [`docs/audit/CLAIM_TO_GATE_MATRIX.md`](../audit/CLAIM_TO_GATE_MATRIX.md)
(290 rows), and `scripts/check_claim_gate_matrix.py` enforces a ratchet of
zero ungated rows. 28 status checks are required on `main`, listed in
[`.github/required-checks.json`](../../.github/required-checks.json) and
cross-checked against the live branch protection.

**How do you know a required check actually graded a commit?**
Because that failed here and was measured. Over the last 30 commits before the
fix, only 336 of 660 required-check × commit pairs had been graded and **0 of
22 required checks had graded all 30** — 28 workflows keyed `concurrency` on
`github.ref`, so a push to `main` cancelled the run before it. There is now a
required check named `No workflow can discard a push to main`, and another,
`No required check can skip its own assertions`, for the adjacent failure
where a job runs only its "nothing changed" step and reports success.

---

## Identity and access

**How do users authenticate?**
Email and password with bcrypt, OIDC or SAML single sign-on
([`sso_connections.py`](../../services/api/app/api/v1/endpoints/sso_connections.py)),
or WebAuthn passkeys
([`passkeys.py`](../../services/api/app/api/v1/endpoints/passkeys.py)). Access
tokens expire in 30 minutes and refresh tokens in 7 days by default.

**Is multi-factor authentication enforced?**
**Not today.** WebAuthn passkeys exist and work, which is a passwordless
*sign-in* factor rather than an enforced second factor, and there is no
policy that requires MFA per role or per tenant. This is a gap, listed
[below](#the-gap-list).

**How is authorization decided?**
One path. `CurrentUser.require_permission` in
[`deps.py`](../../services/api/app/api/v1/deps.py) is the only permission
check in the service, and `scripts/check_one_permission_model.py` enforces
that it stays the only one. Two shipped side by side once — 275 routes read a
hardcoded map while 27 read the database the console's RBAC screen writes to,
so an operator could grant a permission, watch it appear in the UI, and have
275 of 302 routes ignore it.

**Can a user grant themselves more access than they hold?**
No, and the property is enforced on the *granter* rather than enumerated per
route: [`role_grants.py`](../../services/api/app/core/role_grants.py) refuses
any grant of a role, scope or permission the caller does not itself hold, and
refuses the wildcard roles to everyone. An allow-list per route was the
tempting repair and the wrong one — four other routes had the same defect, and
the fifth written next year would have been a new advisory
([GHSA-pm3f-h6gc-rvgp](https://github.com/beenuar/AiSOC/security/advisories/GHSA-pm3f-h6gc-rvgp)).

**Does every endpoint require authentication?**
Yes or listed. `scripts/check_route_auth.py` is default-deny over every route
under `services/`: a route with no auth dependency must appear in one of three
tables with its reason, and the gate fails both on an unexplained route and on
a stale exemption that no longer matches one. `services/mesh` is public by
design (Ed25519 plus k-anonymity; a bearer token would break federation rather
than secure it) and is recorded as such.

**Does every endpoint that changes state check a permission?**
Most, and the rest are counted rather than hidden.
`scripts/check_route_authz.py` reports the ratio and holds a ceiling that can
only fall. Its own docstring calls the number "not a target, a debt balance".

**Is there just-in-time privileged access?**
**No.** A role is held permanently or not at all, so an analyst who needs a
permission once either holds it every day or waits for somebody who does.
Migration `087_enterprise_iam.sql` created a `privilege_grants` table for
exactly this and **nothing reads it**, which is worse than the table not
existing: a row written into it confers nothing while reading as though it
does. Listed as a gap [below](#the-gap-list).

**How do services authenticate to each other?**
With a shared service token, and **the tenant is a mandatory header verified
against the `tenants` table**. A service naming no tenant is refused rather
than resolving to an unscoped read — every cross-tenant leak in this codebase
has taken the other shape, a scope that was absent rather than narrow and a
read that treated absent as "no filter".

The weakness of one shared token is real and worth stating: it cannot be
attributed to a particular service, cannot be scoped so the ingest pipeline
carries less authority than the agents worker, and cannot be rotated without
restarting everything at once. A `workload_identities` table exists for that
and, like `privilege_grants`, has no reader. Both are in the gap list.

This area had a worse defect that is fixed: the API once posted to the
connectors service with **no `Authorization` header at all** from two modules,
and the resulting 401 read to an operator as the customer's own SIEM rejecting
us. `scripts/check_service_token_wiring.py` is the guard.

---

## Tenant isolation

**How is one customer's data kept from another's?**
Per store, because Postgres row-level security covers one of six.
[The table is here](architecture-and-data-flow.md#tenant-isolation-per-store).
Two layers of test: an offline half asserting each read path constructs a
scope, and a live half seeding two tenants into real containers and asserting
a read as A returns zero B rows — after first asserting both rows exist
unscoped, so a scoped pass cannot be vacuous.

**Does the application connect to the database as a superuser?**
No, and that detail is load-bearing: RLS was decorative until it was fixed,
because a superuser ignores every policy even under `FORCE ROW LEVEL
SECURITY`. Services connect as a DML-only `aisoc_app` role, held by
`scripts/check_runtime_db_role.py`.

**Can a caller choose which tenant they act for?**
No. The tenant comes from the authenticated principal, or for a service caller
from a header the model cannot influence.
`scripts/check_route_tenant_scope.py` fails on a route that takes a tenant
identifier without an auth dependency, and on one that accepts a tenant
without intersecting it with the caller's scope.

---

## Encryption

**At rest?**
Connector credentials are encrypted by the application in every deployment —
Fernet by default, or envelope encryption with a KMS-held key-encryption key.
Backups are AES-256-GCM, chunked, with the chunk index and final flag bound as
additional authenticated data so a reordered or truncated archive is refused.
Disk-level encryption for the datastores is a property of your infrastructure.
[Full table](data-handling.md#encryption).

**In transit?**
Browser-to-edge TLS is your terminator's job; the compose stack serves plain
HTTP behind a reverse proxy. **Service-to-service traffic inside the container
network is plaintext on the default stack** — stated rather than implied, and
a deployment needing mutual TLS between services should supply it at the
platform layer.

**Key management and rotation?**
Rotation under envelope mode is a *re-wrap*, not a re-encrypt: the data key is
unwrapped with its original key-encryption key and re-wrapped with the current
one, and the secret body is never touched. Gated by
`services/api/tests/test_envelope_cipher.py`. The residual risk is stated in
the [platform threat model](platform-threat-model.md#residual-risk): the
running API must be able to decrypt, so a live KMS `decrypt` permission on
that host remains a compromise path.

---

## Logging, audit and monitoring

**Is there an audit trail, and can it be tampered with?**
Every mutating API call writes a row carrying the actor, and the rows are
hash-chained so truncation, reordering or rewriting is detectable. A
`BEFORE UPDATE OR DELETE` trigger
([migration 004](../../services/api/migrations/004_audit_log.sql)) refuses the
normal SQL path; the chain catches what a trigger cannot, including an
operator who can disable triggers.

**Could an unauthenticated caller write to it?**
They could, and that is fixed and gated.
[GHSA-w4r8-969c-67p2](https://github.com/beenuar/AiSOC/security/advisories/GHSA-w4r8-969c-67p2):
the audit middleware decoded the bearer token with signature verification
disabled, so a self-crafted JWT got 401 from the route and still planted an
actor of the attacker's choosing into any known tenant's chain. It now audits
only the principal authentication verified, and
[`audit-forgery-live.yml`](../../.github/workflows/audit-forgery-live.yml)
proves it against real Postgres with a negative control that reintroduces the
vulnerability and requires the suite to go red.

**Are AI decisions auditable?**
Yes — the Investigation Ledger records every agent step with its prompt,
response and tools used, and `aisoc_explain_step` over MCP returns them.

**Is there monitoring?**
Partially, and the gap is published rather than papered over. **5 of 19**
services expose `/metrics`; `scripts/audit_prometheus_targets.py` names the
14 that do not, in its own output, so the gap is a line of the gate's report
rather than something a reader has to go looking for. Service-level objective
alerts are generated only for scraped services, so none can be permanently
dead.

---

## Vulnerability management

**How are dependencies managed?**
Every Python service installs from a committed `poetry.lock`; the pip
fallbacks were deleted, because a fallback that resolves a different version
set means the image boots on software nobody tested.
`scripts/check_dependency_pins.py` holds the toolchain equal across fourteen
declaration sites, and `No two install paths disagree` is a required check.

**What scans run?**
CodeQL across three languages, with
[`codeql-alert-gate.yml`](../../.github/workflows/codeql-alert-gate.yml)
failing on any open alert at **any** severity including `note` — and refusing
a vacuous pass: an unanalysed ref, a declared language with no analysis, an
analysis older than ten days, or an analysis belonging to a different commit
than the run's all fail. `Zero open CodeQL alerts`, `Secret scan (gitleaks)`,
`Trivy filesystem`, and the two ratcheted infrastructure-as-code scans are
required checks.

**Why is Semgrep not a required check?**
Because it is non-deterministic on this repository and that was measured: four
pull requests on one base, within thirteen minutes, over an identical
2,267-file corpus with an identical rule set, split 102/40 and 101/39.
Requiring it would red roughly one pull request in twenty for a reason no
author can act on. The sharper consequence is that a ratchet over a scanner
that can lose a finding at random **fails open**, so the decision not to
require it is recorded in three places, each naming the condition under which
requiring it becomes reasonable.

**Supply chain?**
Releases publish an SPDX SBOM, sign images keylessly with cosign, and attach
SLSA provenance (`provenance: mode=max`) — see
[`release.yml`](../../.github/workflows/release.yml). Plugin installs verify
signed Ed25519 manifests against an allow-list and pin image digests at
install time, re-verifying on every load.

---

## Resilience

**Are backups tested?**
Yes, and this is the row to copy if you only check one.
`Backup → destroy → restore (Postgres via S3)` is a **required** status check
that seeds real data, encrypts it, destroys the database, restores it,
measures recovery time and proves a bit-flipped archive is refused. It is
required because "we take backups" and "we have restored one" are different
claims.

**What happens to a message that cannot be processed?**
A poison event goes to a dead-letter queue
([`dlq.py`](../../services/fusion/app/services/dlq.py)) with a replay path,
rather than stopping the consumer. Consumers distinguish permanent from
transient faults and say which — a consumer detached from its topic while
`/health` returns 200 is indistinguishable from an idle one, which is exactly
what made one such bug invisible for a long time.

---

## AI-specific controls

**What stops prompt injection from driving a response action?**
A layered answer, and the honest number is published with it. Telemetry is
wrapped in a per-run nonce fence the attacker cannot predict; a guard scans
for instruction-shaped content and demotes the case to manual review on a
high-severity hit; model output is re-validated against a schema, so a coerced
free-text verdict is not authoritative; and every tool call is governed by a
capability contract with an approval tier.

**And the numbers?** On the field-native corpus the guard went from 66.7% to
98.1% detection, and on the prose corpus from 0.852 to 0.96 recall with false
positives still at 0.00. Those are the flattering ones. The one that matters
is that **held-out payloads moved only 3.6% to 7.1%** — the hardening fitted
the corpus far more than it closed the threat, and it is published *because*
it is unflattering. An MIT-licensed guard in a public repository
means white box is the correct threat model. Per-family flip rates are
published too, including `fake_tool_output` at 1.0 flip and 0.0 catch,
recorded at that value rather than patched.

**Can the model execute an action on its own?**
Not by default. The shipped posture is copilot with human approval. Where
autonomy is enabled, the tier is per tenant and per capability, risk and
reversibility are declared on the *verb* rather than the vendor, and a
capability whose effect cannot be verified is not eligible for automatic
execution — "unverifiable means not autonomous" demoted two capabilities that
had claimed it.

**Is customer data used to train models?**
No. The project neither trains nor fine-tunes on customer data and has no
mechanism to receive it. What a provider you configure does with what you send
is between you and them, which is why the pseudonymizer sits at the contract
layer.

**Can the model choose its own tenant?**
No, and this one is worth naming because it is easy to get wrong: an MCP tool
that declares a `tenant_id` argument and forwards it is a latent cross-tenant
read even when unexploitable. The tenant comes from the principal or from a
header, and the parameter is deleted rather than validated.

---

## Privacy and data-subject rights

**Where is personal data processed?**
Wherever you run it. See [sub-processors](subprocessors.md) — for self-hosted
the answer is "your infrastructure and the vendors you chose", and for the
hosted service that page says plainly what this repository cannot establish.

**Is there a data-subject-request workflow?**
**No dedicated endpoint exists.** Audit export and tenant deletion exist and
are linked from [data handling](data-handling.md#retention-and-deletion), but
a subject-request route is not in the tree. ADR-0002 names it as an open
question. Listed as a gap below.

**Is there a published GDPR posture?**
**No.** ADR-0002 committed to `docs/compliance/gdpr.md` "alongside this ADR"
and it does not exist. Listed as a gap below.

---

## The gap list

Collected so a reviewer does not have to assemble it from the prose above.
Each is a real absence, not a caveat.

| Gap | State today | Where it is recorded |
|---|---|---|
| **Enforced MFA** | Passkeys exist as a sign-in factor; no per-role or per-tenant enforcement policy | This page |
| **Just-in-time elevation** | `privilege_grants` exists as schema with no reader; a row in it confers nothing | This page |
| **Attribute conditions on a permission** | `permission_conditions` exists as schema with no reader; a row in it denies nothing | This page |
| **Per-service internal credentials** | `workload_identities` exists as schema with no reader; the one shared token is unattributable, unscopable and effectively unrotatable | This page |
| **SOC 2 / ISO 27001** | Not commissioned; "controls aligned to" framing held by convention | [ADR-0002](../decisions/0002-compliance-claims.md) |
| **The gate ADR-0002 claims guards that framing** | `scripts/audit_compliance_claims.py` does not exist and no workflow references it | [`REALITY_REPORT.md`](../audit/REALITY_REPORT.md) |
| **Penetration test** | Not commissioned; 16 published advisories instead | [`SECURITY.md`](../../SECURITY.md) |
| **Hosted-service sub-processor list** | Does not exist; ADR-0002 promised one that never landed | [Sub-processors](subprocessors.md) |
| **GDPR posture document** | `docs/compliance/gdpr.md` promised by ADR-0002, absent | [Sub-processors](subprocessors.md) |
| **Data-subject-request endpoint** | Not in the tree | This page |
| **Service-to-service TLS** | Plaintext inside the container network on the default stack | [Data handling](data-handling.md#encryption) |
| **`/metrics` coverage** | 5 of 19 services; the other 14 named in the gate's own output | `scripts/audit_prometheus_targets.py` |
| **Prompt-injection guard on held-out payloads** | 7.1%. Published because it is the honest number | [Agent threat model](agent-threat-model.md#residual-risk) |
| **Connector scope conformance gate** | The least-privilege document is enforced in review, not by CI | [Least privilege](connector-least-privilege.md#audit) |

If a control you need is absent from both the answers and this table, it is
more likely that nobody asked than that it is deliberately omitted —
[open an issue](https://github.com/beenuar/AiSOC/issues) and it will be
answered the same way: with the file, or with "no".
