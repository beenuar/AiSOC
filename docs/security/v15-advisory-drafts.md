# v15.0.0 — draft security advisories

Thirteen defects, all fixed in [`v15.0.0`](https://github.com/beenuar/AiSOC/releases/tag/v15.0.0)
(2026-10-01). This file is the **draft text for the GitHub Security Advisory
of each**, kept in the repository so the wording is reviewable in a diff
rather than typed once into a web form.

## How to read the severities

Every CVSS vector below is v3.1 and is scored against **a default
deployment of `v14.0.0`**, not against a worst-case configuration. Where a
defect's impact depends on something an operator chose, that is stated in
the vector's scope rather than assumed in the operator's favour.

Three of these are deliberately scored *lower* than their description might
suggest, and the reason is given in each: a cookie no code reads, a
control that is defence in depth behind a guard that was itself correct,
and a path reachable only by an already-authenticated principal.

**None of these were reported by an external researcher.** They were found
by reading the code at the `v14.0.0` tag. No exploitation is known, and the
disclosure is therefore retrospective rather than coordinated — the
maintainer's decision, recorded in `SECURITY_BATCH_PROGRESS.md` as
deviation D0.

---

## S1. Anonymous requests were served as a tenant administrator

**Severity:** Critical — CVSS 3.1 **9.1**
`AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N`
**CWE-287** Improper Authentication · **CWE-1188** Insecure Default

`is_dev_mode()` granted an unauthenticated caller the `admin` role in the
demo tenant, and `DEMO_TENANT_ID` was the *same UUID* that
`bootstrap_admin.py` seeds as the first real tenant
(`00000000-0000-0000-0000-000000000001`). A deployment that never set
`ENVIRONMENT` therefore served anonymous requests as an administrator of
its own production tenant.

Scope is Changed because the anonymous principal crosses into a tenant it
was never issued for.

**Fixed by** requiring three independent conditions — `ENVIRONMENT` in the
development set, an explicit `AISOC_DEV_AUTH_BYPASS=1`, and every published
bind address being loopback — and by moving the demo tenant to a distinct
UUID so the collision cannot recur.

**Workaround for `v14.0.0`:** set `ENVIRONMENT=production`.

---

## S2. One tenant's Copilot conversations and saved hunts were readable by every other

**Severity:** High — CVSS 3.1 **7.7**
`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N`
**CWE-639** Authorization Bypass Through User-Controlled Key · **CWE-668** Exposure to Wrong Sphere

Conversations and saved searches lived in module-level dictionaries with no
tenant column. `GET /api/v1/copilot/conversations` returned every tenant's
conversations to any authenticated caller;
`GET /api/v1/copilot/conversations/{id}` returned any conversation to
anyone holding its id.

This is not chat history. A conversation carries the analyst's question —
naming hosts and users — and the model's answer, which quotes the alert
evidence it was grounded on.

Integrity is Low rather than None because the same store accepted writes;
Availability is None because a restart lost the data for everyone equally.

**Fixed by** migration `076`, which moves both into tenant-scoped tables
with `tenant_id NOT NULL`, forced RLS, and a query-layer predicate.

---

## S3 / S4. Fabricated records served as tenant data

**Severity:** Low — CVSS 3.1 **4.3**
`AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N`
**CWE-1230** Exposure of Sensitive Information Through Metadata

`/api/v1/shifts` returned three invented shifts with named analysts and a
fabricated ticket id; `/api/v1/threatintel/stix/*` returned invented
indicators and collections. Both accepted writes into the same shared
lists, so one tenant's POST was readable by another.

Scored Low deliberately: the data was fictional, so the confidentiality
impact is the cross-tenant leak of what a *caller wrote*, not of real
security telemetry. The more serious problem was honesty rather than
disclosure.

**Fixed by** deleting the shift board (no caller existed anywhere) and
answering 404 on the STIX reads outside demo mode. **Breaking.**

---

## S5. No rate limit on credential verification

**Severity:** High — CVSS 3.1 **7.5**
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
**CWE-307** Improper Restriction of Excessive Authentication Attempts

`POST /api/v1/auth/login` applied no throttle, lockout or backoff, so
password guessing was bounded only by network throughput.

**Fixed by** a two-counter throttle — per account and per source address —
with exponential backoff and temporary lockout. A successful login clears
the account counter but **not** the source counter, so a spray that happens
to succeed once does not reset the attacker's budget.

---

## S6. Both SSO handlers minted a session for an identity nobody authenticated

**Severity:** High — CVSS 3.1 **8.1**
`AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`
**CWE-287** Improper Authentication · **CWE-1188** Insecure Default

`app/auth/saml.py` issued a signed token for `stub-saml-user` whenever
`python3-saml` failed to import — and `python3-saml` was declared in **no
install path**, so that branch was the only reachable path through the
assertion consumer on every deployment. `app/auth/oidc.py` did the same for
`oidc-stub-user` whenever `OIDC_ISSUER` was unset, which is the default.

Attack Complexity is High and this is **not** scored 9.8 for one reason:
the API verifies a bearer token and does not read the `aisoc_token` cookie
these set. The token was real and signed; nothing consumed it. A cookie the
API ignores today is one it might read tomorrow, which is why this was
fixed before SSO was made to work rather than after.

**Fixed by** deleting both branches, answering 501, and declaring
`python3-saml` so the 501 is clearable.

---

## S7. The audit log could not name the credential that acted

**Severity:** Medium — CVSS 3.1 **5.3**
`AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N`
**CWE-778** Insufficient Logging

An API key owned by a user resolved to that user's email, so an entry read
identically whether the person acted at the console or a key they minted a
year ago acted from a script. Revoking a key and disabling a person are
different responses, and the log could not say which applied.

Separately, `tenant_admin` did not hold `audit_log:read`: the only roles
that did held `*` across every tenant, so a customer could not review their
own trail. That is a compliance failure against SOC 2 CC7.2 and ISO 27001
A.12.4 rather than a vulnerability, and is not scored.

**Fixed by** carrying the key prefix on the principal and recording
`auth_method` on every entry, and by granting `tenant_admin` a
tenant-scoped read.

---

## S8. Six of seven `mssp_*` tables had no row-level security

**Severity:** Medium — CVSS 3.1 **6.5**
`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N`
**CWE-566** Authorization Bypass Through User-Controlled SQL Primary Key

Only `mssp_tenant_metrics` carried a policy. On the other six the query
predicate was the single control between one MSSP's portfolio and
another's.

Scored 6.5 rather than higher because this is **defence in depth that was
absent, not a reachable bypass**: the route guards were correct at the time
of the release. The reason it matters is the precedent —
`POST /mssp/overrides` previously wrote a caller-supplied child tenant id
onto a row the resolver read back filtered on the victim's tenant, and when
that guard was wrong there was no second layer.

**Fixed by** migration `077`. Forced RLS now covers 123 tables, up from
117.

---

## S9. State-changing routes that authenticated and authorized nothing

**Severity:** Medium — CVSS 3.1 **6.5**
`AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N`
**CWE-862** Missing Authorization

`POST /knowledge-base/query` reached the tenant's knowledge base and could
spend an LLM call on bare identity. Four MSSP routes managing portfolio
membership were *correctly* guarded by an organisation-role dependency the
coverage gate did not recognise — reported here for completeness because
the published figure was wrong, not because those routes were open.

**Fixed by** a named `knowledge_base:read` entitlement, by teaching the
gate to recognise organisation-role decisions, and by requiring every
remaining identity-only route to carry a written reason.

---

## S10. An AI triage could suppress an attacker's own alerts

**Severity:** High — CVSS 3.1 **7.1**
`AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:L`
**CWE-349** Acceptance of Extraneous Untrusted Data · **CWE-807** Reliance on Untrusted Inputs in a Security Decision

Three AI-authored outcomes at ≥0.90 confidence on one evidence signature
auto-closed every later alert sharing it, with no human having looked. The
corroboration threshold was never a mitigation, because **the attacker
chooses how many alerts to send** — raising it from three to thirty changes
the cost, not the outcome.

Integrity is High because the result is a detection the SOC no longer sees;
Availability is Low because the alert path remains functional for
everything else. Confidentiality is None.

**Fixed by** restricting suppression to human-confirmed priors, expiring
priors 90 days after their last confirmation, and refusing to suppress on
evidence that tripped the prompt-injection guard.

---

## S11. Every Kafka client, and every Postgres client, spoke cleartext

**Severity:** Medium — CVSS 3.1 **6.8**
`AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`
**CWE-319** Cleartext Transmission of Sensitive Information

Thirteen Kafka clients across Python, Go and TypeScript each took the
library default, which is `PLAINTEXT` in all three. The spine carries raw
event bodies, usernames, hostnames and command lines. `sslmode` was unset
on every Postgres client, which libpq reads as `prefer` — TLS when offered,
cleartext when not, with no way to tell which happened.

Attack Vector is Adjacent and Complexity High because this requires a
position on the broker's network path.

**Fixed by** one transport resolver per language that refuses cleartext in
a protected environment, and by reporting both an explicit and an *unset*
`sslmode` at boot.

---

## S12. A shipped integration credential

**Severity:** Medium — CVSS 3.1 **5.9**
`AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:L`
**CWE-1392** Use of Default Credentials

`caldera_api_key` defaulted to `ADMIN123`, Caldera's own published
first-run credential. A deployment that never configured Caldera still
built a client holding it and pointed it at whatever `caldera_url`
resolved to — so the failure mode was not "purple-team does not work", it
was "purple-team authenticates to a Caldera instance with the default
password", which succeeds against any Caldera nobody rotated.

**Fixed by** removing the default and refusing with a 503 that names
`CALDERA_API_KEY`.

---

## S13. A permission granted in the console governed 27 routes out of 302

**Severity:** Medium — CVSS 3.1 **6.5**
`AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N`
**CWE-863** Incorrect Authorization

275 route dependencies read a hardcoded role map while 27 read the RBAC
tables the console's administration screen writes to. An operator could
grant a permission, watch it appear in the UI, and have 275 of 302 routes
ignore it — and **revoking worked no better**, which is the direction that
makes this a vulnerability rather than a usability defect.

Worse, the database path fell back to the static map whenever a user had no
rows in `user_roles`, so **removing every role from a user restored their
static permissions**.

**Fixed by** resolving permissions once at authentication from the
database, and by distinguishing "this tenant has no RBAC configured" from
"this user has been deprovisioned" — a question answered at the tenant
level, not the user's row count.

---

## What is deliberately not claimed

These severities are the maintainer's own assessment and have not been
reviewed by a third party or assigned CVE identifiers. No exploitation of
any of them is known, and no telemetry exists that would show it if it had
occurred — which is itself worth stating, because "no evidence of
exploitation" and "evidence of no exploitation" are different sentences and
only the first is true here.
