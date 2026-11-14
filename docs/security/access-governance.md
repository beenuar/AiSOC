# Access governance: conditions, elevation and workload identities

Three controls that narrow or time-bound what a principal may do, all
enforced inside the one permission path.

Every statement below names the file or gate that makes it true. Where a
control is narrower than it sounds, the limit is stated here rather than
left for a reader to discover.

## Where enforcement happens, and why that matters

`CurrentUser.require_permission` in
[`services/api/app/api/v1/deps.py`](../../services/api/app/api/v1/deps.py) is
the single permission check. Three ways to be allowed — an API key's explicit
scopes, the RBAC tables widened by live elevation, or the static role map when
nothing resolved a set — and one way to be narrowed, which runs after
whichever of the three allowed.

Conditions are applied *after* and can only deny. A condition that could grant
would be a second authorization system reaching a different answer from the
first, and the two would disagree on the day it mattered — the shape that
produced [GHSA-pm3f-h6gc-rvgp](https://github.com/beenuar/AiSOC/security/advisories/GHSA-pm3f-h6gc-rvgp).

[`scripts/check_one_permission_model.py`](../../scripts/check_one_permission_model.py)
holds that placement. It fails if the condition call moves *inside* a branch,
where it would bind console sessions and silently not API keys, and if the
check stops consulting live elevation. Its `--self-test` runs ten probes, each
removing one half of the wiring and requiring the gate to notice.

## Attribute conditions

A row in `permission_conditions` narrows one permission for one tenant.

| Field | Meaning |
|---|---|
| `permission` | The permission constrained. `cases:write`, `cases:*` or `*`. |
| `role` | Optional. `NULL` binds every role in the tenant. |
| `condition` | `{"operator": …, "value": …}` |
| `enabled` | How a rule is turned off without deleting it. |

Administered at `/api/v1/access-conditions`
([`access_conditions.py`](../../services/api/app/api/v1/endpoints/access_conditions.py)),
which requires `access_conditions:read` / `access_conditions:write`.
Evaluated by
[`services/api/app/security/abac.py`](../../services/api/app/security/abac.py).

### What this deployment can actually enforce

The evaluator implements eight operators. The write surface accepts six —
`GET /api/v1/access-conditions/operators` returns the live answer, with the
reason for each refusal.

The refusal that matters is `mfa_satisfied`. The authenticated principal does
not carry whether MFA was satisfied, so a stored condition naming it could
only ever be *indeterminate*, and indeterminate denies. Accepting the row
would leave an operator with a permanent 403 and nothing explaining it, so the
write is refused instead with that sentence.

The attributes a condition may name are a closed set, because the evaluation
context is a closed set: `source_ip`, `role` and `auth_method`. They are
produced by `CurrentUser.bind_connection_attributes`, and
`test_access_governance.py` asserts every addressable attribute is one that
binding actually sets.

### The attribute cannot be set by the caller

`source_ip` goes through
[`resolve_client_ip`](../../services/api/app/core/trusted_proxy.py), which
honours `X-Forwarded-For` only when the direct peer is inside
`AISOC_TRUSTED_PROXIES`. With no trusted proxies configured — the default —
the header is ignored entirely. An attribute a caller can set is not a
constraint on that caller, and
`test_a_forwarded_header_cannot_move_the_caller_into_the_permitted_range`
asserts it.

### Limits, stated

- **A condition the request carries no data for denies.** That is deliberate:
  treating it as satisfied would mean a caller who omits a header is less
  constrained than one who sends it.
- **Conditions are resolved at authentication and cached**, on the same
  per-tenant version counter as permissions. Adding or disabling one through
  the API bumps that counter, so every replica picks it up on its next
  request. A row written directly into the table with SQL is picked up within
  the 15-second fallback TTL, or immediately if Redis is reachable and
  something bumps the counter.
- **Conditions do not apply to the shared service token or to workload
  credentials acting for a tenant they are scoped to** any differently than to
  anyone else: they are judged on the same three attributes, and
  `auth_method` is how an operator distinguishes them.

## Time-boxed elevation

A row in `privilege_grants` confers a set of permissions to one user until
`expires_at`.

Administered at `/api/v1/elevation`
([`elevation.py`](../../services/api/app/api/v1/endpoints/elevation.py)):
request with `elevation:request`, approve or revoke with `elevation:approve`,
read the tenant's history with `elevation:read`.

| Property | How it is enforced |
|---|---|
| Permissions, not roles | The row names permissions. Elevating to `admin` to isolate one host would confer the wildcard. |
| Nothing until approved | `resolve_elevation` requires `approved_by_id`. A row without one is a request. |
| Nobody approves their own | The approve route refuses when the approver is the requester. |
| No escalation through the approval door | `authorize_permission_grant` refuses an approver who does not already hold every permission the grant confers. |
| Bounded | `expires_at` is `NOT NULL` in the schema, and the route caps a single grant at `MAX_DURATION` (8 hours). |

### Expiry needs no worker

`expires_at` is checked where the grant is *used*, in
`CurrentUser.elevated_permissions`. A sweep job is a job that can be down, and
a grant outliving its window because a worker crashed is the failure mode
just-in-time elevation exists to remove. Revocation writes `revoked_at` and
bumps the RBAC version, so every replica drops the grant on its next request
rather than when its own TTL happens to lapse.

### Elevation does not widen an API key

A key's scopes are a deliberately narrower grant chosen at mint time. Letting
a person's temporary elevation flow into a bearer credential they minted a
year ago would make the elevation outlive its own window by however long the
key lives. `test_elevation_does_not_widen_an_api_key` asserts it.

### It does not escape a condition

Grants widen and conditions narrow, in that order. If a grant were applied
after conditions, elevation would be a way around every attribute rule a
tenant configured. `test_an_elevated_permission_is_still_subject_to_conditions`
asserts it against the live stack.

## Workload identities

A row in `workload_identities` is a credential for one internal service.
Secrets are prefixed `aisoc_wl_` and stored only as a SHA-256 digest.

Administered at `/api/v1/workload-identities`
([`workload_identities.py`](../../services/api/app/api/v1/endpoints/workload_identities.py)),
requiring `workload_identities:read` / `workload_identities:write`.

### What the shared token cannot do

`AISOC_SERVICE_TOKEN` is one string every internal caller presents:

- **Attribution.** Every internal call is "a service".
- **Scoping.** The ingest pipeline presents the same authority as the agents
  worker, so a leak anywhere is a leak everywhere.
- **Rotation.** Changing it means restarting every service at once, which is
  why it does not get changed.

A workload identity fixes all three. The shared-token path is unchanged and
still works — this sits beside it rather than replacing it, because every
existing deployment is configured with the shared token.

### The tenant is a header, and it is mandatory

A workload credential identifies a *service*, not a tenant: the agents
container triages alerts for every tenant on the deployment. So the tenant
comes from `X-AiSOC-Tenant-ID` on each request, is verified against the
`tenants` table, and **a caller that names none is refused**. An empty scope
refuses rather than widening; every cross-tenant leak in this codebase has
taken the other shape, a scope that was absent rather than narrow and a read
that treated absent as "no filter".

This is identical to the shared-token path on purpose — both now call one
`_resolve_tenant_for_service`, because two copies of that rule are two chances
for one of them to treat a missing tenant as no filter.

### Rotation

`POST /workload-identities/{id}/rotate` issues a new secret and keeps the old
one working for 24 hours. A superseded secret with **no** window set is
treated as expired rather than unlimited: "not set" must not be the most
permissive state of a credential. Revoking clears the previous secret too, so
a revocation does not leave a rotation's grace window alive for a day after an
operator believed they had killed it.

### Minting is a platform act

`workload_identities:write` is held only by the wildcard roles (`admin`,
`platform_admin`) and by no tenant-scoped role. That is a decision rather than
an oversight: these credentials are deployment-wide and act for whichever
tenant they name, so minting one from a tenant-scoped session would confer
cross-tenant authority. `test_workload_credentials_are_a_platform_act_not_a_tenant_one`
asserts no non-wildcard role holds it.

Scopes are still bounded by the minter — `authorize_permission_grant` refuses
a scope the caller does not hold, so being able to mint is not being able to
mint anything.

## What proves all of this

| Evidence | Where |
|---|---|
| Live suite: real app, real Postgres, real JWTs, `ENVIRONMENT=production` | [`tests/isolation/test_abac_elevation_live.py`](../../tests/isolation/test_abac_elevation_live.py) |
| The job that runs it, with two negative controls | [`.github/workflows/access-governance-live.yml`](../../.github/workflows/access-governance-live.yml) |
| Offline shape and vocabulary agreement | [`services/api/tests/test_access_governance.py`](../../services/api/tests/test_access_governance.py) |
| The single-path structural gate | [`scripts/check_one_permission_model.py`](../../scripts/check_one_permission_model.py) |
| Every state-changing route authorizes | [`scripts/check_route_authz.py`](../../scripts/check_route_authz.py) |
| Schema | [`services/api/migrations/087_enterprise_iam.sql`](../../services/api/migrations/087_enterprise_iam.sql), [`096_access_governance_permissions.sql`](../../services/api/migrations/096_access_governance_permissions.sql) |

`ENVIRONMENT=production` in the live job is not incidental. `development` is in
`AUTH_BYPASS_ENVIRONMENTS`, so an uncredentialed request there resolves to a
demo administrator — inside the one suite whose purpose is proving that
authorization narrows, that would make every assertion pass for the wrong
reason.

The two negative controls delete one half of the wiring each — the condition
call, and the elevation resolution — and require the suite to go red. Both
were run before the job was written: removing the condition call turned two
assertions red, and removing elevation resolution turned one red.
