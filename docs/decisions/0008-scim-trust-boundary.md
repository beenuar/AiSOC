# ADR-0008: SCIM is a third-party write surface into identity, and is scoped by its credential

- **Status**: accepted
- **Date**: 2026-09-27
- **Relates to**: gap-closure plan Phase 13.1

## Context

Every write path in this platform up to now has been driven by a person
holding a session, or by a service token this project issued to its own
workers. SCIM is neither. It is a long-lived bearer credential, pasted into a
configuration screen in somebody else's product, used unattended on that
product's sync schedule, to create principals, change what they may do, and
end their access.

That is a trust boundary, and it moves in three directions at once:

1. **Who may create a principal.** Before SCIM, an account came from a
   sign-up flow or an administrator. After it, an account comes from whoever
   controls the identity provider's assignment rules.
2. **Who may raise a principal's authority.** Group membership decides what
   a person may do. Group names are chosen in the customer's directory, by a
   set of people that is usually larger than the set of platform
   administrators.
3. **What "deprovisioned" means.** An identity provider that reports a
   successful deprovisioning has discharged its duty. If access has not
   actually ended on this side, nobody is looking any further.

There is also a specific, well-documented hazard in the protocol itself. The
two identity providers this platform supports both implement RFC 7644 and
disagree about PATCH in five places. One of those disagreements is that a
deactivation arrives as the JSON string `"False"` rather than the boolean
`false`. In Python, `bool("False")` is `True`, so the obvious implementation
accepts the request, deactivates nothing, and returns 200. The provider
records the deprovisioning as done.

## Decision

**The tenant comes from the credential, and there is no request field that
can influence it.** `aisoc_scim_tokens.tenant_id` is `NOT NULL` and is the
only source of tenancy on the SCIM surface. RFC 7643 defines no tenant
attribute, so this is not a restriction we are imposing on the protocol; it
is the absence of any alternative. `org_id` is nullable beside it, so a
single-tenant deployment can run SCIM with no operator organisation while an
MSSP can still join a provisioning event to the organisation that caused it.

**The credential is stored as a digest and rotates with an overlap window.**
A SHA-256 digest for lookup and a 12-character prefix for display, matching
the convention `api_keys` already uses. The token is 192 bits from `secrets`,
so a digest is correct and a password KDF would be wrong twice over: there is
no low-entropy guess to slow down, and a KDF on the request path would put a
deliberate delay in front of every call a provider makes. Rotation mints a
replacement and puts the superseded row on a clock rather than revoking it,
because a rotation that cuts over instantly takes the integration down for as
long as it takes a person to paste the new secret across, and that is why
rotation gets deferred and secrets get old. A zero grace window is supported
for rotation after a disclosure.

**Deprovisioning ends access rather than marking it.** Three things, and the
second and third are the ones that make it more than a flag:

- `users.is_active = false`, which the request path re-reads on every
  authenticated call, so an in-flight session stops at the next request;
- `users.sessions_revoked_at = now`, checked against a new `iat` claim, so a
  token minted before the deprovisioning stays refused even if the principal
  is later re-activated while that token is still inside its expiry window;
- every `api_keys` row the principal owns is deactivated, because an API key
  outlives sessions entirely and neither of the first two steps reaches it.

**An unrecognised directory group confers nothing.** A pushed group either
resolves to one of the roles `ROLE_PERMISSIONS` actually enforces, or it
resolves to `NULL` and is membership-only: recorded, audited, and granting no
privilege. `platform_admin`, `admin` and `api_service` are unreachable from
any group name at all, so nobody who can create a group in the customer's
directory can mint a wildcard role by choosing its name.

**Every operation is audited against the credential that performed it.** The
actor of a SCIM change is a machine, and an audit trail that cannot say which
machine is not an audit trail. The record carries the credential's name and
id and, for a deprovisioning, the count of programmatic credentials it
revoked.

## Consequences

- New migration `071_scim_provisioning.sql` adds four tenant-scoped tables
  with the standard row-level-security shape and `aisoc_app` grants, plus
  `users.sessions_revoked_at`.
- Access and refresh tokens now carry `iat`. The claim is additive and the
  nine services that verify these tokens ignore unknown claims, so this is
  backward compatible. A token with no `iat` is treated as revoked whenever a
  revocation exists, which fails closed for credentials minted before the
  upgrade.
- A pre-existing defect is closed alongside: `_resolve_api_key` fell through
  when a key named a user who was inactive or gone, leaving the key working
  under a generic `api_service` role. Deprovisioning a user therefore did not
  end the programmatic access they had minted for themselves.
- `scripts/check_scim_contract.py` keeps the discovery documents, the routes,
  the audit calls and the role mapping in agreement, in both directions.
- Filtering implements one comparison shape and refuses everything else.
  Silently dropping an unsupported filter would return every principal in the
  tenant, and a provider reading that concludes the user it was about to
  create already exists.

## Alternatives considered

**Put the tenant in a path segment, `/scim/v2/{tenant}/Users`.** Rejected.
It reintroduces the exact shape this repository has already been burned by:
a boundary that is a request parameter. The credential would still have to be
checked against the segment, so the segment adds a failure mode and no
capability.

**Create a platform role for every pushed group.** Rejected. It manufactures
roles that grant nothing and that read, in a console, as though they grant
something. Mapping to the enforced vocabulary and leaving the rest null makes
"unrecognised" mean powerless rather than unknown.

**Delete the principal on `DELETE /Users/{id}`.** Rejected. A deleted row
takes its audit attribution, case ownership and approval history with it, and
this platform's own records reference the principal. Access ends completely
either way, which is what DELETE means here; RFC 7644 permits deactivation as
the implementation of delete.

**Implement the full RFC 7644 filter grammar.** Rejected for now. It would
mean a parser whose untested branches are reachable from an
authentication-adjacent surface, to serve queries no provisioning client
sends. An unsupported filter is a documented SCIM error and providers handle
it.

**Leave `users.is_active` as the whole of revocation.** Rejected. It is
genuinely effective while the flag is down, which is what makes it
attractive, but it is reversible: re-enabling an account resurrects every
token minted before the deactivation that has not yet expired.
