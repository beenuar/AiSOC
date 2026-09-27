---
title: SCIM provisioning
sidebar_label: SCIM provisioning
description: Provision and deprovision AiSOC principals from your identity provider using SCIM 2.0.
---

# SCIM provisioning

AiSOC implements SCIM 2.0 (RFC 7643 and RFC 7644) so your identity provider
can create principals, keep their attributes current, map directory groups
onto AiSOC roles, and end access when somebody leaves.

The base URL is:

```
https://<your-aisoc-host>/scim/v2
```

Your identity provider appends `/Users` and `/Groups` to that itself.

## What is implemented

| Capability | Status |
|---|---|
| `/Users` (list, get, create, replace, patch, delete) | Supported |
| `/Groups` (list, get, create, replace, patch, delete) | Supported |
| `/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas` | Supported |
| PATCH | Supported |
| Filtering | One `attribute eq "value"` comparison |
| Bulk | Not implemented |
| Sorting | Not implemented |
| Password change through SCIM | Not implemented |

`/ServiceProviderConfig` is the authoritative answer and is checked against
the routes in CI, so it cannot advertise something this build does not serve.

Filtering deliberately supports one comparison rather than the full RFC 7644
grammar, because that is the shape provisioning sends: a lookup before a
create. An unsupported filter returns a SCIM error rather than being ignored.
Ignoring it would return every principal in your tenant, and a provider
reading that result may conclude the user it was about to create already
exists.

## Creating a credential

SCIM authenticates with a bearer token scoped to one tenant. Mint one from
the console, or through the API:

```bash
curl -X POST https://<your-aisoc-host>/api/v1/scim-tokens \
  -H "Authorization: Bearer $AISOC_SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "corporate-directory", "expires_in_days": 365}'
```

The response carries the raw secret once. It is stored as a SHA-256 digest,
so it cannot be recovered afterwards; if it is lost, rotate.

Requires the `settings:write` permission.

## Rotating a credential

```bash
curl -X POST https://<your-aisoc-host>/api/v1/scim-tokens/<id>/rotate \
  -H "Authorization: Bearer $AISOC_SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"grace_hours": 24}'
```

Both secrets work during the grace window, so you can paste the replacement
into your identity provider without a failed sync in between. The superseded
token expires by itself at the end of the window.

If you are rotating because a secret was disclosed, send `{"grace_hours": 0}`.
That revokes the old secret immediately and your next sync will fail until
the new one is in place, which is the correct trade in that situation.

## Mapping groups to roles

Push the groups you want AiSOC to act on. Each group resolves to one AiSOC
role by name:

| Group name contains | Resolves to |
|---|---|
| `tenant` and `admin` | `tenant_admin` |
| `soc` and `lead`, `soc` and `manager`, or `incident commander` | `soc_lead` |
| `threat hunter`, `threat hunting`, or `hunter` | `threat_hunter` |
| `soc analyst`, `triage`, or `analyst` | `soc_analyst` |
| `viewer`, `read only`, or `auditor` | `viewer` |

Matching ignores case, punctuation and plurals, so `AiSOC-SOC-Analysts`,
`soc analyst` and `SOC_Analysts` all reach `soc_analyst`.

A group whose name matches nothing is still created and its membership is
still tracked, and it confers no privilege at all. The group's resolved role
is returned on the Group resource under
`urn:aisoc:params:scim:schemas:extension:2.0:Group`, so you can confirm what
a group grants by reading the same response your identity provider sees:

```json
{
  "urn:aisoc:params:scim:schemas:extension:2.0:Group": { "mappedRole": "soc_lead" }
}
```

A `null` there means the group grants nothing. Rename the group to match the
table above if that was not what you intended.

When a principal belongs to several mapped groups they hold the highest of
those roles, so the result does not depend on the order your provider happens
to sync in. A principal in no mapped group holds `viewer`.

**No group name can grant `platform_admin`, `admin` or `api_service`.** Those
roles hold wildcard permissions, and the set of people who can create a group
in a corporate directory is usually larger than the set of AiSOC
administrators. Assign them in AiSOC directly.

## What deprovisioning does

Deactivating a principal (`active: false`, or `DELETE /Users/{id}`) does
three things:

1. Marks the account inactive. AiSOC re-reads this on every authenticated
   request, so an open session stops at the next call rather than at the next
   token expiry.
2. Records a session-revocation timestamp. Access and refresh tokens issued
   before that instant are refused permanently, so re-enabling the account
   later does not resurrect a token minted before the person left.
3. Deactivates every API key that principal owns. An API key outlives
   sessions and is not reached by either step above.

`DELETE` deactivates rather than erasing the row, which RFC 7644 permits.
Erasing it would take the principal's audit attribution, case ownership and
approval history with it. Access ends completely either way.

Re-activating a principal restores sign-in and does **not** restore their API
keys. Mint fresh ones; a key whose owner cannot see it was revoked is a key
nobody will rotate.

## Auditing

Every SCIM operation writes to the tamper-evident audit log, under actions
`scim:user:create`, `scim:user:patch`, `scim:user:replace`,
`scim:user:delete`, `scim:group:create`, `scim:group:patch`,
`scim:group:replace` and `scim:group:delete`, plus `scim:token:create`,
`scim:token:rotate` and `scim:token:revoke` for credential administration.

Because the actor is a machine rather than a person, each record carries the
credential that performed it under `provisioned_by`. A deprovisioning record
additionally carries `programmatic_access_revoked`, the number of API keys
that went with it, and `sessions_revoked_at`.

`last_used_at` on each credential is how you find an abandoned integration.
A token nobody has used for months is a standing credential with no owner.

## Tested against

The provisioning flows are tested against request shapes from Okta and
Microsoft Entra ID, which differ from each other in several places that a
single-provider implementation gets wrong:

- deactivation with no `path` and an object value, versus an explicit `path`
  and the string `"False"`
- `op` spelled lowercase versus capitalised
- group member removal through a path filter with no value, versus
  `path: "members"` with the id in a value array
- `userName` omitted in favour of `emails` when the directory's username
  attribute is unset

Both providers' full sequences (create, update, group membership, deactivate)
run in CI.

## Troubleshooting

**Every sync fails with 401.** The credential is wrong, revoked, or expired.
The response does not say which, on purpose. Check `last_used_at` and the
audit log for `scim:token:revoke`, then rotate.

**A group syncs but nobody gains any permission.** The group name did not
resolve. Read `mappedRole` on the Group resource; if it is `null`, rename the
group to match the table above.

**A create returns 409.** A principal with that `userName` already exists in
the tenant. This is the correct answer and your provider will reconcile
against the existing record; AiSOC will not create a second account for the
same address.

**A filter returns 400 with `scimType: "invalidFilter"`.** The filter is
outside the supported comparison. Providers fall back to listing.
