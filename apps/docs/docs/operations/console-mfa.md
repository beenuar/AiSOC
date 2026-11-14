---
id: console-mfa
title: Two-factor authentication
sidebar_label: Two-factor auth
---

# Two-factor authentication

A time-based one-time password on the desktop console, with recovery
codes, per-tenant enforcement, and an audit row for every enrolment and
reset.

## What this replaced

Nothing. Before this, `POST /api/v1/auth/login` verified a password and
returned a token pair, and no user or administrator could make that
insufficient. Passkeys existed on `/responder/*` — the mobile PWA — so
the surface an analyst works from all day was single-factor by
construction.

## Enrolling

**Settings → Two-factor auth → Set up.** The console shows a key to add
to any authenticator app, you enter the code it displays, and the
response carries ten recovery codes.

The recovery codes exist in plaintext exactly once. They are stored as
SHA-256 hashes — not bcrypt, deliberately: a code is 100 bits of
generated entropy with no dictionary to slow an attacker down, and
verification walks every unused code you hold, so ten bcrypt comparisons
per attempt would be a second of CPU on the login path.

An enrolment is only a credential once it is **confirmed**. Starting one
and closing the tab locks nobody out.

## Signing in

A correct password for an enrolled account answers **HTTP 202** with a
short-lived `mfa_token` instead of a session:

```json
{ "mfa_required": true, "mfa_token": "eyJ…", "methods": ["totp", "recovery_code"] }
```

`POST /api/v1/auth/mfa/verify` with that token and a code — either from
the app or one of the recovery codes — returns the ordinary token pair.

:::note Why 202 and not an extended 200
`access_token` and `refresh_token` are required fields of
`TokenResponse`. Making either optional is a break for every generated
client, which `scripts/openapi_diff.py` correctly refuses. A 401 would
have collided with the console's own `handleUnauthorized`, which clears
stored credentials and bounces to `/login`.
:::

A code is spent once it is used. `last_used_step` records the 30-second
step it authenticated at, so a code read over your shoulder cannot be
replayed for the rest of its window. The practical effect worth knowing:
the code you confirm an enrolment with is not reusable to sign in a few
seconds later — wait for the next one.

## Requiring it across a tenant

**Settings → Two-factor auth → Require for everyone**, or
`PUT /api/v1/auth/mfa/policy` with `{"require_totp": true}`. Needs
`settings:write`.

Members who have not enrolled are **asked to enrol at their next
sign-in**, not locked out: the 202 they receive carries
`mfa_enrollment_required` and a challenge token the enrolment endpoints
accept, and the login page walks them through it.

The trade-off is stated rather than hidden: somebody holding a stolen
password can enrol *their own* authenticator before the real user does.
It is bounded by the password still being required, by the window closing
as soon as the real user enrols, and by `mfa.enrolled` being audited with
the source address. Refusing instead would lock out every unenrolled
member of the tenant at the moment the policy is turned on.

A tenant that has never visited this endpoint has **no policy row at
all**, and absence means not required. No migration writes one — a
backfill of a row per tenant would change the meaning of every predicate
that counts rows in that table.

## Losing a phone

Use a recovery code. Each works once.

With none left, an administrator holding `users:write` can clear the
factor:

```http
POST /api/v1/auth/mfa/reset/{user_id}
{ "reason": "lost phone, verified by voice" }
```

Three constraints, because an administrative reset is normally the
weakest link in an MFA deployment:

- the target must be in the caller's own tenant, taken from the
  authenticated principal and never from the request;
- the `reason` is required and lands in the audit row;
- an administrator may **not** reset their own factor here. That would be
  a self-disable with no code. Removing your own factor goes through
  `DELETE /api/v1/auth/mfa`, which requires a current code — otherwise a
  stolen session could strip the thing protecting it.

## What is audited

`mfa.enrolled`, `mfa.disabled`, `mfa.reset`, `mfa.recovery_code_used` and
`mfa.policy_changed`, all on the tenant's own hash-chained audit log, each
carrying the source address.

## Storage

The TOTP secret is vault-encrypted (`vault:v1:` / `vault:v2:`), never the
base32 you scanned. A database dump that yields TOTP secrets yields the
second factor for every account in it, which is most of the reason for
having one. A secret this deployment can no longer decrypt — a rotated
credential key with no rotation-from value — fails **closed**: sign-in is
refused with a message naming the cause, and an administrator resets the
factor.

## Related

- [Enterprise SSO](./enterprise-sso.md)
- [Security model](./security.md)
