---
id: enterprise-sso
title: Enterprise SSO
sidebar_label: Enterprise SSO
---

# Enterprise SSO

SAML and OIDC sign-in, and the connection record that makes either
work.

## Off by default

The whole surface sits behind `SSO_ENABLED` (default `false`). The login
screen asks `GET /api/v1/auth/sso/status` and renders the SSO button only
when the flag is on and an enabled connection exists, so a deployment that
has configured nothing shows nothing. After a successful callback the
browser lands on `/login?next=…` with the tokens in the **fragment** —
destination guards used to drop the fragment, which is v17.1.0's reason the
callback lands there and nowhere else.

For a lockout drill there is `SSO_LOCAL_ADMIN_ONLY`: password sign-in stays
open for wildcard roles only, so a broken IdP cannot strand the break-glass
administrator, and everyone else keeps going through the IdP.

:::warning If you tried this before and it 403'd
You were not doing it wrong. `aisoc_sso_connections` was created by a
migration and **written by nothing** — no API, no console, no script.
`resolve_connection` selects from it on every callback and raises when
there is no row, so both handlers answered 403 on every deployment.

The handlers themselves were complete and tested the whole time. They
were simply unreachable, which is why nothing failed in CI.
:::

## Why the tenant is not in the assertion

This is the design decision the whole feature is built around.

**An identity provider that can name its own tenant can name somebody
else's.** So the tenant is a property of the *connection* an
administrator configured here, and the assertion only says who the
person is.

Group mapping works the same way: an IdP group confers a role only
because an administrator in this deployment said it should.

## Creating a connection

```http
POST /api/v1/sso-connections
{
  "provider": "oidc",
  "issuer": "https://login.example.com",
  "display_name": "Example Corp",
  "enabled": false,
  "default_role": "viewer",
  "allowed_email_domains": ["example.com"],
  "jit_provisioning": true,
  "group_role_mode": "first_login_only",
  "group_role_mapping": {
    "soc-analysts": "infosec"
  }
}
```

Create it **disabled**, check the mapping, then enable it. A disabled
connection does not resolve, so sign-ins keep failing the same way
until you are ready.

### The provisioning policy (v17.1.0)

Three per-connection fields decide who gets created and what they hold:

- **`allowed_email_domains`** is enforced at the provisioning chokepoint —
  an assertion whose verified email is outside the list authenticates
  nobody, however valid the token.
- **`jit_provisioning`** controls whether an unknown identity becomes a
  user at all. When it does, the account lands as **`viewer`**; nothing an
  IdP says can mint anything stronger than the mapping below allows.
- **`group_role_mode`** defaults to **`first_login_only`**: IdP groups set
  the role once, at creation, and administrators own every change after
  it. The alternative keeps re-asserting the mapping on each login — pick
  it only if the IdP is the system of record for roles, because an admin's
  manual correction will not survive the next sign-in.

SSO logins, provisioning events and admin role changes are all audited;
role changes additionally require a `reason` and refuse to demote the last
active administrator.

The example maps to `infosec` — the analyst/hunter role with no
user/role/settings/credential doors — because it is the strongest role a
mapping should normally confer. Legacy names like `soc_analyst` or
`soc_lead` name no catalog row (migration `093` moves users holding one to
`viewer` and reports the count), so a mapping to them provisions the
default role, not the role you meant.

### What is refused

**A mapping to `admin` or `platform_admin`.** v14.0.0 made those
unreachable from every API route so that only `bootstrap_admin` can
mint one, and a group mapping would be a way back in: register an
issuer, claim a group, hold the wildcard.

**Any role you cannot grant yourself.** A connection is a standing
grant to everyone who can authenticate against that issuer, so it is
held to the same bar as creating one user with that role — checked
against the same authority, not a second list that would eventually
disagree.

**An issuer another tenant already claims.** One connection per
issuer, deployment-wide. Two tenants claiming one issuer would make an
assertion ambiguous about which tenant it provisions into. The 409
deliberately does not say which tenant holds it.

## OIDC verification

The `id_token` is verified against the provider's published JWKS —
signature, issuer, audience and expiry — and a token that fails any
check is **discarded, not downgraded**.

It used to be decoded with `verify_signature: False` under a comment
saying to use JWKS in production. An unverified `id_token` is a base64
blob anyone can author, and its `sub`, `email` and `groups` claims were
merged into the identity.

The `nonce` is now compared against the one generated for that
sign-in. It was generated, sent, and never checked, which left the
authorization-code flow open to replay of a token minted for a
different attempt.

### State across replicas

The sign-in state store is Redis-backed. As a process dictionary it
broke roughly **(n-1)/n of sign-ins on an n-replica deployment**: the
browser is redirected by the instance that generated the state and
comes back to whichever instance the load balancer picks.

An in-process fallback covers single-replica and test deployments. The
entry holds the PKCE verifier and the nonce and expires after ten
minutes, which bounds how long an authorization code may sit
unredeemed.

## SAML

`python3-saml` is declared and locked in `services/api`. Both SAML
routes are live; configure the connection with either `metadata_url`
or `metadata_xml`.

### The trust anchor is the connection, not the environment

Until v17.2.0 it was neither: `SAML_IDP_ENTITY_ID`, `SAML_IDP_SSO_URL`
and `SAML_IDP_CERT` decided which identity provider the deployment
trusted, and the `metadata_url` / `metadata_xml` you set on a connection
were stored, returned by `GET /sso-connections`, and read by nothing. A
stock install sets none of those variables, so the trust anchor was
empty and every assertion was refused — with the console showing a
connection that looked configured.

Now the connection decides. `metadata_xml` wins over `metadata_url`,
because a document you pasted is your explicit statement of the trust
material and should not be silently replaced by whatever a URL serves
today. A `metadata_url` is fetched by the API through the same SSRF
guard outbound playbook steps use, and cached for ten minutes per
replica so an IdP outage does not sit in front of every sign-in.

The `SAML_IDP_*` variables still work as a fallback, so a deployment
configured before this change keeps working. A connection wins whenever
one resolves.

:::note More than one identity provider
`/auth/saml/login` with no `?issuer=` resolves the single enabled SAML
connection. With several configured it refuses rather than picking one,
so link each provider's button to
`/auth/saml/login?issuer=<entity id>`.
:::

### Why reading the assertion's `Issuer` is not a hole

`/auth/saml/acs` reads `<saml:Issuer>` out of the POSTed response before
anything has been verified, and uses it to choose which connection's
certificate to verify against.

That looks like the thing this feature refuses to do everywhere else,
and it is not. The asserted issuer selects a **trust anchor**; it does
not confer trust. An assertion naming an issuer whose private key the
sender does not hold fails signature verification and authenticates
nobody. The tenant still comes from the connection row — and the entity
id handed to provisioning is the one the *connection* declares, not the
one the assertion claimed.

### Where the callback lands

On `/login?next=…`, with the access and refresh tokens in the fragment —
the same place the OIDC callback lands, and for the same reason. It used
to redirect straight to the RelayState destination, whose auth guard
rebuilds its bounce target from `pathname + search` and therefore
**drops the fragment**, taking the only copy of the token with it. The
fragment consumer lives on `/login`.

## Checking it works

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/sso-connections | jq '.[] | {provider, issuer, enabled}'
```

If this returns `[]`, every SSO sign-in will 403 — and that is the
state every deployment was in.

## Related

- [SCIM provisioning](./scim.md)
- [Security model](./security.md)
