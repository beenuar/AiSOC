---
id: enterprise-sso
title: Enterprise SSO
sidebar_label: Enterprise SSO
---

# Enterprise SSO

SAML and OIDC sign-in, and the connection record that makes either
work.

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
  "group_role_mapping": {
    "soc-analysts": "soc_analyst",
    "soc-leads": "soc_lead"
  }
}
```

Create it **disabled**, check the mapping, then enable it. A disabled
connection does not resolve, so sign-ins keep failing the same way
until you are ready.

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
