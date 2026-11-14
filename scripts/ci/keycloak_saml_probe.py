#!/usr/bin/env python3
"""A real Keycloak signs somebody in to the real app, over SAML.

Depth 8.1. Driven by `.github/workflows/sso-live.yml`.

What this proves that the sibling probes do not
-----------------------------------------------
`keycloak_oidc_probe.py` takes a real Keycloak `id_token` through the API's
own verifier. It is a strong check on one function and it stops at the
function: nothing about it says a sign-in completes.

`tests/isolation/test_sso_live.py` drives the whole SAML sign-in, but
against an identity provider this repository authors — a keypair and a
metadata document it also writes. A self-authored provider agrees with a
self-authored expectation by construction, which is the shape this
repository keeps rediscovering as "the test double was more capable than
the real thing".

This probe closes the gap between them. It walks the **entire SP-initiated
SAML flow**: the app builds an `AuthnRequest` from the trust material an
operator stored on the connection, a real Keycloak renders its own login
page, a real person's credentials are posted to it, Keycloak mints and
signs a real `Response`, and that document is posted back to the real
`/auth/saml/acs` of an application built by `create_application()` against
real Postgres with every migration applied.

There is no browser, but there is a browser *hop*: the redirect is
followed, the login form is parsed out of Keycloak's own HTML and
submitted with a cookie jar, and the auto-submitting POST form Keycloak
answers with is what supplies the assertion. The only thing a browser
would add is JavaScript, which Keycloak's login form does not require.

The negative control
--------------------
After the positive run, the **same** assertion is replayed against the
same connection with one byte-range changed: the certificate in the stored
metadata is swapped for a different realm's. A handler that skipped
signature verification — or that read its trust anchor from somewhere
other than the connection — would sign Alice in twice. It must refuse the
second.
"""

from __future__ import annotations

import asyncio
import os
import re
import sys
import uuid
from html import unescape
from pathlib import Path
from typing import Any

import httpx

_HERE = Path(__file__).resolve()
# `services/api` is the import root for `app.*`; this file's own directory
# is the import root for `keycloak_realm`.
sys.path.insert(0, str(_HERE.parents[2] / "services" / "api"))
sys.path.insert(0, str(_HERE.parent))

from keycloak_realm import (  # noqa: E402
    EMAIL,
    GROUP,
    PASSWORD,
    SP_ACS_URL,
    SP_ENTITY_ID,
    SP_ORIGIN,
    USERNAME,
    KeycloakError,
    admin_token,
    bootstrap,
    saml_descriptor,
    saml_entity_id,
)

KEYCLOAK = os.environ.get("KEYCLOAK_URL", "http://localhost:8080")

# A realm whose only purpose is to own a signing key this deployment does
# not trust, for the negative control.
UNTRUSTED_REALM = "aisoc-ci-untrusted"

# The group the connection maps to a role. `infosec`, not `admin`: a group
# must never be able to confer the wildcard, and asserting the mapping
# landed is only meaningful for a role that is not the default.
MAPPED_ROLE = "infosec"

# Written into `display_name` so a re-run can find and clear the row it
# left behind, whatever issuer that run used.
CONNECTION_MARKER = "Containerised Keycloak"

# Every tenant this probe creates is slugged with it, so a re-run can
# remove its own leftovers and nothing else.
TENANT_SLUG_PREFIX = "kc-probe-"


def _dsn() -> str:
    value = (os.environ.get("ISOLATION_SSO_DSN") or os.environ.get("DATABASE_URL") or "").strip()
    if not value:
        raise SystemExit(
            "ISOLATION_SSO_DSN is not set. This probe needs real Postgres with every "
            "migration applied; it has no offline mode and must not appear to pass without one."
        )
    return value


def _untrusted_certificate() -> str:
    """A signing certificate from a realm this deployment never configured."""
    headers = {"Authorization": f"Bearer {admin_token(KEYCLOAK)}"}
    response = httpx.post(
        f"{KEYCLOAK}/admin/realms",
        json={"realm": UNTRUSTED_REALM, "enabled": True},
        headers=headers,
        timeout=30,
    )
    if response.status_code not in (201, 204, 409):
        raise KeycloakError(f"could not create the untrusted realm: {response.status_code} {response.text[:300]}")

    descriptor = httpx.get(f"{KEYCLOAK}/realms/{UNTRUSTED_REALM}/protocol/saml/descriptor", timeout=30)
    descriptor.raise_for_status()
    match = re.search(r"<ds:X509Certificate>([^<]+)</ds:X509Certificate>", descriptor.text)
    if not match:
        raise KeycloakError("the untrusted realm's descriptor carries no certificate")
    return match.group(1)


def _form_action(html: str, *, needle: str) -> str:
    """The `action` of the form in *html* whose markup contains *needle*."""
    for form in re.finditer(r"<form\b[^>]*>", html, flags=re.IGNORECASE):
        action = re.search(r'action="([^"]+)"', form.group(0))
        if action and needle in form.group(0):
            return unescape(action.group(1))
    # Keycloak renders exactly one form on its login page, so falling back
    # to "the only form there is" is honest rather than a guess — and it
    # survives a theme that drops the id this would otherwise match on.
    only = re.search(r'<form\b[^>]*action="([^"]+)"', html, flags=re.IGNORECASE)
    if only:
        return unescape(only.group(1))
    raise KeycloakError("Keycloak's login page carried no form; its login theme has changed shape")


def _hidden_field(html: str, name: str) -> str | None:
    match = re.search(
        rf'<input[^>]*name="{re.escape(name)}"[^>]*value="([^"]*)"',
        html,
        flags=re.IGNORECASE,
    )
    if match:
        return unescape(match.group(1))
    # Attribute order is not fixed in generated markup.
    match = re.search(
        rf'<input[^>]*value="([^"]*)"[^>]*name="{re.escape(name)}"',
        html,
        flags=re.IGNORECASE,
    )
    return unescape(match.group(1)) if match else None


class _Cookies:
    """The hop's own cookie store, because the stock one cannot do this.

    Keycloak sets `AUTH_SESSION_ID`, `KC_RESTART` and
    `KC_AUTH_SESSION_HASH` with `SameSite=None` — SAML's POST binding is
    cross-site by design — and the cookie specification requires
    `SameSite=None` to be paired with `Secure`. It does so whatever the
    realm's `sslRequired` says, so there is no Keycloak setting that
    turns it off.

    Python's `http.cookiejar` then refuses to return a `Secure` cookie
    over `http://`. Browsers make an exception for loopback, which they
    treat as a trustworthy origin, and that exception is the only reason
    anybody can run Keycloak's dev mode at all. `httpx` offers no way to
    supply that rule: `Client._merge_cookies` rebuilds the jar with the
    default policy on every outgoing request, so a custom
    `CookiePolicy` is silently discarded and the symptom is Keycloak's
    "cookies are disabled in your browser".

    Carrying the cookies explicitly is not a more capable fake — it is
    the browser behaviour Keycloak is relying on, written out. Nothing
    about AiSOC is stubbed by it.
    """

    def __init__(self) -> None:
        self._jar: dict[str, str] = {}

    def absorb(self, response: httpx.Response) -> None:
        for raw in response.headers.get_list("set-cookie"):
            name, _, rest = raw.partition("=")
            value = rest.split(";", 1)[0]
            self._jar[name.strip()] = value

    def header(self) -> dict[str, str]:
        if not self._jar:
            return {}
        return {"Cookie": "; ".join(f"{k}={v}" for k, v in self._jar.items())}


def _follow(client: httpx.Client, cookies: _Cookies, response: httpx.Response, *, limit: int = 10) -> httpx.Response:
    """Walk redirects by hand, absorbing cookies at every hop.

    `follow_redirects=True` would hide the intermediate `Set-Cookie`
    headers from the store above, which is where Keycloak puts the
    session it then asks for back.
    """
    for _ in range(limit):
        cookies.absorb(response)
        if response.status_code not in (301, 302, 303, 307, 308):
            return response
        location = response.headers.get("location", "")
        if not location:
            return response
        response = client.get(str(response.url.join(location)), headers=cookies.header())
    raise KeycloakError("Keycloak redirected more times than a sign-in should need")


def browser_hop(sso_redirect_url: str) -> tuple[str, str]:
    """Walk Keycloak's login page the way a browser would.

    Returns `(SAMLResponse, RelayState)` exactly as the auto-submitting
    form Keycloak answers with carries them.
    """
    cookies = _Cookies()
    with httpx.Client(timeout=30, follow_redirects=False) as browser:
        page = _follow(browser, cookies, browser.get(sso_redirect_url))
        if page.status_code != 200:
            raise KeycloakError(f"Keycloak did not render a login page: {page.status_code} {page.text[:300]}")

        action = _form_action(page.text, needle="kc-form-login")
        posted = _follow(
            browser,
            cookies,
            browser.post(
                action,
                data={"username": USERNAME, "password": PASSWORD, "credentialId": ""},
                headers={**cookies.header(), "Content-Type": "application/x-www-form-urlencoded"},
            ),
        )

        saml_response = _hidden_field(posted.text, "SAMLResponse")
        if not saml_response:
            raise KeycloakError("Keycloak did not answer the login with a SAMLResponse. Its reply began: " + posted.text[:400])
        return saml_response, (_hidden_field(posted.text, "RelayState") or "")


async def _seed_connection(dsn: str, *, issuer: str, metadata_xml: str) -> uuid.UUID:
    """A tenant and the enabled SAML connection an administrator would create.

    Written through SQL rather than through `POST /sso-connections`
    because that route needs an authenticated administrator, and minting
    one here would make the probe depend on the very login it is proving.
    The row's shape is the route's shape, pinned by the route's own tests.

    Idempotent for the same reason the Keycloak bootstrap is: a retried
    step, or a second run against a database that is not fresh, must not
    fail on the deployment-wide unique index over `issuer`. A failure here
    reads as "SAML is broken" when it only means "this ran twice".
    """
    import sqlalchemy
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    engine = create_async_engine(dsn, future=True)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    tenant_id = uuid.uuid4()
    try:
        async with maker() as session:
            # `users.email` is unique across the whole deployment, so the
            # account a previous run provisioned would make
            # `complete_sso_login` fail on its insert — a collision
            # between two runs, reported as a broken sign-in.
            #
            # The *user* is removed and the tenant is left behind, on
            # purpose. Deleting the tenant cascades into `audit_log`,
            # whose trigger refuses a DELETE outright (migration `101`),
            # so a probe that tidied up properly would be refused by the
            # immutability control — correctly. `audit_log.actor_id` is
            # `ON DELETE SET NULL`, which is why removing the user is
            # allowed where removing the tenant is not.
            await session.execute(
                sqlalchemy.text("DELETE FROM users WHERE email = :e"),
                {"e": EMAIL},
            )
            await session.execute(
                sqlalchemy.text("INSERT INTO tenants (id, name, slug) VALUES (:i, :n, :s)"),
                {
                    "i": tenant_id,
                    "n": f"{TENANT_SLUG_PREFIX}{tenant_id.hex[:8]}",
                    "s": f"{TENANT_SLUG_PREFIX}{tenant_id.hex[:8]}",
                },
            )
            # The table's `WITH CHECK` has no null escape: a tenant
            # configures its own connection, so this write binds the
            # context exactly as the console's session does. The *read* on
            # the callback path is unbound, because resolving the row is
            # what decides the tenant.
            await session.execute(
                sqlalchemy.text("SELECT set_config('app.current_tenant_id', :t, FALSE)"),
                {"t": str(tenant_id)},
            )
            # The delete is unbound on purpose: a leftover row from an
            # earlier run belongs to a tenant this session is not bound
            # to, so a bound delete would match nothing and the insert
            # below would still collide.
            #
            # Matched on the marker as well as the issuer. A previous run
            # against a different `KEYCLOAK_URL` left a row under a
            # *different* issuer, and `resolve_saml_connection` then
            # correctly refuses to guess between two providers — so the
            # probe would fail with "no connection configured" for a
            # reason that is not a defect.
            await session.execute(sqlalchemy.text("SELECT set_config('app.current_tenant_id', '', FALSE)"))
            await session.execute(
                sqlalchemy.text("DELETE FROM aisoc_sso_connections WHERE issuer = :i OR display_name = :marker"),
                {"i": issuer, "marker": CONNECTION_MARKER},
            )
            await session.execute(
                sqlalchemy.text("SELECT set_config('app.current_tenant_id', :t, FALSE)"),
                {"t": str(tenant_id)},
            )
            await session.execute(
                sqlalchemy.text("""
                    INSERT INTO aisoc_sso_connections
                        (tenant_id, provider, issuer, display_name, enabled,
                         group_role_mapping, default_role, metadata_xml)
                    VALUES (:t, 'saml', :iss, :marker, TRUE,
                            CAST(:map AS jsonb), 'viewer', :xml)
                """),
                {
                    "t": tenant_id,
                    "iss": issuer,
                    "map": f'{{"{GROUP}": "{MAPPED_ROLE}"}}',
                    "marker": CONNECTION_MARKER,
                    "xml": metadata_xml,
                },
            )
            await session.commit()
    finally:
        await engine.dispose()
    return tenant_id


async def _replace_connection_metadata(dsn: str, *, issuer: str, metadata_xml: str) -> None:
    import sqlalchemy
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    engine = create_async_engine(dsn, future=True)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with maker() as session:
            row = (
                await session.execute(
                    sqlalchemy.text("SELECT tenant_id FROM aisoc_sso_connections WHERE issuer = :i"),
                    {"i": issuer},
                )
            ).first()
            if row is None:
                raise KeycloakError("the connection this probe created is gone")
            await session.execute(
                sqlalchemy.text("SELECT set_config('app.current_tenant_id', :t, FALSE)"),
                {"t": str(row[0])},
            )
            await session.execute(
                sqlalchemy.text("UPDATE aisoc_sso_connections SET metadata_xml = :x WHERE issuer = :i"),
                {"x": metadata_xml, "i": issuer},
            )
            await session.commit()
    finally:
        await engine.dispose()


def _application() -> Any:
    """The real app, configured the way a SAML deployment is.

    `ENVIRONMENT=test` and never `development`: `development` is in
    `AUTH_BYPASS_ENVIRONMENTS`, so an uncredentialed request would resolve
    to a demo administrator — inside the one probe whose point is that the
    principal comes from the assertion.

    `SAML_IDP_*` deliberately names a provider whose key this deployment
    does not hold. If the handler ever goes back to reading its trust
    anchor from the environment, nothing below can pass.
    """
    os.environ["ENVIRONMENT"] = "test"
    os.environ["SSO_ENABLED"] = "true"
    os.environ["SAML_SP_ACS_URL"] = SP_ACS_URL
    os.environ["SAML_SP_ENTITY_ID"] = SP_ENTITY_ID
    os.environ["SAML_IDP_ENTITY_ID"] = "https://environment-idp.invalid/metadata"
    os.environ["SAML_IDP_SSO_URL"] = "https://environment-idp.invalid/sso"
    os.environ["SAML_IDP_CERT"] = ""
    os.environ["OTEL_SDK_DISABLED"] = "true"

    from app.main import create_application  # noqa: PLC0415

    return create_application()


async def main() -> int:
    dsn = _dsn()
    os.environ["DATABASE_URL"] = dsn

    bootstrap(KEYCLOAK)
    descriptor = saml_descriptor(KEYCLOAK)
    issuer = saml_entity_id(descriptor)
    await _seed_connection(dsn, issuer=issuer, metadata_xml=descriptor)
    print(f"OK: an enabled SAML connection carries Keycloak's own descriptor (issuer={issuer}).")

    transport = httpx.ASGITransport(app=_application())
    async with httpx.AsyncClient(transport=transport, base_url=SP_ORIGIN) as app_client:
        # 1. The app builds an AuthnRequest from the connection's metadata.
        start = await app_client.get("/auth/saml/login", params={"redirect": "/alerts"})
        if start.status_code not in (302, 303, 307):
            raise SystemExit(f"/auth/saml/login did not redirect: {start.status_code} {start.text[:400]}")
        location = start.headers["location"]
        if not location.startswith(KEYCLOAK):
            raise SystemExit(
                f"/auth/saml/login redirected to {location[:200]!r}, which is not the Keycloak the "
                "connection names — the trust anchor did not come from the connection."
            )
        print("OK: the app's AuthnRequest is addressed to the IdP the connection names.")

        # 2. A real person signs in at a real Keycloak.
        saml_response, relay_state = browser_hop(location)
        print("OK: Keycloak authenticated the user and signed a Response.")

        # 3. That Response is posted back to the real ACS.
        landed = await app_client.post(
            "/auth/saml/acs",
            data={"SAMLResponse": saml_response, "RelayState": relay_state or "/alerts"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if landed.status_code != 302:
            raise SystemExit(f"the ACS refused a genuine assertion: {landed.status_code} {landed.text[:600]}")
        fragment = landed.headers["location"]
        match = re.search(r"#access_token=([^&]+)", fragment)
        if not match:
            raise SystemExit(f"the ACS issued no access token; it redirected to {fragment[:200]!r}")
        access_token = match.group(1)

        # 4. The token is the API's own, and it describes the right person.
        from app.core.security import decode_token  # noqa: PLC0415

        claims = decode_token(access_token)
        if (claims.get("email") or "").lower() != EMAIL:
            raise SystemExit(f"signed in as {claims.get('email')!r}, expected {EMAIL!r}")
        if claims.get("role") != MAPPED_ROLE:
            raise SystemExit(
                f"the connection maps {GROUP!r} to {MAPPED_ROLE!r} but the session carries "
                f"{claims.get('role')!r}; a group the IdP asserted did not reach the role mapping"
            )
        print(
            f"OK: a real Keycloak SAML assertion signed {EMAIL} in to the real app "
            f"(role={claims.get('role')}, tenant={claims.get('tenant_id')})."
        )

        # 5. The negative control. Same assertion, same connection, one
        #    certificate swapped for a realm this deployment never trusted.
        trusted_certificate = re.search(r"<ds:X509Certificate>([^<]+)</ds:X509Certificate>", descriptor)
        if trusted_certificate is None:
            # `saml_descriptor` already refused a document with no
            # certificate, so this is unreachable — and saying so beats a
            # `# type: ignore`, which would also suppress the day the
            # descriptor's shape changes and the negative control starts
            # silently comparing a document against itself.
            raise KeycloakError("the descriptor that signed this assertion carries no certificate to swap")
        untrusted = descriptor.replace(trusted_certificate.group(1), _untrusted_certificate())
        await _replace_connection_metadata(dsn, issuer=issuer, metadata_xml=untrusted)
        replayed = await app_client.post(
            "/auth/saml/acs",
            data={"SAMLResponse": saml_response, "RelayState": relay_state or "/alerts"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if replayed.status_code == 302 and "access_token=" in replayed.headers.get("location", ""):
            print("FAIL: the same assertion was accepted against a certificate this deployment does not trust.")
            return 1
        print(f"OK: the same assertion is refused once the connection names another key ({replayed.status_code}).")

    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
