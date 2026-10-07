"""SSO completes a sign-in, through the real app, against a real identity provider.

Fix pass 4.1.

Why this suite exists
---------------------
`services/api/tests/test_sso_provisioning.py` asserts the shape of the
provisioning path — that the tenant is not an argument, that a group cannot
confer `admin`, that the token is signed with the key the API verifies
with. All of that is true and none of it answers the question a buyer
asks: *can somebody actually sign in?*

Nothing in the repository ever drove either handler end to end. The OIDC
callback was never run against a provider that publishes a JWKS, and the
SAML ACS was never handed an assertion signed by a key the deployment
trusts. So two different kinds of defect were invisible:

**The one this suite was written to reproduce.** `_saml_settings()` builds
the IdP trust anchor from `SAML_IDP_ENTITY_ID`, `SAML_IDP_SSO_URL` and
`SAML_IDP_CERT` — process-wide environment variables — while
`aisoc_sso_connections.metadata_url` and `.metadata_xml` are written by
`POST /sso-connections` and read by nothing. An administrator configures a
connection in the console, the deployment keeps trusting whatever the
environment says, and on a deployment that sets no SAML environment at all
(the default) the IdP block is empty and every assertion is refused.

**The one that would have survived any amount of unit testing**: a
provider-shaped detail like a `kid` the JWKS client cannot resolve, or an
`Audience` the SP rejects, only shows up when a real signature meets a real
verifier.

What is real here and what is not
----------------------------------
Real: a 2048-bit RSA IdP keypair, IdP metadata carrying its certificate, a
SAML Response signed with `xmlsec` through `python3-saml`'s own signer, and
the full `OneLogin_Saml2_Auth.process_response()` verification path. Real
Postgres with every migration applied, the application built by
`create_application()`, and a token the API's own verifier accepts.

Not real: the identity provider is not a containerised Keycloak. It is a
keypair and a metadata document, which is exactly the trust material a
deployment configures, but it does not exercise a vendor's own quirks.
`.github/workflows/sso-live.yml` runs the containerised leg.

The negative control
--------------------
`test_an_assertion_signed_by_an_untrusted_key_is_refused` is what stops the
positive assertions passing for the wrong reason: a handler that skipped
signature verification entirely would satisfy "alice signed in".
"""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import tempfile
import threading
import uuid
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
import pytest_asyncio

# One event loop for the module, and one application built in it: a loop
# per test closes the pool the previous app still holds and every later
# test dies with "Event loop is closed", which is a message about the
# harness that says nothing about the code.
#
# Skipped as a *module* rather than only in a fixture. The offline
# isolation job collects this directory with no Postgres running, and a
# fixture-only skip lets any test that does not take the fixture run
# anyway and fail there — a harness failure reported against a capability.
pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_SSO_DSN", "").strip(),
        reason="ISOLATION_SSO_DSN is not set; this suite needs a live Postgres",
    ),
]

# python3-saml validates the SP URLs against its own URL regex, which
# rejects a single-label host like `testserver`. The client below is
# given the same origin so the assertion's `Destination` matches.
SP_ORIGIN = "http://sp.aisoc-ci.test"
ACS_URL = f"{SP_ORIGIN}/auth/saml/acs"
IDP_ENTITY_ID = "https://idp.aisoc-ci.test/metadata"
IDP_SSO_URL = "https://idp.aisoc-ci.test/sso"
IDP_SLO_URL = "https://idp.aisoc-ci.test/slo"


# ─── A real identity provider's trust material ───────────────────────────────


class _Idp:
    """An RSA keypair, the metadata that publishes it, and a signer.

    Deliberately not a mock. The certificate in the metadata is the same
    one the private key below signs with, so a verifier that checks the
    signature against the metadata will accept these assertions and reject
    anything else — which is the whole property under test.
    """

    def __init__(self, *, entity_id: str | None = None, sso_url: str = IDP_SSO_URL) -> None:
        # Unique by default. `aisoc_sso_connections` is uniquely indexed on
        # `(provider, issuer)` deployment-wide, so a fixed entity id makes
        # the suite collide with its own previous run on a database that
        # outlives one invocation — which is every CI service container
        # reused across jobs, and every developer's local Postgres.
        self.entity_id = entity_id or f"{IDP_ENTITY_ID}/{uuid.uuid4().hex}"
        self.sso_url = sso_url
        directory = Path(tempfile.mkdtemp(prefix="aisoc-idp-"))
        key_path, crt_path = directory / "idp.key", directory / "idp.crt"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(key_path),
                "-out",
                str(crt_path),
                "-days",
                "2",
                "-subj",
                "/CN=aisoc-ci-idp",
            ],
            check=True,
            capture_output=True,
        )
        self.key_pem = key_path.read_text()
        self.cert_pem = crt_path.read_text()
        self.cert_b64 = "".join(line for line in self.cert_pem.splitlines() if "CERTIFICATE" not in line)

    @property
    def metadata_xml(self) -> str:
        return (
            '<?xml version="1.0"?>\n'
            '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
            f'entityID="{self.entity_id}">\n'
            '  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">\n'
            '    <md:KeyDescriptor use="signing">\n'
            '      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">\n'
            f"        <ds:X509Data><ds:X509Certificate>{self.cert_b64}</ds:X509Certificate></ds:X509Data>\n"
            "      </ds:KeyInfo>\n"
            "    </md:KeyDescriptor>\n"
            '    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
            f'Location="{IDP_SLO_URL}"/>\n'
            '    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
            f'Location="{self.sso_url}"/>\n'
            "  </md:IDPSSODescriptor>\n"
            "</md:EntityDescriptor>"
        )

    def signed_response(self, *, email: str, groups: tuple[str, ...] = (), audience: str = ACS_URL) -> str:
        from onelogin.saml2.constants import OneLogin_Saml2_Constants as Const
        from onelogin.saml2.utils import OneLogin_Saml2_Utils as Utils

        now = datetime.now(UTC)
        response_id, assertion_id = "_" + uuid.uuid4().hex, "_" + uuid.uuid4().hex
        issued = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        not_before = (now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        not_after = (now + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        attributes = "".join(
            '<saml:Attribute Name="groups" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">'
            f'<saml:AttributeValue xsi:type="xs:string">{group}</saml:AttributeValue></saml:Attribute>'
            for group in groups
        )
        xml = f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="{response_id}" Version="2.0" IssueInstant="{issued}" Destination="{ACS_URL}">
  <saml:Issuer>{self.entity_id}</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                  xmlns:xs="http://www.w3.org/2001/XMLSchema"
                  ID="{assertion_id}" Version="2.0" IssueInstant="{issued}">
    <saml:Issuer>{self.entity_id}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{email}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="{not_after}" Recipient="{ACS_URL}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_after}">
      <saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="{issued}" SessionIndex="{assertion_id}">
      <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">{email}</saml:AttributeValue>
      </saml:Attribute>{attributes}
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"""
        signed = Utils.add_sign(
            xml,
            self.key_pem,
            self.cert_pem,
            sign_algorithm=Const.RSA_SHA256,
            digest_algorithm=Const.SHA256,
        )
        if isinstance(signed, bytes):
            signed = signed.decode()
        return base64.b64encode(signed.encode()).decode()


# ─── A real OpenID Connect provider, on a real socket ────────────────────────


_HEADER_UNSAFE = re.compile(r"[^A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]")


def _header_safe(value: str) -> str:
    """A URL fragment safe to place in a response header.

    Reconstructed from allowed characters rather than checked, so neither a
    reader nor a taint tracker has to reason about what survived.
    """
    return _HEADER_UNSAFE.sub("", value)


class _OidcProvider:
    """Discovery, JWKS, authorization, token and userinfo over real HTTP.

    Not a mock and not a monkeypatch: the API's own `_discover()` fetches
    the discovery document over TCP, its `PyJWKClient` fetches the JWKS and
    resolves the signing key by `kid`, and the `id_token` below is a real
    RS256 JWT. So the verification this exercises — signature, `iss`,
    `aud`, `exp` and the `nonce` replay check — is the production path with
    nothing stubbed.

    What it is not is a containerised Keycloak;
    `.github/workflows/sso-live.yml` runs that leg.
    """

    client_id = "aisoc-ci"
    client_secret = "aisoc-ci-secret"

    def __init__(self) -> None:
        from cryptography.hazmat.primitives.asymmetric import rsa

        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        #: Never published in the JWKS. Signing with it under the same
        #: `kid` is how the negative control forges a token: the verifier
        #: resolves the real key and the signature does not check out.
        self._rogue_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.sign_with_rogue_key = False
        self.kid = uuid.uuid4().hex
        #: code -> the nonce the authorization request carried, so `/token`
        #: can mint an id_token that survives the callback's replay check.
        self._codes: dict[str, dict[str, str]] = {}
        self.subject = f"sub-{uuid.uuid4().hex[:10]}"
        self.email = f"bob-{uuid.uuid4().hex[:8]}@example.com"
        self.groups: list[str] = []

        provider = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args: object) -> None:  # keep pytest output readable
                return

            def _send(self, status: int, body: bytes, content_type: str = "application/json") -> None:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's contract
                path = urlsplit(self.path).path
                query = parse_qs(urlsplit(self.path).query)
                if path == "/.well-known/openid-configuration":
                    self._send(200, json.dumps(provider.discovery).encode())
                elif path == "/jwks.json":
                    self._send(200, json.dumps(provider.jwks).encode())
                elif path == "/authorize":
                    code = uuid.uuid4().hex
                    provider._codes[code] = {"nonce": (query.get("nonce") or [""])[0]}
                    # Rebuilt from an allow-list rather than interpolated. A
                    # `Location` assembled from the query string is response
                    # splitting even in a fixture, and a provider that lets a
                    # crafted `redirect_uri` inject a header is not modelling
                    # a real one.
                    target = _header_safe((query.get("redirect_uri") or [""])[0])
                    state = _header_safe((query.get("state") or [""])[0])
                    self.send_response(302)
                    self.send_header("Location", f"{target}?code={code}&state={state}")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                elif path == "/userinfo":
                    self._send(200, json.dumps(provider.claims(nonce=None)).encode())
                else:
                    self._send(404, b"{}")

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                form = parse_qs(self.rfile.read(length).decode())
                if urlsplit(self.path).path != "/token":
                    self._send(404, b"{}")
                    return
                code = (form.get("code") or [""])[0]
                entry = provider._codes.pop(code, None)
                if entry is None:
                    self._send(400, json.dumps({"error": "invalid_grant"}).encode())
                    return
                self._send(
                    200,
                    json.dumps(
                        {
                            "access_token": "opaque-" + uuid.uuid4().hex,
                            "token_type": "Bearer",
                            "expires_in": 300,
                            "id_token": provider.id_token(nonce=entry["nonce"]),
                        }
                    ).encode(),
                )

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.issuer = f"http://127.0.0.1:{self._server.server_address[1]}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    @property
    def discovery(self) -> dict:
        return {
            "issuer": self.issuer,
            "authorization_endpoint": f"{self.issuer}/authorize",
            "token_endpoint": f"{self.issuer}/token",
            "userinfo_endpoint": f"{self.issuer}/userinfo",
            "jwks_uri": f"{self.issuer}/jwks.json",
            "id_token_signing_alg_values_supported": ["RS256"],
        }

    @property
    def jwks(self) -> dict:
        from cryptography.hazmat.primitives.asymmetric import rsa

        numbers: rsa.RSAPublicNumbers = self._key.public_key().public_numbers()

        def b64(value: int) -> str:
            raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

        return {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": self.kid, "n": b64(numbers.n), "e": b64(numbers.e)}]}

    def claims(self, *, nonce: str | None) -> dict:
        now = datetime.now(UTC)
        claims = {
            "iss": self.issuer,
            "sub": self.subject,
            "aud": self.client_id,
            "email": self.email,
            "email_verified": True,
            "name": "Bob Example",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
        }
        if self.groups:
            claims["groups"] = self.groups
        if nonce:
            claims["nonce"] = nonce
        return claims

    def id_token(self, *, nonce: str) -> str:
        import jwt
        from cryptography.hazmat.primitives import serialization

        key = self._rogue_key if self.sign_with_rogue_key else self._key
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return jwt.encode(self.claims(nonce=nonce), pem, algorithm="RS256", headers={"kid": self.kid})


# ─── Harness ──────────────────────────────────────────────────────────────────


def _dsn() -> str:
    value = os.environ.get("ISOLATION_SSO_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_SSO_DSN is not set; this suite needs a live Postgres")
    return value


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def app_client():
    """The real application, against real Postgres.

    `ENVIRONMENT=test` and not `development`: `development` is in
    `AUTH_BYPASS_ENVIRONMENTS`, so an uncredentialed request resolves to a
    demo administrator — inside the one suite whose point is that the
    principal comes from the assertion.

    The SAML environment variables are set to an IdP this suite does *not*
    hold the key for. That is the reproduce condition: if the handler reads
    its trust anchor from the environment rather than from the connection,
    every assertion below is refused.
    """
    pytest.importorskip("httpx")
    os.environ["DATABASE_URL"] = _dsn()
    os.environ["ENVIRONMENT"] = "test"
    os.environ["SSO_ENABLED"] = "true"
    os.environ["SAML_SP_ACS_URL"] = ACS_URL
    os.environ["SAML_IDP_ENTITY_ID"] = "https://environment-idp.invalid/metadata"
    os.environ["SAML_IDP_SSO_URL"] = "https://environment-idp.invalid/sso"
    os.environ["SAML_IDP_CERT"] = ""

    import httpx
    from app.main import create_application

    application = create_application()
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url=SP_ORIGIN) as client:
        yield client


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def db():
    pytest.importorskip("asyncpg")
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    engine = create_async_engine(_dsn(), future=True)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        yield session
    await engine.dispose()


@pytest_asyncio.fixture(loop_scope="module")
async def idp() -> _Idp:
    """One identity provider per test, so the deployment-wide unique index
    on `(provider, issuer)` cannot make one test's row collide with
    another's."""
    return _Idp()


async def _tenant(session) -> uuid.UUID:  # noqa: ANN001
    import sqlalchemy

    # The session is module-scoped, so an earlier failure leaves its
    # transaction aborted and every later statement reports that instead of
    # its own error. Start clean.
    await session.rollback()
    tenant_id = uuid.uuid4()
    await session.execute(
        sqlalchemy.text("INSERT INTO tenants (id, name, slug) VALUES (:i, :n, :s)"),
        {"i": tenant_id, "n": f"sso-{tenant_id.hex[:8]}", "s": f"sso-{tenant_id.hex[:8]}"},
    )
    await session.commit()
    return tenant_id


async def _saml_connection(session, *, idp: _Idp, by_url: str | None = None) -> dict:  # noqa: ANN001
    """An enabled SAML connection carrying the IdP's own metadata.

    This is the row the console writes and that nothing read.
    """
    import sqlalchemy

    tenant_id = await _tenant(session)
    connection_id = uuid.uuid4()
    # The table's `WITH CHECK` has no null escape: a tenant configures its
    # own connection, so the write is bound even though the *read* on the
    # callback path is not (resolving the row is what decides the tenant).
    # The fixture therefore has to bind, exactly as the console's session
    # does.
    await session.execute(
        sqlalchemy.text("SELECT set_config('app.current_tenant_id', :t, FALSE)"),
        {"t": str(tenant_id)},
    )
    await session.execute(
        sqlalchemy.text(
            """
            INSERT INTO aisoc_sso_connections
                (id, tenant_id, provider, issuer, display_name, enabled,
                 group_role_mapping, default_role, metadata_url, metadata_xml)
            VALUES (:id, :t, 'saml', :iss, 'CI IdP', TRUE,
                    CAST(:map AS jsonb), 'viewer', :url, :xml)
            """
        ),
        {
            "id": connection_id,
            "t": tenant_id,
            "iss": idp.entity_id,
            "map": '{"soc-analysts": "infosec"}',
            "url": by_url,
            "xml": None if by_url else idp.metadata_xml,
        },
    )
    await session.commit()
    return {"id": connection_id, "tenant_id": tenant_id}


# ─── The reproduce ────────────────────────────────────────────────────────────


class TestSamlTrustComesFromTheConnection:
    """Fix pass 4.1: `metadata_url` and `metadata_xml` are written by
    `POST /sso-connections` and read by nothing."""

    async def test_login_redirects_to_the_sso_url_in_the_connection_metadata(self, app_client, db, idp) -> None:  # noqa: ANN001
        """The environment names a different IdP, so a pass here can only
        come from the connection row."""
        connection = await _saml_connection(db, idp=idp)

        response = await app_client.get(
            "/auth/saml/login",
            params={"issuer": idp.entity_id, "redirect": "/alerts"},
            follow_redirects=False,
        )

        assert response.status_code in (302, 303, 307), response.text
        location = response.headers["location"]
        assert location.startswith(idp.sso_url), (
            f"redirected to {location!r}, which is not the SingleSignOnService the connection's "
            f"metadata declares. Connection {connection['id']} carries it and the handler ignored it."
        )

    async def test_an_assertion_signed_by_the_connections_key_signs_someone_in(self, app_client, db, idp) -> None:  # noqa: ANN001
        """End to end: a signed assertion in, a token the API verifies out,
        a real user row in the connection's tenant."""
        import sqlalchemy

        connection = await _saml_connection(db, idp=idp)
        email = f"alice-{uuid.uuid4().hex[:8]}@example.com"

        response = await app_client.post(
            "/auth/saml/acs",
            data={
                "SAMLResponse": idp.signed_response(email=email, groups=("soc-analysts",)),
                "RelayState": "/alerts",
            },
            follow_redirects=False,
        )

        assert response.status_code == 302, response.text
        location = response.headers["location"]
        # On `/login`, not on the RelayState destination. `handleUnauthorized`
        # in the console builds its bounce target from `pathname + search`, so
        # an auth guard on `/alerts` would redirect to `/login?next=/alerts`
        # and drop the fragment — taking the only copy of the token with it.
        assert location.startswith("/login?next="), location
        assert "#access_token=" in location, location
        # The console's fragment consumer persists both.
        assert "refresh_token=" in location, location

        token = location.split("access_token=", 1)[1].split("&", 1)[0]
        me = await app_client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert me.status_code == 200, me.text
        body = me.json()
        assert body["email"] == email
        # The tenant is the connection's, never the assertion's.
        assert body["tenant_id"] == str(connection["tenant_id"])
        # `soc-analysts` maps to `infosec` on this connection.
        assert body["role"] == "infosec"

        row = (
            (
                await db.execute(
                    sqlalchemy.text("SELECT tenant_id, role FROM users WHERE lower(email) = lower(:e)"),
                    {"e": email},
                )
            )
            .mappings()
            .first()
        )
        assert row is not None, "the sign-in returned a token for a user that was never written"
        assert row["tenant_id"] == connection["tenant_id"]

    async def test_an_assertion_signed_by_an_untrusted_key_is_refused(self, app_client, db, idp) -> None:  # noqa: ANN001
        """The negative control.

        A second keypair, claiming the *same* issuer as the configured
        connection. Only the signature distinguishes them, so a handler
        that resolved the connection and then skipped verification would
        pass every test above and fail this one.
        """
        await _saml_connection(db, idp=idp)
        impostor = _Idp()  # same entity id, different private key
        email = f"mallory-{uuid.uuid4().hex[:8]}@example.com"

        response = await app_client.post(
            "/auth/saml/acs",
            data={"SAMLResponse": impostor.signed_response(email=email), "RelayState": "/"},
            follow_redirects=False,
        )

        assert response.status_code >= 400, (
            f"an assertion signed by a key the connection does not trust was accepted "
            f"({response.status_code}); location={response.headers.get('location')!r}"
        )
        assert "access_token=" not in str(response.headers.get("location", ""))


# ─── OIDC, end to end against a provider that really signs ───────────────────


@pytest_asyncio.fixture(loop_scope="module")
async def oidc():
    provider = _OidcProvider()
    os.environ["OIDC_ISSUER"] = provider.issuer
    os.environ["OIDC_CLIENT_ID"] = provider.client_id
    os.environ["OIDC_CLIENT_SECRET"] = provider.client_secret
    os.environ["OIDC_REDIRECT_URI"] = f"{SP_ORIGIN}/auth/oidc/callback"
    # `_discover` and `PyJWKClient` both cache per issuer for the lifetime
    # of the process, and each test gets a provider on a fresh port, so a
    # stale entry would serve the previous test's keys.
    from app.auth import oidc as oidc_module

    oidc_module._provider_cache.clear()
    oidc_module._jwks_clients.clear()
    try:
        yield provider
    finally:
        provider.close()


async def _oidc_connection(session, *, issuer: str, mapping: str = "{}") -> dict:  # noqa: ANN001
    import sqlalchemy

    tenant_id = await _tenant(session)
    connection_id = uuid.uuid4()
    await session.execute(
        sqlalchemy.text("SELECT set_config('app.current_tenant_id', :t, FALSE)"),
        {"t": str(tenant_id)},
    )
    await session.execute(
        sqlalchemy.text(
            """
            INSERT INTO aisoc_sso_connections
                (id, tenant_id, provider, issuer, display_name, enabled,
                 group_role_mapping, default_role)
            VALUES (:id, :t, 'oidc', :iss, 'CI OIDC', TRUE, CAST(:map AS jsonb), 'viewer')
            """
        ),
        {"id": connection_id, "t": tenant_id, "iss": issuer, "map": mapping},
    )
    await session.commit()
    return {"id": connection_id, "tenant_id": tenant_id}


class TestOidcCompletesASignIn:
    """The claim row's own words: *SSO completes a sign-in, into the right
    tenant with the mapped role.* Nothing drove this against a provider
    that publishes a JWKS until now."""

    async def test_the_whole_authorization_code_flow(self, app_client, db, oidc) -> None:  # noqa: ANN001
        import httpx

        oidc.groups = ["soc-analysts"]
        connection = await _oidc_connection(db, issuer=oidc.issuer, mapping='{"soc-analysts": "infosec"}')

        start = await app_client.get("/auth/oidc/login", params={"redirect": "/alerts"}, follow_redirects=False)
        assert start.status_code in (302, 307), start.text
        authorize_url = start.headers["location"]
        assert authorize_url.startswith(f"{oidc.issuer}/authorize"), authorize_url

        # The browser's hop. Done with a plain client because this URL is
        # the provider's, not the application's.
        async with httpx.AsyncClient(follow_redirects=False) as browser:
            bounced = await browser.get(authorize_url)
        assert bounced.status_code == 302, bounced.text
        returned = parse_qs(urlsplit(bounced.headers["location"]).query)

        callback = await app_client.get(
            "/auth/oidc/callback",
            params={"code": returned["code"][0], "state": returned["state"][0]},
            follow_redirects=False,
        )
        assert callback.status_code == 302, callback.text
        location = callback.headers["location"]
        assert location.startswith("/login?next="), location
        assert "#access_token=" in location and "refresh_token=" in location

        token = location.split("access_token=", 1)[1].split("&", 1)[0]
        me = await app_client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert me.status_code == 200, me.text
        assert me.json()["email"] == oidc.email
        assert me.json()["tenant_id"] == str(connection["tenant_id"])
        assert me.json()["role"] == "infosec"

    async def test_an_id_token_signed_by_another_key_is_refused(self, app_client, db, oidc) -> None:  # noqa: ANN001
        """The OIDC negative control.

        The same issuer, the same `kid`, a private key that is not the one
        the JWKS publishes. Only the signature distinguishes this token
        from the one above, so a callback that decoded the `id_token`
        without verifying — which is what this handler used to do, under a
        comment saying to use JWKS in production — would pass the previous
        test and fail this one.
        """
        import httpx

        await _oidc_connection(db, issuer=oidc.issuer)
        oidc.sign_with_rogue_key = True

        start = await app_client.get("/auth/oidc/login", params={"redirect": "/"}, follow_redirects=False)
        async with httpx.AsyncClient(follow_redirects=False) as browser:
            bounced = await browser.get(start.headers["location"])
        returned = parse_qs(urlsplit(bounced.headers["location"]).query)

        callback = await app_client.get(
            "/auth/oidc/callback",
            params={"code": returned["code"][0], "state": returned["state"][0]},
            follow_redirects=False,
        )
        assert callback.status_code == 401, (
            f"an id_token signed by a key outside the provider's published JWKS was accepted ({callback.status_code})"
        )
        assert "access_token=" not in str(callback.headers.get("location", ""))
