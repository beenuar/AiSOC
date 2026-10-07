"""SAML trust comes from the connection row, not from the process environment.

Fix pass 4.1.

The defect
----------
`_saml_settings()` built the `idp` block from `SAML_IDP_ENTITY_ID`,
`SAML_IDP_SSO_URL` and `SAML_IDP_CERT`, while
`aisoc_sso_connections.metadata_url` and `.metadata_xml` — written by
`POST /sso-connections` and returned by `GET /sso-connections` — were read
nowhere. A stock install sets none of those variables, so the IdP block was
empty and every assertion was refused while the console showed a configured
connection.

This file is the offline half, so the module is graded by the job that runs
on every pull request. `tests/isolation/test_sso_live.py` is the half that
proves a real signed assertion actually signs somebody in, and it needs
Postgres and the whole application; the redirect targets and the token the
console receives are asserted there, against the real routes, rather than
by reading the handler's source here.
"""

from __future__ import annotations

import base64
import inspect

import pytest
from app.auth import saml
from app.auth.saml_metadata import (
    SamlTrustError,
    environment_idp_is_configured,
    issuer_from_saml_response,
    parse_idp_metadata,
)

CERT = (
    "MIIDBzCCAe+gAwIBAgIUKavXqjNUj2n6MqmhKoZappnTk5gwDQYJKoZIhvcNAQELBQAwEzERMA8GA1UEAwwIaWRwLnRlc3Qw"
    "HhcNMjYxMDA3MTEwNjQ5WhcNMjYxMDA5MTEwNjQ5WjATMREwDwYDVQQDDAhpZHAudGVzdA=="
)

_KEY_DESCRIPTOR = f"""  <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data><ds:X509Certificate>{CERT}</ds:X509Certificate></ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
"""

_SSO_SERVICE = """    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                            Location="https://idp.example/sso"/>
"""


def _metadata(*, key_descriptor: bool = True) -> str:
    """IdP metadata, with or without a published signing certificate.

    Assembled from parts so the no-certificate case is still *well-formed*
    XML. Deleting a slice of a string would also test that the parser
    rejects broken markup, which is not the property under test.
    """
    return (
        '<?xml version="1.0"?>\n'
        '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"\n'
        '                     entityID="https://idp.example/metadata">\n'
        '  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">\n'
        + (_KEY_DESCRIPTOR if key_descriptor else "")
        + _SSO_SERVICE
        + "  </md:IDPSSODescriptor>\n"
        "</md:EntityDescriptor>"
    )


class TestParsingMetadata:
    def test_it_yields_the_entity_id_sso_url_and_certificate(self) -> None:
        idp = parse_idp_metadata(_metadata())
        assert idp["entityId"] == "https://idp.example/metadata"
        assert idp["singleSignOnService"]["url"] == "https://idp.example/sso"
        assert idp["x509cert"].startswith("MIIDBzCC")

    def test_metadata_with_no_certificate_is_refused(self) -> None:
        """Rather than accepted and left to fail later as `invalid_response`.

        With no certificate there is nothing to verify a signature against,
        and `strict` mode would then refuse every assertion with a message
        about the *response* instead of about the configuration — so the
        operator reads "the IdP sent something wrong" and goes looking in
        the wrong place.
        """
        with pytest.raises(SamlTrustError, match="no signing certificate"):
            parse_idp_metadata(_metadata(key_descriptor=False))

    def test_an_external_entity_reference_is_refused(self) -> None:
        """A metadata document is operator-supplied and parsed by this
        service, so XXE is in scope. `python3-saml` parses with
        `forbid_dtd=True, forbid_entities=True`; this pins that the path
        taken here is that one, and not a looser parser added later."""
        hostile = (
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>\n'
            '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="&xxe;">\n'
            "</md:EntityDescriptor>"
        )
        with pytest.raises(SamlTrustError):
            parse_idp_metadata(hostile)


class TestSelectingAConnectionByTheAssertedIssuer:
    """The issuer an unverified response names is a **lookup key**: it picks
    which certificate to verify against, and an assertion naming an issuer
    whose private key the sender does not hold fails that check."""

    def test_it_reads_the_response_level_issuer(self) -> None:
        xml = (
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
            "<saml:Issuer>https://idp.example/metadata</saml:Issuer></samlp:Response>"
        )
        assert issuer_from_saml_response(base64.b64encode(xml.encode()).decode()) == "https://idp.example/metadata"

    def test_it_falls_back_to_the_assertions_issuer(self) -> None:
        """A provider may sign only the assertion and omit the outer element."""
        xml = (
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
            "<saml:Assertion><saml:Issuer>https://inner.example/idp</saml:Issuer></saml:Assertion>"
            "</samlp:Response>"
        )
        assert issuer_from_saml_response(base64.b64encode(xml.encode()).decode()) == "https://inner.example/idp"

    @pytest.mark.parametrize("payload", ["", "not-base64-!!!", base64.b64encode(b"<not-saml/>").decode()])
    def test_an_unparseable_response_names_no_issuer(self, payload: str) -> None:
        """`None`, never a guess. `resolve_saml_connection` then falls back
        to the single configured connection, and a guess there would pick an
        arbitrary identity provider for somebody's sign-in."""
        assert issuer_from_saml_response(payload) is None


class TestTheSettingsBuilder:
    def test_the_idp_block_is_whatever_the_caller_resolved(self) -> None:
        idp = {"entityId": "https://from-the-connection/idp"}
        assert saml._saml_settings(idp)["idp"] is idp

    def test_it_falls_back_to_the_environment_only_when_given_nothing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Kept so a deployment that configured SAML before connections were
        readable survives the upgrade. It is not the path a new deployment
        takes."""
        monkeypatch.setenv("SAML_IDP_ENTITY_ID", "https://legacy.example/idp")
        monkeypatch.setenv("SAML_IDP_SSO_URL", "https://legacy.example/sso")
        monkeypatch.setenv("SAML_IDP_CERT", CERT)
        assert environment_idp_is_configured() is True
        assert saml._saml_settings()["idp"]["entityId"] == "https://legacy.example/idp"

    def test_an_environment_with_no_certificate_does_not_count_as_configured(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The stock install. Counting it as configured is what would let
        `_resolve_idp` answer with an empty trust anchor instead of saying
        no connection exists."""
        monkeypatch.setenv("SAML_IDP_ENTITY_ID", "https://legacy.example/idp")
        monkeypatch.setenv("SAML_IDP_SSO_URL", "https://legacy.example/sso")
        monkeypatch.setenv("SAML_IDP_CERT", "")
        assert environment_idp_is_configured() is False


class TestTheTenantStillDoesNotComeFromTheAssertion:
    """4.1 adds a read of the asserted issuer, which is the one place this
    feature could grow the hole it was built to avoid.

    Structural rather than behavioural on purpose, and it is the same
    reasoning `test_sso_provisioning.py` uses: the live suite can show that
    *today* the two issuers are equal — the signature verified against that
    connection's certificate, so they must be — and therefore cannot
    distinguish a handler that passes the connection's value from one that
    passes the assertion's. Only the code can.
    """

    def test_the_acs_passes_the_connections_issuer_to_provisioning(self) -> None:
        source = inspect.getsource(saml.saml_acs)
        assert "issuer=connection_issuer" in source, (
            "the ACS hands `complete_sso_login` something other than the issuer the connection declares"
        )
        assert "_resolve_idp(db, issuer=claimed_issuer)" in source
        # `claimed_issuer` may reach `_resolve_idp` and nothing else.
        after_call = source.split("complete_sso_login(", 1)[-1]
        assert "claimed_issuer" not in after_call

    def test_complete_sso_login_still_takes_no_tenant(self) -> None:
        from app.auth.sso_provisioning import complete_sso_login

        assert "tenant_id" not in inspect.signature(complete_sso_login).parameters
