"""Entra app certificate credentials (RS256 ``client_assertion``), written once.

Shared by the Microsoft connectors that accept an app certificate instead of a
client secret. The JWT is hand-built with ``cryptography`` (already a
dependency), reusing ``b64url`` from ``gcp_service_account``.
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.connectors.gcp_service_account import b64url

ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
_LIFETIME_SECONDS = 600
_CERT_BEGIN = b"-----BEGIN CERTIFICATE-----"

CERT_HELP = (
    "Recommended over a client secret. Paste a PEM containing the PRIVATE KEY "
    "(and optionally the CERTIFICATE) for the certificate whose public .cer you uploaded under "
    "Entra portal > App registrations > your app > Certificates & secrets."
)
THUMBPRINT_HELP = (
    "SHA-1 thumbprint shown next to the certificate under App registrations > "
    "Certificates & secrets. Optional when the PEM above also contains the certificate."
)


def cert_schema_fields(field_cls: Any) -> list[Any]:
    """The three optional certificate fields, built with the caller's ``Field``."""
    return [
        field_cls("certificate_pem", "secret", "Certificate PEM (private key)", required=False, help_text=CERT_HELP),
        field_cls("certificate_thumbprint", "string", "Certificate Thumbprint", required=False, help_text=THUMBPRINT_HELP),
        field_cls(
            "private_key_password",
            "secret",
            "Private Key Password",
            required=False,
            help_text="Only if the private key in the PEM is encrypted.",
        ),
    ]


class CertificateCredential:
    """Parses the PEM once (so bad input fails at construction) and signs assertions."""

    def __init__(self, pem: str, thumbprint: str = "", password: str = ""):
        data = pem.encode("utf-8")
        try:
            key = serialization.load_pem_private_key(data, password=password.encode() if password else None)
        except Exception as exc:
            raise ValueError(
                f"certificate_pem must be a PEM containing the app's PRIVATE KEY (plus private_key_password if encrypted): {exc}"
            ) from exc
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError("certificate_pem private key must be RSA (Entra certificate credentials use RS256).")
        self._key = key
        self._x5t_s256: str | None = None
        if _CERT_BEGIN in data:
            try:
                cert = x509.load_pem_x509_certificate(data[data.index(_CERT_BEGIN) :])
            except Exception as exc:
                raise ValueError(f"certificate_pem contains an unreadable CERTIFICATE block: {exc}") from exc
            # Vendor-mandated: the JWT `x5t` header IS the certificate's SHA-1
            # thumbprint — Microsoft identifies the uploaded certificate by it
            # and rejects an assertion without it. Nothing security-bearing is
            # hashed here; the signature itself is RS256. The SHA-256 variant
            # rides along as `x5t#S256` when the cert is present.
            # nosemgrep: security.semgrep.python.cryptography.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1
            sha1 = cert.fingerprint(hashes.SHA1())  # noqa: S303 - Entra identifies certs by SHA-1 (x5t)
            self._x5t_s256 = b64url(cert.fingerprint(hashes.SHA256()))
        else:
            hexval = thumbprint.replace(":", "").replace(" ", "").strip()
            if not hexval:
                raise ValueError(
                    "certificate_thumbprint is required when certificate_pem has no CERTIFICATE block "
                    "(copy it from Entra portal > App registrations > Certificates & secrets)."
                )
            try:
                sha1 = bytes.fromhex(hexval)
            except ValueError as exc:
                raise ValueError("certificate_thumbprint must be a hex SHA-1 thumbprint.") from exc
        self._x5t = b64url(sha1)

    def assertion(self, client_id: str, audience: str) -> str:
        now = int(time.time())
        header: dict[str, str] = {"alg": "RS256", "typ": "JWT", "x5t": self._x5t}
        if self._x5t_s256:
            header["x5t#S256"] = self._x5t_s256
        claims = {
            "aud": audience,
            "iss": client_id,
            "sub": client_id,
            "jti": str(uuid.uuid4()),
            "nbf": now,
            "iat": now,
            "exp": now + _LIFETIME_SECONDS,
        }
        parts = [b64url(json.dumps(d, separators=(",", ":")).encode()) for d in (header, claims)]
        signing_input = ".".join(parts)
        sig = self._key.sign(signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
        return signing_input + "." + b64url(sig)


def build_credential(
    client_secret: str, certificate_pem: str, certificate_thumbprint: str, private_key_password: str
) -> CertificateCredential | None:
    """None means secret auth. Exactly one method must be configured; the certificate wins if both."""
    if certificate_pem.strip():
        return CertificateCredential(certificate_pem, certificate_thumbprint, private_key_password)
    if not client_secret:
        raise ValueError("Configure either client_secret or certificate_pem (+ certificate_thumbprint); neither was provided.")
    return None


def token_form(cred: CertificateCredential | None, client_id: str, client_secret: str, audience: str) -> dict[str, str]:
    """Credential part of the client-credentials token form."""
    if cred is None:
        return {"client_id": client_id, "client_secret": client_secret}
    return {
        "client_id": client_id,
        "client_assertion_type": ASSERTION_TYPE,
        "client_assertion": cred.assertion(client_id, audience),
    }
