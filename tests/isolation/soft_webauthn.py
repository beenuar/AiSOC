"""A software WebAuthn authenticator, enough of one to complete a ceremony.

Why this exists rather than a mocked verifier
---------------------------------------------
The claim under test in ``test_auth_escalation_live.py`` is that a narrowly
scoped API key can trade itself for a full interactive session. A 200 on the
*first* step of that chain is suggestive; only driving it to a minted
``access_token`` proves it, and the reporter explicitly left the WebAuthn
mechanics out as "standard, omitted here".

A test double for the verifier would have settled nothing, because the thing
being asserted is what ``py_webauthn`` accepts. So this produces real
attestations and real assertions — ES256 over the real client-data hash — and
the production verifier is the one that judges them.

Scope: one credential, "none" attestation, UP+UV+AT flags, which is what
``verify_registration_response(require_user_verification=True)`` demands. It is
not a conformant authenticator and is not trying to be.

Imports: ``cbor2`` and ``cryptography`` are deliberately resolved inside the
methods that need them rather than at module scope. ``tests/isolation`` is
collected by an offline job that installs a minimal dependency set, and a
module-scope import of something that job does not install is a **collection**
error — it takes down every unrelated test in the directory, not just this one.
That has happened here before, where one such import failed 241 tests that had
nothing to do with it. The live job installs the API's full lockfile, where
both are present as dependencies of ``webauthn``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
from typing import Any

#: All-zero, the conventional "no attestation identity" value.
AAGUID = b"\x00" * 16

_FLAG_USER_PRESENT = 0x01
_FLAG_USER_VERIFIED = 0x04
_FLAG_ATTESTED_CREDENTIAL_DATA = 0x40


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class SoftAuthenticator:
    """One credential and its keypair, reusable across both ceremonies."""

    def __init__(self, rp_id: str = "localhost", origin: str = "http://localhost:3000") -> None:
        from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415 — see the module docstring

        self.rp_id = rp_id
        self.origin = origin
        self._private_key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(32)
        self.sign_count = 0

    def _cose_public_key(self) -> bytes:
        import cbor2  # noqa: PLC0415 — see the module docstring

        numbers = self._private_key.public_key().public_numbers()
        return cbor2.dumps(
            {
                1: 2,  # kty: EC2
                3: -7,  # alg: ES256
                -1: 1,  # crv: P-256
                -2: numbers.x.to_bytes(32, "big"),
                -3: numbers.y.to_bytes(32, "big"),
            }
        )

    def _authenticator_data(self, *, attested: bool) -> bytes:
        flags = _FLAG_USER_PRESENT | _FLAG_USER_VERIFIED
        if attested:
            flags |= _FLAG_ATTESTED_CREDENTIAL_DATA
        self.sign_count += 1
        data = hashlib.sha256(self.rp_id.encode()).digest() + bytes([flags]) + struct.pack(">I", self.sign_count)
        if attested:
            cose = self._cose_public_key()
            data += AAGUID + struct.pack(">H", len(self.credential_id)) + self.credential_id + cose
        return data

    def _client_data(self, *, challenge: bytes, ceremony: str) -> bytes:
        return json.dumps(
            {"type": ceremony, "challenge": b64url(challenge), "origin": self.origin, "crossOrigin": False},
            separators=(",", ":"),
        ).encode()

    def register(self, challenge: bytes) -> dict[str, Any]:
        """An attestation response ``verify_registration_response`` accepts."""
        import cbor2  # noqa: PLC0415 — see the module docstring

        client_data = self._client_data(challenge=challenge, ceremony="webauthn.create")
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": self._authenticator_data(attested=True)})
        return {
            "id": b64url(self.credential_id),
            "rawId": b64url(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url(client_data),
                "attestationObject": b64url(attestation),
                "transports": ["internal"],
            },
            "clientExtensionResults": {},
        }

    def authenticate(self, challenge: bytes) -> dict[str, Any]:
        """An assertion ``verify_authentication_response`` accepts."""
        from cryptography.hazmat.primitives import hashes  # noqa: PLC0415 — see the module docstring
        from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415

        client_data = self._client_data(challenge=challenge, ceremony="webauthn.get")
        authenticator_data = self._authenticator_data(attested=False)
        signature = self._private_key.sign(
            authenticator_data + hashlib.sha256(client_data).digest(),
            ec.ECDSA(hashes.SHA256()),
        )
        return {
            "id": b64url(self.credential_id),
            "rawId": b64url(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url(client_data),
                "authenticatorData": b64url(authenticator_data),
                "signature": b64url(signature),
                "userHandle": None,
            },
            "clientExtensionResults": {},
        }
