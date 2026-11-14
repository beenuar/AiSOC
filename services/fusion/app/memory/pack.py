"""Portable, signed memory packs.

`aisoc memory export` produces a signed memory pack so an MSSP can bootstrap a
new child tenant from a curated baseline (and the marketplace can carry a
memory-pack artifact type). The pack is Ed25519-signed; import verifies the
signature and rejects a tampered pack, so a bootstrap baseline can't be forged.
"""

from __future__ import annotations

import base64
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from app.memory.distill import MemoryPack


class PackVerificationError(Exception):
    """Raised when a memory pack's signature does not verify."""


def _canonical(pack: MemoryPack) -> bytes:
    return json.dumps(pack.to_json(), sort_keys=True, separators=(",", ":")).encode()


def export_pack(pack: MemoryPack, private_key_b64: str) -> str:
    """Export a signed memory pack as a JSON string (base64 Ed25519 signature)."""
    priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_key_b64))
    signature = base64.b64encode(priv.sign(_canonical(pack))).decode()
    envelope = {
        "format": "aisoc-memory-pack",
        "format_version": 1,
        "signature": signature,
        "public_key": base64.b64encode(priv.public_key().public_bytes_raw()).decode(),
        "pack": pack.to_json(),
    }
    return json.dumps(envelope, indent=2)


def import_pack(signed_json: str, *, expected_public_key_b64: str | None = None) -> MemoryPack:
    """Verify + parse a signed memory pack.

    If ``expected_public_key_b64`` is given, the pack's embedded key must match
    it (pin the publisher). Raises :class:`PackVerificationError` on any
    signature/format failure.
    """
    try:
        envelope = json.loads(signed_json)
    except json.JSONDecodeError as exc:
        raise PackVerificationError(f"invalid pack JSON: {exc}") from exc

    if envelope.get("format") != "aisoc-memory-pack":
        raise PackVerificationError("not an aisoc-memory-pack")

    pub_b64 = envelope.get("public_key", "")
    if expected_public_key_b64 is not None and pub_b64 != expected_public_key_b64:
        raise PackVerificationError("pack public key does not match the expected publisher")

    pack = MemoryPack.from_json(envelope["pack"])
    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64))
        pub.verify(base64.b64decode(envelope["signature"]), _canonical(pack))
    except (InvalidSignature, ValueError, KeyError) as exc:
        raise PackVerificationError("memory pack signature failed to verify (tampered or wrong key)") from exc
    return pack
