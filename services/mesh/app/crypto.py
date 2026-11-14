"""Ed25519 per-instance signing + IOC hashing for the mesh.

Every artifact an instance publishes is signed with its Ed25519 key (reusing
the plugin-signing infra's key type). The hub verifies the signature before
counting the artifact toward k-anonymity, so a single actor can't inflate
consensus by replaying under many fake instance IDs — each distinct instance is
a distinct verified public key.

IOC values are never published in the clear. We publish the SHA-256 of the
normalized ``<type>:<value>`` so the hub (and peers) learn a *reputation exists*
for a hash without learning the value — a private-set-intersection style
exchange: you learn the raw IOC only if you already have it (i.e. you can
compute the same hash).
"""

from __future__ import annotations

import base64
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def generate_instance_key() -> tuple[str, str]:
    """Return (private_key_b64, public_key_b64) for a new instance identity."""
    priv = Ed25519PrivateKey.generate()
    priv_raw = priv.private_bytes_raw()
    pub_raw = priv.public_key().public_bytes_raw()
    return base64.b64encode(priv_raw).decode(), base64.b64encode(pub_raw).decode()


def sign(private_key_b64: str, message: bytes) -> str:
    priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_key_b64))
    return base64.b64encode(priv.sign(message)).decode()


def verify(public_key_b64: str, message: bytes, signature_b64: str) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        pub.verify(base64.b64decode(signature_b64), message)
        return True
    except (InvalidSignature, ValueError):
        return False


def normalize_ioc(ioc_type: str, value: str) -> str:
    """Normalize an IOC before hashing so the same indicator hashes identically
    across instances (lowercase, strip, defang)."""
    v = value.strip().lower().replace("[.]", ".").replace("hxxp", "http")
    return f"{ioc_type.strip().lower()}:{v}"


def ioc_hash(ioc_type: str, value: str) -> str:
    """SHA-256 of the normalized IOC. This is what's published — never the value."""
    return hashlib.sha256(normalize_ioc(ioc_type, value).encode()).hexdigest()
