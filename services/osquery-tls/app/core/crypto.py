"""Cryptographic primitives for the AiSOC osquery TLS service.

Kept in a separate module (rather than security.py) to avoid the cyclic
import that would arise if security.py imported from node_registry.py and
node_registry.py imported from security.py.
"""

from __future__ import annotations

import secrets


def generate_node_key() -> str:
    """Generate a cryptographically random node key (128-bit hex)."""
    return secrets.token_hex(16)
