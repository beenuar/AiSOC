"""Privacy / redaction primitives for the investigation agent.

The single sanctioned way to pseudonymize untrusted evidence before it leaves
the process for a third-party LLM. See :mod:`app.privacy.redactor`.
"""

from __future__ import annotations

from app.privacy.redactor import Pseudonymizer, RedactionConfig, default_pseudonymizer

__all__ = ["Pseudonymizer", "RedactionConfig", "default_pseudonymizer"]
