"""Prompt-construction safety primitives for the investigator agents.

This package is the single sanctioned path for placing untrusted evidence
into an LLM prompt. See :mod:`app.prompting.envelope`.
"""

from __future__ import annotations

from app.prompting.envelope import (
    EvidenceEnvelope,
    GuardSignal,
    GuardVerdict,
    PromptInjectionGuard,
    make_nonce,
    system_rule,
)

__all__ = [
    "EvidenceEnvelope",
    "GuardSignal",
    "GuardVerdict",
    "PromptInjectionGuard",
    "make_nonce",
    "system_rule",
]
