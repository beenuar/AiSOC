"""Model pinning + provider fallback chain (Phase 8 — LLMOps).

Before this, the model name came from scattered `os.getenv("AISOC_LLM_MODEL",
"gpt-4o-mini")` / `os.getenv("OPENAI_MODEL", ...)` calls — a silent default that
could drift per module and had no notion of a fallback provider. This module
pins each logical role to a concrete model and an ordered provider fallback
chain that ALWAYS terminates in the deterministic tier, so the system has a
defined, non-silent degradation path when the primary provider is unavailable.

Pins are overridable by env (operators pin their own models) but the *shape* —
every chain ending in `deterministic` — is enforced by a gate so a
mis-configuration can't leave the system with no floor.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

DETERMINISTIC = "deterministic"


@dataclass(frozen=True)
class ModelPin:
    """A logical role pinned to a primary model + an ordered fallback chain."""

    role: str
    primary_model: str
    fallback_chain: list[str] = field(default_factory=list)

    def resolved_chain(self) -> list[str]:
        """primary → fallbacks, guaranteed to end in the deterministic tier."""
        chain = [self.primary_model, *self.fallback_chain]
        if chain[-1] != DETERMINISTIC:
            chain.append(DETERMINISTIC)
        return chain


# Shipped pins. Since #478 the pinned primary is a **logical gateway alias**
# (`aisoc-<role>`), not a concrete model — the LiteLLM gateway
# (`infra/litellm/config.yaml`) owns the alias → real-model mapping and any
# model-level fallback, so each AiSOC-side chain only needs its `deterministic`
# floor. One role per AiSOC LLM workload named in #478.
#
# Escape hatch for deployments not running the gateway: override any primary via
# env (`AISOC_MODEL_PIN_<ROLE>`, e.g. `AISOC_MODEL_PIN_TRIAGE=gpt-4o-mini`) to
# send a concrete provider model directly. Every chain still terminates in
# `deterministic`.
_DEFAULT_PINS: dict[str, ModelPin] = {
    "triage": ModelPin("triage", "aisoc-triage", [DETERMINISTIC]),
    "recon": ModelPin("recon", "aisoc-recon", [DETERMINISTIC]),
    "investigation": ModelPin("investigation", "aisoc-investigation", [DETERMINISTIC]),
    "copilot": ModelPin("copilot", "aisoc-copilot", [DETERMINISTIC]),
    "summary": ModelPin("summary", "aisoc-summary", [DETERMINISTIC]),
    "report": ModelPin("report", "aisoc-report", [DETERMINISTIC]),
    "nl": ModelPin("nl", "aisoc-nl", [DETERMINISTIC]),
}


def _env_override(role: str) -> str | None:
    return os.environ.get(f"AISOC_MODEL_PIN_{role.upper()}")


def get_pin(role: str) -> ModelPin:
    """Return the pin for a role, honouring an env override of the primary."""
    base = _DEFAULT_PINS.get(role)
    if base is None:
        # Unknown role — deterministic-only floor, never a silent guess.
        return ModelPin(role, DETERMINISTIC, [])
    override = _env_override(role)
    if override:
        return ModelPin(role, override, base.fallback_chain)
    return base


def all_roles() -> list[str]:
    return sorted(_DEFAULT_PINS)


def verify_pins() -> list[str]:
    """Return violations; empty means every pin has a safe deterministic floor."""
    problems: list[str] = []
    for role in all_roles():
        chain = get_pin(role).resolved_chain()
        if chain[-1] != DETERMINISTIC:
            problems.append(f"pin '{role}' chain does not terminate in the deterministic tier: {chain}")
        if not chain[0]:
            problems.append(f"pin '{role}' has an empty primary model")
    return problems
