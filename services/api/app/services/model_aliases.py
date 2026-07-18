"""Task role → LiteLLM gateway alias for the API service (#478).

The API service is a separate package from ``services/agents``, so it can't
import ``app.llm.factory``. This is the small mirror of
:func:`services.agents.app.llm.factory.resolve_model_alias`: each LLM-backed API
endpoint (translation, hunts, knowledge base, phishing) asks for a **logical
alias**; the LiteLLM gateway (``infra/litellm/config.yaml``) owns the alias →
real-model mapping. There is no hardcoded default model.

Escape hatch for deployments not running the gateway: override any role with a
concrete provider model via ``AISOC_MODEL_PIN_<ROLE>`` (kept in lockstep with the
agents-side pins), or set a global ``LLM_MODEL`` at the call site.
"""

from __future__ import annotations

import os

# Mirrors the roles in services/agents/app/llm/model_pins.py.
ROLES = frozenset({"triage", "recon", "investigation", "copilot", "summary", "report", "nl"})


def resolve_model_alias(role: str) -> str:
    """Return the ``aisoc-<role>`` alias, honouring an ``AISOC_MODEL_PIN_<ROLE>`` override."""
    override = os.environ.get(f"AISOC_MODEL_PIN_{role.upper()}", "").strip()
    return override or f"aisoc-{role}"
