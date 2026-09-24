"""Fail-closed LLM input contract for ``services/api`` (T2.3).

Seven endpoints in this service POSTed untrusted input straight to a
chat-completions API with no contract of any kind:

* ``phishing.py`` — a submitted email body. Attacker-authored by definition.
* ``translation.py`` — a vendor rule pasted into a fenced block.
* ``knowledge_base.py`` — retrieved KB chunks plus the question.
* ``hunts.py`` — an analyst hypothesis.
* ``nl_detection.py`` — a detection description.
* ``detection_loop.py`` — ``alert_fields``, i.e. raw alert data.
* ``services/alert_explain.py`` — alert title, description and tags.

``services/agents`` has had a fail-closed contract since T2.3 landed there, and
the module this file replaces was described in the repo's own notes as already
existing here. It did not: ``services/api/app/services/llm_safety.py`` was
absent from the tree, so the API half of the same contract was never written.

The classifier is the *same* one the agents service runs, vendored at
``app/_vendor/llm_contract_rules.py`` and kept byte-identical by
``scripts/sync_vendored_llm_contract.py --check``. Two heuristics that disagreed
about what counts as a raw log would be worse than one, because a prompt
rejected in one service and accepted in the other reads as a bug in the
rejection.

What this is and is not
=======================

It is a **minimum-leak** control: it aborts a call that is about to ship raw
OCSF, vendor log lines, Sysmon XML or secret-shaped values to a third party. It
is **not** an injection sanitizer — that is `PromptInjectionGuard` in the agents
service, which detects and demotes rather than refusing.

Enforcement follows the agents service's flag
(``AISOC_AGENTS_LLM_CONTRACT_ENFORCED``, default on) so one setting governs both
halves. Disabling it in one service only would leave a contract that holds on
whichever path the traffic did not take.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import httpx

# `X as X` is the explicit re-export form (PEP 484). These names are this
# module's public surface — callers do
# `from app.services.llm_safety import LLMContractViolation` — and without the
# `as` both ruff and CodeQL read them as imports nothing here uses. An
# `__all__` would say the same thing to a human and nothing to either tool,
# which is how the previous arrangement collected an alert for declaring a
# public surface no importer consults.
from app._vendor.llm_contract_rules import (
    LLMContractViolation as LLMContractViolation,
)
from app._vendor.llm_contract_rules import (
    LLMInputContract as LLMInputContract,
)
from app._vendor.llm_contract_rules import (
    classify_message as classify_message,
)
from app._vendor.llm_contract_rules import (
    is_contract_enforced as is_contract_enforced,
)
from app._vendor.llm_contract_rules import (
    validate_messages as validate_messages,
)

# These names are re-exports: callers do
# `from app.services.llm_safety import LLMContractViolation`, and the rules
# themselves live in the vendored copy so `services/api` can carry them
# without the agents service's LangChain dependency.
#
# `__all__` rather than the PEP 484 `X as X` form. The `as` form satisfies
# ruff and *not* CodeQL, which still reads each one as an import nothing uses
# — so it traded one note-level alert for four. `__all__` is what CodeQL
# models as marking a re-export.
__all__ = [
    "LLMContractViolation",
    "LLMInputContract",
    "classify_message",
    "is_contract_enforced",
    "safe_chat_completions_request",
    "validate_messages",
]

DEFAULT_COMPLETIONS_URL = "https://api.openai.com/v1/chat/completions"


async def safe_chat_completions_request(
    *,
    api_key: str,
    model: str,
    messages: Iterable[Any],
    url: str = DEFAULT_COMPLETIONS_URL,
    timeout: float = 30.0,
    extra_headers: dict[str, str] | None = None,
    client: httpx.AsyncClient | None = None,
    **extra_body: Any,
) -> dict[str, Any]:
    """Validate ``messages``, then POST them to a chat-completions endpoint.

    Raises :class:`LLMContractViolation` **before** the network call, so a
    prompt that breaches the contract never reaches the provider. That ordering
    is the whole point: a check that runs after the request is a log line, not
    a control.

    Mirrors the signature of the agents service's function of the same name so
    a call site can move between services without rewriting. ``client`` is
    accepted so callers that already hold a pooled ``AsyncClient`` — and tests
    — do not each construct one.
    """
    validated = LLMInputContract.validate(messages)

    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)
    payload: dict[str, Any] = {"model": model, "messages": validated, **extra_body}

    if client is not None:
        response = await client.post(url, headers=headers, json=payload, timeout=timeout)
        response.raise_for_status()
        return dict(response.json())

    async with httpx.AsyncClient(timeout=timeout) as owned:
        response = await owned.post(url, headers=headers, json=payload)
        response.raise_for_status()
        return dict(response.json())
