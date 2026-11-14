"""LLM input contract + safe-call wrapper (T2.3).

Every LLM call originating in ``services/agents`` must pass through
:func:`safe_ainvoke` (or instantiate a chat model via
:func:`make_safe_chat_model`). The wrapper validates message contents
against :class:`LLMInputContract` and raises :class:`LLMContractViolation`
on contract breach (raw OCSF JSON, raw log lines, or any other
forbidden-shape payload). Fail-closed: prefer aborting the LLM call to
leaking raw payloads to a third-party model.
"""

from .contract import (
    AGENTS_LLM_CONTRACT_ENFORCED_ENV,
    CONTRACT_DICT_KEY_BLOCKLIST,
    LLMContractViolation,
    LLMInputContract,
    classify_message,
    is_contract_enforced,
    make_safe_chat_model,
    safe_ainvoke,
    safe_astream,
    set_contract_enforcement,
    validate_messages,
)

__all__ = [
    "AGENTS_LLM_CONTRACT_ENFORCED_ENV",
    "CONTRACT_DICT_KEY_BLOCKLIST",
    "LLMContractViolation",
    "LLMInputContract",
    "classify_message",
    "is_contract_enforced",
    "make_safe_chat_model",
    "safe_ainvoke",
    "safe_astream",
    "set_contract_enforcement",
    "validate_messages",
]
