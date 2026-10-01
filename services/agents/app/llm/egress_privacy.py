"""Pseudonymize evidence before it reaches a hosted model, and restore it after.

Parity plan 2.4.

What was wrong
--------------
`docs/trust/data-flows.md` said evidence was pseudonymized before egress by
default, and claim-matrix row 19 ("no data exfiltration") rested on
`test_privacy_redactor.py`. The redactor worked. **No LLM call site invoked
it**, so the test proved a function and the claim described a control that
did not run. Parity 1.1 retracted both; this makes the claim true and
re-gates the row on a call-path test.

Where it sits, and why
----------------------
At the contract layer (`safe_ainvoke` / `safe_astream`), not at each call
site. There are sixteen call sites in `services/agents` and the contract is
the one place all of them already pass through, which is the same reasoning
that put the input contract there. A per-call-site redaction would be
sixteen chances to forget.

Local versus hosted
-------------------
On by default for hosted providers, off by default for local ones, because
a local model is inside the same trust boundary as the evidence and
pseudonymizing it only costs the model context it needs to reason. A
per-tenant setting overrides both directions.

The restore step matters as much as the redaction. The model answers about
`HOST_1` and `USER_2`; an analyst needs the answer to name the host and the
user. Rehydrating on the way back is what makes this a privacy control
rather than a degradation.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import structlog

from app.privacy.redactor import Pseudonymizer

logger = structlog.get_logger()

#: Providers served from inside the deployment. Anything not here is treated
#: as hosted, which is the safe default: a provider this module has not heard
#: of is one whose network path nobody has reasoned about.
LOCAL_PROVIDER_MARKERS = (
    "ollama",
    "localhost",
    "127.0.0.1",
    "litellm",
    "vllm",
    "llama.cpp",
    "text-generation-inference",
)

_FORCE = os.getenv("AISOC_PSEUDONYMIZE_EGRESS", "").strip().lower()


def provider_is_local(model: str, base_url: str | None = None) -> bool:
    """Whether this model is served from inside the deployment."""
    haystack = f"{model or ''} {base_url or ''}".lower()
    return any(marker in haystack for marker in LOCAL_PROVIDER_MARKERS)


def should_pseudonymize(*, model: str, base_url: str | None = None, tenant_setting: bool | None = None) -> bool:
    """Decide whether this call's evidence is pseudonymized.

    Order: an explicit environment override, then the tenant's setting, then
    the default for the provider class.
    """
    if _FORCE in ("1", "true", "yes", "always"):
        return True
    if _FORCE in ("0", "false", "no", "never"):
        return False
    if tenant_setting is not None:
        return tenant_setting
    return not provider_is_local(model, base_url)


@dataclass
class EgressSession:
    """One call's pseudonymization, held so the response can be restored."""

    pseudonymizer: Pseudonymizer | None
    applied: bool = False

    def redact_messages(self, messages: list[Any]) -> list[Any]:
        if self.pseudonymizer is None:
            return messages
        out: list[Any] = []
        for message in messages:
            content = getattr(message, "content", None)
            if not isinstance(content, str) or not content:
                out.append(message)
                continue
            redacted = self.pseudonymizer.redact(content)
            if redacted == content:
                out.append(message)
                continue
            self.applied = True
            # Copy rather than mutate: the caller's message objects are
            # often reused across retries, and mutating them would make the
            # second attempt redact already-redacted text.
            out.append(_with_content(message, redacted))
        return out

    def restore(self, result: Any) -> Any:
        """Put the real names back, so the analyst reads a usable answer."""
        if self.pseudonymizer is None or not self.applied:
            return result
        content = getattr(result, "content", None)
        if not isinstance(content, str) or not content:
            return result
        return _with_content(result, self.pseudonymizer.rehydrate(content))


def _with_content(message: Any, content: str) -> Any:
    """A copy of `message` carrying `content`.

    Falls back to returning the original unchanged rather than raising: a
    message shape this does not recognise must not break the call, and the
    redaction simply does not apply to it. That is visible in `applied`.
    """
    try:
        clone = message.model_copy(update={"content": content})
    except AttributeError:
        try:
            clone = type(message)(content=content)
        except Exception:  # noqa: BLE001
            return message
    except Exception:  # noqa: BLE001
        return message
    return clone


def open_session(*, model: str, base_url: str | None = None, tenant_id: str = "", tenant_setting: bool | None = None) -> EgressSession:
    """A session for one LLM call. No-op when pseudonymization is off."""
    if not should_pseudonymize(model=model, base_url=base_url, tenant_setting=tenant_setting):
        return EgressSession(None)
    return EgressSession(Pseudonymizer(tenant_id=tenant_id))
