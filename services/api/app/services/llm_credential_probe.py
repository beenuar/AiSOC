"""Place one real call with a tenant's BYOK credential, and report what happened.

Why this exists
---------------
`GET`/`PUT`/`DELETE /api/v1/llm/credentials` validate *shape*: that the URL
parses, that the provider/key/base-URL combination is internally consistent.
None of them talks to the provider. So an operator who pasted a revoked key,
or pointed at a host that is not running, found out when triage silently fell
back to the deterministic path -- a failure that is quiet by design, which is
precisely what makes it hard to attribute to the key.

The guard, and why it is not the webhook one
--------------------------------------------
This makes an outbound request to a URL the tenant supplied, so it needs an
SSRF guard. The API already has one and it is the wrong shape:
`destinations.py::_guard_url` rejects every private and loopback address
outright. That is correct for a webhook and would refuse `local-ollama`,
`local-vllm` and `local-litellm` -- three of the seven providers migration 038
explicitly allows, and the ones most likely to be on a private address.

`validate_outbound_url(url, allow_private=True)` is the shape that fits: a
private host is permitted while loopback and link-local are still rejected, so
the cloud-metadata endpoint at 169.254.169.254 stays blocked *even though*
private addresses are allowed. Vendored from the agents service and held
byte-identical by `scripts/sync_vendored_ssrf_guard.py`.

Air-gap
-------
Checked before anything is dialled, and reported as `unverified` rather than
as a failure: an air-gapped deployment refusing egress is the posture working,
not a broken credential.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Literal

import httpx
import structlog

from app._vendor.ssrf_guard import SSRFError, validate_outbound_url
from app.core.airgap import AirgapViolation, enforce_airgap_for_url
from app.services.llm_safety import safe_chat_completions_request

logger = structlog.get_logger(__name__)

Outcome = Literal["ok", "refused", "unreachable", "unverified"]

#: Short. A human is waiting on this in a settings panel, and a provider that
#: takes longer than this to answer a one-token completion is not one triage
#: should be pointed at either.
PROBE_TIMEOUT_SECONDS = 15.0

#: Where each provider's chat-completions endpoint lives when the tenant did
#: not give a base URL. Only the hosted ones have a default; the local and
#: custom providers are required to supply one (migration 038's CHECK and
#: `_enforce_provider_invariants` both say so).
_DEFAULT_BASE: dict[str, str] = {
    "openai": "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com/v1",
}

#: A model has to be named to complete anything. These are the cheapest
#: generally-available model per provider, used only when the tenant left the
#: field blank -- the probe says which one it used so the result is readable.
_FALLBACK_MODEL: dict[str, str] = {
    "openai": "gpt-4o-mini",
    "anthropic": "claude-3-5-haiku-20241022",
    "azure-openai": "gpt-4o-mini",
    "local-ollama": "llama3.2:3b-instruct-q4_K_M",
    "local-vllm": "default",
    "local-litellm": "aisoc-triage",
    "custom": "default",
}


@dataclass
class ProbeResult:
    outcome: Outcome
    detail: str
    model: str | None = None
    latency_ms: int | None = None


def _base_url_for(provider: str, base_url: str | None) -> str | None:
    return (base_url or _DEFAULT_BASE.get(provider) or "").rstrip("/") or None


def _from_status(response: httpx.Response, model: str, latency_ms: int) -> ProbeResult:
    """Turn the provider's refusal into something an operator can act on."""
    code = response.status_code

    if code in (401, 403):
        return ProbeResult(
            outcome="refused",
            detail=f"The provider rejected the credential (HTTP {code}). Check the key.",
            model=model,
            latency_ms=latency_ms,
        )
    if code == 404:
        return ProbeResult(
            outcome="refused",
            detail=(
                f"The provider answered 404 for model '{model}'. The key may be fine and the "
                "model name wrong, or not available to this account."
            ),
            model=model,
            latency_ms=latency_ms,
        )
    if code == 429:
        # Reached it, and authenticated enough to be counted against a quota,
        # which answers the question being asked.
        return ProbeResult(
            outcome="ok",
            detail="Reached the provider and was rate-limited, so the credential works.",
            model=model,
            latency_ms=latency_ms,
        )
    body = (response.text or "")[:200].replace("\n", " ")
    return ProbeResult(
        outcome="refused",
        detail=f"The provider answered HTTP {code}: {body}",
        model=model,
        latency_ms=latency_ms,
    )


async def probe_credential(
    *,
    provider: str,
    base_url: str | None,
    model: str | None,
    api_key: str | None,
) -> ProbeResult:
    """One minimal completion. Never raises; every failure is a reported state."""
    resolved_base = _base_url_for(provider, base_url)
    if not resolved_base:
        return ProbeResult(
            outcome="refused",
            detail=f"provider '{provider}' has no base URL configured and no default for it.",
        )

    resolved_model = model or _FALLBACK_MODEL.get(provider) or "default"

    # Air-gap first, before anything is dialled, and through the same function
    # every other outbound call uses -- so this cannot drift from what the
    # deployment would actually permit, and it is a no-op when the flag is off.
    #
    # Called rather than reading `settings.AISOC_AIRGAPPED` here: a module-level
    # reference to the settings object goes stale the moment anything reloads
    # `app.core.config`, and a security check that silently stops applying is
    # the worst kind. `enforce_airgap_for_url` reads the flag at call time.
    try:
        enforce_airgap_for_url(resolved_base)
    except AirgapViolation as exc:
        return ProbeResult(
            outcome="unverified",
            detail=(
                f"This deployment is air-gapped, so the call was not attempted: {exc} That is the policy working, not a bad credential."
            ),
            model=resolved_model,
        )

    try:
        # `allow_private=True` on purpose: see the module docstring. Loopback
        # and link-local are still rejected, so metadata stays unreachable.
        validate_outbound_url(resolved_base, allow_private=True)
    except SSRFError as exc:
        return ProbeResult(
            outcome="refused",
            detail=f"The base URL was refused: {exc}",
            model=resolved_model,
        )

    # Anthropic authenticates with `x-api-key` rather than a bearer token and
    # wants its API version pinned. The helper always sets `Authorization`,
    # which Anthropic ignores.
    extra_headers: dict[str, str] = {}
    if provider == "anthropic":
        extra_headers = {"x-api-key": api_key or "", "anthropic-version": "2023-06-01"}

    url = f"{resolved_base}/messages" if provider == "anthropic" else f"{resolved_base}/chat/completions"

    started = time.monotonic()
    try:
        # Through `safe_chat_completions_request`, not a raw `client.post`.
        #
        # The prompt here is a constant carrying no untrusted input, so the
        # contract has nothing to reject -- but the rule is that *every* call
        # to a completions endpoint goes through it, and a call site that
        # argues its way out is how the next one, with a real prompt, gets
        # written the same way. `tests/test_llm_contract_no_bypass.py`
        # enforces this and caught the first version of this function.
        #
        # One token: a reachability and authorisation check, not a capability
        # evaluation, and a longer generation bills the tenant for output
        # nobody reads.
        await safe_chat_completions_request(
            api_key=api_key or "",
            model=resolved_model,
            messages=[{"role": "user", "content": "ping"}],
            url=url,
            timeout=PROBE_TIMEOUT_SECONDS,
            extra_headers=extra_headers or None,
            max_tokens=1,
        )
    except httpx.HTTPStatusError as exc:
        # The helper calls `raise_for_status`, and the status code is exactly
        # what separates "the key is wrong" from "the model name is wrong"
        # from "you were rate-limited, so it works".
        return _from_status(exc.response, resolved_model, int((time.monotonic() - started) * 1000))
    except httpx.TimeoutException:
        return ProbeResult(
            outcome="unreachable",
            detail=f"{resolved_base} did not answer within {PROBE_TIMEOUT_SECONDS:.0f}s.",
            model=resolved_model,
        )
    except Exception as exc:  # noqa: BLE001 - every failure is a state
        logger.info("llm_probe.unreachable", provider=provider, error=type(exc).__name__)
        return ProbeResult(
            outcome="unreachable",
            detail=f"Could not reach {resolved_base} ({type(exc).__name__}).",
            model=resolved_model,
        )

    latency_ms = int((time.monotonic() - started) * 1000)
    return ProbeResult(
        outcome="ok",
        detail=f"Completed a one-token request against '{resolved_model}' in {latency_ms} ms.",
        model=resolved_model,
        latency_ms=latency_ms,
    )


__all__ = ["Outcome", "ProbeResult", "probe_credential"]
