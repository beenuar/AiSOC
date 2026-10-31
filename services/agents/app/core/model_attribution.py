"""Which model actually served a call, and how that is known.

The gap this closes
-------------------
Every row of the published verdict-quality table placed 72 model calls and
shipped ``resolved_models: []``. The runs were served by an OpenAI-compatible
endpoint directly — no LiteLLM gateway, so no ``x-litellm-model-name`` header —
and the header extractor in :mod:`app.core.gateway_cost` was the only serving
identity reader in the tree. The scorecard could prove the calls happened and
could not say which model took them, which the benchmark page had to disclose
as "per-decision model attribution is unverified".

The serving identity was in the response body the whole time: every
OpenAI-compatible server names the model it served in the chat completion's
``model`` field. This module reads it — carefully, because the obvious read is
wrong.

The trap in the obvious read
----------------------------
``langchain_openai`` builds ``response_metadata["model_name"]`` as::

    response_dict.get("model", self.model_name)

— the **requested** name is the fallback when the body carried none. Reading
the key naively would therefore fill missing serving-model metadata by copying
the requested alias, which is the one thing an attribution record must never
do: a scorecard would then claim a serving identity nobody reported.

So the body value is credited only when there is evidence it came from the
body:

* the reported name **differs** from the requested one (nothing but the body
  could have put it there), or
* the response carries its own ``id``, which langchain copies into
  ``response_metadata`` only when the body had one (``llm_output["id"]`` is
  set under ``if "id" in response_dict``). A body that carried ``id`` had the
  chance to state its model, and the OpenAI chat-completions schema carries
  both fields together.

The residual blind spot is stated rather than hidden: a nonstandard server
returning ``id`` without ``model`` would make langchain's fallback read as a
body echo. None of the servers this project routes to (OpenAI, LiteLLM,
Ollama, vLLM) omits ``model``, and the gateway header outranks the body
whenever both are present.

Three provenance levels, ordered
--------------------------------
``gateway_header``
    The LiteLLM gateway said what it resolved the alias to. The gateway is
    the party that routed the call, so this is the strongest claim available
    and the only one labelled *verified*.

``response_body``
    The serving endpoint named itself in the completion body. A server's own
    claim about itself — *self-reported*, trusted for attribution and
    labelled at its strength, never promoted to verified.

``None``
    Nobody said. Reported as unattributed, never filled from the request.

Stdlib only, and it never raises — same contract as
:mod:`app.core.gateway_cost`, for the same reason: an attribution module that
can throw would take down the LLM call it is describing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.core.gateway_cost import RESOLVED_MODEL_HEADER, response_headers

__all__ = [
    "ADVERTISABLE_STATUSES",
    "ATTRIBUTION_GATEWAY_HEADER",
    "ATTRIBUTION_RESPONSE_BODY",
    "STATUS_MIXED_SERVING",
    "STATUS_NO_CALLS",
    "STATUS_SELF_REPORTED",
    "STATUS_UNATTRIBUTED",
    "STATUS_VERIFIED",
    "ServingAttribution",
    "extract_serving_attribution",
    "models_match",
    "run_provenance_status",
]

#: The gateway named the model it routed the alias to. Verified: the party
#: that placed the provider call is the one speaking.
ATTRIBUTION_GATEWAY_HEADER = "gateway_header"

#: The serving endpoint named itself in the completion body. Self-reported.
ATTRIBUTION_RESPONSE_BODY = "response_body"

#: Run-level provenance statuses. A scorecard carries exactly one of these,
#: and only the first two may be advertised as performance of a named model.
STATUS_VERIFIED = "verified"
STATUS_SELF_REPORTED = "self_reported"
#: Calls were placed and no party named the serving model (or named it for
#: only some calls — the ``:partial`` suffix says which).
STATUS_UNATTRIBUTED = "unattributed"
#: A serving identity was reported and it does not answer for the requested
#: model. A run in this state measured *something*, and the one thing it must
#: not be published as is the requested model's performance.
STATUS_MIXED_SERVING = "serving_mismatch"
#: No model call was placed at all. The deterministic tier's honest answer,
#: and the state the verdict harness refuses to publish as live.
STATUS_NO_CALLS = "no_calls"

#: Statuses under which a run may be described as measured performance of the
#: model it names. Everything else is a diagnostic with a limitation.
ADVERTISABLE_STATUSES = (STATUS_VERIFIED, STATUS_SELF_REPORTED)

#: Shape of a logical task alias. An alias is a label the gateway resolves,
#: so any concrete serving model is a correct answer for one. Mirrors
#: ``_GATEWAY_ALIAS_PREFIX`` in :mod:`app.core.cost_telemetry`.
_ALIAS_PREFIX = "aisoc-"


@dataclass(frozen=True)
class ServingAttribution:
    """What served one call, by whose account."""

    #: The serving model, or ``None`` when no party named one. Never a copy
    #: of the requested name.
    serving_model: str | None = None
    #: :data:`ATTRIBUTION_GATEWAY_HEADER`, :data:`ATTRIBUTION_RESPONSE_BODY`,
    #: or ``None`` when unattributed.
    source: str | None = None
    #: The backend's own configuration fingerprint, when it published one
    #: (OpenAI's ``system_fingerprint``). The closest thing to an immutable
    #: deployment digest the chat-completions surface exposes.
    system_fingerprint: str | None = None
    #: The completion id, for joining a record to provider-side logs.
    response_id: str | None = None

    @property
    def attributed(self) -> bool:
        return self.serving_model is not None


def _clean(value: Any) -> str | None:
    text = str(value).strip() if value is not None else ""
    return text or None


def extract_serving_attribution(response: Any, *, requested: str) -> ServingAttribution:
    """The serving identity for ``response``, by the strongest party that spoke.

    ``requested`` is the model string the client asked for — the alias or the
    pin. It is used only to *refuse* an ambiguous body value, never as a
    fallback answer.
    """
    metadata = getattr(response, "response_metadata", None)
    metadata = metadata if isinstance(metadata, dict) else {}
    fingerprint = _clean(metadata.get("system_fingerprint"))
    response_id = _clean(metadata.get("id"))

    header_model = _clean(response_headers(response).get(RESOLVED_MODEL_HEADER))
    if header_model:
        return ServingAttribution(
            serving_model=header_model,
            source=ATTRIBUTION_GATEWAY_HEADER,
            system_fingerprint=fingerprint,
            response_id=response_id,
        )

    body_model = _clean(metadata.get("model_name"))
    if body_model:
        requested_clean = (requested or "").strip()
        # Credited only with evidence the body was parsed: a name the client
        # did not ask for, or the body's own ``id`` beside it. An equal name
        # with no witness is indistinguishable from langchain's fallback to
        # the requested model, and copying the request into serving metadata
        # is the defect this module exists to prevent.
        if body_model != requested_clean or response_id is not None:
            return ServingAttribution(
                serving_model=body_model,
                source=ATTRIBUTION_RESPONSE_BODY,
                system_fingerprint=fingerprint,
                response_id=response_id,
            )

    return ServingAttribution(system_fingerprint=fingerprint, response_id=response_id)


def _bare(model: str) -> str:
    """The model name with any provider prefix dropped: ``ollama/x`` -> ``x``."""
    return model.rsplit("/", 1)[-1].strip().lower()


def models_match(*, requested: str, serving: str) -> bool:
    """Whether ``serving`` answers for ``requested``.

    Three accepted shapes, each from a measured behaviour:

    * an ``aisoc-<role>`` alias is resolved by the gateway, so any concrete
      serving model is the correct answer for it (and is still named);
    * a provider prefix on the serving side (``ollama/qwen2:1.5b`` for
      ``qwen2:1.5b``) is routing, not substitution;
    * a version suffix on the serving side (``gpt-4o-2024-08-06`` for
      ``gpt-4o``) is the provider pinning the ask, not changing it. The
      suffix must extend the requested name at a ``-`` boundary, so
      ``gpt-4o-mini`` does not pass as ``gpt-4o``.
    """
    req = (requested or "").strip().lower()
    srv = (serving or "").strip().lower()
    if not req or not srv:
        return False
    if req.startswith(_ALIAS_PREFIX):
        return True
    req_bare, srv_bare = _bare(req), _bare(srv)
    if req_bare == srv_bare:
        return True
    # A dated/version suffix: the serving name extends the requested one at a
    # separator, and the extension is digit-led (a date or build number), so a
    # sibling model sharing the prefix (`gpt-4o-mini`) does not pass.
    if srv_bare.startswith(req_bare + "-"):
        suffix = srv_bare[len(req_bare) + 1 :]
        return bool(suffix) and suffix[0].isdigit()
    return False


def run_provenance_status(
    *,
    llm_calls: int,
    attributed_by_source: dict[str, int],
    serving_models: tuple[str, ...] | list[str],
    requested: tuple[str, ...] | list[str],
) -> str:
    """One status for a whole run, computed from per-call attribution.

    The order of the checks is the order of the claims a reader cares about:

    1. nothing was called — the strongest fact about the run;
    2. something served that was not what was asked for — a substitution is
       disqualifying however well-attributed it is;
    3. attribution incomplete — some or all calls have no named server;
    4. every call attributed: verified when the gateway spoke for every call,
       self-reported when any call rests on the body's own claim.
    """
    if llm_calls <= 0:
        return STATUS_NO_CALLS

    for serving in serving_models:
        if not any(models_match(requested=req, serving=serving) for req in requested if req):
            return STATUS_MIXED_SERVING

    attributed = sum(attributed_by_source.values())
    if attributed <= 0:
        return STATUS_UNATTRIBUTED
    if attributed < llm_calls:
        return f"{STATUS_UNATTRIBUTED}:partial"

    if attributed_by_source.get(ATTRIBUTION_GATEWAY_HEADER, 0) == llm_calls:
        return STATUS_VERIFIED
    return STATUS_SELF_REPORTED
