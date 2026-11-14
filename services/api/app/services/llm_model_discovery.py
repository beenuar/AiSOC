"""List the chat models an OpenAI-compatible endpoint serves, for the BYOK selector.

Why this exists
---------------
The ``custom`` provider points a tenant at any OpenAI-compatible endpoint, and
the model was a hand-typed id. Nothing checked it, so a typo or an id the
endpoint does not serve surfaced as triage quietly falling back to the
deterministic path. Most such endpoints publish ``GET {base}/models``; this asks
it, with the tenant's key, and offers the chat-capable answers as choices. The
hand-typed id stays: discovery is a convenience over it, never a gate on it.

Bounds
------
The URL and the response are both tenant-controlled, so neither decides what
this process spends:

* :data:`DISCOVERY_TIMEOUT_SECONDS` is a deadline on the *whole* exchange, not
  httpx's per-read timeout, so an endpoint that drips one byte every nine
  seconds cannot hold a settings panel open;
* :data:`DISCOVERY_MAX_BYTES` caps the body as it streams in, after content
  decoding, so a compressed response cannot expand past it either;
* :data:`DISCOVERY_MAX_ROWS` caps how many rows are examined and
  :data:`DISCOVERY_MAX_MODELS` how many chat models are returned. They are
  separate on purpose: an aggregating endpoint can list hundreds of image,
  audio and embedding rows ahead of its chat models, and capping the raw rows
  at the selector size would drop chat models for the sake of rows that were
  going to be filtered out anyway.

Redirects are not followed. A ``3xx`` is reported, not chased to a host the
guard below never saw.

What counts as chat-capable
---------------------------
AiSOC calls ``POST {base}/chat/completions`` and nothing else, so the question
is whether an id can serve that. The OpenAI ``/models`` shape does not say: a
row is ``{"id", "object", "created", "owned_by"}``. Endpoints that aggregate
many model families often add a field that does, under one of a few spellings.
Each row is judged on what it declares, strongest evidence first:

1. **Declared metadata.** Three optional fields are read when present:

   * ``capabilities`` -- an object with a boolean ``chat``,
     ``completion_chat``, ``chat_completion`` or ``chat_completions`` key, or
     a list naming one of those;
   * modalities -- ``architecture.modality`` as ``"text+image->text"``,
     ``architecture.input_modalities`` / ``output_modalities``, the same two
     at the top level, or ``modalities`` as ``{"input": [...],
     "output": [...]}``. Output without ``text``, or input without ``text``,
     is not chat. Text in and text out is;
   * a label -- ``type`` or ``mode``, split into words. A word naming a
     non-text family (image, video, audio, speech, embedding, rerank,
     moderation, ...) is not chat; ``chat``, ``llm``, ``vlm``, ``language``
     or ``conversational`` is.

   A declared negative wins over a declared positive: a row that is wrongly
   hidden can still be typed by hand, and a row that is wrongly offered fails
   at triage time, quietly.

2. **A label the catalogue uses as a classifier.** Some endpoints list one row
   per (model, endpoint) pair and name the endpoint in ``type`` -- a model that
   only serves an asynchronous or non-chat route appears under a label that is
   neither ``chat`` nor a known non-text family. When *any* row's label says
   chat, the catalogue has shown how it spells chat, and a row whose label says
   something else is not offered. When no row's label says chat, the field is
   not a capability classifier in that catalogue (it may mean "base" vs
   "fine-tuned") and it is ignored.

3. **The id, when nothing was declared.** A plain OpenAI-compatible server
   (vLLM, a local runtime, most proxies) declares nothing, and its rows are
   chat models unless the id names a non-text family -- ``embed``,
   ``embedding``, ``tts``, ``whisper``, ``transcribe``, ``image``, ``video``,
   ``rerank``, ``moderation`` and the like, matched as whole words of the id.
   Everything else is offered.

An id appearing on several rows is offered once, if any of its rows is chat.
The heuristic is a selector filter, not an authorisation: what an endpoint
actually serves is decided by the endpoint, and the Test button remains the
way to find out.

SSRF and air-gap
----------------
The same two guards :mod:`app.services.llm_credential_probe` applies to this
very base URL, in the same order: air-gap first, before anything is dialled,
then ``validate_outbound_url(..., allow_private=True)`` so a private model host
is reachable while loopback and link-local -- the cloud-metadata address --
stay refused. See that module for why the webhook guard is the wrong shape.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Any, Literal

import httpx
import structlog

from app._vendor.ssrf_guard import SSRFError, validate_outbound_url
from app.core.airgap import AirgapViolation, enforce_airgap_for_url
from app.services.model_aliases import completions_url_for_base

logger = structlog.get_logger(__name__)

Outcome = Literal["ok", "refused", "unreachable", "unverified"]
Verdict = Literal["chat", "not_chat", "unknown"]

#: A human is waiting on this in a settings panel.
DISCOVERY_TIMEOUT_SECONDS = 10.0
#: A model list is a few hundred kilobytes even for an endpoint aggregating
#: hundreds of models; two megabytes is generous and still bounded.
DISCOVERY_MAX_BYTES = 2_000_000
#: Rows examined. Bounds the work on a body that fits under the byte cap by
#: being nothing but tiny rows.
DISCOVERY_MAX_ROWS = 5_000
#: Chat models returned. More than this is not a dropdown anyone can use, and
#: the response says when it was reached.
DISCOVERY_MAX_MODELS = 500

_CHAT_COMPLETIONS_SUFFIX = "/chat/completions"

_WORD = re.compile(r"[a-z0-9]+")

#: Words in a ``type``/``mode`` label that mean the row serves chat.
_CHAT_LABEL_WORDS = frozenset({"chat", "llm", "vlm", "language", "conversational"})

#: Words that name a family which cannot answer a text chat completion. Used
#: for labels and, when a row declares nothing, for the id.
_NON_CHAT_WORDS = frozenset(
    {
        "audio",
        "diffusion",
        "embed",
        "embedding",
        "embeddings",
        "image",
        "images",
        "moderation",
        "moderations",
        "music",
        "ocr",
        "realtime",
        "rerank",
        "reranker",
        "reranking",
        "speech",
        "transcribe",
        "transcription",
        "transcriptions",
        "tts",
        "video",
        "videos",
        "whisper",
    }
)

_CHAT_CAPABILITY_KEYS = ("chat", "completion_chat", "chat_completion", "chat_completions")
_LABEL_FIELDS = ("type", "mode")


@dataclass(frozen=True)
class DiscoveredModel:
    """What a selector needs. No pricing, no owner blob, nothing echoed raw."""

    id: str
    name: str | None = None


@dataclass(frozen=True)
class Discovery:
    """Outcome of one discovery attempt.

    ``listed`` counts the distinct ids the endpoint returned and ``excluded``
    the ones judged not chat-capable, so the console can say "2 of 5"
    rather than present a filtered list as the whole catalogue.
    """

    outcome: Outcome
    detail: str
    models: list[DiscoveredModel] = field(default_factory=list)
    listed: int = 0
    excluded: int = 0
    truncated: bool = False


class _DiscoveryError(Exception):
    def __init__(self, outcome: Outcome, detail: str) -> None:
        super().__init__(detail)
        self.outcome: Outcome = outcome
        self.detail = detail


# --------------------------------------------------------------- the URL


def models_url_for_base(base_url: str) -> str:
    """``/models`` beside the chat-completions URL the runtime will call.

    Derived from :func:`completions_url_for_base` rather than by appending to
    the base, so a base given as ``https://host`` or as
    ``https://host/v1/chat/completions`` lists models from the same place triage
    sends completions to.
    """
    completions = completions_url_for_base(base_url)
    return completions[: -len(_CHAT_COMPLETIONS_SUFFIX)] + "/models"


# --------------------------------------------------------------- the filter


def _words(value: str) -> set[str]:
    return set(_WORD.findall(value.lower()))


def _label(row: dict[str, Any]) -> str | None:
    for key in _LABEL_FIELDS:
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def label_verdict(label: str) -> Verdict:
    """Judge a ``type``/``mode`` label. A non-text word wins over a chat word."""
    words = _words(label)
    if words & _NON_CHAT_WORDS:
        return "not_chat"
    if words & _CHAT_LABEL_WORDS:
        return "chat"
    return "unknown"


def _capabilities_verdict(row: dict[str, Any]) -> Verdict | None:
    caps = row.get("capabilities")
    if isinstance(caps, dict):
        for key in _CHAT_CAPABILITY_KEYS:
            if isinstance(caps.get(key), bool):
                return "chat" if caps[key] else "not_chat"
        return None
    if isinstance(caps, list):
        named = {item.strip().lower() for item in caps if isinstance(item, str)}
        if named & set(_CHAT_CAPABILITY_KEYS):
            return "chat"
    return None


def _modality_list(value: Any) -> list[str] | None:
    if isinstance(value, list):
        return [item.strip().lower() for item in value if isinstance(item, str)]
    return None


def _modalities_verdict(row: dict[str, Any]) -> Verdict | None:
    raw_arch = row.get("architecture")
    arch: dict[str, Any] = raw_arch if isinstance(raw_arch, dict) else {}
    declared = row.get("modalities")

    inputs = _modality_list(arch.get("input_modalities"))
    if inputs is None:
        inputs = _modality_list(row.get("input_modalities"))
    outputs = _modality_list(arch.get("output_modalities"))
    if outputs is None:
        outputs = _modality_list(row.get("output_modalities"))
    if isinstance(declared, dict):
        if inputs is None:
            inputs = _modality_list(declared.get("input"))
        if outputs is None:
            outputs = _modality_list(declared.get("output"))
    elif inputs is None:
        inputs = _modality_list(declared)

    arrow = arch.get("modality") if isinstance(arch.get("modality"), str) else row.get("modality")
    if isinstance(arrow, str) and "->" in arrow:
        left, right = arrow.lower().split("->", 1)
        if inputs is None:
            inputs = [part.strip() for part in left.split("+") if part.strip()]
        if outputs is None:
            outputs = [part.strip() for part in right.split("+") if part.strip()]

    if outputs is not None and "text" not in outputs:
        return "not_chat"
    if inputs is not None and "text" not in inputs:
        return "not_chat"
    if outputs is not None:
        return "chat"
    # Text input alone says nothing: an embedding model takes text too.
    return None


def row_verdict(row: dict[str, Any], *, labels_classify: bool) -> Verdict:
    """Judge one row. See the module docstring for the order and why.

    ``labels_classify`` is the catalogue-level fact from step 2: whether any
    row's label said chat.
    """
    label = _label(row)
    declared = [
        _capabilities_verdict(row),
        _modalities_verdict(row),
        label_verdict(label) if label is not None else None,
    ]
    if "not_chat" in declared:
        return "not_chat"
    if "chat" in declared:
        return "chat"
    if label is not None and labels_classify:
        return "not_chat"
    model_id = row.get("id")
    if isinstance(model_id, str) and _words(model_id) & _NON_CHAT_WORDS:
        return "not_chat"
    return "chat"


def filter_chat_models(rows: list[Any]) -> Discovery:
    """Apply the filter to a ``data`` list. Pure, so it is testable on fixtures."""
    usable: list[dict[str, Any]] = []
    for row in rows[:DISCOVERY_MAX_ROWS]:
        if not isinstance(row, dict):
            continue
        model_id = row.get("id")
        if isinstance(model_id, str) and model_id.strip() and len(model_id) <= 256:
            usable.append(row)

    labels_classify = any(label_verdict(label) == "chat" for label in (_label(row) for row in usable) if label is not None)

    seen: dict[str, DiscoveredModel] = {}
    all_ids: set[str] = set()
    for row in usable:
        model_id = row["id"].strip()
        all_ids.add(model_id)
        if model_id in seen or row_verdict(row, labels_classify=labels_classify) != "chat":
            continue
        name = row.get("name")
        seen[model_id] = DiscoveredModel(id=model_id, name=name.strip()[:200] if isinstance(name, str) and name.strip() else None)

    chat = sorted(seen.values(), key=lambda m: m.id)
    truncated = len(chat) > DISCOVERY_MAX_MODELS or len(rows) > DISCOVERY_MAX_ROWS
    chat = chat[:DISCOVERY_MAX_MODELS]
    excluded = len(all_ids) - len(seen)

    if not chat:
        detail = f"The endpoint listed {len(all_ids)} model(s) and none looked chat-capable. Type the model id instead."
    else:
        detail = f"{len(chat)} chat model(s) of {len(all_ids)} listed."
        if truncated:
            detail += " The list was longer than this panel shows; type an id that is not offered."
    return Discovery(outcome="ok", detail=detail, models=chat, listed=len(all_ids), excluded=excluded, truncated=truncated)


# --------------------------------------------------------------- the call


async def _read_bounded(client: httpx.AsyncClient, url: str, headers: dict[str, str]) -> bytes:
    async with client.stream("GET", url, headers=headers) as response:
        code = response.status_code
        if code in (401, 403):
            raise _DiscoveryError("refused", f"The endpoint rejected the key when listing models (HTTP {code}).")
        if code == 404:
            raise _DiscoveryError(
                "refused",
                "The endpoint does not publish a model list at /models (HTTP 404). Type the model id instead.",
            )
        if code != 200:
            raise _DiscoveryError("refused", f"The endpoint answered HTTP {code} when listing models.")
        chunks: list[bytes] = []
        total = 0
        async for chunk in response.aiter_bytes():
            total += len(chunk)
            if total > DISCOVERY_MAX_BYTES:
                raise _DiscoveryError(
                    "refused",
                    f"The model list is larger than {DISCOVERY_MAX_BYTES // 1_000_000} MB, so it was not read. Type the model id instead.",
                )
            chunks.append(chunk)
        return b"".join(chunks)


async def discover_chat_models(
    *,
    base_url: str,
    api_key: str | None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> Discovery:
    """List the endpoint's chat models. Never raises; every failure is a state.

    ``transport`` exists for tests: they keep the real client, the real
    streaming read and the real guards, and swap only what is on the wire.
    """
    base = (base_url or "").strip().rstrip("/")
    if not base:
        return Discovery(outcome="refused", detail="No base URL is configured, so there is nothing to list.")
    url = models_url_for_base(base)

    try:
        enforce_airgap_for_url(url)
    except AirgapViolation as exc:
        return Discovery(
            outcome="unverified",
            detail=f"This deployment is air-gapped, so the model list was not requested: {exc}",
        )

    try:
        validate_outbound_url(url, allow_private=True)
    except SSRFError as exc:
        return Discovery(outcome="refused", detail=f"The base URL was refused: {exc}")

    headers = {"Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    try:
        async with asyncio.timeout(DISCOVERY_TIMEOUT_SECONDS):
            async with httpx.AsyncClient(
                timeout=DISCOVERY_TIMEOUT_SECONDS,
                follow_redirects=False,
                transport=transport,
            ) as client:
                raw = await _read_bounded(client, url, headers)
    except _DiscoveryError as exc:
        return Discovery(outcome=exc.outcome, detail=exc.detail)
    except (TimeoutError, httpx.TimeoutException):
        return Discovery(
            outcome="unreachable",
            detail=f"{base} did not return its model list within {DISCOVERY_TIMEOUT_SECONDS:.0f}s.",
        )
    except Exception as exc:  # noqa: BLE001 - every failure is a state
        logger.info("llm_discovery.unreachable", error=type(exc).__name__)
        return Discovery(outcome="unreachable", detail=f"Could not reach {base} ({type(exc).__name__}).")

    try:
        body = json.loads(raw)
    except ValueError:
        return Discovery(outcome="refused", detail="The endpoint's model list was not JSON.")

    rows = body.get("data") if isinstance(body, dict) else body
    if not isinstance(rows, list):
        return Discovery(outcome="refused", detail="The endpoint's answer had no `data` list of models.")

    return filter_chat_models(rows)


__all__ = [
    "DISCOVERY_MAX_BYTES",
    "DISCOVERY_MAX_MODELS",
    "DISCOVERY_MAX_ROWS",
    "DISCOVERY_TIMEOUT_SECONDS",
    "DiscoveredModel",
    "Discovery",
    "discover_chat_models",
    "filter_chat_models",
    "label_verdict",
    "models_url_for_base",
    "row_verdict",
]
