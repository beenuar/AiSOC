"""OrcaRouter Cyber Inference — origins, PKCE connect, and model discovery.

One module owns everything that is specific to OrcaRouter, so the credential
write path, the connect flow, the probe and the settings UI all agree about
which origin answers which question:

* authentication and code exchange live on ``https://www.orcarouter.ai`` —
  the authorize screen at ``/auth`` and the exchange at
  ``/api/v1/auth/keys``;
* inference and model discovery live on ``https://api.orcarouter.ai/v1``.

They are different origins on purpose and neither is derived from the other by
swapping a hostname or appending ``/v1``. ``https://api.orcarouter.ai/v1/auth/keys``
is a 404 and is the most common way an integration of this kind is written
wrong. A self-hosted deployment may put both on one origin; that is what the
shared ``ORCA_BASE_URL`` fallback is for, and it is opt-in rather than
inferred.

The key handed back by the connect flow is a normal OrcaRouter API key
(``sk-orca-…``). It is durable and it is **not** a refresh token: there is no
refresh grant, so a revoked key means re-authentication, never a silent
rotation. Every error raised here is safe to show a user and carries no
credential material.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import urlencode, urlparse

import httpx

#: The two provider ids. They share one inference adapter, one base URL and one
#: catalog; they differ only in how the key arrives. Keeping them separate
#: means the settings UI can say which one is configured, and a logout /
#: re-authentication never has to guess which path minted the stored key.
API_KEY_PROVIDER = "orcarouter"
OAUTH_PROVIDER = "orcarouter-oauth"
ORCAROUTER_PROVIDERS: tuple[str, str] = (API_KEY_PROVIDER, OAUTH_PROVIDER)

#: The public defaults. Authentication on ``www``, inference on ``api``.
DEFAULT_AUTH_BASE = "https://www.orcarouter.ai"
DEFAULT_API_BASE = "https://api.orcarouter.ai/v1"

#: Fixed and never configurable: the consent screen and the exchange endpoint.
AUTHORIZE_PATH = "/auth"
EXCHANGE_PATH = "/api/v1/auth/keys"

#: The default model. Carries the vendor namespace because OrcaRouter model ids
#: do, and it is the one entry that works for every key without a workspace
#: grant.
DEFAULT_MODEL = "orcarouter/auto"

#: What the selector offers above the live catalog, in the order this
#: integration recommends it: the default router first, then the two dedicated
#: cyber models, then the general-purpose fallback. These are provider-published
#: routing ids rather than discovery results, so they are returned in their own
#: field and never merged into ``Catalog.models`` — an entry here must not be
#: readable as "this account can run it".
RECOMMENDED_MODELS: tuple[dict[str, Any], ...] = (
    {
        "id": "orcarouter/auto",
        "name": "OrcaRouter Auto (default routing)",
        "context_length": None,
        "input_modalities": [],
        "supported_endpoint_types": ["openai", "anthropic", "gemini"],
        "reasoning_efforts": [],
    },
    {
        "id": "orcacyber-ultra-1.0",
        "name": "OrcaCyber Ultra",
        "context_length": None,
        "input_modalities": ["text"],
        "supported_endpoint_types": ["openai"],
        "reasoning_efforts": [],
    },
    {
        "id": "orcacyber-zero-1.5",
        "name": "OrcaCyber Zero",
        "context_length": None,
        "input_modalities": ["text"],
        "supported_endpoint_types": ["openai"],
        "reasoning_efforts": [],
    },
    {
        "id": "orcarouter/fusion",
        "name": "OrcaRouter Fusion (general fallback)",
        "context_length": None,
        "input_modalities": ["text"],
        "supported_endpoint_types": ["openai"],
        "reasoning_efforts": [],
    },
)


def recommended_models() -> list[dict[str, Any]]:
    """Copies, so a caller cannot mutate the module constant."""
    return [dict(entry) for entry in RECOMMENDED_MODELS]


#: Bounds on catalog discovery. A catalog response must not be able to decide
#: how much memory this process spends, and a settings panel must not wait on
#: a provider that has stopped answering.
CATALOG_TIMEOUT_SECONDS = 10.0
CATALOG_MAX_BYTES = 2_000_000
CATALOG_MAX_ITEMS = 500

#: Endpoint types that can carry a text chat completion. A model advertising
#: only one of the non-text routes below is not a dropdown entry for a chat
#: surface, and capability is read from metadata rather than guessed from a
#: model name.
TEXT_ENDPOINT_TYPES = frozenset({"openai", "openai-response", "anthropic", "gemini"})
NON_TEXT_ENDPOINT_TYPES = frozenset({"image-generation", "openai-video", "jina-rerank", "embeddings", "rerank", "audio"})

#: Keyed by capability. Today AiSOC's LLM surfaces are text chat only (triage,
#: investigation, reports, copilot, NL→query, hunt, detection tuning and the
#: explain path), so ``chat`` is the only one any caller asks for.
_CAPABILITY_QUERY = {"chat": "chat", "embedding": "embedding", "image": "image"}


class OrcaRouterError(RuntimeError):
    """A failure that is safe to show a user.

    ``code`` is a stable machine-readable string; ``message`` never contains a
    key, an auth code or a verifier. Callers map ``code`` to a status code and
    an actionable sentence rather than re-deriving intent from prose.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


# --------------------------------------------------------------- origins


def _is_loopback(host: str | None) -> bool:
    return (host or "").lower() in {"127.0.0.1", "localhost", "::1"}


def _validated_origin(raw: str, *, setting: str) -> str:
    """Return ``raw`` if it is an origin this module is willing to dial.

    HTTPS everywhere; HTTP only for loopback development. No userinfo, no
    fragment — a credential must never be able to ride in a URL this code
    composes.
    """
    value = (raw or "").strip().rstrip("/")
    if not value:
        raise OrcaRouterError("config", f"{setting} is empty.")
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"}:
        raise OrcaRouterError("config", f"{setting} must be an http(s) URL.")
    if parsed.username or parsed.password:
        raise OrcaRouterError("config", f"{setting} must not carry userinfo.")
    if parsed.fragment:
        raise OrcaRouterError("config", f"{setting} must not carry a fragment.")
    if parsed.scheme == "http" and not _is_loopback(parsed.hostname):
        raise OrcaRouterError("config", f"{setting} must use https unless it points at loopback.")
    if not parsed.hostname:
        raise OrcaRouterError("config", f"{setting} must include a hostname.")
    return value


def auth_base() -> str:
    """Origin that serves the consent screen and the code exchange.

    Precedence: explicit ``ORCAROUTER_AUTH_BASE_URL``, then the shared
    self-hosted ``ORCA_BASE_URL``, then the public default. The inference
    origin is never consulted for this answer.
    """
    explicit = os.environ.get("ORCAROUTER_AUTH_BASE_URL", "").strip()
    if explicit:
        return _validated_origin(explicit, setting="ORCAROUTER_AUTH_BASE_URL")
    shared = os.environ.get("ORCA_BASE_URL", "").strip()
    if shared:
        return _validated_origin(shared, setting="ORCA_BASE_URL")
    return DEFAULT_AUTH_BASE


def _with_version(base: str) -> str:
    """Append ``/v1`` to a shared origin unless it already names a version.

    Only the shared ``ORCA_BASE_URL`` case needs this. It is not used to derive
    the auth origin, and no other origin is ever produced by string surgery.
    """
    parsed = urlparse(base)
    last = (parsed.path or "").rstrip("/").rsplit("/", 1)[-1]
    if last.startswith("v") and last[1:].isdigit():
        return base
    return base.rstrip("/") + "/v1"


def api_base() -> str:
    """Origin + version prefix for inference and model discovery."""
    explicit = os.environ.get("ORCAROUTER_API_BASE_URL", "").strip()
    if explicit:
        return _validated_origin(explicit, setting="ORCAROUTER_API_BASE_URL")
    shared = os.environ.get("ORCA_BASE_URL", "").strip()
    if shared:
        return _with_version(_validated_origin(shared, setting="ORCA_BASE_URL"))
    return DEFAULT_API_BASE


def exchange_url() -> str:
    """Full URL of the code exchange. Always on the auth origin."""
    return auth_base() + EXCHANGE_PATH


# --------------------------------------------------------------- PKCE


@dataclass(frozen=True)
class PkceAttempt:
    """One authorization attempt. The verifier never leaves the process."""

    verifier: str
    challenge: str
    state: str


def new_pkce_attempt() -> PkceAttempt:
    """Fresh verifier, S256 challenge and state from a cryptographic RNG.

    Called once per attempt — never reused, never derived from a timestamp, a
    user id or a fixed salt.
    """
    verifier = secrets.token_urlsafe(48)[:96]
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return PkceAttempt(verifier=verifier, challenge=challenge, state=secrets.token_urlsafe(32))


def build_authorize_url(challenge: str, state: str, *, app_name: str = "AiSOC") -> str:
    """Compose the out-of-band consent URL.

    ``callback_url=oob`` is spelled out rather than omitted so the mode is
    asked for. ``S256`` is mandatory for a code a person can read off a screen,
    and the consent screen lets a user choose that delivery even when a
    callback was supplied, so it is always sent.
    """
    query = urlencode(
        {
            "callback_url": "oob",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
            "app_name": app_name,
            "scope": "api",
        }
    )
    return f"{auth_base()}{AUTHORIZE_PATH}?{query}"


def states_match(expected: str, supplied: str) -> bool:
    """Constant-time state comparison."""
    return hmac.compare_digest((expected or "").encode("utf-8"), (supplied or "").encode("utf-8"))


@dataclass(frozen=True)
class ExchangeResult:
    key: str = field(repr=False)
    scope: str
    user_id: str | None = None


def _raise_for_exchange_status(status_code: int) -> None:
    if status_code == 400:
        raise OrcaRouterError(
            "protocol",
            "OrcaRouter refused the exchange: the challenge method did not match the one sent at authorize time.",
        )
    if status_code == 403:
        raise OrcaRouterError(
            "denied",
            "OrcaRouter refused the code: it is unknown, expired, already used, or the verifier did not match. Start the connection again.",
        )
    if status_code == 429:
        raise OrcaRouterError(
            "rate_limit",
            "OrcaRouter is rate-limiting authorizations for this account (10 keys per 24 hours). "
            "Reuse the stored key or try again tomorrow.",
        )
    if status_code >= 500:
        raise OrcaRouterError("network", f"OrcaRouter answered HTTP {status_code} during the exchange. Try again shortly.")
    raise OrcaRouterError("protocol", f"OrcaRouter answered HTTP {status_code} during the exchange.")


async def exchange_code(code: str, verifier: str, *, client: httpx.AsyncClient | None = None) -> ExchangeResult:
    """Redeem an out-of-band code for a durable OrcaRouter API key.

    The request goes to the auth origin at ``/api/v1/auth/keys`` with the
    verifier in the body. Neither the code nor the verifier is logged, put in a
    URL, or included in an error message.
    """
    payload = {"code": code, "code_verifier": verifier, "code_challenge_method": "S256"}
    owns_client = client is None
    client = client or httpx.AsyncClient(timeout=30.0)
    try:
        response = await client.post(exchange_url(), json=payload)
    except httpx.TimeoutException as exc:
        raise OrcaRouterError("timeout", "The OrcaRouter exchange timed out. No key was issued; start again.") from exc
    except httpx.HTTPError as exc:
        raise OrcaRouterError("network", f"Could not reach OrcaRouter to exchange the code ({type(exc).__name__}).") from exc
    finally:
        if owns_client:
            await client.aclose()

    if response.status_code != 200:
        _raise_for_exchange_status(response.status_code)

    try:
        body = response.json()
    except ValueError as exc:
        raise OrcaRouterError("protocol", "OrcaRouter returned a response that was not JSON.") from exc

    key = body.get("key") if isinstance(body, dict) else None
    if not isinstance(key, str) or not key.startswith("sk-orca-"):
        # Never echo the body: a malformed response is not an invitation to
        # copy whatever it contained into a log or an error.
        raise OrcaRouterError("protocol", "OrcaRouter's exchange response did not contain an API key.")

    granted = str(body.get("scope") or "").strip()
    if granted != "api":
        # What was granted, not what was asked for: a workspace role can
        # approve less than the request named.
        raise OrcaRouterError(
            "scope",
            f'The workspace granted scope "{granted or "unknown"}", which cannot call the inference API. '
            "Ask a workspace admin for access, or use an API key instead.",
        )
    return ExchangeResult(key=key, scope=granted, user_id=_optional_str(body.get("user_id")))


def _optional_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


# --------------------------------------------------------------- catalog


#: Verified cold-start seed. Used only when live discovery fails, and replaced
#: wholesale by live discovery when it succeeds. Metadata is the value the
#: provider advertised when this list was last checked against
#: ``https://api.orcarouter.ai/v1/models`` (2026-10-23); ``orcarouter/auto`` is
#: the provider's documented default alias rather than a catalog row, so it
#: declares no context window and no non-text modality.
VERIFIED_CHAT_SEED: tuple[dict[str, Any], ...] = (
    {
        "id": "openai/gpt-5.5",
        "name": "OpenAI GPT-5.5",
        "context_length": None,
        "input_modalities": ["file", "image", "text"],
        "supported_endpoint_types": ["openai", "openai-response"],
        "reasoning_efforts": ["low", "medium", "high", "xhigh"],
    },
    {
        "id": "anthropic/claude-opus-4.8",
        "name": "Anthropic Claude Opus 4.8",
        "context_length": 1000000,
        "input_modalities": ["text", "image", "file"],
        "supported_endpoint_types": ["openai", "anthropic", "openai-response"],
        "reasoning_efforts": [],
    },
    {
        "id": "google/gemini-3.5-flash",
        "name": "Google Gemini 3.5 Flash",
        "context_length": 1048576,
        "input_modalities": ["text", "image", "video", "file", "audio"],
        "supported_endpoint_types": ["openai", "gemini"],
        "reasoning_efforts": [],
    },
    {
        "id": "deepseek/deepseek-v4-pro",
        "name": "DeepSeek V4 Pro",
        "context_length": 1048576,
        "input_modalities": ["text"],
        "supported_endpoint_types": ["openai", "openai-response"],
        "reasoning_efforts": [],
    },
    {
        "id": "orcarouter/auto",
        "name": "OrcaRouter Auto",
        "context_length": None,
        "input_modalities": [],
        "supported_endpoint_types": ["openai", "openai-response", "anthropic", "gemini"],
        "reasoning_efforts": [],
    },
)


@dataclass(frozen=True)
class ModelEntry:
    """The minimum a selector needs. No key, no pricing, no owner blob."""

    id: str
    name: str
    context_length: int | None = None
    input_modalities: list[str] = field(default_factory=list)
    supported_endpoint_types: list[str] = field(default_factory=list)
    reasoning_efforts: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "context_length": self.context_length,
            "input_modalities": list(self.input_modalities),
            "supported_endpoint_types": list(self.supported_endpoint_types),
            "reasoning_efforts": list(self.reasoning_efforts),
        }


@dataclass(frozen=True)
class Catalog:
    """Outcome of a discovery attempt.

    ``source`` is ``live`` or ``fallback`` and is never mixed: when live
    discovery succeeds its answer is authoritative, and when it fails the
    verified seed stands in with ``degraded`` set and a human-readable reason.
    """

    models: list[ModelEntry]
    source: Literal["live", "fallback"]
    degraded: bool = False
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "object": "list",
            "data": [m.as_dict() for m in self.models],
            "source": self.source,
            "degraded": self.degraded,
            "detail": self.detail,
        }


def _str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value[:32] if isinstance(item, str) and item]


def _int_or_none(value: Any) -> int | None:
    return value if isinstance(value, int) and value > 0 else None


def parse_model(item: Any) -> ModelEntry | None:
    """Accept one catalog row, or ``None`` when its shape is not usable.

    Fails closed on anything the selector cannot speak: an unknown row is
    dropped rather than guessed at.
    """
    if not isinstance(item, dict):
        return None
    model_id = item.get("id")
    if not isinstance(model_id, str) or not model_id.strip():
        return None
    architecture = item.get("architecture") if isinstance(item.get("architecture"), dict) else {}
    raw_efforts = item.get("reasoning_efforts")
    if raw_efforts is None and isinstance(item.get("supported_parameters"), list):
        raw_efforts = [p for p in item["supported_parameters"] if isinstance(p, str) and p in {"low", "medium", "high", "xhigh"}]
    return ModelEntry(
        id=model_id.strip(),
        name=str(item.get("name") or model_id.strip()),
        context_length=_int_or_none(item.get("context_length")),
        input_modalities=_str_list(architecture.get("input_modalities")),
        supported_endpoint_types=_str_list(item.get("supported_endpoint_types")),
        reasoning_efforts=_str_list(raw_efforts),
    )


def is_chat_capable(model: ModelEntry) -> bool:
    """Whether a catalog row can serve a text chat completion.

    Requires an endpoint type that speaks chat, and refuses a row whose only
    routes are non-text (image, video, rerank) or whose declared input
    modalities exclude text. Un-declared metadata is left to the endpoint-type
    test — an absent field is not evidence of a non-text model, while a
    declared exclusion is.
    """
    types = set(model.supported_endpoint_types)
    if not types & TEXT_ENDPOINT_TYPES:
        return False
    if types and types <= NON_TEXT_ENDPOINT_TYPES:
        return False
    if model.input_modalities and "text" not in model.input_modalities:
        return False
    return True


def filter_chat(models: list[ModelEntry]) -> list[ModelEntry]:
    """Chat-capable rows, de-duplicated by id, bounded and ordered."""
    seen: set[str] = set()
    out: list[ModelEntry] = []
    for model in models:
        if model.id in seen or not is_chat_capable(model):
            continue
        seen.add(model.id)
        out.append(model)
        if len(out) >= CATALOG_MAX_ITEMS:
            break
    return sorted(out, key=lambda m: m.id)


def seed_catalog(detail: str) -> Catalog:
    return Catalog(
        models=filter_chat([m for m in (parse_model(dict(item)) for item in VERIFIED_CHAT_SEED) if m]),
        source="fallback",
        degraded=True,
        detail=detail,
    )


async def _get_bounded(client: httpx.AsyncClient, url: str, api_key: str) -> bytes:
    """GET with a byte ceiling, so a catalog cannot decide our memory use."""
    async with client.stream("GET", url, headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"}) as response:
        if response.status_code != 200:
            _raise_for_catalog_status(response.status_code)
        chunks: list[bytes] = []
        total = 0
        async for chunk in response.aiter_bytes():
            total += len(chunk)
            if total > CATALOG_MAX_BYTES:
                raise OrcaRouterError("protocol", "The OrcaRouter model catalog exceeded the size this client accepts.")
            chunks.append(chunk)
        return b"".join(chunks)


def _raise_for_catalog_status(status_code: int) -> None:
    if status_code in (401, 403):
        raise OrcaRouterError(
            "auth",
            f"OrcaRouter rejected the stored key (HTTP {status_code}). Re-enter the key or sign in again.",
        )
    if status_code == 429:
        raise OrcaRouterError("rate_limit", "OrcaRouter rate-limited model discovery. The last known list is shown.")
    raise OrcaRouterError("protocol", f"OrcaRouter answered HTTP {status_code} for model discovery.")


async def fetch_catalog(
    api_key: str,
    *,
    capability: str = "chat",
    base_url: str | None = None,
    client: httpx.AsyncClient | None = None,
) -> Catalog:
    """Discover models from the configured inference origin.

    On any failure the verified seed is returned with ``degraded`` set, so a
    fresh install can still open a selector during an outage. The seed is never
    merged into a successful live answer.
    """
    if not api_key:
        return seed_catalog("No OrcaRouter API key is stored for this tenant.")

    query = _CAPABILITY_QUERY.get(capability, capability)
    url = f"{(base_url or api_base()).rstrip('/')}/models?capability={query}"

    owns_client = client is None
    client = client or httpx.AsyncClient(timeout=CATALOG_TIMEOUT_SECONDS)
    try:
        raw = await _get_bounded(client, url, api_key)
    except OrcaRouterError as exc:
        return seed_catalog(exc.message)
    except httpx.TimeoutException:
        return seed_catalog(f"Model discovery timed out after {CATALOG_TIMEOUT_SECONDS:.0f}s.")
    except httpx.HTTPError as exc:
        return seed_catalog(f"Could not reach OrcaRouter for model discovery ({type(exc).__name__}).")
    finally:
        if owns_client:
            await client.aclose()

    try:
        body = json.loads(raw)
    except ValueError:
        return seed_catalog("The OrcaRouter model catalog was not JSON.")

    rows = body.get("data") if isinstance(body, dict) else None
    if not isinstance(rows, list):
        return seed_catalog("The OrcaRouter model catalog had no `data` list.")

    parsed = [m for m in (parse_model(row) for row in rows[:CATALOG_MAX_ITEMS]) if m]
    models = filter_chat(parsed) if capability == "chat" else parsed
    if not models:
        return seed_catalog("The OrcaRouter model catalog advertised no compatible chat model.")
    return Catalog(models=models, source="live")


def needs_reauth(settings: dict[str, Any] | None) -> bool:
    """Whether the stored OrcaRouter credential is known to be revoked."""
    return bool((settings or {}).get("needs_reauth"))


__all__ = [
    "API_KEY_PROVIDER",
    "DEFAULT_API_BASE",
    "DEFAULT_AUTH_BASE",
    "DEFAULT_MODEL",
    "ORCAROUTER_PROVIDERS",
    "OAUTH_PROVIDER",
    "Catalog",
    "ExchangeResult",
    "ModelEntry",
    "OrcaRouterError",
    "PkceAttempt",
    "VERIFIED_CHAT_SEED",
    "api_base",
    "auth_base",
    "build_authorize_url",
    "exchange_code",
    "exchange_url",
    "fetch_catalog",
    "filter_chat",
    "is_chat_capable",
    "needs_reauth",
    "new_pkce_attempt",
    "parse_model",
    "seed_catalog",
    "states_match",
]
