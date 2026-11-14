"""Embedding layer with a real provider and a deterministic fallback.

Production setups should set `AISOC_EMBEDDING_PROVIDER=openai` (or
`sentence-transformers`) so episodic recall actually picks up semantic
similarity. The default `hashbag` provider is a tiny deterministic
hash-bag projection so the platform always boots — even offline — and
unit tests stay reproducible.

The module degrades gracefully:

* If the configured real provider's SDK is missing or the network call
  fails, we fall back to the hash-bag projection and log a warning.
* The vector dimension is sticky for the process: the first successful
  call decides it so SQLite-stored episodic vectors stay comparable.
"""
from __future__ import annotations

import hashlib
import logging
import math
import re
from threading import Lock
from typing import Callable

from app.config import settings

logger = logging.getLogger(__name__)


# ── Hash-bag fallback ─────────────────────────────────────────────────
def _hashbag_embed(text: str, dim: int) -> list[float]:
    """Hash each token into ``dim`` buckets, L2-normalize."""
    vec = [0.0] * dim
    tokens = re.findall(r"[A-Za-z0-9_]+", text.lower())
    for tok in tokens:
        h = int(hashlib.md5(tok.encode()).hexdigest(), 16)
        idx = h % dim
        sign = 1.0 if (h >> 7) & 1 else -1.0
        vec[idx] += sign
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


# ── Provider singletons (lazy, thread-safe) ───────────────────────────
_provider_lock = Lock()
_provider_fn: Callable[[str], list[float]] | None = None
_provider_name: str | None = None
_vector_dim: int | None = None


def _resolve_provider() -> tuple[str, Callable[[str], list[float]]]:
    """Pick the embedding callable based on settings; cache the result.

    Falls back to hash-bag on any setup error so the platform never
    fails to boot for missing optional dependencies.
    """
    global _provider_fn, _provider_name, _vector_dim
    if _provider_fn is not None and _provider_name is not None:
        return _provider_name, _provider_fn
    with _provider_lock:
        if _provider_fn is not None and _provider_name is not None:
            return _provider_name, _provider_fn

        configured = (settings.embedding_provider or "hashbag").lower()
        dim = settings.embedding_dim

        if configured == "openai":
            api_key = settings.openai_api_key
            if not api_key:
                logger.warning(
                    "embedding_provider=openai but AISOC_OPENAI_API_KEY missing; "
                    "falling back to hashbag",
                )
            else:
                try:
                    from openai import OpenAI  # type: ignore

                    client = OpenAI(api_key=api_key)
                    model = settings.embedding_model

                    def _openai_embed(text: str) -> list[float]:
                        resp = client.embeddings.create(model=model, input=text or " ")
                        return list(resp.data[0].embedding)

                    _provider_fn = _openai_embed
                    _provider_name = "openai"
                    _vector_dim = None  # learned on first call
                    return _provider_name, _provider_fn
                except Exception as exc:  # pragma: no cover - depends on env
                    logger.warning(
                        "Failed to initialize OpenAI embeddings (%s); falling back to hashbag",
                        exc,
                    )

        elif configured in {"sentence-transformers", "st", "sbert"}:
            try:
                from sentence_transformers import SentenceTransformer  # type: ignore

                model_name = settings.embedding_st_model
                st_model = SentenceTransformer(model_name)

                def _st_embed(text: str) -> list[float]:
                    arr = st_model.encode(text or " ", normalize_embeddings=True)
                    return list(float(x) for x in arr.tolist())

                _provider_fn = _st_embed
                _provider_name = "sentence-transformers"
                _vector_dim = None
                return _provider_name, _provider_fn
            except Exception as exc:  # pragma: no cover - depends on env
                logger.warning(
                    "Failed to initialize sentence-transformers (%s); falling back to hashbag",
                    exc,
                )

        # Default / fallthrough: hash-bag.
        _provider_fn = lambda text: _hashbag_embed(text, dim)  # noqa: E731
        _provider_name = "hashbag"
        _vector_dim = dim
        return _provider_name, _provider_fn


def embed(text: str) -> list[float]:
    """Return an embedding vector for ``text`` using the configured provider."""
    global _vector_dim
    _, fn = _resolve_provider()
    try:
        vec = fn(text or " ")
    except Exception as exc:  # network blip etc.
        logger.warning("Embedding call failed (%s); using hashbag for this call", exc)
        vec = _hashbag_embed(text or " ", settings.embedding_dim)
    if _vector_dim is None and vec:
        _vector_dim = len(vec)
    return vec


def embedding_provider_name() -> str:
    name, _ = _resolve_provider()
    return name


def embedding_dim() -> int:
    """Best-effort vector dimension; learned on first successful call."""
    if _vector_dim is not None:
        return _vector_dim
    # Trigger lazy init.
    embed("")
    return _vector_dim or settings.embedding_dim


def cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    # Vectors from real providers should already be unit-norm; recompute
    # defensively so we still get a correct similarity if not.
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a)) or 1.0
    nb = math.sqrt(sum(x * x for x in b)) or 1.0
    return dot / (na * nb)


# Back-compat alias: existing modules read DIM as a module-level constant.
DIM = settings.embedding_dim
