"""Natural-language query → multi-dialect execution (Stage 2 #16).

Accepts a plain-English security question, translates it to ES|QL, SPL, and
KQL via the deterministic translator in :mod:`services.agents.app.nl_query`,
optionally enhances the translation with an LLM (when one is configured and
the air-gap policy allows the call), validates every emitted query against
the dialect grammar, and finally executes the ES|QL variant against a
connected Elasticsearch cluster.

The previous implementation emitted ``// TODO: translate → <question>``
fallbacks whenever no LLM was available. Stage 2 #16 removes that pattern
entirely: the deterministic translator always produces a syntactically valid
query, scored against the eval set in
``services/agents/tests/eval_data/nl_query_eval.json`` to guarantee
≥ 85% syntactic validity and ≥ 70% semantic match.

Endpoints
---------
* ``POST /nl-query/translate``      Translate NL → ES|QL / SPL / KQL.
* ``POST /nl-query/execute``        Translate + execute against Elasticsearch.
"""

from __future__ import annotations

import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, status
from pydantic import BaseModel, Field

from app.api.v1.deps import AuthUser
from app.core.airgap import AirgapViolation, enforce_airgap_for_url
from app.core.config import settings

if TYPE_CHECKING:
    # Static-only re-export so type checkers can see the dataclass fields and
    # function signatures of the translator. At runtime we load the module
    # dynamically (see ``_load_nl_query_module`` below) to avoid colliding
    # with the API service's own ``app`` package.
    from services.agents.app.nl_query import (  # noqa: F401
        GrammarError,
        NLQuery,
        TranslatedQuery,
        enhance_with_llm,
    )
    from services.agents.app.nl_query import translate as deterministic_translate  # noqa: F401

# ---------------------------------------------------------------------------
# Bootstrap import path for ``services/agents/app/nl_query``.
#
# The translator is owned by ``services/agents`` so that the eval harness, the
# agents themselves, and the API can all share the same code path. We load it
# via ``importlib`` under a unique module name (``aisoc_agents_nl_query``) so
# it does not collide with the API service's own ``app`` package — both
# services define their own ``app/__init__.py`` regular package and Python's
# importer will not merge them.
# ---------------------------------------------------------------------------


def _candidate_nl_query_dirs() -> list[Path]:
    """Return ordered list of directories that may contain the nl_query module.

    The first entry is the in-tree vendored copy under
    ``services/api/app/_vendor/nl_query/`` — this is what ships inside the
    ``aisoc-api`` Docker image. The second entry is the source-of-truth tree
    at ``services/agents/app/nl_query/``, used during local development when
    the API runs outside of Docker.
    """
    here = Path(__file__).resolve()
    candidates: list[Path] = []

    # 1) Vendored copy — same Python package as this endpoint, so it lives at
    #    ``<api-app-root>/_vendor/nl_query/``. ``parents[3]`` resolves to the
    #    ``app`` directory: endpoints → v1 → api → app.
    try:
        api_app_root = here.parents[3]
        vendored = api_app_root / "_vendor" / "nl_query"
        if vendored.joinpath("__init__.py").is_file():
            candidates.append(vendored)
    except IndexError:  # pragma: no cover - defensive
        pass

    # 2) Source-of-truth tree — walk up the repo until we find it.
    for ancestor in here.parents:
        source = ancestor / "services" / "agents" / "app" / "nl_query"
        if source.joinpath("__init__.py").is_file():
            candidates.append(source)
            break

    return candidates


def _load_nl_query_module():
    """Load the nl_query translator under a collision-free module name.

    Prefers the in-tree vendored copy (so the module is available inside the
    Dockerized ``aisoc-api`` service whose build context excludes
    ``services/agents``) and falls back to the source-of-truth tree at
    ``services/agents/app/nl_query/`` for local non-Docker development.
    """
    import importlib.util

    package_name = "aisoc_agents_nl_query"
    if package_name in sys.modules:
        return sys.modules[package_name]

    candidates = _candidate_nl_query_dirs()
    if not candidates:
        raise ImportError(
            "NL query module not found — expected either "
            "services/api/app/_vendor/nl_query/ (vendored) or "
            "services/agents/app/nl_query/ (source)."
        )

    nl_query_dir = candidates[0]
    init_file = nl_query_dir / "__init__.py"

    spec = importlib.util.spec_from_file_location(
        package_name,
        init_file,
        submodule_search_locations=[str(nl_query_dir)],
    )
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise ImportError(f"Could not build spec for {init_file}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[package_name] = module
    spec.loader.exec_module(module)
    return module


_nl_query = _load_nl_query_module()
if not TYPE_CHECKING:
    GrammarError = _nl_query.GrammarError
    NLQuery = _nl_query.NLQuery
    TranslatedQuery = _nl_query.TranslatedQuery
    enhance_with_llm = _nl_query.enhance_with_llm
    deterministic_translate = _nl_query.translate

router = APIRouter(prefix="/nl-query", tags=["nl_query"])


def _validate_es_url(url: str) -> str:
    """Validate *url* against the configured Elasticsearch/OpenSearch host.

    Raises ValueError if the host or scheme does not match, preventing SSRF.
    Returns a *reconstructed* URL built solely from the validated scheme and
    netloc — this discards any user-supplied path/query components so that
    CodeQL's taint tracking does not flag the returned value as tainted.
    """
    allowed_raw = (
        getattr(settings, "ES_URL", None)
        or getattr(settings, "ELASTICSEARCH_URL", None)
        or getattr(settings, "OPENSEARCH_URL", "http://localhost:9200")
    )
    allowed = urlparse(allowed_raw)
    candidate = urlparse(url)
    if candidate.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported URL scheme: {candidate.scheme!r}")
    if candidate.netloc != allowed.netloc:
        raise ValueError(f"ES URL host {candidate.netloc!r} is not the configured host {allowed.netloc!r}")
    # Reconstruct from validated components only — no user-supplied path/query.
    return f"{candidate.scheme}://{candidate.netloc}"


# ────────────────────────────────────────────────────────────────────────────
# Pydantic schemas
# ────────────────────────────────────────────────────────────────────────────


class NLQueryTranslateRequest(BaseModel):
    question: str = Field(
        ...,
        min_length=10,
        description="Plain-English security question (e.g. 'Show failed logins per user in the last 24 h').",
    )
    index_pattern: str = Field(
        "logs-*,aisoc-events-*",
        description="Elasticsearch index pattern to scope the ES|QL query.",
    )
    time_range_hours: int = Field(
        24,
        ge=1,
        le=8760,
        description="Look-back window in hours.",
    )


class NLQueryTranslateResponse(BaseModel):
    request_id: uuid.UUID
    question: str
    esql: str
    spl: str
    kql: str
    explanation: str
    created_at: datetime
    # Translator metadata — surfaces which engine produced the query so the
    # UI can flag deterministic vs. LLM-assisted answers.
    engine: str = Field("deterministic", description="`deterministic` or `llm`.")
    grammar_validated: bool = Field(True, description="True if every emitted query passed grammar checks.")


class NLQueryExecuteRequest(NLQueryTranslateRequest):
    es_url: str | None = Field(
        None,
        description="Override Elasticsearch URL (defaults to settings.ES_URL if set).",
    )
    es_api_key: str | None = Field(
        None,
        description="Override ES API key (defaults to settings.ES_API_KEY if set).",
    )
    max_rows: int = Field(500, ge=1, le=5000)


class QueryResult(BaseModel):
    columns: list[str]
    rows: list[list[Any]]
    total_rows: int
    took_ms: int | None = None


class NLQueryExecuteResponse(NLQueryTranslateResponse):
    result: QueryResult | None = None
    execution_error: str | None = None


# ────────────────────────────────────────────────────────────────────────────
# Translation orchestration
# ────────────────────────────────────────────────────────────────────────────


async def _translate(
    question: str,
    index_pattern: str,
    time_range_hours: int,
) -> tuple[TranslatedQuery, str]:
    """Translate *question* into ES|QL / SPL / KQL.

    Returns a tuple of ``(TranslatedQuery, engine)`` where ``engine`` is
    either ``"deterministic"`` or ``"llm"``. The deterministic translator is
    always run first so that the response is guaranteed to be grammar-valid;
    if an LLM API key is configured *and* the air-gap policy allows the
    outbound call, we attempt to enhance the result with an LLM-generated
    translation, but fall back to the deterministic output on any error.
    """

    nl = NLQuery(
        question=question,
        index_pattern=index_pattern,
        time_range_hours=time_range_hours,
    )
    deterministic = deterministic_translate(
        question,
        index_pattern=index_pattern,
        time_range_hours=time_range_hours,
    )

    api_key = getattr(settings, "OPENAI_API_KEY", None) or getattr(settings, "LLM_API_KEY", None)
    if not api_key:
        return deterministic, "deterministic"

    completions_url = "https://api.openai.com/v1/chat/completions"
    try:
        enforce_airgap_for_url(completions_url)
    except AirgapViolation:
        return deterministic, "deterministic"

    enhanced = await enhance_with_llm(nl, api_key=api_key, fallback=deterministic)
    engine = "llm" if enhanced is not deterministic else "deterministic"
    return enhanced, engine


# ────────────────────────────────────────────────────────────────────────────
# Elasticsearch execution helper
# ────────────────────────────────────────────────────────────────────────────


async def _execute_esql(esql: str, es_url: str, es_api_key: str, max_rows: int) -> QueryResult:
    """Run an ES|QL query against Elasticsearch and return structured results."""
    # Validate URL against configured host before making any outbound request.
    try:
        safe_url = _validate_es_url(es_url)
    except ValueError as exc:
        raise httpx.RequestError(str(exc)) from exc

    es_query_url = f"{safe_url.rstrip('/')}/_query"
    enforce_airgap_for_url(es_query_url)

    # Ensure LIMIT clause
    query = esql if "| LIMIT" in esql.upper() else f"{esql}\n| LIMIT {max_rows}"
    import time

    t0 = time.monotonic()
    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.post(
            es_query_url,
            headers={
                "Authorization": f"ApiKey {es_api_key}",
                "Content-Type": "application/json",
            },
            json={"query": query},
        )
        resp.raise_for_status()
        data = resp.json()

    took_ms = int((time.monotonic() - t0) * 1000)
    columns = [col["name"] for col in data.get("columns", [])]
    rows = data.get("values", [])
    return QueryResult(columns=columns, rows=rows, total_rows=len(rows), took_ms=took_ms)


# ────────────────────────────────────────────────────────────────────────────
# Endpoints
# ────────────────────────────────────────────────────────────────────────────


@router.post(
    "/translate",
    response_model=NLQueryTranslateResponse,
    status_code=status.HTTP_200_OK,
    summary="Translate a natural-language security question to ES|QL / SPL / KQL",
)
async def translate_query(
    body: NLQueryTranslateRequest,
    user: AuthUser,
) -> NLQueryTranslateResponse:
    translated, engine = await _translate(body.question, body.index_pattern, body.time_range_hours)
    return NLQueryTranslateResponse(
        request_id=uuid.uuid4(),
        question=body.question,
        esql=translated.esql,
        spl=translated.spl,
        kql=translated.kql,
        explanation=translated.explanation,
        created_at=datetime.now(UTC),
        engine=engine,
        grammar_validated=True,
    )


@router.post(
    "/execute",
    response_model=NLQueryExecuteResponse,
    status_code=status.HTTP_200_OK,
    summary="Translate NL question and execute ES|QL against Elasticsearch",
)
async def execute_query(
    body: NLQueryExecuteRequest,
    user: AuthUser,
) -> NLQueryExecuteResponse:
    translated, engine = await _translate(body.question, body.index_pattern, body.time_range_hours)

    # Always read the ES URL from server-side settings — never from user-supplied
    # body fields — to prevent partial-SSRF attacks (CodeQL py/partial-ssrf).
    es_url = getattr(settings, "ES_URL", None) or getattr(settings, "ELASTICSEARCH_URL", None)
    es_api_key = body.es_api_key or getattr(settings, "ES_API_KEY", None)

    base = NLQueryExecuteResponse(
        request_id=uuid.uuid4(),
        question=body.question,
        esql=translated.esql,
        spl=translated.spl,
        kql=translated.kql,
        explanation=translated.explanation,
        created_at=datetime.now(UTC),
        engine=engine,
        grammar_validated=True,
    )

    if not es_url or not es_api_key:
        base.execution_error = "ES_URL or ES_API_KEY not configured. Set them in environment variables or pass in the request body."
        return base

    try:
        base.result = await _execute_esql(
            translated.esql,
            es_url=es_url,
            es_api_key=es_api_key,
            max_rows=body.max_rows,
        )
    except AirgapViolation as exc:
        base.execution_error = (
            f"Air-gapped policy refused outbound request: {exc}. "
            "Add the Elasticsearch host to AISOC_AIRGAP_ALLOWLIST or point ES_URL at a private endpoint."
        )
    except GrammarError as exc:
        # Should never happen — every translator output is validated — but if a
        # caller somehow passes through a hand-edited query we want a clean error.
        base.execution_error = f"Refusing to execute malformed ES|QL: {exc}"
    except httpx.HTTPStatusError as exc:
        base.execution_error = f"ES query failed ({exc.response.status_code}): {exc.response.text[:500]}"
    except Exception as exc:
        base.execution_error = str(exc)

    return base
