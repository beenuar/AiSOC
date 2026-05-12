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
from typing import Any
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, status
from pydantic import BaseModel, Field

from app.api.v1.deps import AuthUser
from app.core.airgap import AirgapViolation, enforce_airgap_for_url
from app.core.config import settings

# ---------------------------------------------------------------------------
# Bootstrap import path for ``services/agents/app/nl_query``.
#
# The translator is owned by ``services/agents`` so that the eval harness, the
# agents themselves, and the API can all share the same code path. Mirroring
# the pattern in detection_proposals.py we add the agents service to
# ``sys.path`` lazily — this keeps services decoupled at deploy time while
# letting both the API process and the eval CLI import the same module.
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[5]
_AGENTS_PATH = str(_REPO_ROOT / "services" / "agents")
if _AGENTS_PATH not in sys.path:
    sys.path.insert(0, _AGENTS_PATH)

from app.nl_query import (  # noqa: E402  -- requires the sys.path tweak above
    GrammarError,
    NLQuery,
    TranslatedQuery,
    enhance_with_llm,
)
from app.nl_query import (  # noqa: E402  -- requires the sys.path tweak above
    translate as deterministic_translate,
)

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
