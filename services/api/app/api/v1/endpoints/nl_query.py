"""Natural-language query → multi-dialect execution (tier2-nl-query).

Accepts a plain-English security question, translates it to ES|QL, SPL, and
KQL, then (optionally) executes the ES|QL variant against a connected
Elasticsearch cluster and returns structured results ready for charting.

Endpoints
---------
* ``POST /nl-query/translate``      Translate NL → ES|QL / SPL / KQL.
* ``POST /nl-query/execute``        Translate + execute against Elasticsearch.
"""

from __future__ import annotations

import json
import textwrap
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.api.v1.deps import AuthUser
from app.core.config import settings

router = APIRouter(prefix="/nl-query", tags=["nl_query"])

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
# LLM translation helper
# ────────────────────────────────────────────────────────────────────────────

_SYS_PROMPT = textwrap.dedent(
    """
    You are a senior security data engineer. The user will provide:
    - A plain-English security question.
    - The Elasticsearch index pattern and time range.

    Translate the question into three query dialects and return JSON only:
    {
      "esql": "...",         // Elasticsearch ES|QL query
      "spl":  "...",         // Splunk SPL query
      "kql":  "...",         // Microsoft Sentinel KQL query
      "explanation": "..."   // 1–2 sentences describing what the query does
    }

    Guidelines:
    - Use `FROM <index_pattern>` and `| WHERE @timestamp > NOW() - <hours>h` for ES|QL.
    - Prefer `STATS ... BY ...` for aggregations in ES|QL.
    - Map common field names: user → user.name, src_ip → source.ip, dest_ip → destination.ip.
    - Keep queries concise; add a `| LIMIT 500` to ES|QL.
    """
).strip()


async def _translate(
    question: str, index_pattern: str, time_range_hours: int
) -> dict[str, str]:
    api_key = getattr(settings, "OPENAI_API_KEY", None) or getattr(
        settings, "LLM_API_KEY", None
    )
    if not api_key:
        return _template_fallback(question, index_pattern, time_range_hours)

    user_msg = json.dumps(
        {
            "question": question,
            "index_pattern": index_pattern,
            "time_range_hours": time_range_hours,
        }
    )
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": "gpt-4o-mini",
                    "response_format": {"type": "json_object"},
                    "messages": [
                        {"role": "system", "content": _SYS_PROMPT},
                        {"role": "user", "content": user_msg},
                    ],
                },
            )
            resp.raise_for_status()
            return json.loads(resp.json()["choices"][0]["message"]["content"])
    except Exception:
        return _template_fallback(question, index_pattern, time_range_hours)


def _template_fallback(
    question: str, index_pattern: str, time_range_hours: int
) -> dict[str, str]:
    return {
        "esql": (
            f"FROM {index_pattern}\n"
            f"| WHERE @timestamp > NOW() - {time_range_hours}h\n"
            f"// TODO: translate → {question}\n"
            "| LIMIT 500"
        ),
        "spl": (
            f"index=* earliest=-{time_range_hours}h\n"
            f"// TODO: translate → {question}"
        ),
        "kql": (
            f"// TODO: translate → {question}\n"
            f"| where TimeGenerated > ago({time_range_hours}h)"
        ),
        "explanation": f"Template placeholder for: {question}",
    }


# ────────────────────────────────────────────────────────────────────────────
# Elasticsearch execution helper
# ────────────────────────────────────────────────────────────────────────────


async def _execute_esql(
    esql: str, es_url: str, es_api_key: str, max_rows: int
) -> QueryResult:
    """Run an ES|QL query against Elasticsearch and return structured results."""
    # Ensure LIMIT clause
    query = esql if "| LIMIT" in esql.upper() else f"{esql}\n| LIMIT {max_rows}"
    import time

    t0 = time.monotonic()
    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.post(
            f"{es_url.rstrip('/')}/_query",
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
    translated = await _translate(
        body.question, body.index_pattern, body.time_range_hours
    )
    return NLQueryTranslateResponse(
        request_id=uuid.uuid4(),
        question=body.question,
        esql=translated.get("esql", ""),
        spl=translated.get("spl", ""),
        kql=translated.get("kql", ""),
        explanation=translated.get("explanation", ""),
        created_at=datetime.now(UTC),
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
    translated = await _translate(
        body.question, body.index_pattern, body.time_range_hours
    )

    es_url = (
        body.es_url
        or getattr(settings, "ES_URL", None)
        or getattr(settings, "ELASTICSEARCH_URL", None)
    )
    es_api_key = body.es_api_key or getattr(settings, "ES_API_KEY", None)

    base = NLQueryExecuteResponse(
        request_id=uuid.uuid4(),
        question=body.question,
        esql=translated.get("esql", ""),
        spl=translated.get("spl", ""),
        kql=translated.get("kql", ""),
        explanation=translated.get("explanation", ""),
        created_at=datetime.now(UTC),
    )

    if not es_url or not es_api_key:
        base.execution_error = (
            "ES_URL or ES_API_KEY not configured. "
            "Set them in environment variables or pass in the request body."
        )
        return base

    try:
        base.result = await _execute_esql(
            translated.get("esql", ""),
            es_url=es_url,
            es_api_key=es_api_key,
            max_rows=body.max_rows,
        )
    except httpx.HTTPStatusError as exc:
        base.execution_error = f"ES query failed ({exc.response.status_code}): {exc.response.text[:500]}"
    except Exception as exc:
        base.execution_error = str(exc)

    return base
