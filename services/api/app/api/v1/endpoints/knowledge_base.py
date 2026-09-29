"""Knowledge-base + RAG over org docs/runbooks (tier3-rag).

Analysts ingest organisation documents (runbooks, policies, playbooks, SOPs)
into a full-text-searchable store.  A ``/query`` endpoint retrieves relevant
chunks and, when an LLM key is configured, synthesises a cited answer.

Endpoints
---------
* ``POST /kb/ingest``       Ingest a document (chunked automatically).
* ``GET  /kb/documents``    List indexed documents.
* ``GET  /kb/documents/{id}`` Get a document.
* ``DELETE /kb/documents/{id}`` Remove a document.
* ``POST /kb/query``        Semantic/keyword search + optional LLM synthesis.
* ``GET  /kb/runbooks/for-triage`` Internal: retrieval for the agents service,
  with a point-in-time cutoff. Gap-closure Phase 6.3.

Authorization
-------------
``POST /ingest`` and ``DELETE /documents/{id}`` require ``settings:write``.
The knowledge base is the tenant's operational content of record — runbooks,
policies, SOPs — and the delete is wider than its path suggests: it removes
*every chunk sharing the document's title*, tenant-wide, so one request from a
``viewer`` erased a runbook for everybody. It is also what the agents service
retrieves during triage, so a document planted here is a document the model
is told to follow.

``POST /query`` is deliberately **left ungated** and counted in
``scripts/check_route_authz.py``'s ledger. Searching the runbook library is
something every role should be able to do, and the vocabulary has no
knowledge-base permission: every candidate is either held by every role
including machine keys (``cases:read``, ``reports:read``) or restricted to
tenant administrators (``settings:read``), which would take the runbooks away
from the analysts who need them mid-incident. Choosing one on the strength of
its role list rather than what the route does would be reverse-engineering a
permission from the answer. The open questions are whether reading the
library is an entitlement at all and whether LLM synthesis — which spends the
tenant's budget — needs a stronger one than retrieval; both are product
decisions, not gaps to be papered over.
"""

from __future__ import annotations

import logging
import os
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.api.v1.endpoints.alert_writeback import service_token_valid
from app.core.airgap import AirgapViolation, enforce_airgap_for_url
from app.db.rls import set_rls_context
from app.services.kb_chunking import chunk_text
from app.services.llm_safety import LLMContractViolation, safe_chat_completions_request
from app.services.model_aliases import chat_completions_url, resolve_api_key, resolve_model_alias

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/kb", tags=["knowledge_base"])

# ────────────────────────────────────────────────────────────────────────────
# Schemas
# ────────────────────────────────────────────────────────────────────────────

DocKind = Literal["runbook", "policy", "playbook", "sop", "wiki", "other"]


class IngestRequest(BaseModel):
    title: str = Field(..., min_length=2)
    content: str = Field(..., min_length=10)
    doc_kind: DocKind = "runbook"
    source_url: str | None = None
    tags: list[str] = Field(default_factory=list)


class KBDocResponse(BaseModel):
    id: uuid.UUID
    title: str
    doc_kind: str
    source_url: str | None
    tags: list[str]
    chunk_index: int
    chunk_total: int
    content_preview: str
    created_at: datetime
    created_by: str | None


class QueryRequest(BaseModel):
    question: str = Field(..., min_length=3)
    doc_kinds: list[DocKind] = Field(default_factory=list)
    top_k: int = Field(5, ge=1, le=20)
    synthesise: bool = Field(True, description="Use LLM to synthesise an answer from retrieved chunks.")


class KBChunk(BaseModel):
    doc_id: uuid.UUID
    title: str
    chunk_index: int
    content: str
    score: float | None = None


class QueryResponse(BaseModel):
    question: str
    chunks: list[KBChunk]
    answer: str | None  # None when synthesise=False or no LLM key
    sources: list[str]


# ────────────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────────────


def _row_to_doc(row: Any) -> KBDocResponse:
    return KBDocResponse(
        id=row.id,
        title=row.title,
        doc_kind=row.doc_kind,
        source_url=row.source_url,
        tags=list(row.tags or []),
        chunk_index=row.chunk_index,
        chunk_total=row.chunk_total,
        content_preview=row.content[:200],
        created_at=row.created_at,
        created_by=row.created_by,
    )


_SYNTH_SYSTEM = """You are a helpful security operations assistant.
Answer the analyst's question using ONLY the provided context chunks.
Cite document titles inline as [Doc Title].
If the answer cannot be found in the context, say so clearly."""


async def _synthesise(question: str, chunks: list[KBChunk]) -> str | None:
    model = os.getenv("LLM_MODEL") or resolve_model_alias("nl")
    # Resolved together with the route: when the call goes to the bundled
    # gateway the bearer is the gateway's master key, not a provider key.
    api_key = resolve_api_key(model)
    if not api_key:
        return None
    context = "\n\n".join(f"[{c.title}] chunk {c.chunk_index}:\n{c.content}" for c in chunks)
    completions_url = chat_completions_url(model)
    enforce_airgap_for_url(completions_url)
    try:
        # T2.3 — the retrieved KB chunks are the untrusted half here: a
        # document ingested from a vendor advisory can carry a log excerpt.
        body = await safe_chat_completions_request(
            api_key=api_key,
            model=model,
            messages=[
                {"role": "system", "content": _SYNTH_SYSTEM},
                {"role": "user", "content": f"CONTEXT:\n{context}\n\nQUESTION: {question}"},
            ],
            url=completions_url,
            timeout=45.0,
            temperature=0.2,
        )
        return str(body["choices"][0]["message"]["content"]).strip()
    except LLMContractViolation as exc:
        # %-style: stdlib Logger, not structlog. See translation.py.
        logger.warning("knowledge_base.llm_contract_violation reason=%s", exc.reason)
        return None
    except Exception:
        return None


# ────────────────────────────────────────────────────────────────────────────
# Endpoints
# ────────────────────────────────────────────────────────────────────────────


@router.post(
    "/ingest", response_model=list[KBDocResponse], status_code=status.HTTP_201_CREATED, summary="Ingest document into knowledge base"
)
async def ingest(
    body: IngestRequest, db: DBSession, user: Annotated[AuthUser, Depends(require_permission("settings:write"))]
) -> list[KBDocResponse]:
    chunks = chunk_text(body.content)
    now = datetime.now(UTC)
    rows = []
    for idx, chunk_content in enumerate(chunks):
        doc_id = uuid.uuid4()
        q = text("""
            INSERT INTO aisoc_kb_documents (
                id, tenant_id, title, doc_kind, source_url, content, tags,
                chunk_index, chunk_total, created_at, updated_at, created_by
            ) VALUES (
                :id, :tenant_id, :title, :kind, :url, :content, CAST(:tags AS text[]),
                :idx, :total, :now, :now, :user
            ) RETURNING *
        """).bindparams(
            id=doc_id,
            tenant_id=user.tenant_id,
            title=body.title,
            kind=body.doc_kind,
            url=body.source_url,
            content=chunk_content,
            tags=body.tags or [],
            idx=idx,
            total=len(chunks),
            now=now,
            user=user.email if user else "system",
        )
        try:
            row = (await db.execute(q)).fetchone()
            rows.append(row)
        except Exception as exc:
            await db.rollback()
            logger.exception("Database error in knowledge_base endpoint")
            raise HTTPException(status_code=503, detail="Database error") from exc
    await db.commit()
    return [_row_to_doc(r) for r in rows]


@router.get("/documents", response_model=list[KBDocResponse], summary="List KB documents")
async def list_documents(db: DBSession, user: AuthUser) -> list[KBDocResponse]:
    try:
        rows = (
            await db.execute(
                text(
                    "SELECT * FROM aisoc_kb_documents WHERE chunk_index = 0 AND tenant_id = :tenant_id ORDER BY created_at DESC LIMIT 200"
                ).bindparams(tenant_id=user.tenant_id)
            )
        ).fetchall()
        return [_row_to_doc(r) for r in rows]
    except Exception as exc:
        logger.exception("Database error in knowledge_base endpoint")
        raise HTTPException(status_code=503, detail="Database error") from exc


@router.get("/documents/{doc_id}", response_model=KBDocResponse, summary="Get KB document")
async def get_document(doc_id: uuid.UUID, db: DBSession, user: AuthUser) -> KBDocResponse:
    row = (
        await db.execute(
            text("SELECT * FROM aisoc_kb_documents WHERE id = :id AND tenant_id = :tenant_id").bindparams(
                id=doc_id, tenant_id=user.tenant_id
            )
        )
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Document not found.")
    return _row_to_doc(row)


@router.delete("/documents/{doc_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None, summary="Remove KB document")
async def delete_document(
    doc_id: uuid.UUID, db: DBSession, user: Annotated[AuthUser, Depends(require_permission("settings:write"))]
) -> None:
    existing = (
        await db.execute(
            text("SELECT title FROM aisoc_kb_documents WHERE id = :id AND tenant_id = :tenant_id").bindparams(
                id=doc_id, tenant_id=user.tenant_id
            )
        )
    ).fetchone()
    if not existing:
        raise HTTPException(status_code=404, detail="Document not found.")
    # Remove all chunks with same title within this tenant only.
    await db.execute(
        text("DELETE FROM aisoc_kb_documents WHERE title = :title AND tenant_id = :tenant_id").bindparams(
            title=existing.title, tenant_id=user.tenant_id
        )
    )
    await db.commit()


@router.post("/query", response_model=QueryResponse, summary="Search knowledge base + optional LLM synthesis")
async def query_kb(body: QueryRequest, db: DBSession, user: AuthUser) -> QueryResponse:
    wheres = ["to_tsvector('english', content) @@ plainto_tsquery('english', :q)", "tenant_id = :tenant_id"]
    params: dict[str, Any] = {"q": body.question, "tenant_id": user.tenant_id, "limit": body.top_k}
    if body.doc_kinds:
        # `CAST(... AS text[])` rather than `:kinds::text[]`. SQLAlchemy's
        # bound-parameter scanner skips a name followed by a colon, so that
        # the Postgres `::` cast operator is not mistaken for one - which
        # means `:kinds::text[]` declares no parameter at all and
        # `.bindparams(kinds=...)` raises. Every call to this route that named
        # a `doc_kinds` filter therefore came back as a 503 "Database error"
        # before ever reaching the database. Found while adding the retrieval
        # route below, which had copied the same spelling.
        wheres.append("doc_kind = ANY(CAST(:kinds AS text[]))")
        params["kinds"] = body.doc_kinds

    sql = text(f"""
        SELECT *, ts_rank(to_tsvector('english', content), plainto_tsquery('english', :q)) AS rank
        FROM aisoc_kb_documents
        WHERE {" AND ".join(wheres)}
        ORDER BY rank DESC
        LIMIT :limit
    """).bindparams(**params)

    try:
        db_rows = (await db.execute(sql)).fetchall()
    except Exception as exc:
        logger.exception("Database error in knowledge_base endpoint")
        raise HTTPException(status_code=503, detail="Database error") from exc

    chunks = [
        KBChunk(
            doc_id=r.id,
            title=r.title,
            chunk_index=r.chunk_index,
            content=r.content,
            score=float(r.rank) if hasattr(r, "rank") else None,
        )
        for r in db_rows
    ]
    answer: str | None = None
    if body.synthesise and chunks:
        # Air-gapped deployments refuse the LLM call; still return the retrieved
        # chunks with no synthesized answer rather than failing the whole query.
        try:
            answer = await _synthesise(body.question, chunks)
        except AirgapViolation:
            answer = None

    sources = list(dict.fromkeys(c.title for c in chunks))
    return QueryResponse(question=body.question, chunks=chunks, answer=answer, sources=sources)


# ────────────────────────────────────────────────────────────────────────────
# Internal route: retrieval for triage, with a point-in-time cutoff
# ────────────────────────────────────────────────────────────────────────────


class TriageRunbookChunk(BaseModel):
    """One retrieved chunk, carrying everything a citation has to resolve to."""

    doc_id: uuid.UUID
    title: str
    doc_kind: str
    source_url: str | None
    chunk_index: int
    chunk_total: int
    content: str
    created_at: datetime | None
    score: float | None


class TriageRunbooksResponse(BaseModel):
    tenant_id: str
    as_of: datetime | None
    chunks: list[TriageRunbookChunk]
    #: Chunks that matched the query and were refused for post-dating the
    #: cutoff. Zero when no cutoff was asked for. This is what tells a replay
    #: report whether the freeze did anything: without it, "the cutoff worked"
    #: and "nothing would have been returned anyway" print the same number.
    excluded_after_cutoff: int
    #: Matching chunks with no ``created_at`` at all, which the cutoff cannot
    #: test. The column is ``NOT NULL`` with a default, so this should stay
    #: zero; it is published for the same reason ``statements_without_timestamp``
    #: is, because "should be zero" is how the statement gap went unnoticed.
    without_timestamp: int


#: Retrieval is full-text over ``content`` with the rank the console's own
#: ``/kb/query`` uses, so triage and an analyst searching by hand see the same
#: ordering over the same corpus. ``{cutoff}`` is the only thing that varies
#: and it is a fixed literal, not caller data.
_TRIAGE_RETRIEVAL_SQL = """
WITH matches AS (
    SELECT id, title, doc_kind, source_url, chunk_index, chunk_total, content, created_at,
           ts_rank(to_tsvector('english', content), plainto_tsquery('english', :q)) AS rank
    FROM aisoc_kb_documents
    WHERE tenant_id = :tenant_id
      AND doc_kind = ANY(CAST(:kinds AS text[]))
      AND to_tsvector('english', content) @@ plainto_tsquery('english', :q)
),
counted AS (
    SELECT
        count(*) FILTER (WHERE {excluded}) AS excluded_after_cutoff,
        count(*) FILTER (WHERE created_at IS NULL) AS without_timestamp
    FROM matches
)
SELECT c.excluded_after_cutoff, c.without_timestamp,
       m.id, m.title, m.doc_kind, m.source_url, m.chunk_index, m.chunk_total,
       m.content, m.created_at, m.rank
FROM counted c
LEFT JOIN LATERAL (
    SELECT * FROM matches
    {cutoff}
    ORDER BY rank DESC, id
    LIMIT :limit
) m ON TRUE
"""

#: Runbooks, playbooks and SOPs tell an analyst what to do about an alert of
#: this shape. A policy or a wiki page usually does not, and every chunk in
#: the prompt is prompt budget the evidence does not get.
_TRIAGE_DOC_KINDS: tuple[str, ...] = ("runbook", "playbook", "sop")


def triage_retrieval_sql(*, cutoff: bool) -> str:
    """The statement the route runs, with or without the point-in-time predicate.

    A function rather than two constants because the live test in
    ``tests/isolation/`` has to run *this* statement. Its first version
    formatted the template with its own idea of what the cutoff clause was,
    and it therefore kept passing after the clause was deleted from the route:
    a test comparing a producer against a copy of itself. One function, two
    callers, and deleting the predicate below breaks both.
    """
    if not cutoff:
        return _TRIAGE_RETRIEVAL_SQL.format(excluded="FALSE", cutoff="")
    return _TRIAGE_RETRIEVAL_SQL.format(excluded="created_at > :as_of", cutoff="WHERE created_at <= :as_of")


@router.get(
    "/runbooks/for-triage",
    response_model=TriageRunbooksResponse,
    include_in_schema=False,
    summary="Runbook chunks for the agents service, as of a point in time",
)
async def retrieve_runbooks_for_triage(
    db: DBSession,
    tenant_id: uuid.UUID,
    q: Annotated[str, Query(min_length=1, max_length=1024)],
    as_of: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=10)] = 3,
    x_aisoc_service_token: Annotated[str | None, Header()] = None,
) -> TriageRunbooksResponse:
    """Retrieve the tenant's runbooks for one alert, optionally as of an instant.

    Gap-closure Phase 6.3. The agents service has never read the knowledge
    base; this is the route that lets it, and ``as_of`` is what keeps a replay
    honest when it does.

    Why a cutoff rather than a captured snapshot. The other three context
    stores are small enough that a replay freezes them by capturing the whole
    set once. This one is a per-alert query against a corpus that can hold
    every document a SOC has ever written, so there is nothing sensible to
    capture up front. The freeze is therefore a *parameter*: the frozen reader
    supplies the split instant and the predicate lands in the SQL above, which
    is also why the counts come back beside the rows. A cutoff that silently
    matched nothing and a cutoff that refused fifty documents are the same
    empty list from outside.

    ``as_of`` is deliberately not defaulted. A default of "now" would make an
    unfrozen caller look frozen, and a default of the epoch would make every
    live triage return nothing.

    The token is checked in band rather than through a bearer dependency, the
    same shape ``/tenant-skills/resolved/active`` and ``/mcp-servers/resolved``
    use, because the caller is a service with no session. ``tenant_id`` is the
    scope rather than a narrowing of one, for the same reason: a service token
    carries no tenant, so there is nothing to intersect it with.
    """
    if not service_token_valid(x_aisoc_service_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="this route is reachable only by an AiSOC service holding the shared service token",
        )

    await set_rls_context(db, tenant_id)

    params: dict[str, Any] = {
        "q": q,
        "tenant_id": tenant_id,
        "kinds": list(_TRIAGE_DOC_KINDS),
        "limit": limit,
    }
    if as_of is not None:
        params["as_of"] = as_of
    sql = triage_retrieval_sql(cutoff=as_of is not None)

    try:
        rows = (await db.execute(text(sql).bindparams(**params))).fetchall()
    except Exception as exc:
        logger.exception("Database error in knowledge_base endpoint")
        raise HTTPException(status_code=503, detail="Database error") from exc

    excluded = int(rows[0].excluded_after_cutoff) if rows else 0
    undated = int(rows[0].without_timestamp) if rows else 0
    chunks = [
        TriageRunbookChunk(
            doc_id=r.id,
            title=r.title,
            doc_kind=r.doc_kind,
            source_url=r.source_url,
            chunk_index=r.chunk_index,
            chunk_total=r.chunk_total,
            content=r.content,
            created_at=r.created_at,
            score=float(r.rank) if r.rank is not None else None,
        )
        # The LATERAL yields one all-NULL row when nothing survives the cutoff,
        # which is the case the counts above exist to describe.
        for r in rows
        if r.id is not None
    ]
    return TriageRunbooksResponse(
        tenant_id=str(tenant_id),
        as_of=as_of,
        chunks=chunks,
        excluded_after_cutoff=excluded,
        without_timestamp=undated,
    )
