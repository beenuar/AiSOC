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
"""

from __future__ import annotations

import logging
import os
import uuid
from datetime import UTC, datetime
from typing import Any, Literal

import httpx
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.api.v1.deps import AuthUser, DBSession
from app.core.airgap import AirgapViolation, enforce_airgap_for_url
from app.services.kb_chunking import chunk_text

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
    api_key = os.getenv("OPENAI_API_KEY") or os.getenv("LLM_API_KEY")
    if not api_key:
        return None
    base_url = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1")
    model = os.getenv("LLM_MODEL", "gpt-4o-mini")
    context = "\n\n".join(f"[{c.title}] chunk {c.chunk_index}:\n{c.content}" for c in chunks)
    completions_url = f"{base_url}/chat/completions"
    enforce_airgap_for_url(completions_url)
    try:
        async with httpx.AsyncClient(timeout=45) as client:
            resp = await client.post(
                completions_url,
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": _SYNTH_SYSTEM},
                        {"role": "user", "content": f"CONTEXT:\n{context}\n\nQUESTION: {question}"},
                    ],
                    "temperature": 0.2,
                },
            )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"].strip()
    except Exception:
        return None


# ────────────────────────────────────────────────────────────────────────────
# Endpoints
# ────────────────────────────────────────────────────────────────────────────


@router.post(
    "/ingest", response_model=list[KBDocResponse], status_code=status.HTTP_201_CREATED, summary="Ingest document into knowledge base"
)
async def ingest(body: IngestRequest, db: DBSession, user: AuthUser) -> list[KBDocResponse]:
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
                :id, :tenant_id, :title, :kind, :url, :content, :tags::text[],
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
            user=str(user) if user else "system",
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
async def delete_document(doc_id: uuid.UUID, db: DBSession, user: AuthUser) -> None:
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
        wheres.append("doc_kind = ANY(:kinds::text[])")
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
