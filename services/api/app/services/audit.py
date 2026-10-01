"""Audit log helpers.

Usage::

    from app.services.audit import emit_audit

    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        action="cases:create",
        resource="case",
        resource_id=str(case.id),
        changes={"title": case.title},
        request=request,  # optional FastAPI Request for IP / user-agent
    )

Hardening (BATCH 7 — H-4 + M-12)
--------------------------------

* **Source-IP attribution.** ``actor_ip`` is resolved through
  :func:`app.core.trusted_proxy.resolve_client_ip`, which only honours
  ``X-Forwarded-For`` when the direct peer is on the configured
  ``AISOC_TRUSTED_PROXIES`` allow-list. The previous version trusted
  the header unconditionally, letting any client forge their audit IP.
  It also had an operator-precedence bug
  (``A or B if C else None``) that silently broke when ``request.client``
  was ``None``.
* **Changes redaction & size cap.** The ``changes`` payload is passed
  through :func:`app.services.audit_redaction.redact_changes` so
  password/token/secret keys are masked and oversized payloads are
  reduced to a marker row. Without this we were one bad endpoint away
  from persisting raw secrets into an immutable, RLS-scoped table.
* **Tamper-evident hash chain.** Each row stores ``prev_hash`` and
  ``entry_hash`` (sha256, computed by
  :mod:`app.services.audit_hash`) so an external verifier can prove
  the chain was not truncated, reordered, or rewritten — even by an
  operator with ``DISABLE TRIGGER`` privileges. The DB-side
  immutability trigger (migration 004) still defends the normal SQL
  path; the chain catches what the trigger cannot.
"""

from __future__ import annotations

import logging
import uuid
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

from fastapi import Request
from prometheus_client import Counter
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.trusted_proxy import resolve_client_ip
from app.db.best_effort import savepoint
from app.models.audit import AuditLog
from app.services.audit_hash import compute_entry_hash
from app.services.audit_redaction import redact_changes

logger = logging.getLogger("aisoc.audit")

#: Rows written without a hash link, by the action that produced them.
#:
#: Defined here rather than in ``app.main`` so that importing the audit
#: service is enough to register it: a counter declared beside the HTTP
#: metrics would be missing from any process that emits audit events without
#: serving requests, and a metric that exists on one replica and not another
#: reads as zero.
AUDIT_CHAIN_FAILURES = Counter(
    "aisoc_audit_chain_failures_total",
    "Audit rows written with no hash link, so tamper-evidence does not cover them.",
    ["action"],
)

# Hard caps on header-derived metadata that lands in the audit row.
# These exist independently of changes-payload redaction and protect
# the ``metadata`` JSONB column from arbitrary client growth.
_MAX_UA_LEN = 512
_MAX_REQUEST_ID_LEN = 128


# ─── One audit writer per request ───────────────────────────────────────────
#
# The measured fork had two writers inside a single request: a handler's
# ``emit_audit`` on the request session, and ``AuditMiddleware`` on a session
# of its own. Serializing them is not enough, because the middleware runs
# before the request session's dependency teardown — it would be waiting on a
# transaction that cannot commit until the middleware returns. That cycle is
# what timed out and dropped a row when a lock was last tried here.
#
# So the second writer goes away instead: ``AuditMiddleware`` writes its row
# only for requests that produced none. That also removes a duplicate the log
# has carried all along — an audited route wrote two rows for one action, one
# from the handler with the real ``changes`` payload and one from the
# middleware with a route-derived label.
#
# The channel is a **mutable dict in a ContextVar**, not the ContextVar value
# itself. ``BaseHTTPMiddleware`` runs the downstream app in a task spawned
# from the middleware's context, and a context is *copied* at spawn: a value
# the endpoint sets is invisible to the middleware. A reference the middleware
# put there first, mutated downstream, is visible to both.
#
# ``request.state`` would also work and is used as a second channel where a
# ``Request`` is to hand, because a handler that dispatches audit work into
# its own task would lose the ContextVar and silently re-earn the duplicate.
_REQUEST_AUDIT: ContextVar[dict[str, int] | None] = ContextVar("aisoc_request_audit", default=None)


def begin_request_audit_scope() -> object:
    """Open a per-request tally of audit rows. Returns a reset token."""
    return _REQUEST_AUDIT.set({"emitted": 0})


def end_request_audit_scope(token: object) -> None:
    """Close the scope opened by :func:`begin_request_audit_scope`.

    Deliberately total. ``BaseHTTPMiddleware`` can unwind in a different
    context than the one that opened the scope, and ``ContextVar.reset``
    raises a different exception for each way that can go wrong: ``ValueError``
    for a token from another context, ``TypeError`` for something that is not
    a token, ``RuntimeError`` for one already used. None of them is worth
    turning into a 500 — the cost of failing to reset is a duplicate audit
    row, and the cost of raising is the request.
    """
    try:
        _REQUEST_AUDIT.reset(token)  # type: ignore[arg-type]
    except (TypeError, ValueError, LookupError, RuntimeError):
        # Intentionally swallowed. The scope is per-request bookkeeping and
        # the context it lived in is already gone; there is nothing to undo
        # and nothing an operator could act on. Re-raising would turn a
        # duplicate audit row into a failed request.
        pass


def request_emitted_audit(request: Request | None = None) -> bool:
    """Whether this request already wrote an audit row.

    Checked by ``AuditMiddleware`` to decide whether its own row would be a
    second writer. Reads both channels: a handler may have emitted with no
    ``Request`` to hand, or from a task that did not inherit the ContextVar.
    """
    scope = _REQUEST_AUDIT.get()
    if scope is not None and scope.get("emitted", 0) > 0:
        return True
    if request is not None:
        return bool(getattr(request.state, "aisoc_audit_emitted", False))
    return False


def _mark_request_emitted(request: Request | None) -> None:
    scope = _REQUEST_AUDIT.get()
    if scope is not None:
        scope["emitted"] = scope.get("emitted", 0) + 1
    if request is not None:
        # ``request.state`` is backed by ``scope["state"]``, the same dict for
        # every Request built from this ASGI scope, so the middleware sees it.
        request.state.aisoc_audit_emitted = True


#: Epoch stamped on rows produced by the serialized appender below.
#:
#: Migration 074 leaves the column default at 1, so a pre-074 replica writing
#: during a rolling deploy stays in epoch 1 and outside the unique index that
#: only epoch 2 is expected to satisfy.
CHAIN_EPOCH = 2

#: Take the tenant's append lock and read the head, in one statement.
#:
#: ``ON CONFLICT DO UPDATE`` rather than ``DO NOTHING`` because only the
#: UPDATE arm takes the row lock; ``DO NOTHING`` would return no row for an
#: existing tenant and lock nothing, which is the race this exists to close.
#: The assignment is a deliberate no-op — the lock and the ``RETURNING`` are
#: the entire point.
_LOCK_AND_READ_HEAD = text(
    """
    INSERT INTO audit_chain_head (tenant_id, head_hash, next_index)
    VALUES (:tid, NULL, 0)
    ON CONFLICT (tenant_id) DO UPDATE SET tenant_id = audit_chain_head.tenant_id
    RETURNING head_hash, next_index
    """
)

_ADVANCE_HEAD = text(
    """
    UPDATE audit_chain_head
       SET head_hash = :head, next_index = :next_index, updated_at = NOW()
     WHERE tenant_id = :tid
    """
)


async def _resolve_prev_hash(db: AsyncSession, tenant_id: uuid.UUID) -> str | None:
    """Return the tenant's current chain head.

    Reads ``audit_chain_head`` rather than scanning ``audit_log``, and does so
    **under the tenant's append lock** — the two are the same statement, which
    is what makes the read and the insert that follows atomic with respect to
    other appenders.

    Kept as a function of its own because it is also the honest answer to
    "what is the head?" for callers that only want to look. Note that looking
    is not free: it takes the lock, so a reader serializes against writers.
    """
    row = (await db.execute(_LOCK_AND_READ_HEAD, {"tid": tenant_id})).mappings().one()
    return row["head_hash"]


async def _append_to_chain(db: AsyncSession, event: AuditLog) -> None:
    """Chain-link ``event`` onto its tenant's history, serialized per tenant.

    Why this is serialized at all
    -----------------------------
    Appending to a hash chain is a read-modify-write on a shared head. Two
    writers that read the same head both append to it, and the chain forks —
    measured on ``POST /alerts/{id}/explain``, two milliseconds apart::

        alerts:create   entry=dabf5207f866  prev=-
        alerts.explain  entry=66eed8144cee  prev=dabf5207f866
        alerts:create   entry=ca30ed264f98  prev=dabf5207f866   <- fork

    There is no lock-free way to append to a dense linked list: serialization
    at the append point is inherent, not an implementation choice. So the
    design question is only *where* it happens and whether it can deadlock or
    drop a row.

    Why the lock is safe here when the previous attempt was not
    ----------------------------------------------------------
    A transaction-scoped advisory lock was tried and reverted because the two
    writers were in the **same request** — a handler's ``emit_audit`` and
    ``audit_middleware`` on separate sessions — and the middleware runs before
    the request session's dependency teardown. The middleware waited on a
    transaction that could not commit until the middleware returned. Its
    acquisition timed out and its row was dropped, which is worse than the
    fork: a missing audit row is undetectable, a forked one is not.

    ``AuditMiddleware`` no longer writes a second row for a request that
    already produced one, so that cycle cannot form. What remains is one
    writer waiting on another *request's* transaction, which is an ordinary
    wait that ends when that request commits.

    **No lock timeout, deliberately.** Waiting is correct; timing out drops a
    row. The lock is a single row lock per append, so the protocol has no
    cycle of its own and cannot deadlock against itself.

    The invariant does not rest on any of this
    ------------------------------------------
    ``uq_audit_log_chain_successor`` is UNIQUE on ``(tenant_id, prev_hash)``,
    and a fork *is* two rows claiming the same predecessor. The database
    cannot store one. If this function, the middleware change and the lock
    were all removed, the second writer would get a constraint violation
    rather than quietly forking.
    """
    head = (await db.execute(_LOCK_AND_READ_HEAD, {"tid": event.tenant_id})).mappings().one()
    prev: str | None = head["head_hash"]
    index = int(head["next_index"])

    event.prev_hash = prev
    event.chain_index = index
    event.chain_epoch = CHAIN_EPOCH
    event.entry_hash = compute_entry_hash(
        prev_hash=prev,
        row_id=event.id,
        tenant_id=event.tenant_id,
        actor_id=event.actor_id,
        actor_email=event.actor_email,
        actor_ip=event.actor_ip,
        action=event.action,
        resource=event.resource,
        resource_id=event.resource_id,
        changes=event.changes,
        metadata=event.metadata_,
        created_at=event.created_at,
    )

    await db.execute(
        _ADVANCE_HEAD,
        {"head": event.entry_hash, "next_index": index + 1, "tid": event.tenant_id},
    )


def _safe_truncate(value: str | None, limit: int) -> str | None:
    """Trim a header value to ``limit`` characters, preserving None."""
    if value is None:
        return None
    if len(value) <= limit:
        return value
    return value[:limit]


async def emit_audit(
    *,
    db: AsyncSession,
    tenant_id: uuid.UUID,
    actor_id: uuid.UUID | None = None,
    actor_email: str | None = None,
    action: str,
    resource: str | None = None,
    resource_id: str | None = None,
    changes: dict[str, Any] | None = None,
    request: Request | None = None,
    api_key_prefix: str | None = None,
) -> AuditLog:
    """Append an immutable, hash-chained audit event to the log.

    The caller still owns the transaction — ``db.add()`` is queued, but
    we do not commit. Callers that need a strict guarantee that the
    audit row outlives the rest of their work (i.e. a request can fail
    *after* committing audit but *before* the business write) should
    wrap their handler in a savepoint and commit the audit row first.
    The hash chain is robust either way; in-flight rows simply do not
    yet have an ``entry_hash`` reader.

    Parameters
    ----------
    db:           Active async session.
    tenant_id:    Tenant this event belongs to.
    actor_id:     User UUID performing the action (optional).
    actor_email:  Email for denormalised search (optional).
    action:       Dot/colon action string, e.g. ``cases:create``.
    resource:     Resource type, e.g. ``case``.
    resource_id:  Primary key / identifier of the affected object.
    changes:      Before/after dict or delta payload. Will be redacted
                  and size-capped before persistence.
    request:      FastAPI ``Request`` to extract IP & user-agent.
    api_key_prefix:
                  Set when the caller authenticated with an API key. A key
                  owned by a user resolves to that user's email, so without
                  this an entry read identically whether the person acted at
                  the console or a key they minted acted from a script —
                  and revoking a key and disabling a person are different
                  responses to the same log line.
    """
    actor_ip: str | None = None
    meta: dict[str, Any] = {}

    if request is not None:
        # Trusted-proxy aware IP resolution — see services/api/app/core/trusted_proxy.py.
        try:
            actor_ip = resolve_client_ip(request)
        except Exception:  # noqa: BLE001
            # We never want audit attribution to take down a mutating
            # request. Log and fall through with no IP attached.
            logger.warning("audit: failed to resolve client IP", exc_info=True)
            actor_ip = None

        ua = _safe_truncate(request.headers.get("user-agent"), _MAX_UA_LEN)
        if ua:
            meta["user_agent"] = ua
        rid = _safe_truncate(request.headers.get("x-request-id"), _MAX_REQUEST_ID_LEN)
        if rid:
            meta["request_id"] = rid

    if api_key_prefix:
        # The prefix, never the key. It is the identifier the console shows
        # and the one an operator revokes by, which is exactly what an
        # investigator reading this row needs to act on.
        meta["auth_method"] = "api_key"
        meta["api_key_prefix"] = _safe_truncate(api_key_prefix, 32)
    elif request is not None:
        meta["auth_method"] = "session"

    # Sanitize before persistence. Anything secret-shaped is masked,
    # and oversized payloads collapse to a marker row.
    safe_changes = redact_changes(changes)

    # Stable created_at — set explicitly so the hash uses the same
    # value the DB will store. Without this, default=lambda runs at
    # flush time and we'd hash one timestamp and persist another.
    created_at = datetime.now(UTC)

    event = AuditLog(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_email=actor_email,
        actor_ip=actor_ip,
        action=action,
        resource=resource,
        resource_id=resource_id,
        changes=safe_changes,
        metadata_=meta or None,
        created_at=created_at,
    )

    # Chain-link this row onto the tenant's prior history. If the
    # lookup fails for any reason (e.g. transient DB blip) we still
    # write the row — falling back to an unchained entry is strictly
    # better than failing the originating mutation, and the gap is
    # detectable by the verifier.
    #
    # Inside a savepoint, because "we still write the row" was not true.
    # PostgreSQL aborts the whole transaction on a statement error, so a
    # failed SELECT here left the INSERT below failing too and the event was
    # never written at all. Observed on `alerts.explain`, where the SELECT was
    # not itself at fault — an earlier best-effort cost INSERT had already
    # aborted the transaction, and this was simply the next statement to run.
    try:
        async with savepoint(db):
            await _append_to_chain(db, event)
    except Exception:  # noqa: BLE001
        # `error`, a counter and a health surface — not a warning.
        #
        # This was `logger.warning` and nothing else, and it fired on every
        # `alerts.explain` against a default install for as long as the cost
        # writer could abort the transaction. Nobody noticed, because an
        # append-only log going quiet looks exactly like an idle one. A
        # compliance control whose only failure signal is a line in a stream
        # nobody greps is a control in name only.
        #
        # `aisoc_audit_chain_failures_total` is scraped on /metrics, so this
        # is alertable, and `GET /api/v1/health/audit-chain` answers the same
        # question on demand for an auditor who is not watching a dashboard.
        AUDIT_CHAIN_FAILURES.labels(action=action).inc()
        logger.error(
            "audit: failed to compute hash chain for tenant=%s action=%s — "
            "this row is written UNCHAINED and the tamper-evidence claim does not hold for it",
            tenant_id,
            action,
            exc_info=True,
        )
        event.prev_hash = None
        event.entry_hash = None

    db.add(event)
    # Marked even when the chain computation above failed. The point of the
    # mark is "this request already has a writer", and an unchained row is
    # still a row — letting the middleware add a second one would put two
    # writers back in the request, which is the defect, not the mitigation.
    _mark_request_emitted(request)
    return event
