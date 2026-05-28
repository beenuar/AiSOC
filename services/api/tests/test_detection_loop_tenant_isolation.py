"""Tenant-isolation tests for /detection-loop (security fix).

Sibling of :mod:`tests.test_alerts_tenant_isolation` — exercises the
detection-loop endpoints exposed by
:mod:`app.api.v1.endpoints.detection_loop` and asserts that the
cross-tenant attack vectors closed by the security fix stay closed.

The contract being protected
----------------------------
* ``POST /detection-loop/suggest`` must scope the **alert lookup** and
  the **rule body lookup** on the caller's ``tenant_id``. A cross-tenant
  ``alert_id`` must 404 *before* any evidence or rule body is read, and
  no detection-rule-proposal row may be inserted.
* The auto-created ``aisoc_detection_rule_proposals`` row must bind the
  **caller's** ``tenant_id`` — never one derived from a database read,
  so a poisoned ``aisoc_alerts.tenant_id`` cannot redirect the write.
* ``GET /detection-loop/suggestions`` and
  ``GET /detection-loop/suggestions/{id}`` operate over a process-wide
  in-memory ``_SUGGESTIONS`` dict. Filtering on the stored ``tenant_id``
  must hide other tenants' drafts. A cross-tenant GET-by-id must 404
  (not 403) so we don't leak existence.
* The ``tenant_id`` we tag onto the in-memory record is *internal
  metadata* — it must not appear in any response body.

These tests call the endpoint functions directly with a mocked
:class:`AsyncSession`, the same pattern used in
:mod:`tests.test_alerts_tenant_isolation`.
"""

from __future__ import annotations

import re
import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import detection_loop as detection_loop_module
from app.api.v1.endpoints.detection_loop import (
    SuggestionResponse,
    SuggestRequest,
    get_suggestion,
    list_suggestions,
    suggest_fp_fix,
)
from fastapi import HTTPException

# ────────────────────────────────────────────────────────────────────────────
# Fixtures / helpers
# ────────────────────────────────────────────────────────────────────────────


def _user(tenant_id: uuid.UUID | None = None) -> CurrentUser:
    """Build a CurrentUser without touching JWT plumbing or the DB."""
    return CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=tenant_id or uuid.uuid4(),
        role="soc_analyst",
        email="analyst@example.com",
    )


def _alert_row(tenant_id: uuid.UUID, rule_id: uuid.UUID | None = None, evidence: dict[str, Any] | None = None) -> MagicMock:
    """Build a fake ``aisoc_alerts`` row exposing the columns the endpoint reads."""
    row = MagicMock()
    row.rule_id = rule_id
    row.evidence = evidence or {"process_name": "powershell.exe", "User": "svc-ci"}
    row.tenant_id = tenant_id
    return row


def _rule_row(body: str = "title: Stub\nlogsource:\n  product: windows\n") -> MagicMock:
    row = MagicMock()
    row.rule_body = body
    return row


def _mk_db(rows: list[Any]) -> MagicMock:
    """Mock AsyncSession that returns queued rows one execute() at a time.

    Mirrors the helper in ``test_alerts_tenant_isolation`` so SQL + bind
    parameter assertions work the same way: each ``execute(clause)`` call
    pushes ``(str(clause), clause.compile().params)`` onto ``db.executed``.

    The queued payloads serve as ``result.fetchone()`` returns — the
    detection-loop endpoint uses ``row.fetchone()`` rather than
    ``scalars().all()``, so the mock returns the raw payload (``None`` for
    the cross-tenant 404 path).
    """
    db = MagicMock()
    db.executed: list[tuple[str, dict[str, Any]]] = []
    iterator = iter(rows)

    async def _execute(clause: Any, *args: Any, **kwargs: Any) -> MagicMock:
        sql = str(clause)
        try:
            params = dict(clause.compile().params) if hasattr(clause, "compile") else {}
        except Exception:  # pragma: no cover — defensive: never crash the mock.
            params = {}
        db.executed.append((sql, params))
        try:
            payload = next(iterator)
        except StopIteration:
            payload = None
        result = MagicMock()
        result.fetchone = MagicMock(return_value=payload)
        return result

    db.execute = AsyncMock(side_effect=_execute)
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    return db


def _find_select(executed: list[tuple[str, dict[str, Any]]], table: str) -> tuple[str, dict[str, Any]] | None:
    """Return the first executed SELECT against ``table`` (case-insensitive), or None."""
    for sql, params in executed:
        normalized = re.sub(r"\s+", " ", sql).lower()
        if normalized.startswith("select") and table.lower() in normalized:
            return sql, params
    return None


def _find_insert(executed: list[tuple[str, dict[str, Any]]], table: str) -> tuple[str, dict[str, Any]] | None:
    """Return the first executed INSERT into ``table``, or None."""
    for sql, params in executed:
        normalized = re.sub(r"\s+", " ", sql).lower()
        if "insert into" in normalized and table.lower() in normalized:
            return sql, params
    return None


@pytest.fixture(autouse=True)
def _clear_suggestions_store() -> Any:
    """The ``_SUGGESTIONS`` dict is process-wide; reset it per test."""
    detection_loop_module._SUGGESTIONS.clear()
    yield
    detection_loop_module._SUGGESTIONS.clear()


@pytest.fixture
def _stub_llm(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Replace the LLM call so tests stay hermetic and fast.

    The endpoint dispatches to ``_llm_draft_sigma`` which, in the
    template-fallback path, would still need ``alert_fields`` to be a
    real dict. Returning the canned dict here keeps the assertion
    surface focused on tenant scoping rather than LLM contract drift.
    """
    canned = {
        "rule_name": "fp-exclusion-draft",
        "sigma_yaml": "filter:\n  - process_name: 'powershell.exe'\ncondition: selection and not filter\n",
        "rationale": "Auto-generated exclusion for the FP analyst flagged.",
    }
    monkeypatch.setattr(
        detection_loop_module,
        "_llm_draft_sigma",
        AsyncMock(return_value=canned),
    )
    return canned


# ────────────────────────────────────────────────────────────────────────────
# POST /detection-loop/suggest
# ────────────────────────────────────────────────────────────────────────────


async def test_suggest_cross_tenant_alert_id_returns_404(_stub_llm: dict[str, Any]) -> None:
    """A caller in tenant A cannot pull tenant B's alert evidence by id.

    Pre-fix: ``SELECT ... WHERE id = :aid`` returned the row regardless
    of tenant, then the endpoint echoed ``evidence`` (and a rule_id
    that resolved against ``aisoc_detection_rules`` cross-tenant).

    Post-fix: the SELECT is scoped to ``user.tenant_id``, so a
    cross-tenant id returns no row and we 404 before any other read
    or any proposal INSERT runs.
    """
    tenant_a = _user()
    # SELECT scoped to tenant A's id returns nothing — the row exists in
    # tenant B but our WHERE clause now filters it out.
    db = _mk_db([None])

    with pytest.raises(HTTPException) as exc:
        await suggest_fp_fix(
            body=SuggestRequest(alert_id=uuid.uuid4()),
            db=db,
            user=tenant_a,
        )

    assert exc.value.status_code == 404

    # The alert SELECT must have been tenant-scoped.
    alert_select = _find_select(db.executed, "aisoc_alerts")
    assert alert_select is not None, "expected a SELECT against aisoc_alerts"
    sql, params = alert_select
    assert "tenant_id" in re.sub(r"\s+", " ", sql).lower(), f"alert SELECT not tenant-scoped: {sql}"
    assert (
        params.get("tenant_id") == tenant_a.tenant_id
    ), f"alert SELECT did not bind the caller's tenant_id; params={params}; expected={tenant_a.tenant_id}"

    # Critical: no rule lookup and no proposal INSERT must have run.
    assert _find_select(db.executed, "aisoc_detection_rules") is None, "rule body lookup must not run when the alert lookup 404s"
    assert _find_insert(db.executed, "aisoc_detection_rule_proposals") is None, "no proposal must be inserted when the alert lookup 404s"
    # And nothing must land in the in-memory store.
    assert detection_loop_module._SUGGESTIONS == {}


async def test_suggest_same_tenant_scopes_alert_rule_and_proposal(_stub_llm: dict[str, Any]) -> None:
    """Same-tenant suggest: alert + rule SELECTs and the proposal INSERT all bind the caller's tenant."""
    user = _user()
    rule_id = uuid.uuid4()
    alert = _alert_row(user.tenant_id, rule_id=rule_id)
    rule = _rule_row()
    # Three executes: alert SELECT, rule SELECT, proposal INSERT.
    db = _mk_db([alert, rule, None])

    response = await suggest_fp_fix(
        body=SuggestRequest(alert_id=uuid.uuid4(), analyst_note="benign automation"),
        db=db,
        user=user,
    )

    assert isinstance(response, SuggestionResponse)
    assert response.base_rule_id == rule_id

    # Alert SELECT — tenant-scoped on caller's tenant.
    alert_select = _find_select(db.executed, "aisoc_alerts")
    assert alert_select is not None
    sql, params = alert_select
    assert "tenant_id" in re.sub(r"\s+", " ", sql).lower()
    assert params.get("tenant_id") == user.tenant_id

    # Rule SELECT — also tenant-scoped on caller's tenant.
    rule_select = _find_select(db.executed, "aisoc_detection_rules")
    assert rule_select is not None, "expected a SELECT against aisoc_detection_rules"
    sql, params = rule_select
    assert "tenant_id" in re.sub(r"\s+", " ", sql).lower()
    assert params.get("tenant_id") == user.tenant_id

    # Proposal INSERT — the ``tid`` bind must equal the *caller's* tenant.
    proposal_insert = _find_insert(db.executed, "aisoc_detection_rule_proposals")
    assert proposal_insert is not None, "expected an INSERT into aisoc_detection_rule_proposals"
    _sql, params = proposal_insert
    assert (
        params.get("tid") == user.tenant_id
    ), f"proposal INSERT did not bind the caller's tenant; params={params}; expected={user.tenant_id}"

    # The in-memory record must be tagged with the caller's tenant
    # (used by list/get for cross-tenant filtering) and must hold the
    # full response.
    stored = detection_loop_module._SUGGESTIONS[response.suggestion_id]
    assert stored["tenant_id"] == user.tenant_id


async def test_suggest_proposal_insert_binds_caller_tenant_not_db_row_tenant(_stub_llm: dict[str, Any]) -> None:
    """Defence in depth: even if a poisoned alert row leaks past RLS, the proposal binds caller's tenant.

    The fix replaces ``tid=alert_row.tenant_id`` with ``tid=user.tenant_id``.
    This test forges an alert row whose ``tenant_id`` differs from the
    caller's (a hypothetical "RLS bypassed" scenario), confirms the
    endpoint still reaches the INSERT (because we mocked the SELECT to
    return the row), and asserts the INSERT binds the *caller's*
    tenant — not the value read from the database.
    """
    user = _user()
    poisoned_row_tenant = uuid.uuid4()
    rule_id = uuid.uuid4()
    forged_alert = _alert_row(poisoned_row_tenant, rule_id=rule_id)
    rule = _rule_row()
    db = _mk_db([forged_alert, rule, None])

    response = await suggest_fp_fix(
        body=SuggestRequest(alert_id=uuid.uuid4()),
        db=db,
        user=user,
    )

    proposal_insert = _find_insert(db.executed, "aisoc_detection_rule_proposals")
    assert proposal_insert is not None
    _sql, params = proposal_insert
    # The critical assertion: never trust a value we read back from the DB
    # for an authorization decision on a write.
    assert params.get("tid") == user.tenant_id
    assert params.get("tid") != poisoned_row_tenant

    # And the in-memory tag also follows the caller, not the row.
    stored = detection_loop_module._SUGGESTIONS[response.suggestion_id]
    assert stored["tenant_id"] == user.tenant_id


async def test_suggest_alert_without_rule_id_skips_rule_select(_stub_llm: dict[str, Any]) -> None:
    """If the alert has no ``rule_id`` we must not blindly query the rules table.

    Guards against a regression where someone adds a tenant_id-less
    rule lookup back. Also locks down that the proposal INSERT still
    fires (with ``base_rule_id=NULL``) so suggest_fp_fix remains usable
    for orphan alerts.
    """
    user = _user()
    alert = _alert_row(user.tenant_id, rule_id=None)
    # Only two executes: alert SELECT and proposal INSERT.
    db = _mk_db([alert, None])

    response = await suggest_fp_fix(
        body=SuggestRequest(alert_id=uuid.uuid4()),
        db=db,
        user=user,
    )

    assert response.base_rule_id is None
    assert _find_select(db.executed, "aisoc_detection_rules") is None
    proposal_insert = _find_insert(db.executed, "aisoc_detection_rule_proposals")
    assert proposal_insert is not None
    assert proposal_insert[1].get("tid") == user.tenant_id


# ────────────────────────────────────────────────────────────────────────────
# GET /detection-loop/suggestions
# ────────────────────────────────────────────────────────────────────────────


def _seed_suggestion(tenant_id: uuid.UUID, rule_name: str = "fp-fix-draft") -> uuid.UUID:
    """Insert a stub row directly into ``_SUGGESTIONS`` for list/get tests."""
    sid = uuid.uuid4()
    from datetime import UTC, datetime  # noqa: PLC0415 — keep helper hermetic.

    detection_loop_module._SUGGESTIONS[sid] = {
        "suggestion_id": sid,
        "alert_id": uuid.uuid4(),
        "base_rule_id": uuid.uuid4(),
        "draft_rule_name": rule_name,
        "draft_sigma_yaml": "filter:\n  - User: 'svc-ci'\n",
        "rationale": "test",
        "proposal_id": uuid.uuid4(),
        "created_at": datetime.now(UTC),
        "tenant_id": tenant_id,
    }
    return sid


async def test_list_suggestions_only_returns_caller_tenant() -> None:
    """A list call must return only the caller-tenant's suggestions, never others'."""
    tenant_a = _user()
    tenant_b = _user()
    a1 = _seed_suggestion(tenant_a.tenant_id, "a-1")
    a2 = _seed_suggestion(tenant_a.tenant_id, "a-2")
    # Seed a tenant-B suggestion solely to prove it doesn't leak into tenant A's
    # list response below; we never need its id here.
    _seed_suggestion(tenant_b.tenant_id, "b-1")

    resp = await list_suggestions(user=tenant_a)

    assert resp.total == 2
    returned_ids = {item.suggestion_id for item in resp.suggestions}
    assert returned_ids == {a1, a2}, "tenant A's list returned the wrong set — possible cross-tenant leak"


async def test_list_suggestions_does_not_leak_internal_tenant_id_field() -> None:
    """The internal ``tenant_id`` tag must not appear in the response body."""
    user = _user()
    _seed_suggestion(user.tenant_id)

    resp = await list_suggestions(user=user)

    assert resp.total == 1
    item = resp.suggestions[0]
    # ``SuggestionResponse`` does not declare ``tenant_id`` and pydantic
    # will not expose attributes that aren't declared. Verify defensively
    # in case someone adds the field to the schema later.
    assert not hasattr(item, "tenant_id"), "internal tenant_id metadata must not be part of the API response"
    dumped = item.model_dump()
    assert "tenant_id" not in dumped


async def test_list_suggestions_empty_when_no_caller_tenant_rows() -> None:
    """A caller in a fresh tenant must see an empty list — not other tenants' work."""
    tenant_a = _user()
    other = _user()
    _seed_suggestion(other.tenant_id, "other-1")
    _seed_suggestion(other.tenant_id, "other-2")

    resp = await list_suggestions(user=tenant_a)

    assert resp.total == 0
    assert resp.suggestions == []


# ────────────────────────────────────────────────────────────────────────────
# GET /detection-loop/suggestions/{id}
# ────────────────────────────────────────────────────────────────────────────


async def test_get_suggestion_cross_tenant_returns_404() -> None:
    """Looking up another tenant's suggestion by id must 404 — not 403, not 200."""
    tenant_a = _user()
    tenant_b = _user()
    target = _seed_suggestion(tenant_b.tenant_id, "b-only")

    with pytest.raises(HTTPException) as exc:
        await get_suggestion(suggestion_id=target, user=tenant_a)

    # 404 (not 403) avoids leaking the existence of suggestions owned
    # by other tenants.
    assert exc.value.status_code == 404


async def test_get_suggestion_unknown_id_returns_404() -> None:
    """A non-existent suggestion id must 404, not 500 or 200."""
    user = _user()
    # Store contains rows for *other* tenants — exercise the "key missing"
    # branch separately from the "wrong tenant" branch.
    _seed_suggestion(uuid.uuid4())

    with pytest.raises(HTTPException) as exc:
        await get_suggestion(suggestion_id=uuid.uuid4(), user=user)

    assert exc.value.status_code == 404


async def test_get_suggestion_same_tenant_returns_item() -> None:
    """A caller can read its own suggestion and the response excludes ``tenant_id``."""
    user = _user()
    sid = _seed_suggestion(user.tenant_id, "mine")

    resp = await get_suggestion(suggestion_id=sid, user=user)

    assert resp.suggestion_id == sid
    assert resp.draft_rule_name == "mine"
    dumped = resp.model_dump()
    assert "tenant_id" not in dumped
