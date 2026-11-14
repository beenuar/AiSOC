"""Smoke test for the reverse-action / paired-rollback flow.

Verifies the contract established by ``t1-reverse-actions``:

  1. A ``WRITE_REVERSIBLE`` forward action through a ``ResponderAgent``
     produces a ``ToolCall`` row whose ``rollback_of_id`` is NULL and
     whose registry ``ToolDef`` advertises a ``reverse_tool``.
  2. ``rollback_eligibility`` correctly classifies that row as eligible
     and materializes a deterministic ``reverse_params_preview``.
  3. ``execute_rollback`` dispatches the reverse tool through the
     Responder, persists a paired ``ToolCall`` row with
     ``rollback_of_id`` set, and atomically stamps the forward row's
     ``rolled_back_at`` / ``rolled_back_by``.
  4. A second rollback of the same forward row is rejected with
     ``RollbackNotEligible("already rolled back")`` — never silently a
     no-op.
  5. Tools that are intentionally non-reversible (``idp.reset_password``,
     classified ``WRITE_SIGNIFICANT`` and explicitly marked
     ``forward_only_reason``) are surfaced as ineligible with the
     *documented* forward-only reason in the eligibility verdict, not a
     generic "no reverse handler" placeholder. This matters because the
     reason flows into the analyst-visible audit trail when a rollback
     is refused.
  6. ``list_rollback_eligible`` honors the tenant filter, omits already
     reversed rows by default, and never returns a rollback row as a
     candidate for further reversal.

We deliberately run in ``autonomy_level=autonomous`` for the test so
the HITL gateway does not block forward calls. The rollback path
itself still flows through ``BaseAgent.call_tool`` — including the
prompt-injection defense, the per-tenant allowlist, and the
``rolled_back_by`` stamping — so any breakage there shows up here.

Run with:

    cd platform/backend
    python -m tests._check_rollback
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path

# Force ephemeral DB *and* autonomous mode before app imports so we
# don't touch the real DB and the HITL gate doesn't block forward
# WRITE-REVERSIBLE calls during the test. Both must be set before
# `app.config.settings` is constructed.
TMP_DIR = Path(tempfile.mkdtemp(prefix="aisoc-rollback-"))
os.environ["AISOC_DB_PATH"] = str(TMP_DIR / "rollback-test.db")
os.environ["AISOC_AUTONOMY_LEVEL"] = "autonomous"
os.environ.setdefault("AISOC_ENV", "development")

# Repo root on path so `app.*` imports resolve when run as a script.
HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parent.parent))

from app.agents.responder import ResponderAgent
from app.db import engine, init_db
from app.models.case import Case, Severity
from app.models.tool_call import ToolCall
from app.rollback.service import (
    RollbackNotEligible,
    execute_rollback,
    list_rollback_eligible,
    rollback_eligibility,
)
# Importing the tool modules triggers registration on the global registry.
from app.tools import edr as _edr  # noqa: F401
from app.tools import email_tool as _email  # noqa: F401
from app.tools import idp as _idp  # noqa: F401
from app.tools.registry import registry
from sqlmodel import Session, select


TENANT = "tenant-rollback"


def _make_case(db: Session) -> int:
    case = Case(
        tenant_id=TENANT,
        title="rollback smoke test",
        severity=Severity.HIGH,
    )
    db.add(case)
    db.commit()
    db.refresh(case)
    assert case.id is not None
    return case.id


async def _check_edr_isolate_release_cycle() -> None:
    """Forward isolate → eligibility → execute_rollback → audit pairing."""
    with Session(engine) as db:
        case_id = _make_case(db)
        responder = ResponderAgent(db=db, case_id=case_id, tenant_id=TENANT)

        # ── 1. Forward action ────────────────────────────────────────
        # NOTE: `edr.isolate_host` expects `host` + `reason` (the SDK
        # signature, not the legacy `host_id`). Defender wraps the result
        # with `__provenance__` / `__llm_view__` but spreads the sanitized
        # payload at the top level too, so `.get("host")` works directly.
        forward_result = await responder.call_tool(
            "edr.isolate_host",
            {"host": "host-001", "reason": "contain ransomware beacon"},
            rationale="contain ransomware beacon",
        )
        assert forward_result.get("isolated") is True, forward_result
        assert forward_result.get("host") == "host-001", forward_result

        forward_tc = db.exec(
            select(ToolCall)
            .where(ToolCall.case_id == case_id)
            .where(ToolCall.tool_name == "edr.isolate_host")
            .order_by(ToolCall.id.desc())  # type: ignore[attr-defined]
        ).first()
        assert forward_tc is not None
        assert forward_tc.success is True
        assert forward_tc.rollback_of_id is None
        assert forward_tc.rolled_back_at is None
        forward_id = forward_tc.id
        assert forward_id is not None
        print(f"OK  forward edr.isolate_host persisted as tool_call={forward_id}")

        # ── 2. Eligibility ───────────────────────────────────────────
        verdict = rollback_eligibility(db, forward_id)
        assert verdict.eligible, verdict.reason
        assert verdict.reverse_tool == "edr.release_host"
        assert verdict.reverse_params_preview.get("host") == "host-001", (
            verdict.reverse_params_preview
        )
        print("OK  rollback_eligibility=true with deterministic reverse params")

        # ── 3. Execute rollback ──────────────────────────────────────
        rb = await execute_rollback(
            db,
            tool_call_id=forward_id,
            actor="user:alice@cyble.com",
            rationale="false positive on isolate",
        )
        assert rb["rollback_of_id"] == forward_id
        assert rb["reverse_tool"] == "edr.release_host"
        # MockEdrConnector.release_host returns {host, isolated:False, ticket}.
        # `isolated: False` is how we model "released" — the reverse tool
        # intentionally mirrors the forward shape so the audit pair is
        # symmetric in storage.
        assert rb["result"].get("host") == "host-001", rb["result"]
        assert rb["result"].get("isolated") is False, rb["result"]
        assert rb["rolled_back_at"] is not None
        assert rb["rolled_back_by"]
        assert "user:alice@cyble.com" in rb["rolled_back_by"], rb["rolled_back_by"]
        print("OK  execute_rollback returned paired reverse-tool result")

        # ── 4. Audit pairing: forward row stamped, reverse row created ───
        db.refresh(forward_tc)
        assert forward_tc.rolled_back_at is not None
        assert forward_tc.rolled_back_by is not None
        assert "user:alice@cyble.com" in forward_tc.rolled_back_by

        reverse_tc = db.exec(
            select(ToolCall)
            .where(ToolCall.rollback_of_id == forward_id)
        ).first()
        assert reverse_tc is not None, "reverse ToolCall row was not persisted"
        assert reverse_tc.tool_name == "edr.release_host"
        assert reverse_tc.success is True
        assert reverse_tc.tenant_id == TENANT
        assert reverse_tc.case_id == case_id
        print(
            f"OK  audit pairing: forward={forward_id} ↔ reverse={reverse_tc.id} "
            "with rolled_back_at/by stamped"
        )

        # ── 5. Re-rollback rejected ──────────────────────────────────
        try:
            await execute_rollback(
                db, tool_call_id=forward_id, actor="user:alice@cyble.com"
            )
        except RollbackNotEligible as exc:
            assert "already rolled back" in str(exc), str(exc)
            assert exc.code == "INELIGIBLE"
            print("OK  re-rollback of same forward row rejected with INELIGIBLE")
        else:
            raise AssertionError(
                "second execute_rollback should have raised RollbackNotEligible"
            )

        # ── 6. Reverse row itself is not a candidate for further rollback ──
        assert reverse_tc.id is not None
        verdict_on_reverse = rollback_eligibility(db, reverse_tc.id)
        assert not verdict_on_reverse.eligible
        assert "itself a rollback" in verdict_on_reverse.reason, (
            verdict_on_reverse.reason
        )
        print("OK  rollback row itself classified ineligible (no recursive undo)")


async def _check_non_reversible_significant() -> None:
    """``idp.reset_password`` is WRITE_SIGNIFICANT and explicitly forward-only.

    The tool is registered and callable, but ``ToolDef.reverse_tool`` is
    None and ``ToolDef.forward_only_reason`` is set. The rollback service
    must surface that as a structured eligibility failure whose reason
    includes the *documented* justification, so an analyst seeing the
    refused rollback knows *why* it's forward-only — not just that it is.
    """
    td = registry.get("idp.reset_password")
    assert td is not None
    assert td.reverse_tool is None
    assert td.is_reversible is False
    assert td.is_forward_only is True, (
        "idp.reset_password should carry a forward_only_reason; without it "
        "the rollback service can't tell the difference between 'we forgot "
        "to wire a reverse' and 'this is intentionally one-way'"
    )
    assert td.forward_only_reason is not None
    documented_reason = td.forward_only_reason

    with Session(engine) as db:
        case_id = _make_case(db)
        responder = ResponderAgent(db=db, case_id=case_id, tenant_id=TENANT)

        result = await responder.call_tool(
            "idp.reset_password",
            {"user": "bob@corp.example"},
            rationale="credential compromise suspected",
        )
        # MockIdpConnector returns a result dict; we just care it succeeded.
        assert isinstance(result, dict)

        tc = db.exec(
            select(ToolCall)
            .where(ToolCall.case_id == case_id)
            .where(ToolCall.tool_name == "idp.reset_password")
            .order_by(ToolCall.id.desc())  # type: ignore[attr-defined]
        ).first()
        assert tc is not None and tc.id is not None
        assert tc.success is True

        verdict = rollback_eligibility(db, tc.id)
        assert not verdict.eligible
        # The verdict reason must (a) say it's forward-only by design, not
        # blame a "missing handler", and (b) carry the actual documented
        # justification through so it shows up in the audit trail.
        assert "forward-only by design" in verdict.reason, verdict.reason
        assert documented_reason in verdict.reason, (
            f"documented forward_only_reason was not propagated into the "
            f"eligibility verdict; got: {verdict.reason!r}"
        )
        print(
            "OK  idp.reset_password forward-only reason propagated into "
            "rollback eligibility verdict"
        )

        try:
            await execute_rollback(db, tool_call_id=tc.id, actor="user:alice")
        except RollbackNotEligible as exc:
            assert exc.code == "INELIGIBLE"
            assert "forward-only by design" in str(exc), str(exc)
            print(
                "OK  execute_rollback refused forward-only WRITE_SIGNIFICANT "
                "with documented reason"
            )
        else:
            raise AssertionError(
                "execute_rollback on idp.reset_password should be ineligible"
            )


async def _check_email_clawback_restore_cycle() -> None:
    """``email.clawback_message`` ↔ ``email.restore_message`` pairing.

    Exercises a second connector family to make sure the reverse-params
    builder works against real forward params (``message_id``) without
    leaking forward kwargs the reverse tool does not accept.
    """
    with Session(engine) as db:
        case_id = _make_case(db)
        responder = ResponderAgent(db=db, case_id=case_id, tenant_id=TENANT)

        await responder.call_tool(
            "email.clawback_message",
            {"message_id": "msg-phish-42"},
            rationale="confirmed phishing",
        )
        tc = db.exec(
            select(ToolCall)
            .where(ToolCall.case_id == case_id)
            .where(ToolCall.tool_name == "email.clawback_message")
            .order_by(ToolCall.id.desc())  # type: ignore[attr-defined]
        ).first()
        assert tc is not None and tc.id is not None

        verdict = rollback_eligibility(db, tc.id)
        assert verdict.eligible, verdict.reason
        assert verdict.reverse_tool == "email.restore_message"
        assert verdict.reverse_params_preview.get("message_id") == "msg-phish-42"

        rb = await execute_rollback(
            db, tool_call_id=tc.id, actor="user:alice@cyble.com"
        )
        assert rb["reverse_tool"] == "email.restore_message"
        assert rb["result"].get("message_id") == "msg-phish-42"
        print("OK  email.clawback_message ↔ email.restore_message pairing")


async def _check_list_filters() -> None:
    """``list_rollback_eligible`` excludes rolled-back + rollback rows."""
    with Session(engine) as db:
        rows = list_rollback_eligible(
            db, tenant_ids=[TENANT], limit=50, include_ineligible=False
        )
        # All prior cycles rolled back their forward action, so the
        # eligible list should be empty for this tenant by default.
        assert rows == [], (
            f"expected no eligible forward rows left; got {len(rows)}"
        )

        rows_inel = list_rollback_eligible(
            db, tenant_ids=[TENANT], limit=50, include_ineligible=True
        )
        # We expect at least the EDR + email + reset_password forwards.
        names = {tc.tool_name for tc, _ in rows_inel}
        assert "edr.isolate_host" in names, names
        assert "email.clawback_message" in names, names
        assert "idp.reset_password" in names, names
        # And we expect NO rollback rows surface as candidates ever.
        for tc, _ in rows_inel:
            assert tc.rollback_of_id is None, (
                f"rollback row {tc.id} leaked into list_rollback_eligible"
            )

        # Tenant isolation: an unknown tenant sees nothing.
        rows_other = list_rollback_eligible(
            db, tenant_ids=["tenant-other"], limit=50, include_ineligible=True
        )
        assert rows_other == [], (
            f"tenant isolation broken: got {len(rows_other)} rows for other tenant"
        )
        print(
            "OK  list_rollback_eligible: tenant-scoped, hides rolled-back "
            "by default, never returns rollback rows"
        )


async def _main() -> None:
    init_db()
    await _check_edr_isolate_release_cycle()
    await _check_non_reversible_significant()
    await _check_email_clawback_restore_cycle()
    await _check_list_filters()
    print("\nALL ROLLBACK SMOKE CHECKS PASSED")


if __name__ == "__main__":
    asyncio.run(_main())
