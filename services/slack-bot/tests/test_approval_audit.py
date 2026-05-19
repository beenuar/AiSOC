"""
Unit tests for the approval audit sink (T3.6 audit trail contract).
"""

from __future__ import annotations

import pytest
from app.services.approval_audit import (
    ApprovalAuditEvent,
    InMemoryAuditSink,
    NullAuditSink,
    StructlogAuditSink,
)


def test_event_as_dict_includes_required_fields():
    event = ApprovalAuditEvent(
        case_id="case-1",
        action_id="action-1",
        approver_id="U42",
        decision="approved",
        channel="C7",
        actor_ip="10.0.0.1",
    )
    d = event.as_dict()
    for key in ("case_id", "action_id", "approver_id", "decision", "channel", "actor_ip", "source", "timestamp"):
        assert key in d, f"audit event missing {key}"
    assert d["source"] == "slack"


def test_event_as_dict_omits_optional_fields_when_unset():
    event = ApprovalAuditEvent(case_id="c", action_id="a", approver_id="u", decision="approved")
    d = event.as_dict()
    assert "error" not in d
    assert "metadata" not in d


@pytest.mark.asyncio
async def test_in_memory_sink_records_events():
    sink = InMemoryAuditSink()
    e1 = ApprovalAuditEvent(case_id="c1", action_id="a1", approver_id="u1", decision="approved")
    e2 = ApprovalAuditEvent(case_id="c2", action_id="a2", approver_id="u2", decision="rejected")
    await sink.record(e1)
    await sink.record(e2)
    assert sink.events == [e1, e2]


@pytest.mark.asyncio
async def test_null_sink_no_op():
    await NullAuditSink().record(ApprovalAuditEvent(case_id="c", action_id="a", approver_id="u", decision="approved"))


@pytest.mark.asyncio
async def test_structlog_sink_emits_event(caplog):
    class _CapturingLogger:
        def __init__(self) -> None:
            self.calls: list[tuple[str, dict]] = []

        def info(self, event: str, **fields) -> None:
            self.calls.append((event, fields))

        def error(self, event: str, **fields) -> None:
            self.calls.append((event, fields))

    logger = _CapturingLogger()
    sink = StructlogAuditSink(logger=logger)
    await sink.record(
        ApprovalAuditEvent(
            case_id="case-99",
            action_id="act-99",
            approver_id="U99",
            decision="approved",
            channel="C7",
            actor_ip="1.2.3.4",
        )
    )
    assert len(logger.calls) == 1
    event, fields = logger.calls[0]
    assert event == "aisoc.approval_decision"
    assert fields["case_id"] == "case-99"
    assert fields["decision"] == "approved"
    assert fields["approver_id"] == "U99"
    assert fields["actor_ip"] == "1.2.3.4"


@pytest.mark.asyncio
async def test_structlog_sink_swallows_logger_failure():
    class _BrokenLogger:
        def info(self, event, **fields):
            raise RuntimeError("logger pipe closed")

        def error(self, event, **fields):
            pass

    sink = StructlogAuditSink(logger=_BrokenLogger())
    # Should not raise.
    await sink.record(ApprovalAuditEvent(case_id="c", action_id="a", approver_id="u", decision="approved"))
