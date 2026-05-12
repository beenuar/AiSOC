"""
Schema-level tests for live-action models.

These are intentionally narrow — they pin the wire shape of
:class:`LiveActionRequest` / :class:`LiveActionResult` so a casual
field rename in ``models.py`` immediately fails CI rather than
silently breaking the agent loop or any deployed plugin that already
serialises to the old shape.
"""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest
from app.live_actions import (
    LiveActionDescriptor,
    LiveActionRequest,
    LiveActionResult,
    LiveActionStatus,
)


def test_request_defaults_are_safe():
    """A bare-minimum request must default to non-destructive values.

    Specifically: ``dry_run`` must default to ``False`` (so the agent
    has to *opt in* to simulation), but ``params`` and ``target`` must
    default to empty so the request is still valid for capabilities
    that don't need a target (e.g. ``pull_alerts``).
    """
    req = LiveActionRequest(capability="isolate_host", vendor_id="crowdstrike")
    assert req.dry_run is False
    assert req.params == {}
    assert req.target == ""
    assert req.requested_by == "system"
    assert isinstance(req.request_id, UUID)


def test_request_id_is_unique_per_instance():
    """Two requests must not share a request_id by accident.

    The dispatcher uses ``request_id`` as the audit-trail correlation
    key; collisions would silently merge unrelated executions in the
    log.
    """
    a = LiveActionRequest(capability="block_ip", vendor_id="aws_security_groups")
    b = LiveActionRequest(capability="block_ip", vendor_id="aws_security_groups")
    assert a.request_id != b.request_id


def test_result_carries_request_id_back():
    """The result must echo the request_id verbatim — the dispatcher
    relies on this for log correlation and in fact fixes it up if an
    executor returns the wrong id (see ``dispatcher.py``)."""
    rid = uuid4()
    res = LiveActionResult(
        request_id=rid,
        status=LiveActionStatus.SUCCEEDED,
        capability="isolate_host",
        vendor_id="crowdstrike",
        summary="ok",
    )
    assert res.request_id == rid


@pytest.mark.parametrize(
    "status_value",
    ["succeeded", "failed", "simulated"],
)
def test_status_enum_round_trip(status_value: str):
    """The string values must stay stable — the frontend filters and
    the playbook engine match on these exact strings."""
    s = LiveActionStatus(status_value)
    assert s.value == status_value


def test_descriptor_shape():
    """The discovery API response shape must include vendor_id,
    capability, description, source, requires_credentials. Anything
    less and the frontend can't render the action menu correctly."""
    d = LiveActionDescriptor(
        vendor_id="okta",
        capability="disable_user",
        description="Deactivate an Okta user.",
        source="builtin",
        requires_credentials=True,
    )
    payload = d.model_dump()
    assert set(payload.keys()) == {
        "vendor_id",
        "capability",
        "description",
        "source",
        "requires_credentials",
    }
