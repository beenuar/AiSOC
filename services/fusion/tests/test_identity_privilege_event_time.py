"""Regression: the privilege resolver must not raise on a normal alert.

resolve promises "never raises, never None" and stamps UNKNOWN instead.
It read alert.timestamp, an attribute RawAlert never had, so every alert
with a username hit AttributeError on the first line past the guards — the
warning surfaced downstream as RawAlert object has no attribute
timestamp while the alert lost its privilege stamp silently.
"""

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.models.alert import RawAlert
from app.services.identity_privilege_context import STAMP_KEY, IdentityPrivilegeResolver


def _alert(**kw) -> RawAlert:
    base = dict(
        tenant_id=uuid4(),
        source="unit",
        title="sign-in as an privileged principal",
        username="svc.backup",
    )
    base.update(kw)
    return RawAlert(**base)


@pytest.mark.asyncio
async def test_resolve_does_not_raise_on_plain_alert() -> None:
    resolver = IdentityPrivilegeResolver(dsn="postgresql://invalid:invalid@127.0.0.1:1/none")
    stamp = await resolver.resolve(_alert())  # must not raise AttributeError
    assert isinstance(stamp, dict) and stamp


@pytest.mark.asyncio
async def test_resolve_accepts_alerts_without_event_time() -> None:
    resolver = IdentityPrivilegeResolver(dsn="postgresql://invalid:invalid@127.0.0.1:1/none")
    stamp = await resolver.resolve(_alert(event_time=None))
    assert isinstance(stamp, dict) and stamp
