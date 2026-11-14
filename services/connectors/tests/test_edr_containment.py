"""Wave 0 — SentinelOne and Cortex XDR connectors must declare the containment
capabilities that services/actions can actually execute (honesty: no declared
capability without a live execution path)."""

from __future__ import annotations

from app.connectors.base import Capability
from app.connectors.cortex_xdr import CortexXDRConnector
from app.connectors.sentinelone import SentinelOneConnector


def test_sentinelone_declares_isolation_and_quarantine():
    caps = set(SentinelOneConnector.capabilities())
    assert Capability.PULL_ALERTS in caps
    assert Capability.ISOLATE_HOST in caps
    assert Capability.UNISOLATE_HOST in caps
    assert Capability.QUARANTINE_FILE in caps
    # S1 has no non-interactive script / PID-kill API — must NOT be claimed.
    assert Capability.RUN_SCRIPT not in caps
    assert Capability.KILL_PROCESS not in caps


def test_cortex_xdr_declares_isolation():
    caps = set(CortexXDRConnector.capabilities())
    assert Capability.PULL_ALERTS in caps
    assert Capability.ISOLATE_HOST in caps
    assert Capability.UNISOLATE_HOST in caps
