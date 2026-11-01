"""The retention route has to say whether anything actually deletes.

Wave 2, Phase 9.5.

`/data-lifecycle/retention` returned three numbers. `RETENTION_WORKER_ENABLED`
defaults to **false**, and the worker has a dry-run mode on top of that, so a
console rendering those three numbers beside a Save button would tell an
operator their raw events are deleted after 90 days when, on a default
deployment, nothing deletes at all.

The windows are not meaningless when the worker is off — compliance evidence
reads them — but "this is our stated retention policy" and "data older than
this is deleted" are different claims, and only the route knows which one is
true for the deployment the console is talking to.

The default matters most, and is asserted here rather than left implied: a
fresh deployment must report **not enforcing**, because that is the state
almost every reader of the page is in.
"""

from __future__ import annotations

import pytest
from app.api.v1.endpoints.data_lifecycle import RetentionOut, _worker_state
from app.core.config import settings


def test_default_deployment_reports_that_nothing_is_deleted():
    """A fresh deployment does not delete, and must say so."""
    assert settings.RETENTION_WORKER_ENABLED is False
    state = _worker_state()
    assert state["purge_worker_enabled"] is False


def test_worker_state_tracks_settings_rather_than_a_stored_copy(monkeypatch: pytest.MonkeyPatch):
    """Read from settings, so there is no second number that can disagree.

    Storing enforcement per tenant would let the console report a state the
    pod does not have — the "two surfaces disagreeing about the same fact"
    shape this repository keeps finding.
    """
    monkeypatch.setattr(settings, "RETENTION_WORKER_ENABLED", True, raising=True)
    monkeypatch.setattr(settings, "RETENTION_WORKER_DRY_RUN", False, raising=True)
    assert _worker_state() == {"purge_worker_enabled": True, "purge_worker_dry_run": False}


def test_dry_run_is_distinct_from_disabled(monkeypatch: pytest.MonkeyPatch):
    """Enabled-but-dry-run deletes nothing, and needs its own answer.

    Collapsing it into "enabled" would tell an operator their data is being
    deleted while the worker is only reporting what it would delete. The two
    need different next actions, so they stay two fields.
    """
    monkeypatch.setattr(settings, "RETENTION_WORKER_ENABLED", True, raising=True)
    monkeypatch.setattr(settings, "RETENTION_WORKER_DRY_RUN", True, raising=True)
    state = _worker_state()
    assert state["purge_worker_enabled"] is True
    assert state["purge_worker_dry_run"] is True


def test_response_model_carries_the_disclosure():
    """The fields are on the wire, not only in the helper.

    A helper nothing serialises is the "exists but nothing calls it" shape;
    this asserts the console can actually read the state.
    """
    payload = RetentionOut(raw_events_days=90, alerts_days=365, audit_days=730, **_worker_state()).model_dump()
    assert "purge_worker_enabled" in payload
    assert "purge_worker_dry_run" in payload
