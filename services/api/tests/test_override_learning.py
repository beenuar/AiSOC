"""Tests for the analyst-override learning service (Tier 1.5).

Covers:
* Signature derivation from alerts (category + connector_type + primary technique).
* Empty / partial signatures don't generalise.
* :func:`find_redisposition_candidates` matches alerts that share a signature
  and excludes ones already on the new disposition.
* :func:`apply_redisposition` is a bulk no-op when the id list is empty.

Pure-logic tests live in this file. End-to-end DB persistence is exercised via
the broader API integration suite once a Postgres fixture is in place.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.services.memory_poisoning import compute_confirmation_token
from app.services.override_learning import (
    AlertSignature,
    RedispositionCandidate,
    apply_redisposition,
    find_redisposition_candidates,
)


def _alert(
    *,
    alert_id: uuid.UUID | None = None,
    category: str | None = "credential_access",
    connector_type: str | None = "okta",
    techniques: list[str] | None = None,
    disposition: str | None = None,
    title: str = "Suspicious sign-in",
    severity: str = "medium",
):
    """Build a stand-in for the Alert ORM row using SimpleNamespace.

    The override learning service only reads attributes, never persists, so a
    namespace is enough for unit-level coverage.
    """
    return SimpleNamespace(
        id=alert_id or uuid.uuid4(),
        category=category,
        connector_type=connector_type,
        mitre_techniques=techniques if techniques is not None else ["T1078"],
        disposition=disposition,
        title=title,
        severity=severity,
        event_time=datetime.now(UTC),
    )


class TestAlertSignature:
    def test_normalises_case_and_whitespace(self):
        alert = _alert(category="  Credential_Access  ", connector_type="OKTA  ", techniques=[" t1078 "])
        sig = AlertSignature.from_alert(alert)
        assert sig.category == "credential_access"
        assert sig.connector_type == "okta"
        assert sig.primary_technique == "T1078"

    def test_empty_when_all_blank(self):
        alert = _alert(category=None, connector_type=None, techniques=[])
        sig = AlertSignature.from_alert(alert)
        assert sig.is_empty() is True

    def test_partial_signature_is_not_empty(self):
        alert = _alert(category="malware", connector_type=None, techniques=[])
        sig = AlertSignature.from_alert(alert)
        assert sig.is_empty() is False

    def test_memory_key_is_deterministic(self):
        a = _alert(category="malware", connector_type="crowdstrike", techniques=["T1059"])
        b = _alert(category="MALWARE", connector_type="CrowdStrike", techniques=["t1059"])
        assert AlertSignature.from_alert(a).memory_key() == AlertSignature.from_alert(b).memory_key()

    def test_memory_key_changes_with_signature(self):
        a = _alert(category="malware", connector_type="crowdstrike", techniques=["T1059"])
        b = _alert(category="malware", connector_type="crowdstrike", techniques=["T1027"])
        assert AlertSignature.from_alert(a).memory_key() != AlertSignature.from_alert(b).memory_key()

    def test_tags_include_all_signature_components(self):
        alert = _alert(category="malware", connector_type="crowdstrike", techniques=["T1059"])
        tags = AlertSignature.from_alert(alert).tags()
        assert "analyst_override" in tags
        assert "category:malware" in tags
        assert "connector:crowdstrike" in tags
        assert "T1059" in tags


class TestRedispositionCandidate:
    def test_to_dict_round_trips(self):
        c = RedispositionCandidate(
            alert_id="abc",
            title="t",
            severity="medium",
            current_disposition=None,
            proposed_disposition="false_positive",
            event_time="2026-01-01T00:00:00",
        )
        d = c.to_dict()
        assert d["alert_id"] == "abc"
        assert d["proposed_disposition"] == "false_positive"
        assert d["current_disposition"] is None


@pytest.mark.asyncio
class TestFindRedispositionCandidates:
    async def test_empty_signature_returns_empty_list(self):
        sig = AlertSignature(category="", connector_type="", primary_technique="")
        db = MagicMock()
        result = await find_redisposition_candidates(
            db,
            tenant_id=uuid.uuid4(),
            signature=sig,
            corrected_verdict="false_positive",
            exclude_alert_id=uuid.uuid4(),
        )
        assert result == []

    async def test_filters_out_alerts_missing_primary_technique(self):
        # Two alerts share category+connector but only one shares the primary
        # technique. Only the matching one should appear.
        match = _alert(category="malware", connector_type="crowdstrike", techniques=["T1059"])
        miss = _alert(category="malware", connector_type="crowdstrike", techniques=["T1027"])

        scalars_result = MagicMock()
        scalars_result.all = MagicMock(return_value=[match, miss])
        db = MagicMock()
        db.scalars = AsyncMock(return_value=scalars_result)

        sig = AlertSignature(
            category="malware",
            connector_type="crowdstrike",
            primary_technique="T1059",
        )
        result = await find_redisposition_candidates(
            db,
            tenant_id=uuid.uuid4(),
            signature=sig,
            corrected_verdict="false_positive",
            exclude_alert_id=uuid.uuid4(),
        )
        assert len(result) == 1
        assert result[0].alert_id == str(match.id)

    async def test_respects_limit(self):
        sig = AlertSignature(
            category="malware",
            connector_type="crowdstrike",
            primary_technique="T1059",
        )
        rows = [_alert(category="malware", connector_type="crowdstrike", techniques=["T1059"]) for _ in range(20)]
        scalars_result = MagicMock()
        scalars_result.all = MagicMock(return_value=rows)
        db = MagicMock()
        db.scalars = AsyncMock(return_value=scalars_result)

        result = await find_redisposition_candidates(
            db,
            tenant_id=uuid.uuid4(),
            signature=sig,
            corrected_verdict="false_positive",
            exclude_alert_id=uuid.uuid4(),
            limit=5,
        )
        assert len(result) == 5


@pytest.mark.asyncio
class TestApplyRedisposition:
    async def test_no_ids_short_circuits(self):
        db = MagicMock()
        db.execute = AsyncMock()
        db.commit = AsyncMock()
        rowcount = await apply_redisposition(
            db,
            tenant_id=uuid.uuid4(),
            alert_ids=[],
            new_disposition="false_positive",
            analyst_id=None,
            confirmation_token="",
        )
        assert rowcount == 0
        db.execute.assert_not_awaited()
        db.commit.assert_not_awaited()

    async def test_returns_rowcount_from_execute(self):
        result = MagicMock()
        result.rowcount = 7
        db = MagicMock()
        db.execute = AsyncMock(return_value=result)
        db.commit = AsyncMock()

        ids = [uuid.uuid4(), uuid.uuid4()]
        token = compute_confirmation_token([str(i) for i in ids], "false_positive")
        rowcount = await apply_redisposition(
            db,
            tenant_id=uuid.uuid4(),
            alert_ids=ids,
            new_disposition="false_positive",
            analyst_id=uuid.uuid4(),
            confirmation_token=token,
        )
        assert rowcount == 7
        db.execute.assert_awaited_once()
        db.commit.assert_awaited_once()

    async def test_bad_token_is_rejected(self):
        db = MagicMock()
        db.execute = AsyncMock()
        db.commit = AsyncMock()
        with pytest.raises(ValueError, match="confirmation_token"):
            await apply_redisposition(
                db,
                tenant_id=uuid.uuid4(),
                alert_ids=[uuid.uuid4()],
                new_disposition="false_positive",
                analyst_id=None,
                confirmation_token="wrong",
            )
        db.execute.assert_not_awaited()

    async def test_batch_over_cap_is_rejected(self):
        db = MagicMock()
        db.execute = AsyncMock()
        db.commit = AsyncMock()
        ids = [uuid.uuid4() for _ in range(6)]
        token = compute_confirmation_token([str(i) for i in ids], "false_positive")
        with pytest.raises(ValueError, match="cap"):
            await apply_redisposition(
                db,
                tenant_id=uuid.uuid4(),
                alert_ids=ids,
                new_disposition="false_positive",
                analyst_id=None,
                confirmation_token=token,
                max_batch=5,
            )
        db.execute.assert_not_awaited()
