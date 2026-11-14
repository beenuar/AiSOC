import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.bridge import (
    OPEN_STATUSES,
    Case,
    NagState,
    crit_payload,
    digest_payload,
    should_escalate_critical,
    should_send_digest,
)


def test_open_statuses_are_real_members_of_the_cases_check_constraint():
    """The first draft filtered on "open", a status aisoc_cases has never had —
    a filter member that can never match is invisible at runtime, so this pins
    OPEN_STATUSES against the migration's own CHECK clause. It also pins the
    one deliberate exclusion set: everything we leave out must be terminal."""
    migration = (
        # parents[2] is services/ — this file sits at services/escalations/tests/.
        Path(__file__).resolve().parents[2] / "api" / "migrations" / "012_case_management.sql"
    ).read_text(encoding="utf-8")
    m = re.search(r"status\s+TEXT[^)]*CHECK \(status IN \(([^)]+)\)\)", migration)
    assert m, "could not locate the aisoc_cases status CHECK in migration 012"
    vocabulary = set(re.findall(r"'([a-z_]+)'", m.group(1)))
    assert set(OPEN_STATUSES) <= vocabulary, f"OPEN_STATUSES not in the CHECK vocabulary: {set(OPEN_STATUSES) - vocabulary}"
    assert vocabulary - set(OPEN_STATUSES) == {"resolved", "closed"}, "a non-terminal status is missing from OPEN_STATUSES"


NOW = datetime(2026, 10, 31, 9, 0, tzinfo=UTC)


def _case(minutes_ago: int) -> Case:
    return Case("a" * 32, "AI-42", "admin brute force", "critical", NOW - timedelta(minutes=minutes_ago))


class TestCriticalLadder:
    def test_inside_grace_not_escalated(self):
        assert should_escalate_critical(_case(10), None, NOW) is False

    def test_past_grace_first_send(self):
        assert should_escalate_critical(_case(31), None, NOW) is True

    def test_no_nag_before_interval(self):
        nag = NagState(count=1, last=(NOW - timedelta(hours=1)).isoformat())
        assert should_escalate_critical(_case(120), nag, NOW) is False

    def test_nag_after_interval(self):
        nag = NagState(count=1, last=(NOW - timedelta(hours=5)).isoformat())
        assert should_escalate_critical(_case(600), nag, NOW) is True

    def test_nag_cap(self):
        nag = NagState(count=3, last=(NOW - timedelta(hours=5)).isoformat())
        assert should_escalate_critical(_case(600), nag, NOW) is False


class TestDigest:
    def test_before_hour(self):
        assert should_send_digest("", datetime(2026, 10, 31, 7, 59, tzinfo=UTC)) is False

    def test_at_hour(self):
        assert should_send_digest("", NOW) is True

    def test_same_day_suppressed(self):
        assert should_send_digest("2026-10-31", NOW) is False

    def test_next_day_fires(self):
        assert should_send_digest("2026-10-30", NOW) is True


class TestPayloads:
    def test_crit_payload_fields(self):
        p = crit_payload(_case(45), 45.0, 1)
        assert p["severity"] == "CRITICAL"
        assert p["case_id"] == "AI-42"
        assert p["url"].endswith("/cases/" + "a" * 32)
        assert "1/3" in p["summary"]

    def test_digest_truncates_list(self):
        cases = [_case(i) for i in range(10, 20)]
        p = digest_payload(cases, "dead-letters 24h: 0", NOW)
        assert p["severity"] == "DIGEST"
        assert "…and 2 more" in p["summary"]
