"""PR2: vulnerability findings are inventory with patch windows, not alerts.

Covers docs/cve-patch-policy.md end to end at the unit level:

* the calendar math (Patch Tuesday -> TEST Wednesday -> PROD +7d),
* the Wazuh stream split (detector events leave ``fetch_alerts`` and arrive
  on ``fetch_vulnerability_findings``),
* the inventory write (due date minted once, fail-closed environment),
* the promotion contract (one grouped alert per CVE, exception-path only).

HTTP routing uses ``respx`` exactly like ``test_wazuh_connector.py``.
"""

from __future__ import annotations

import re
from datetime import UTC, date, datetime

import httpx
import pytest
import respx
from app.connectors.base import Capability
from app.connectors.wazuh import WazuhConnector, is_vulnerability_source
from app.patch_calendar import (
    classify_environment,
    patch_due_for,
    patch_tuesday,
)
from app.patch_calendar import prod_patch_due_for as _prod_patch_due_for
from app.patch_calendar import test_patch_due_for as _test_patch_due_for

INDEXER = "https://wazuh.test.local:9200"
USERNAME = "admin"
PASSWORD = "wazuh-fake-password"


def _detector_hit(cve: str = "CVE-2024-0001", host: str = "prod-tmc-01", cvss=9.8) -> dict:
    return {
        "_id": "doc-vuln",
        "_index": "wazuh-alerts-4.x-2026.10.06",
        "_source": {
            "@timestamp": "2026-10-06T06:00:00.000Z",
            "agent": {"id": "002", "name": host, "ip": "10.0.0.5"},
            "rule": {
                "id": "20570",
                "level": 7,
                "description": f"{cve} affects linux-aws on {host}",
                "groups": ["vulnerability-detector", "vulnerability"],
            },
            "data": {
                "vulnerability": {
                    "cve": cve,
                    "severity": "Critical",
                    "cvss": {"cvss3": {"base_score": cvss}},
                }
            },
        },
    }


def _real_alert_hit() -> dict:
    return {
        "_id": "doc-alert",
        "_index": "wazuh-alerts-4.x-2026.10.06",
        "_source": {
            "@timestamp": "2026-10-06T06:05:00.000Z",
            "agent": {"id": "002", "name": "prod-tmc-01", "ip": "10.0.0.5"},
            "rule": {
                "id": "100100",
                "level": 12,
                "description": "Possible rootkit installation",
                "groups": ["rootcheck", "intrusion_attempt"],
            },
            "data": {"command": "modprobe evil"},
        },
    }


def _hits_response(hits: list[dict]):
    return httpx.Response(200, json={"hits": {"hits": hits}})


class TestTheCalendar:
    """The policy doc's concrete dates are the contract."""

    def test_patch_tuesdays_2026(self):
        assert patch_tuesday(2026, 10) == date(2026, 10, 13)
        assert patch_tuesday(2026, 11) == date(2026, 11, 10)
        assert patch_tuesday(2026, 12) == date(2026, 12, 8)

    def test_windows_match_the_policy_doc(self):
        # TEST: Oct 14, Nov 11, Dec 9 — PROD one week later.
        assert _test_patch_due_for(date(2026, 10, 1)) == date(2026, 10, 14)
        assert _test_patch_due_for(date(2026, 11, 1)) == date(2026, 11, 11)
        assert _test_patch_due_for(date(2026, 12, 1)) == date(2026, 12, 9)
        assert _prod_patch_due_for(date(2026, 10, 14)) == date(2026, 10, 21)
        assert _prod_patch_due_for(date(2026, 11, 11)) == date(2026, 11, 18)
        assert _prod_patch_due_for(date(2026, 12, 9)) == date(2026, 12, 16)

    def test_a_window_never_opens_in_the_past(self):
        # Found after October's window closed -> due in November's window.
        assert _test_patch_due_for(date(2026, 10, 20)) == date(2026, 11, 11)
        # December rolls the year.
        assert _test_patch_due_for(date(2026, 12, 20)) == date(2027, 1, 13)

    def test_environment_classification_fails_closed(self):
        assert classify_environment("dev-tmc-01") == "test"
        assert classify_environment("UAT-app-2") == "test"
        assert classify_environment("cbs-euw1-tmc-01") == "prod"
        assert classify_environment("mgi-tmc-02") == "prod"
        assert classify_environment(None) == "prod"

    def test_due_date_dispatches_by_environment(self):
        found = datetime(2026, 10, 6, 12, 0, tzinfo=UTC)
        assert patch_due_for(found, "test") == date(2026, 10, 14)
        assert patch_due_for(found, "prod") == date(2026, 10, 21)
        # unknown environment string behaves like prod (fail closed)
        assert patch_due_for(found, "garbage") == date(2026, 10, 21)


class TestTheStreamSplit:
    def test_wazuh_declares_the_vulnerability_capability(self):
        assert Capability.PULL_VULNERABILITIES in WazuhConnector.capabilities()

    def test_schema_offers_the_mode_knob(self):
        schema = WazuhConnector.schema()
        field = next((f for f in schema.fields if f.name == "vuln_mode"), None)
        assert field is not None, "operators have no way to see or set the mode"
        assert field.default == "inventory"

    def test_detector_events_are_recognised(self):
        assert is_vulnerability_source(_detector_hit()["_source"])
        assert not is_vulnerability_source(_real_alert_hit()["_source"])

    @pytest.mark.asyncio
    @respx.mock
    async def test_detector_events_leave_the_alert_stream(self):
        route = respx.post(f"{INDEXER}/wazuh-alerts-*/_search").mock(return_value=_hits_response([_detector_hit(), _real_alert_hit()]))
        connector = WazuhConnector(INDEXER, USERNAME, PASSWORD)
        events = await connector.fetch_alerts(since_seconds=300)

        assert route.called
        # The syscheck alert survives; the detector event does not.
        assert len(events) == 1
        assert events[0]["title"] == "Possible rootkit installation"
        # and the query itself asked the indexer to exclude the group, so
        # the 1000-hit page cap can't smuggle scan noise back in.
        body = route.calls.last.request.content.decode()
        assert "vulnerability-detector" in body

    @pytest.mark.asyncio
    @respx.mock
    async def test_legacy_mode_keeps_the_old_behaviour(self):
        route = respx.post(f"{INDEXER}/wazuh-alerts-*/_search").mock(return_value=_hits_response([_detector_hit(), _real_alert_hit()]))
        connector = WazuhConnector(INDEXER, USERNAME, PASSWORD, vuln_mode="alerts")
        events = await connector.fetch_alerts(since_seconds=300)

        assert len(events) == 2
        # ...and the findings path stays empty so nothing double-writes.
        assert await connector.fetch_vulnerability_findings() == []
        # the legacy query has no must_not — that's the point of the mode.
        body = route.calls[0].request.content.decode()
        assert "must_not" not in body

    @pytest.mark.asyncio
    @respx.mock
    async def test_findings_fetch_names_cve_host_and_cvss(self):
        route = respx.post(f"{INDEXER}/wazuh-alerts-*/_search").mock(
            return_value=_hits_response([_detector_hit(cve="CVE-2021-44228", host="dev-tmc-01")])
        )
        connector = WazuhConnector(INDEXER, USERNAME, PASSWORD)
        findings = await connector.fetch_vulnerability_findings()

        assert route.called
        assert len(findings) == 1
        f = findings[0]
        assert f["cve_id"] == "CVE-2021-44228"
        assert f["hostname"] == "dev-tmc-01"
        assert f["cvss_score"] == pytest.approx(9.8)
        assert f["severity"] == "critical"
        assert f["source"] == "wazuh"

    @pytest.mark.asyncio
    @respx.mock
    async def test_anonymous_events_are_skipped_not_guessed(self):
        hit = _detector_hit()
        del hit["_source"]["data"]["vulnerability"]["cve"]
        hit["_source"]["agent"] = {}
        respx.post(f"{INDEXER}/wazuh-alerts-*/_search").mock(return_value=_hits_response([hit]))
        connector = WazuhConnector(INDEXER, USERNAME, PASSWORD)

        assert await connector.fetch_vulnerability_findings() == []


class TestThePromotionContract:
    def test_sql_is_fail_closed_and_scoped(self):
        from app.vuln_promotion_sql import (
            MARK_OVERDUE_SQL,
            PROMOTE_CANDIDATES_SQL,
            UPSERT_ALERT_SQL,
        )

        for sql in (MARK_OVERDUE_SQL, PROMOTE_CANDIDATES_SQL, UPSERT_ALERT_SQL):
            assert "tenant_id" in sql, "every statement is tenant-scoped"
        # The exception path is spelled in the candidate query, not in a
        # prompt: overdue OR CVSS>9 OR exploited OR KEV.
        assert "patch_status IN ('overdue', 'promoted')" in PROMOTE_CANDIDATES_SQL
        assert "cvss_score > 9" in PROMOTE_CANDIDATES_SQL
        assert "is_exploited" in PROMOTE_CANDIDATES_SQL
        assert "threat_intel_iocs" in PROMOTE_CANDIDATES_SQL
        # one grouped alert per CVE via the idempotency key
        assert "ON CONFLICT (tenant_id, idempotency_key)" in UPSERT_ALERT_SQL
        assert "GROUP BY v.cve_id" in PROMOTE_CANDIDATES_SQL

    def test_no_statement_uses_the_colon_cast_spelling(self):
        """``:name::type`` is never substituted and reaches the driver verbatim.

        The assertions above are substring checks on the SQL text, and that is
        the whole reason ``UPSERT_ALERT_SQL`` could carry
        ``:affected_hosts::jsonb`` for its entire life while every test passed:
        the substring was present and correct, and the statement answered
        ``syntax error at or near ":"`` on every execution. This is the one
        property a text assertion *can* decide, so it is asserted here, and
        ``tests/test_vuln_promotion_live.py`` runs the statements for real.
        """
        from app import vuln_promotion_sql

        for name in vuln_promotion_sql.__all__:
            sql = getattr(vuln_promotion_sql, name)
            offenders = re.findall(r"(?<![:\w\\]):(\w+)::", sql)
            assert not offenders, f"{name}: {offenders} are written `:name::type`; use CAST(:name AS type)"

    @pytest.mark.asyncio
    async def test_the_scheduler_actually_registers_the_promotion_job(self):
        """Read off a real APScheduler after a real ``start()``.

        This asserted ``"_vuln_promotion_loop" in inspect.getsource(...)``,
        which proves the identifier appears in the file and nothing about
        whether a job exists. Driving ``start()`` is what makes the six-hour
        interval and the bound coroutine assertable.
        """
        import os

        from app.scheduler import ConnectorScheduler

        os.environ.pop("AISOC_CONNECTORS_LEADER_ELECTION", None)
        scheduler = ConnectorScheduler(
            engine=_NoRowsEngine(),
            ingest_client=_ClosableClient(),
            vault=object(),
        )
        await scheduler.start()
        try:
            job = scheduler._scheduler.get_job("_vuln_promotion_loop")  # noqa: SLF001
            assert job is not None, "the promotion sweep is not scheduled at all"
            assert job.func == scheduler._promote_overdue_findings  # noqa: SLF001
            assert job.trigger.interval.total_seconds() == 6 * 3600.0
        finally:
            await scheduler.stop()

    def test_inventory_insert_mints_the_window_once(self):
        from app.vulnerabilities import _INSERT_VULN, _TOUCH_VULN

        ins = str(_INSERT_VULN)
        assert "patch_due_date" in ins and "environment" in ins and "patch_status" in ins
        touch = str(_TOUCH_VULN)
        # A re-poll must never move the promised date or un-overdue a row.
        assert "patch_due_date" not in touch
        assert "patch_status" not in touch


class _NoRowsEngine:
    """An engine whose reads return nothing, so ``start()`` can run with no DB.

    Only the reload loop reads through it during startup; the promotion job
    this test is about is registered unconditionally.
    """

    def connect(self):  # noqa: ANN201
        return _NoRowsCtx()

    def begin(self):  # noqa: ANN201
        return _NoRowsCtx()


class _NoRowsCtx:
    async def __aenter__(self):  # noqa: ANN204
        return self

    async def __aexit__(self, *exc) -> bool:  # noqa: ANN002
        return False

    async def execute(self, *_args, **_kwargs):  # noqa: ANN202
        return self

    def scalars(self):  # noqa: ANN202
        return self

    def fetchall(self):  # noqa: ANN202
        return []

    def all(self):  # noqa: ANN202
        return []

    def mappings(self):  # noqa: ANN202
        return self


class _ClosableClient:
    """Enough of IngestClient for ``stop()`` to drain cleanly."""

    async def aclose(self) -> None:
        return None
