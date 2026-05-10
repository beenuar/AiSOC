"""Tests for the Sigma bulk-import service (WS-B1).

Two layers of coverage:

1. **Pure-function tests** — exercise the normalisation helpers
   (MITRE extraction, severity mapping, category bucketing,
   provenance shape) without touching the DB. These are the
   contract the orchestrator and API endpoint rely on.

2. **End-to-end pipeline test** — runs the full ``import_sigma_rules``
   call against an in-memory SQLite database. Verifies idempotency
   (re-import becomes update, not duplicate), partial-failure
   isolation (one bad rule doesn't sink the batch), and report
   shape.

We deliberately test against SQLite rather than the real Postgres
JSONB index because the *behavioural* contract is what matters for
this layer — the index is verified by the migration's existence and
the index's syntax (covered separately when migrations are applied
in the integration env).
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
import pytest_asyncio
from app.models.detection_rule import DetectionRule
from app.services.detections import sigma_import as si
from app.services.detections.ocsf_mapping import OcsfClassUid
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker

# ─── SQLite-friendly compilation overrides for PG types ─────────────────────
#
# The model uses Postgres-only types (``JSONB``, ``UUID``) for production
# fidelity. For these tests we run against in-memory SQLite, so we register
# fallback DDL compilation hooks: JSONB → TEXT (we serialise JSON in the
# Python layer), UUID → CHAR(36). This is enough fidelity to exercise the
# persistence path; the JSONB index in migration 036 is a Postgres-only
# optimisation and not behavioural.
#
# These hooks are installed at module import time and are idempotent —
# pytest can re-import this file safely.


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(_type_, _compiler_, **_kw_):
    return "TEXT"


@compiles(UUID, "sqlite")
def _compile_uuid_sqlite(_type_, _compiler_, **_kw_):
    return "CHAR(36)"


# ─── Fixtures ────────────────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def session() -> AsyncSession:
    """In-memory SQLite session with the detection_rules schema.

    The ``@compiles`` overrides above let SQLAlchemy emit valid SQLite
    DDL for the PG-specific column types in :class:`DetectionRule`.
    """
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    async with engine.begin() as conn:
        # Only create the detection_rules table — we don't need the
        # rest of the schema, and creating everything pulls in models
        # (alerts, etc.) that have FK constraints on tenants.
        await conn.run_sync(lambda sync_conn: DetectionRule.__table__.create(sync_conn))

    Session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)  # type: ignore[call-overload]
    async with Session() as s:
        yield s
    await engine.dispose()


def _stable_sigma_rule(
    *,
    rule_id: str = "11111111-2222-3333-4444-555555555555",
    title: str = "Suspicious PowerShell Encoded Command",
    status: str = "stable",
    level: str = "high",
    product: str = "windows",
    category: str = "process_creation",
) -> dict[str, Any]:
    """Build a minimal but realistic Sigma rule dict."""
    return {
        "title": title,
        "id": rule_id,
        "status": status,
        "description": "Detects encoded PowerShell command-line invocations.",
        "references": ["https://attack.mitre.org/techniques/T1059/001/"],
        "author": "Test Suite",
        "date": "2024/01/01",
        "logsource": {"product": product, "category": category},
        "detection": {
            "selection": {
                "Image|endswith": "\\powershell.exe",
                "CommandLine|contains": " -EncodedCommand ",
            },
            "condition": "selection",
        },
        "level": level,
        "tags": [
            "attack.execution",
            "attack.t1059.001",
            "attack.defense_evasion",
            "attack.t1027",
        ],
        "falsepositives": ["Legitimate admin scripts"],
    }


# ─── Pure-function tests ─────────────────────────────────────────────────────


class TestExtractMitreTechniques:
    def test_extracts_techniques_and_subtechniques(self) -> None:
        techniques = si._extract_mitre_techniques(["attack.t1078", "attack.t1078.004", "attack.execution"])
        # Tactic tag (``attack.execution``) is not a technique and is
        # skipped. Sub-technique stays as-is, parent stays as-is.
        assert techniques == ["T1078", "T1078.004"]

    def test_dedupes_preserving_order(self) -> None:
        techniques = si._extract_mitre_techniques(["attack.t1078", "attack.t1078", "attack.t1027"])
        assert techniques == ["T1078", "T1027"]

    def test_ignores_garbage_tags(self) -> None:
        techniques = si._extract_mitre_techniques(
            ["attack.tasdf", "attack.", "not-a-tag", 42, None]  # type: ignore[list-item]
        )
        assert techniques == []

    def test_empty_input_returns_empty_list(self) -> None:
        assert si._extract_mitre_techniques(None) == []
        assert si._extract_mitre_techniques([]) == []


class TestExtractMitreTactics:
    def test_recognises_canonical_tactics(self) -> None:
        tactics = si._extract_mitre_tactics(["attack.execution", "attack.persistence", "attack.t1078"])
        # Technique tags are ignored here (handled by the technique
        # extractor); tactic tags become TA-codes.
        assert tactics == ["TA0002", "TA0003"]

    def test_ignores_unknown_tactic_names(self) -> None:
        tactics = si._extract_mitre_tactics(["attack.g0007", "attack.s0001"])
        assert tactics == []


class TestSeverityMap:
    @pytest.mark.parametrize(
        "level,expected",
        [
            ("low", "low"),
            ("informational", "low"),
            ("medium", "medium"),
            ("high", "high"),
            ("critical", "critical"),
            ("garbage", "medium"),  # unknown → safe medium, never critical
            (None, "medium"),
            ("", "medium"),
        ],
    )
    def test_severity_normalisation(self, level: Any, expected: str) -> None:
        assert si._map_severity(level) == expected


class TestCategoryFor:
    @pytest.mark.parametrize(
        "logsource,expected",
        [
            ({"product": "windows"}, "endpoint"),
            ({"product": "aws"}, "cloud"),
            ({"product": "okta"}, "identity"),
            ({"category": "proxy"}, "network"),
            ({"category": "webserver"}, "application"),
            ({}, "endpoint"),
            (None, "endpoint"),
        ],
    )
    def test_category_bucket(self, logsource: dict | None, expected: str) -> None:
        assert si._category_for(logsource) == expected


class TestNormaliseRule:
    def test_happy_path_produces_full_record(self) -> None:
        rule = _stable_sigma_rule()
        normalised = si._normalise_rule(
            rule,
            source="SigmaHQ/sigma",
            source_commit="abcdef1234567890",
            license_id="DRL-1.1",
            license_url="https://example/license",
            upstream_path="rules/windows/process_creation/proc_creation_win_powershell_encoded.yml",
        )

        assert normalised is not None
        assert normalised.name == "Suspicious PowerShell Encoded Command"
        assert normalised.severity == "high"
        assert normalised.category == "endpoint"
        assert normalised.status == "testing"  # stable upstream → testing here
        assert normalised.mitre_techniques == ["T1059.001", "T1027"]
        assert normalised.mitre_tactics == ["TA0002", "TA0005"]

        # Provenance shape — this is the public contract for re-import
        # idempotency and the WS-B3 management UI.
        prov = normalised.provenance
        assert prov["source"] == "SigmaHQ/sigma"
        assert prov["source_id"] == rule["id"]
        assert prov["license"] == "DRL-1.1"
        assert prov["license_url"] == "https://example/license"
        assert prov["imported_by"] == "sigma_import_service"
        assert prov["upstream_status"] == "stable"
        assert prov["upstream_path"].startswith("rules/")
        assert prov["ocsf"]["class_uid"] == OcsfClassUid.PROCESS_ACTIVITY

    def test_experimental_status_quarantines_rule(self) -> None:
        rule = _stable_sigma_rule(status="experimental")
        normalised = si._normalise_rule(
            rule,
            source="SigmaHQ/sigma",
            source_commit="abc",
            license_id="DRL-1.1",
            license_url="https://x",
            upstream_path=None,
        )
        assert normalised is not None
        # Quarantined rules land in the table but disabled — the
        # operator must opt them in.
        assert normalised.status == "disabled"
        assert normalised.enabled is False

    @pytest.mark.parametrize("status", ["deprecated", "unsupported"])
    def test_skipped_statuses_return_none(self, status: str) -> None:
        rule = _stable_sigma_rule(status=status)
        normalised = si._normalise_rule(
            rule,
            source="SigmaHQ/sigma",
            source_commit="abc",
            license_id="DRL-1.1",
            license_url="https://x",
            upstream_path=None,
        )
        assert normalised is None

    def test_missing_detection_block_skips(self) -> None:
        rule = _stable_sigma_rule()
        rule.pop("detection")
        normalised = si._normalise_rule(
            rule,
            source="SigmaHQ/sigma",
            source_commit="abc",
            license_id="DRL-1.1",
            license_url="https://x",
            upstream_path=None,
        )
        assert normalised is None


# ─── End-to-end pipeline tests ───────────────────────────────────────────────


class TestImportSigmaRulesPipeline:
    @pytest.mark.asyncio
    async def test_inserts_new_rules(self, session: AsyncSession) -> None:
        rules = [_stable_sigma_rule(rule_id=f"00000000-0000-0000-0000-00000000000{i}") for i in range(3)]
        report = await si.import_sigma_rules(session, rules, source="SigmaHQ/sigma")

        assert report.total_seen == 3
        assert len(report.inserted) == 3
        assert len(report.updated) == 0
        assert len(report.failures) == 0

        result = await session.execute(select(DetectionRule))
        rows = list(result.scalars().all())
        assert len(rows) == 3
        # Provenance is populated for every imported rule.
        for row in rows:
            assert row.provenance["source"] == "SigmaHQ/sigma"
            assert row.rule_language == "sigma"
            assert row.is_builtin is False

    @pytest.mark.asyncio
    async def test_reimport_is_idempotent(self, session: AsyncSession) -> None:
        rules = [_stable_sigma_rule()]
        # First run inserts.
        first = await si.import_sigma_rules(session, rules)
        assert len(first.inserted) == 1
        first_id = first.inserted[0].rule_id

        # Second run with the same input should update, not insert.
        second = await si.import_sigma_rules(session, rules)
        assert len(second.inserted) == 0
        assert len(second.updated) == 1
        assert second.updated[0].rule_id == first_id

        # Only one row in the table.
        result = await session.execute(select(DetectionRule))
        assert len(list(result.scalars().all())) == 1

    @pytest.mark.asyncio
    async def test_update_bumps_version(self, session: AsyncSession) -> None:
        rules = [_stable_sigma_rule()]
        await si.import_sigma_rules(session, rules)
        await si.import_sigma_rules(session, rules)

        result = await session.execute(select(DetectionRule))
        row = result.scalar_one()
        # First import = v1; second import bumps to 2.
        assert row.version == 2

    @pytest.mark.asyncio
    async def test_partial_failure_isolation(self, session: AsyncSession) -> None:
        """One malformed rule must not sink the batch."""
        good = _stable_sigma_rule(rule_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        bad_no_id: dict[str, Any] = {"title": "no id here", "detection": {"sel": {"a": "b"}, "condition": "sel"}}
        bad_not_dict = "not even a dict"

        report = await si.import_sigma_rules(
            session,
            [good, bad_no_id, bad_not_dict],  # type: ignore[list-item]
        )
        assert len(report.inserted) == 1
        assert len(report.failures) == 2
        # Failures carry a reason string for the operator.
        assert all(isinstance(f.get("reason"), str) for f in report.failures)

    @pytest.mark.asyncio
    async def test_skipped_rules_appear_in_report(self, session: AsyncSession) -> None:
        deprecated = _stable_sigma_rule(status="deprecated")
        report = await si.import_sigma_rules(session, [deprecated])
        assert len(report.skipped) == 1
        assert "deprecated" in (report.skipped[0].reason or "")
        assert report.total_persisted == 0

    @pytest.mark.asyncio
    async def test_report_to_dict_is_json_safe(self, session: AsyncSession) -> None:
        report = await si.import_sigma_rules(session, [_stable_sigma_rule()])
        out = report.to_dict()
        # API endpoint will serialise this directly; make sure shape
        # matches what the OpenAPI schema will document.
        assert out["summary"] == {
            "total_seen": 1,
            "inserted": 1,
            "updated": 0,
            "skipped": 0,
            "failures": 0,
        }
        assert out["inserted"][0]["action"] == "inserted"
        assert isinstance(out["inserted"][0]["rule_id"], str)

    @pytest.mark.asyncio
    async def test_non_list_input_raises(self, session: AsyncSession) -> None:
        with pytest.raises(si.SigmaImportError):
            await si.import_sigma_rules(session, "not a list")  # type: ignore[arg-type]

    @pytest.mark.asyncio
    async def test_tenant_scoped_rules_do_not_clash(self, session: AsyncSession) -> None:
        """Re-importing the same upstream rule for two different tenants
        produces two rows, not one. The provenance index includes the
        ``(source, source_id)`` lookup but the existence check is
        further scoped by ``tenant_id``."""
        rules = [_stable_sigma_rule()]
        tenant_a = uuid.uuid4()
        tenant_b = uuid.uuid4()

        await si.import_sigma_rules(session, rules, tenant_id=tenant_a)
        await si.import_sigma_rules(session, rules, tenant_id=tenant_b)

        result = await session.execute(select(DetectionRule))
        rows = list(result.scalars().all())
        assert len(rows) == 2
        tenant_ids = {r.tenant_id for r in rows}
        assert tenant_ids == {tenant_a, tenant_b}
