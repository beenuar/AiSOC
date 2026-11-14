"""The asset-context stamp: engine wiring + the resolver's real SQL.

Two halves, two kinds of evidence:

* The **engine** half uses a fake resolver, which is honest here because the
  property under test is the wiring — the stamp lands on
  ``fused.enrichments`` before the scorer reads it, and a resolver failure
  leaves the "unknown" factor in place rather than failing the alert.
* The **resolver** half runs its real SQL against live Postgres (the same
  ``assets`` table the console import writes), because the name/FQDN/IP match
  and the tenant predicate are schema facts a fake pool would invent. Skips
  without a database rather than passing without one; runs in
  ``integration.yml``'s migrations job.
"""

from __future__ import annotations

import os
import uuid
from typing import Any

import pytest
from app.models.alert import AlertSeverity, RawAlert
from app.services.fusion_engine import FusionEngine

DSN = (os.environ.get("DATABASE_URL", "") or "").replace("postgresql+asyncpg://", "postgresql://")
REQUIRED = os.environ.get("MSSP_ISOLATION_REQUIRED", "").strip() not in ("", "0", "false")

TENANT = uuid.UUID("0e700000-0000-0000-0000-0000000000e1")
OTHER = uuid.UUID("0e700000-0000-0000-0000-0000000000e2")


def _alert(**over: Any) -> RawAlert:
    base: dict[str, Any] = {
        "tenant_id": TENANT,
        "source": "edr",
        "title": "Suspicious PowerShell",
        "severity": AlertSeverity.HIGH,
        "hostname": "prod-dc-01",
    }
    base.update(over)
    return RawAlert(**base)


class _NullDedup:
    async def is_duplicate(self, _alert):  # noqa: ANN001, ANN202
        return False, None

    async def register(self, _alert):  # noqa: ANN001, ANN202
        return None


class _NullCorrelator:
    async def correlate(self, alert):  # noqa: ANN001, ANN202
        from app.models.alert import IncidentSummary

        return False, IncidentSummary(id=uuid.uuid4(), tenant_id=alert.tenant_id, title="t", severity=alert.severity)


# ─── Engine wiring (fake resolver — the property is the wiring) ──────────────


class _FixedResolver:
    def __init__(self, result: dict[str, Any] | None = None, *, boom: bool = False) -> None:
        self._result = result
        self._boom = boom

    async def resolve(self, _alert):  # noqa: ANN001, ANN202
        if self._boom:
            raise RuntimeError("inventory store down")
        return self._result


@pytest.mark.asyncio
async def test_the_stamp_lands_before_the_scorer_reads_it() -> None:
    engine = FusionEngine(
        _NullDedup(),  # type: ignore[arg-type]  # duck-typed double; the wiring is under test
        _NullCorrelator(),  # type: ignore[arg-type]
        asset_resolver=_FixedResolver({"criticality": "critical", "matched": "prod-dc-01"}),
    )
    fused = await engine.process(_alert())
    assert fused.enrichments["asset_context"] == {"criticality": "critical", "matched": "prod-dc-01"}
    factor = next(f for f in fused.confidence_rationale if f.factor == "asset_criticality")
    assert factor.value == "critical"
    assert factor.contribution == 1.0


@pytest.mark.asyncio
async def test_a_resolver_failure_leaves_the_honest_unknown() -> None:
    engine = FusionEngine(
        _NullDedup(),  # type: ignore[arg-type]  # duck-typed double; the wiring is under test
        _NullCorrelator(),  # type: ignore[arg-type]
        asset_resolver=_FixedResolver(boom=True),
    )
    fused = await engine.process(_alert())
    assert "asset_context" not in fused.enrichments
    factor = next(f for f in fused.confidence_rationale if f.factor == "asset_criticality")
    assert factor.value == "unknown (no inventory match)"
    assert factor.contribution == 0.0


@pytest.mark.asyncio
async def test_no_resolver_configured_is_the_same_unknown() -> None:
    engine = FusionEngine(
        _NullDedup(),  # type: ignore[arg-type]  # duck-typed double; the wiring is under test
        _NullCorrelator(),  # type: ignore[arg-type]
    )
    fused = await engine.process(_alert())
    factor = next(f for f in fused.confidence_rationale if f.factor == "asset_criticality")
    assert factor.value == "unknown (no inventory match)"
