"""Every figure the portfolio computes has to survive serialisation.

`test_mssp_portfolio_isolation.py` proves the aggregation is right, but it
asserts on `TenantRollup` — the dataclass, one layer below the response model.
A field that is computed, tested, and absent from the `BaseModel` is dropped by
Pydantic without a word, and the service-layer test still passes. That is how
`mttr_minutes` reached review: measured by real SQL over `cases.closed_at`,
carried by `as_dict()`, present in `EMPTY_SUMMARY`, described in the route
comment and the CHANGELOG — and declared on neither `PortfolioTenantOut` nor
`PortfolioSummaryOut`, so no caller could ever read it.

These tests sit at the drop point: dict in, response model out, assert the
value is still there. No database, so they run in the ordinary API job rather
than only where a live Postgres is available.
"""

from __future__ import annotations

import uuid

from app.api.v1.endpoints.mssp import PortfolioSummaryOut, PortfolioTenantOut
from app.services.entitlements import Headroom
from app.services.mssp_portfolio import EMPTY_SUMMARY, TenantRollup, summarise


def _rollup(*, name: str = "Portfolio A", mttr: float | None = 42.5) -> TenantRollup:
    return TenantRollup(
        tenant_id=uuid.uuid4(),
        name=name,
        slug=name.lower().replace(" ", "-"),
        relationship="owner",
        is_active=True,
        open_alerts=3,
        critical_alerts=1,
        high_alerts=1,
        untriaged_alerts=2,
        synthetic_alerts=0,
        open_cases=2,
        sla_breached_cases=1,
        mttr_minutes=mttr,
        connectors_total=2,
        connectors_healthy=1,
        connectors_stale=1,
        connectors_error=0,
        last_event_at=None,
        limits=[Headroom(key="connectors", label="Connectors", used=2, limit=5, state="ok")],
    )


def test_a_tenant_row_carries_its_measured_mttr_to_the_wire() -> None:
    row = PortfolioTenantOut(**_rollup(mttr=42.5).as_dict())
    assert row.mttr_minutes == 42.5
    assert "mttr_minutes" in row.model_dump()


def test_a_tenant_that_closed_nothing_serialises_null_not_zero() -> None:
    """Null and 0.0 are opposite claims: "no data" and "instant resolution"."""
    row = PortfolioTenantOut(**_rollup(mttr=None).as_dict())
    assert row.mttr_minutes is None
    assert row.model_dump()["mttr_minutes"] is None


def test_the_summary_carries_its_mttr_to_the_wire() -> None:
    summary = PortfolioSummaryOut(**summarise([_rollup(mttr=20.0), _rollup(name="Portfolio B", mttr=40.0)]))
    assert summary.mttr_minutes == 30.0


def test_the_summary_mttr_skips_tenants_that_closed_nothing() -> None:
    """Averaging a null as zero would drag the portfolio figure toward a
    number nobody measured."""
    summary = PortfolioSummaryOut(**summarise([_rollup(mttr=20.0), _rollup(name="Portfolio B", mttr=None)]))
    assert summary.mttr_minutes == 20.0


def test_an_empty_portfolio_reports_no_mttr_rather_than_zero() -> None:
    summary = PortfolioSummaryOut(**EMPTY_SUMMARY)
    assert summary.mttr_minutes is None
    assert summary.tenants == 0


def test_every_key_the_service_emits_is_declared_on_the_response_model() -> None:
    """The general form of the bug, so the next dropped field fails here.

    Pydantic ignores unknown keys, so a service that starts emitting a new
    measurement gains a silent no-op rather than a new field. Compared in the
    direction that actually drifts: service → model.
    """
    emitted = set(_rollup().as_dict())
    declared = set(PortfolioTenantOut.model_fields)
    assert emitted - declared == set(), f"computed but never reaches a caller: {sorted(emitted - declared)}"

    emitted_summary = set(summarise([_rollup()]))
    declared_summary = set(PortfolioSummaryOut.model_fields)
    assert emitted_summary - declared_summary == set(), f"computed but never reaches a caller: {sorted(emitted_summary - declared_summary)}"


def test_the_empty_summary_and_the_computed_summary_agree_on_shape() -> None:
    """Otherwise an empty portfolio 500s on a key the populated path added."""
    assert set(EMPTY_SUMMARY) == set(summarise([_rollup()]))
