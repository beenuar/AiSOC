"""`/metrics/prometheus` renders what `/metrics` knows, parseably (#1881).

The bundled Prometheus had scraped the JSON `/metrics` since the job was
written and never recorded a sample, because JSON is not exposition format.
These tests drive the real route through ASGI and parse the output with the
same text-format parser Prometheus uses, so "parseable" is measured rather
than asserted — and they pin the honest-absence rule: a source that answers
`None` has no sample this scrape, never a zero.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api import router as router_mod
from app.api.router import router, set_worker
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from prometheus_client.parser import text_string_to_metric_families


def _worker(
    *,
    lag: int | None = 7,
    pending: int | None = 3,
    oldest: float | None = 41.5,
    by_tenant: dict[str, int] | None = None,
    lake_metrics: dict[str, int] | None = None,
    degraded: bool = False,
) -> MagicMock:
    worker = MagicMock()
    worker.get_metrics = MagicMock(return_value={"errors": 2, "dead_lettered": 1, "durable_capture": 1})
    worker.consumer_lag = AsyncMock(return_value=lag)
    worker.pending_notifications = AsyncMock(return_value=(pending, oldest, dict(by_tenant or {"t-1": 2, "t-2": 1})))
    if lake_metrics is None:
        lake_metrics = {"rows_written": 120, "spool_rows": 4, "rows_dropped": 0}
    worker.lake = MagicMock()
    worker.lake.metrics = MagicMock(return_value=lake_metrics)
    worker.lake.archive_degraded = degraded
    return worker


def _client() -> AsyncClient:
    app = FastAPI()
    app.include_router(router)
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://fusion")


@pytest.fixture(autouse=True)
def _reset_worker():
    yield
    router_mod._worker_ref = None  # noqa: SLF001 — test seam


async def _families(client: AsyncClient) -> dict[str, dict[tuple, float]]:
    response = await client.get("/metrics/prometheus")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    out: dict[str, dict[tuple, float]] = {}
    for family in text_string_to_metric_families(response.text):
        for sample in family.samples:
            out.setdefault(sample.name, {})[tuple(sorted(sample.labels.items()))] = sample.value
    return out


@pytest.mark.asyncio
async def test_the_scrape_is_parseable_and_carries_the_figures() -> None:
    set_worker(_worker())
    async with _client() as client:
        samples = await _families(client)

    assert samples["aisoc_fusion_consumer_errors_total"][()] == 2.0
    assert samples["aisoc_fusion_consumer_dead_lettered_total"][()] == 1.0
    assert samples["aisoc_fusion_consumer_lag"][()] == 7.0
    assert samples["aisoc_fusion_notifications_pending"][()] == 3.0
    assert samples["aisoc_fusion_notifications_oldest_seconds"][()] == 41.5
    assert samples["aisoc_fusion_lake_rows_written_total"][()] == 120.0
    assert samples["aisoc_fusion_lake_spool_rows"][()] == 4.0
    assert samples["aisoc_fusion_lake_degraded"][()] == 0.0
    by_tenant = samples["aisoc_fusion_notifications_pending_by_tenant"]
    assert by_tenant[(("tenant_id", "t-1"),)] == 2.0
    assert by_tenant[(("tenant_id", "t-2"),)] == 1.0


@pytest.mark.asyncio
async def test_an_unreadable_source_is_absent_not_zero() -> None:
    """`None` from lag or the journal means no sample — the JSON rule kept."""
    set_worker(_worker(lag=None, pending=None, oldest=None, by_tenant={}))
    async with _client() as client:
        samples = await _families(client)

    assert "aisoc_fusion_consumer_lag" not in samples, "an unreadable lag rendered as a value"
    assert "aisoc_fusion_notifications_pending" not in samples, "an unreadable journal rendered as a value; absent is the honest state"
    # The readable sources still report.
    assert samples["aisoc_fusion_consumer_errors_total"][()] == 2.0


@pytest.mark.asyncio
async def test_worker_not_started_answers_an_empty_but_valid_scrape() -> None:
    router_mod._worker_ref = None  # noqa: SLF001 — test seam
    async with _client() as client:
        response = await client.get("/metrics/prometheus")
        assert response.status_code == 200
        families = list(text_string_to_metric_families(response.text))
    assert families == [], "no worker means no samples, not invented ones"


@pytest.mark.asyncio
async def test_degraded_archive_reports_one() -> None:
    set_worker(_worker(degraded=True))
    async with _client() as client:
        samples = await _families(client)
    assert samples["aisoc_fusion_lake_degraded"][()] == 1.0
