"""Wave 1 — fuse-time enrichment maps enrichment-service results into the
schema the confidence scorer + vuln boost read, and stays honest (no TI without
a real match) and fail-soft."""

from __future__ import annotations

from uuid import uuid4

import httpx
import pytest
import respx
from app.models.alert import RawAlert
from app.services.alert_enricher import AlertEnricher
from app.services.confidence import _ti_contribution


def _alert(**kw) -> RawAlert:
    base = {"tenant_id": uuid4(), "source": "detection", "title": "t"}
    base.update(kw)
    return RawAlert(**base)


def _enricher() -> AlertEnricher:
    return AlertEnricher(base_url="http://enrich.test:8082", timeout_seconds=1.0, malicious_risk_floor=50.0)


def test_extract_iocs_deduplicates_and_types():
    alert = _alert(src_ip="1.2.3.4", dst_ip="1.2.3.4", domain="evil.test", file_hash="abcd")
    items = AlertEnricher.extract_iocs(alert)
    # src_ip and dst_ip are the same value -> one ip entry.
    assert {"ioc_type": "ip", "value": "1.2.3.4"} in items
    assert {"ioc_type": "domain", "value": "evil.test"} in items
    assert {"ioc_type": "hash", "value": "abcd"} in items
    assert sum(1 for i in items if i["value"] == "1.2.3.4") == 1


def test_to_enrichments_malicious_result_produces_ti_hit_and_fires_scorer():
    results = [
        {
            "value": "45.9.148.99",
            "risk_score": 88.0,
            "malicious_votes": 7,
            "sources": [{"name": "VirusTotal"}, {"name": "OTX"}],
            "classification": {"threat_actors": ["FIN7"]},
            "vulnerabilities": [{"cve": "CVE-2024-1234", "kev": True, "cvss": 9.8, "exploited": True}],
        }
    ]
    enr = _enricher().to_enrichments(results)
    # Source-keyed hits the confidence scorer reads.
    assert enr["virustotal"]["hit"] is True
    assert "45.9.148.99" in enr["virustotal"]["matches"]
    assert enr["otx"]["hit"] is True
    assert enr["kev"]["matches"] == ["CVE-2024-1234"]
    # vuln_boost schema.
    assert enr["vulnerabilities"][0]["cve_id"] == "CVE-2024-1234"
    assert enr["vulnerabilities"][0]["is_exploited"] is True
    # threat_intel summary for the rail.
    assert enr["threat_intel"]["threat_actors"] == ["FIN7"]
    # The confidence TI factor now fires positive (was -0.3 "no TI match").
    contrib, _ = _ti_contribution(enr)
    assert contrib > 0


def test_to_enrichments_benign_result_is_empty_no_fake_ti():
    results = [{"value": "10.0.0.1", "risk_score": 2.0, "malicious_votes": 0, "sources": [{"name": "GreyNoise"}]}]
    enr = _enricher().to_enrichments(results)
    # No malicious signal -> no source-hit keys -> scorer keeps its honest prior.
    assert "virustotal" not in enr
    assert _ti_contribution(enr)[0] < 0


@pytest.mark.asyncio
@respx.mock
async def test_enrich_calls_bulk_endpoint():
    route = respx.post("http://enrich.test:8082/enrich/bulk").mock(
        return_value=httpx.Response(
            200, json={"results": [{"value": "1.2.3.4", "risk_score": 90, "malicious_votes": 3, "sources": [{"name": "VirusTotal"}]}]}
        )
    )
    enr = await _enricher().enrich(_alert(src_ip="1.2.3.4"))
    assert route.called
    assert enr["virustotal"]["hit"] is True


@pytest.mark.asyncio
@respx.mock
async def test_enrich_is_fail_soft_on_error():
    respx.post("http://enrich.test:8082/enrich/bulk").mock(return_value=httpx.Response(503))
    assert await _enricher().enrich(_alert(src_ip="1.2.3.4")) == {}


@pytest.mark.asyncio
async def test_enrich_no_iocs_short_circuits():
    assert await _enricher().enrich(_alert()) == {}
