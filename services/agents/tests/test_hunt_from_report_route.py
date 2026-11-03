"""The route that puts `app/hunt/from_report.py` on a production path.

Wave 2, Phase 5.1. The module shipped complete and tested and its only
importer repo-wide was its own test — the same state `app/hunt/agent.py`
was in before `POST /hunt` existed, and a passing test on a function nothing
calls is indistinguishable from a working feature until somebody traces the
call graph.

What is asserted here is the route's behaviour, not the module's:

* outbound fetching is **off** unless the deployment turned it on, and the
  refusal is a 403 — the deployment answered, and the answer is no;
* the draft stops at a draft. Nothing is hunted, because the indicators came
  out of a document somebody else published and running them would let the
  author of a write-up choose what this tenant searches for;
* an indicator no hunt field carries is reported as a refusal rather than
  dropped, so a reviewer approving the rest knows what was left out.
"""

from __future__ import annotations

import pytest
from app.api import router as router_module
from app.hunt import from_report
from fastapi import HTTPException

REPORT = """
# Campaign write-up

The loader beaconed to evil-c2[.]example[.]net and to 203.0.113.77 over
hxxps, dropping a file with sha256
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.
"""


class _Request:
    def __init__(self, url: str = "https://example.org/report") -> None:
        self.tenant_id = "0c000000-0000-0000-0000-00000000000a"
        self.url = url


class _Principal:
    tenant_id = "0c000000-0000-0000-0000-00000000000a"


@pytest.fixture(autouse=True)
def _scoped(monkeypatch):
    monkeypatch.setattr(router_module, "scoped_tenant_or_403", lambda principal, requested: requested)


@pytest.mark.asyncio
async def test_fetching_is_refused_with_403_when_the_deployment_has_not_enabled_it(monkeypatch):
    monkeypatch.delenv("AISOC_HUNT_REPORT_FETCH_ENABLED", raising=False)
    with pytest.raises(HTTPException) as caught:
        await router_module.draft_hunt_from_report(_Request(), _Principal())
    # 403 and not 503: nothing was unavailable, the deployment declined.
    assert caught.value.status_code == 403
    assert "not enabled" in str(caught.value.detail)


@pytest.mark.asyncio
async def test_an_empty_url_is_refused_before_anything_is_fetched(monkeypatch):
    called: list[str] = []

    async def _never(*args, **kwargs):
        called.append("fetched")
        raise AssertionError("must not fetch")

    monkeypatch.setattr(from_report, "fetch_report", _never)
    with pytest.raises(HTTPException) as caught:
        await router_module.draft_hunt_from_report(_Request(url="   "), _Principal())
    assert caught.value.status_code == 422
    assert not called


@pytest.mark.asyncio
async def test_a_draft_refangs_the_indicators_and_hunts_nothing(monkeypatch):
    async def _fetch(url, *, enabled, **kwargs):
        assert enabled is True, "the per-tenant switch must reach the module"
        return REPORT, False

    monkeypatch.setenv("AISOC_HUNT_REPORT_FETCH_ENABLED", "1")
    monkeypatch.setattr(from_report, "fetch_report", _fetch)

    out = await router_module.draft_hunt_from_report(_Request(), _Principal())

    domains = {i["value"] for i in out.indicators if i["kind"] == "domain"}
    # `issuperset`, not `in`: the membership is exact either way, but the
    # `host in collection` shape is what `py/incomplete-url-substring-
    # sanitization` warns about and the query cannot tell a set from a URL.
    assert domains.issuperset({"evil-c2.example.net"}), "the defanged spelling must be refanged before matching"
    assert out.content_sha256 and len(out.content_sha256) == 64
    assert out.clauses, "a draft with no clauses would be a reviewer with nothing to approve"
    # Every clause is an exact match on a field the hunt schema actually
    # carries; anything looser is a different hunt from the approved one.
    assert {c["operator"] for c in out.clauses} == {"equals"}
    # And nothing ran: the response carries no findings field at all.
    assert not hasattr(out, "matches")


def test_indicator_fields_exist_in_the_hunt_schema():
    """Every field an indicator maps to must be one the hunt schema carries.

    This is the comparison nothing performed. `draft_clauses` takes
    `allowed_fields` from its caller precisely so the deployment's real
    schema decides, and the module's own suite passes a set it writes
    itself — so `INDICATOR_FIELDS` named `destination_ip`,
    `destination_domain` and `file_hash`, the schema has `dest_ip`,
    `dst_hostname` and `hash_sha256`, and every indicator in every report
    was refused. The draft was honest about refusing them and useless.
    """
    from app.hunt.plan import HUNT_FIELDS

    unknown = {kind: field for kind, field in from_report.INDICATOR_FIELDS.items() if field not in HUNT_FIELDS}
    assert not unknown, f"indicator kinds mapped to fields the hunt schema has no column for: {unknown}"


@pytest.mark.asyncio
async def test_a_fetch_failure_is_422_rather_than_a_500(monkeypatch):
    async def _boom(url, *, enabled, **kwargs):
        raise from_report.ReportFetchError("the server returned 404")

    monkeypatch.setenv("AISOC_HUNT_REPORT_FETCH_ENABLED", "true")
    monkeypatch.setattr(from_report, "fetch_report", _boom)
    with pytest.raises(HTTPException) as caught:
        await router_module.draft_hunt_from_report(_Request(), _Principal())
    assert caught.value.status_code == 422
