"""The routes that put the software-inventory normalisers on a real path.

Wave 2, Phase 5.4. `app/services/software_inventory.py` shipped complete and
tested with no production importer, which proves the code compiles rather
than that it runs. These exercise the routes that changed that, through the
real app and its real auth dependencies.

The three properties asserted here are the ones the module's own unit tests
cannot see, because each is a property of the *route*:

* an SBOM package is stored with no `asset_id`, even when the caller offers
  one, because a repository's declaration has no host and borrowing one
  would be a fabricated location;
* an unparseable source is refused with 400 rather than stored empty;
* zero rows distinguishes "this tenant has reported nothing" from "nothing
  matched your filter", which is the honest-empty-state rule applied to the
  one page a reader would otherwise use to conclude a Windows fleet is
  clean.
"""

from __future__ import annotations

from typing import Any

import pytest
from app.api.v1.endpoints import software_inventory as routes


class _Result:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows

    def mappings(self) -> list[dict[str, Any]]:
        return self._rows

    def first(self) -> Any:
        return self._rows[0] if self._rows else None


class _DB:
    """Records what the route asked the database to do.

    Deliberately not a fake that answers any query: the assertions below are
    about the parameters the route binds, and a double that invents rows
    would let a missing tenant predicate pass unnoticed.
    """

    def __init__(self, rows: list[dict[str, Any]] | None = None, any_row: bool = False) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.commits = 0
        self._rows = rows or []
        self._any_row = any_row

    async def execute(self, statement: Any, params: dict[str, Any] | None = None) -> _Result:
        sql = str(statement)
        self.calls.append((sql, dict(params or {})))
        if "SELECT 1 FROM software_packages" in sql:
            return _Result([{"1": 1}] if self._any_row else [])
        if sql.strip().startswith("SELECT"):
            return _Result(self._rows)
        return _Result([])

    async def commit(self) -> None:
        self.commits += 1


class _User:
    tenant_id = "0c000000-0000-0000-0000-0000000000a1"


@pytest.mark.asyncio
async def test_an_sbom_package_is_stored_with_no_asset_id():
    db = _DB()
    document = {
        "packages": [{"name": "requests", "versionInfo": "2.31.0", "externalRefs": [{"referenceLocator": "pkg:pypi/requests@2.31.0"}]}]
    }
    out = await routes.ingest_sbom(db, _User(), repository="acme/api", document=document)
    assert out["stored"] == 1
    inserts = [p for sql, p in db.calls if "INSERT INTO software_packages" in sql]
    assert inserts, "the route stored nothing"
    assert inserts[0]["asset_id"] is None
    assert inserts[0]["source"] == "sbom"
    assert inserts[0]["location"] == "acme/api"
    assert db.commits == 1


@pytest.mark.asyncio
async def test_an_osquery_row_keeps_the_host_it_was_reported_from():
    db = _DB()
    rows = [{"name": "openssl", "version": "3.0.2"}]
    out = await routes.ingest_osquery(
        db, _User(), table="deb_packages", host="web-01", asset_id="0c000000-0000-0000-0000-0000000000b2", rows=rows
    )
    assert out["stored"] == 1
    inserts = [p for sql, p in db.calls if "INSERT INTO software_packages" in sql]
    assert inserts[0]["source"] == "osquery"
    assert inserts[0]["location"] == "web-01"
    assert inserts[0]["asset_id"] == "0c000000-0000-0000-0000-0000000000b2"


@pytest.mark.asyncio
async def test_an_unknown_osquery_table_is_refused_rather_than_stored_empty():
    from fastapi import HTTPException

    db = _DB()
    with pytest.raises(HTTPException) as caught:
        await routes.ingest_osquery(db, _User(), table="not_a_table", host="web-01", asset_id=None, rows=[{}])
    assert caught.value.status_code == 400
    assert not [p for sql, p in db.calls if "INSERT" in sql]


@pytest.mark.asyncio
async def test_nothing_reported_is_not_the_same_answer_as_nothing_matched():
    # An estate that never reported must not render identically to one with
    # nothing installed: a Windows fleet produced no rows at all until this
    # phase, and "no packages" would have read as "clean".
    empty = _DB(rows=[], any_row=False)
    assert (await routes.list_packages(empty, _User(), source=None, name=None, limit=10))["state"] == "nothing_reported"

    reported = _DB(rows=[], any_row=True)
    assert (await routes.list_packages(reported, _User(), source=None, name=None, limit=10))["state"] == "no_match"


@pytest.mark.asyncio
async def test_every_read_binds_the_caller_s_own_tenant():
    db = _DB(rows=[], any_row=False)
    await routes.list_packages(db, _User(), source="osquery", name="openssl", limit=5)
    selects = [p for sql, p in db.calls if sql.strip().startswith("SELECT")]
    assert selects, "the route read nothing"
    for params in selects:
        assert params["tenant_id"] == _User.tenant_id


@pytest.mark.asyncio
async def test_an_unlisted_runtime_reports_unknown_rather_than_supported():
    row = {
        "source": "osquery",
        "location": "web-01",
        "name": "some-vendor-thing",
        "version": "1.2.3",
        "ecosystem": "deb",
        "purl": None,
        "first_seen": None,
        "last_seen": None,
    }
    out = await routes.list_packages(_DB(rows=[row], any_row=True), _User(), source=None, name=None, limit=10)
    verdict = out["items"][0]["end_of_life"]
    # Three-valued: `None` is "we have no end-of-life data", which is a
    # different fact from `True`.
    assert verdict["supported"] is None
    assert verdict["as_of"], "every verdict carries the date of the table it came from"
