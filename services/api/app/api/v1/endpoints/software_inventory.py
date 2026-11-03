"""Package-level software inventory (depth plan wave 2, Phase 5.4).

`assets` is host-level: it records that a host exists and that a CVE applies
to it, never what is installed. These routes are what put the normalisers in
`app.services.software_inventory` on a production path — the module was
complete and tested and nothing imported it, which proves the code compiles
rather than that it runs.

Three routes:

``POST /software-inventory/osquery``  rows an endpoint agent reported
``POST /software-inventory/sbom``     an SPDX document a repository declared
``GET  /software-inventory``          the inventory, with the EOL verdict

Two properties carried from the module and not undone here:

* **The two sources are not merged.** `source` is part of the row identity,
  and an SBOM row carries no `asset_id`, because inventing a host for a
  package a repository merely *declares* would be a fabricated location on
  the one surface whose job is to say where something runs.
* **An unknown end-of-life answer is `unknown`, never "supported".** The
  table is dated and small; a runtime it does not list returns unknown with
  the `as_of` date beside it, because "we have no data for this" and "this
  is fine" are different facts and only one is safe to act on.

The empty state is distinguished the same way everything else here is:
zero rows with nothing ever ingested is `nothing_reported`, not
`no_packages`. An estate that never reported must not render identically to
one with nothing installed — which is exactly the conclusion a reader would
otherwise draw about a Windows fleet, the ecosystem the shipped osquery pack
did not query at all until this phase.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from sqlalchemy import text

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.services.software_inventory import (
    OSQUERY_TABLES,
    InventoryError,
    PackageRow,
    end_of_life,
    from_osquery,
    from_spdx,
)

router = APIRouter(prefix="/software-inventory", tags=["software-inventory"])

#: One statement, written out in full. Casts are spelled `CAST(:name AS t)`:
#: SQLAlchemy's bind-parameter regex backtracks one character over `:name::t`
#: and declares a parameter with the last letter missing, so the matching
#: `bindparams` raises outside the handler's `try` and the route answers an
#: unhandled 500 — a defect this repository has shipped more than once.
_UPSERT = text(
    """
    INSERT INTO software_packages
        (tenant_id, asset_id, source, location, name, version, ecosystem, purl, metadata)
    VALUES
        (CAST(:tenant_id AS uuid), CAST(:asset_id AS uuid), :source, :location,
         :name, :version, :ecosystem, :purl, CAST(:metadata AS jsonb))
    ON CONFLICT (tenant_id, source, location, name, version, ecosystem)
    DO UPDATE SET last_seen = NOW(), metadata = EXCLUDED.metadata
    """
)

_SELECT = text(
    """
    SELECT source, location, name, version, ecosystem, purl, first_seen, last_seen
      FROM software_packages
     WHERE tenant_id = CAST(:tenant_id AS uuid)
       AND (CAST(:source AS text) IS NULL OR source = CAST(:source AS text))
       AND (CAST(:name AS text) IS NULL OR lower(name) = lower(CAST(:name AS text)))
     ORDER BY name, version, location
     LIMIT :limit
    """
)

_ANY_ROW = text("SELECT 1 FROM software_packages WHERE tenant_id = CAST(:tenant_id AS uuid) LIMIT 1")


async def _store(db: DBSession, tenant_id: Any, rows: list[PackageRow], *, asset_id: str | None) -> int:
    import json

    for row in rows:
        await db.execute(
            _UPSERT,
            {
                "tenant_id": str(tenant_id),
                # An SBOM row has no host, and the column stays NULL rather
                # than borrowing one.
                "asset_id": asset_id if row.source == "osquery" else None,
                "source": row.source,
                "location": row.location,
                "name": row.name,
                "version": row.version,
                "ecosystem": row.ecosystem,
                "purl": row.purl,
                "metadata": json.dumps(row.metadata or {}),
            },
        )
    await db.commit()
    return len(rows)


@router.get("/ecosystems", summary="The osquery tables this inventory reads")
async def list_ecosystems(
    _user: Annotated[AuthUser, Depends(require_permission("compliance:read"))],
) -> dict[str, Any]:
    """Published so a console filter is not a second copy of this list.

    A vocabulary declared twice is how a value ends up filterable on one
    surface and invisible on the other.
    """
    return {"tables": dict(OSQUERY_TABLES)}


@router.post("/osquery", summary="Record packages an endpoint agent reported")
async def ingest_osquery(
    db: DBSession,
    user: Annotated[AuthUser, Depends(require_permission("settings:write"))],
    table: str = Query(..., description="The osquery table these rows came from"),
    host: str = Query(..., min_length=1, description="The host that reported them"),
    asset_id: str | None = Query(default=None),
    rows: list[dict[str, Any]] = Body(...),
) -> dict[str, Any]:
    try:
        parsed = from_osquery(table, rows, host=host)
    except InventoryError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    stored = await _store(db, user.tenant_id, parsed, asset_id=asset_id)
    return {"source": "osquery", "table": table, "host": host, "stored": stored}


@router.post("/sbom", summary="Record packages a repository's SBOM declares")
async def ingest_sbom(
    db: DBSession,
    user: Annotated[AuthUser, Depends(require_permission("settings:write"))],
    repository: str = Query(..., min_length=1),
    document: dict[str, Any] = Body(...),
) -> dict[str, Any]:
    try:
        parsed = from_spdx(document, repository=repository)
    except InventoryError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    stored = await _store(db, user.tenant_id, parsed, asset_id=None)
    return {"source": "sbom", "repository": repository, "stored": stored}


@router.get("", summary="Where a package runs, and whether its runtime is still supported")
async def list_packages(
    db: DBSession,
    user: Annotated[AuthUser, Depends(require_permission("compliance:read"))],
    source: str | None = Query(default=None, pattern="^(osquery|sbom)$"),
    name: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=1000),
) -> dict[str, Any]:
    result = await db.execute(_SELECT, {"tenant_id": str(user.tenant_id), "source": source, "name": name, "limit": limit})
    items: list[dict[str, Any]] = []
    for row in result.mappings():
        verdict = end_of_life(row["name"], row["version"])
        items.append(
            {
                **dict(row),
                "end_of_life": {
                    # Three-valued on purpose: `null` means this inventory
                    # has no end-of-life data for the package, which is not
                    # the same fact as "it is supported".
                    "runtime": verdict.runtime,
                    "major": verdict.major,
                    "supported": verdict.supported,
                    "end_of_life": verdict.end_of_life.isoformat() if verdict.end_of_life else None,
                    "as_of": verdict.as_of.isoformat(),
                    "reason": verdict.reason,
                },
            }
        )

    if items:
        return {"items": items, "count": len(items), "state": "ok"}

    # Zero rows has two causes and they call for different actions. Only a
    # tenant that has reported *something* can honestly be described as
    # having no match for this filter.
    ever = await db.execute(_ANY_ROW, {"tenant_id": str(user.tenant_id)})
    reported = ever.first() is not None
    return {
        "items": [],
        "count": 0,
        "state": "no_match" if reported else "nothing_reported",
    }
