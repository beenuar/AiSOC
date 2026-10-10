"""Materialise scanner findings as vulnerability rows.

Fix pass item 5.2. See `plans/aisoc_fix_pass_plan.plan.md`.

Why this lives in the connectors service
----------------------------------------
`asset_vulnerabilities` had exactly one writer in the tree: a route a human
calls by hand. The Tenable connector modelled its findings as alerts, so the
table stayed empty on every deployment whose vulnerability data came from a
scanner -- and `_tenant_has_vulnerability_data` in the API's `kev_exposure`
exists precisely to tell "you are not exposed" apart from "nobody has told me
what you run". KEV exposure therefore answered *no data*, forever.

The obvious fix is for the connector to POST to the API, and it is the wrong
one: the service principal is a deliberately read-only credential whose own
docstring says "anything that changes state at a vendor or in the database is
absent on purpose". Granting it a write verb to close this would undo that
decision for every route at once.

This service already owns a database engine (it decrypts connector credentials
at poll time) and already holds the tenant id the scheduler is polling for. So
the write happens here, under the tenant it was polled for, with no new
credential and no widened principal.

Matching, and why there is no ON CONFLICT
-----------------------------------------
Neither `assets` nor `asset_vulnerabilities` carries a natural unique key, so
there is nothing to conflict on. Matching is explicit: an asset by
`(tenant_id, name)` and a finding by `(tenant_id, asset_id, cve_id, source)`.
A re-poll moves `last_found` and leaves `first_found` alone, because "when did
we first see this" is the question an exposure window is asked.
"""

from __future__ import annotations

import pathlib
import uuid
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

logger = structlog.get_logger(__name__)

#: One poll must not be able to write an unbounded number of rows: a
#: misconfigured scan filter would otherwise turn a 5-minute schedule into a
#: write amplifier against the shared database.
MAX_FINDINGS_PER_SYNC = 2_000

_FIND_ASSET = text(
    """
    SELECT id FROM assets
     WHERE tenant_id = CAST(:tenant_id AS uuid)
       AND lower(name) = lower(:name)
     LIMIT 1
    """
)

_INSERT_ASSET = text(
    """
    INSERT INTO assets (id, tenant_id, asset_type, name, fqdn, ip_addresses,
                        criticality, tags, last_seen, first_seen, metadata,
                        created_at, updated_at)
    VALUES (:id, CAST(:tenant_id AS uuid), 'host', :name, :fqdn,
            :ips, 'medium', CAST(ARRAY[]::text[] AS text[]), :now, :now,
            CAST(:metadata AS jsonb), :now, :now)
    RETURNING id
    """
)

_FIND_VULN = text(
    """
    SELECT id FROM asset_vulnerabilities
     WHERE tenant_id = CAST(:tenant_id AS uuid)
       AND asset_id  = CAST(:asset_id AS uuid)
       AND cve_id    = :cve_id
       AND source    = :source
     LIMIT 1
    """
)

_INSERT_VULN = text(
    """
    INSERT INTO asset_vulnerabilities
        (id, tenant_id, asset_id, cve_id, title, description, severity,
         cvss_score, is_exploited, source, external_id, first_found,
         last_found, metadata, created_at,
         environment, patch_due_date, patch_status)
    VALUES (:id, CAST(:tenant_id AS uuid), CAST(:asset_id AS uuid), :cve_id,
            :title, :description, :severity,
            :cvss_score, false, :source, :external_id,
            :now, :now, CAST(:metadata AS jsonb), :now,
            :environment, :patch_due_date, 'tracked')
    """
)

#: `first_found` is deliberately untouched. A re-poll of a finding that has
#: been present for a month must not reset the clock an exposure window is
#: measured against.
#:
#: The `tenant_id` predicate is not redundant with the tenant-scoped SELECT
#: that produced the id. How a row was *addressed* is irrelevant to whether the
#: write is scoped -- an id arriving from anywhere else, now or after a later
#: edit, would reach another tenant's row. `scripts/check_tenant_query_predicates.py`
#: makes that the rule rather than a convention.
_TOUCH_VULN = text(
    """
    UPDATE asset_vulnerabilities
       SET last_found = :now,
           severity   = :severity,
           title      = :title
     WHERE id        = CAST(:id AS uuid)
       AND tenant_id = CAST(:tenant_id AS uuid)
    """
)


async def sync_findings(
    engine: AsyncEngine,
    *,
    tenant_id: uuid.UUID | str,
    findings: list[dict[str, Any]],
    now: datetime | None = None,
) -> dict[str, int]:
    """Write one poll's findings for one tenant. Returns what it did.

    Counts are returned rather than logged alone because "the sync ran" and
    "the sync wrote something" are different facts, and only the second one
    means KEV exposure will have an answer.
    """
    import json

    if not findings:
        return {"assets_created": 0, "findings_inserted": 0, "findings_touched": 0, "skipped": 0}

    stamp = now or datetime.now(UTC)
    tenant = str(tenant_id)

    if len(findings) > MAX_FINDINGS_PER_SYNC:
        logger.warning(
            "vulnerabilities.sync_truncated",
            tenant_id=tenant,
            received=len(findings),
            cap=MAX_FINDINGS_PER_SYNC,
        )
        findings = findings[:MAX_FINDINGS_PER_SYNC]

    assets_created = inserted = touched = skipped = 0
    asset_ids: dict[str, uuid.UUID] = {}

    async with engine.begin() as conn:
        for finding in findings:
            cve = str(finding.get("cve_id") or "").strip().upper()
            hostname = str(finding.get("hostname") or "").strip()
            if not cve.startswith("CVE-") or not hostname:
                # A finding with no CVE cannot be matched against KEV, and one
                # with no host cannot be attached to an asset. Counted rather
                # than dropped silently.
                skipped += 1
                continue

            key = hostname.lower()
            asset_id = asset_ids.get(key)
            if asset_id is None:
                row = (await conn.execute(_FIND_ASSET, {"tenant_id": tenant, "name": hostname})).first()
                if row is not None:
                    asset_id = row[0]
                else:
                    new_id = uuid.uuid4()
                    ip = finding.get("ip_address")
                    await conn.execute(
                        _INSERT_ASSET,
                        {
                            "id": new_id,
                            "tenant_id": tenant,
                            "name": hostname,
                            "fqdn": hostname,
                            # `ip_addresses` is text[], so asyncpg wants a
                            # Python list rather than a jsonb string or a
                            # Postgres array literal.
                            "ips": [str(ip)] if ip else [],
                            "now": stamp,
                            "metadata": json.dumps({"discovered_by": finding.get("source") or "scanner"}),
                        },
                    )
                    asset_id = new_id
                    assets_created += 1
                asset_ids[key] = asset_id

            source = str(finding.get("source") or "scanner")
            existing = (
                await conn.execute(
                    _FIND_VULN,
                    {"tenant_id": tenant, "asset_id": str(asset_id), "cve_id": cve, "source": source},
                )
            ).first()

            params = {
                "severity": str(finding.get("severity") or "info"),
                "title": str(finding.get("title") or cve),
                "now": stamp,
            }
            if existing is not None:
                await conn.execute(_TOUCH_VULN, {**params, "id": str(existing[0]), "tenant_id": tenant})
                touched += 1
            else:
                # Patch-window policy (docs/cve-patch-policy.md): the due
                # date is minted here, once, from the moment the finding
                # first enters inventory — never recomputed by a re-poll
                # (the touch path deliberately omits it). Environment comes
                # from the hostname classifier; unknown hosts are PROD.
                try:
                    from app.patch_calendar import classify_environment, patch_due_for
                except ModuleNotFoundError:  # pragma: no cover - import-shape only
                    # The isolation harness loads this module by path under a
                    # private name (both services package as ), so the
                    # sibling package is not on sys.modules here. Load the
                    # calendar off disk the same way the harness does.
                    import importlib.util
                    import sys

                    _pc = pathlib.Path(__file__).with_name("patch_calendar.py")
                    _spec = importlib.util.spec_from_file_location("aisoc_patch_calendar", _pc)
                    # `spec_from_file_location` returns None when the path is
                    # not importable, and a spec can carry no loader. Both are
                    # unreachable for a file this package ships, but a bare
                    # `exec_module` on either would raise AttributeError
                    # several frames from the cause — so say what went wrong.
                    if _spec is None or _spec.loader is None:
                        # `from None`: this is a fresh condition, not a
                        # re-raise of the ImportError that put us in this
                        # branch, and chaining the two would suggest the
                        # import error caused it.
                        raise RuntimeError(f"patch calendar is not importable from {_pc}") from None
                    _mod = importlib.util.module_from_spec(_spec)
                    sys.modules[_spec.name] = _mod
                    _spec.loader.exec_module(_mod)
                    classify_environment = _mod.classify_environment
                    patch_due_for = _mod.patch_due_for

                environment = classify_environment(hostname)
                await conn.execute(
                    _INSERT_VULN,
                    {
                        **params,
                        "id": uuid.uuid4(),
                        "tenant_id": tenant,
                        "asset_id": str(asset_id),
                        "cve_id": cve,
                        "description": finding.get("title"),
                        "cvss_score": finding.get("cvss_score"),
                        "source": source,
                        "external_id": str(finding.get("plugin_id") or finding.get("external_id") or "") or None,
                        "metadata": json.dumps({"plugin_id": finding.get("plugin_id")}),
                        "environment": environment,
                        "patch_due_date": patch_due_for(stamp, environment),
                    },
                )
                inserted += 1

    result = {
        "assets_created": assets_created,
        "findings_inserted": inserted,
        "findings_touched": touched,
        "skipped": skipped,
    }
    logger.info("vulnerabilities.synced", tenant_id=tenant, **result)
    return result


__all__ = ["sync_findings", "MAX_FINDINGS_PER_SYNC"]
