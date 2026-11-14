"""Phase C2 — effective-permissions live posture-loader tests.

Proves the loader assembles a resolver-ready Okta snapshot from connector
`get_resource_config` calls (user → groups → apps → admin roles), that the
assembled snapshot actually resolves, that cloud providers consume a
connector-provided reconciled snapshot, and that collection failures degrade
to an empty dict (→ 412), never a crash or a fabricated snapshot.
"""

from __future__ import annotations

import pytest
from app.services.effective_permissions.okta import OktaResolver
from app.services.effective_permissions.posture_loader import POSTURE_SNAPSHOT_ID, collect_snapshot

pytestmark = pytest.mark.asyncio


def _okta_fetcher():
    """A fake get_resource_config for one user, one group, one app, one role."""
    data = {
        "00u-alice": {
            "raw": {
                "group_ids": ["00g-admins"],
                "assigned_apps": [],
                "admin_roles": [],
            }
        },
        "00g-admins": {
            "name": "Admins",
            "raw": {
                "admin_roles": ["role-super"],
                "assigned_apps": ["0oa-console"],
                "admin_role_defs": [{"id": "role-super", "privileges": ["okta.users.manage", "okta.groups.manage"]}],
            },
        },
        "0oa-console": {"name": "Okta Admin Console"},
    }

    async def _fetch(connector_id, resource_id, at_ts):  # noqa: ANN001, ARG001
        return data.get(resource_id, {})

    return _fetch


async def test_okta_snapshot_assembled_from_resource_configs():
    snap = (await collect_snapshot("okta", "00u-alice", fetcher=_okta_fetcher())).snapshot
    assert [p["id"] for p in snap["principals"]] == ["00u-alice"]
    assert snap["principals"][0]["groups"] == ["00g-admins"]
    group = next(g for g in snap["groups"] if g["id"] == "00g-admins")
    assert "role-super" in group["admin_roles"]
    assert "0oa-console" in group["assigned_apps"]
    assert any(r["id"] == "role-super" for r in snap["admin_roles"])
    assert any(a["id"] == "0oa-console" for a in snap["apps"])


async def test_assembled_okta_snapshot_resolves():
    snap = (await collect_snapshot("okta", "00u-alice", fetcher=_okta_fetcher())).snapshot
    result = OktaResolver().resolve("00u-alice", snapshot=snap)
    # Alice inherits the super-admin role via the Admins group → has privileges.
    perms = {d.permission if hasattr(d, "permission") else d for d in result.decisions}
    assert result.decisions  # non-empty: she resolved to real permissions
    assert any("okta.users.manage" in str(p) for p in perms)


async def test_cloud_provider_consumes_reconciled_snapshot():
    reconciled = {"principals": [{"id": "arn:aws:iam::1:user/bob"}], "policies": [], "resources": []}

    async def _fetch(connector_id, resource_id, at_ts):  # noqa: ANN001, ARG001
        assert resource_id == POSTURE_SNAPSHOT_ID
        return {"snapshot": reconciled}

    collected = await collect_snapshot("aws", "arn:aws:iam::1:user/bob", fetcher=_fetch)
    assert collected.snapshot == reconciled
    assert collected.partial is False
    assert collected.notes == ()


async def test_cloud_provider_top_level_snapshot_shape():
    async def _fetch(connector_id, resource_id, at_ts):  # noqa: ANN001, ARG001
        return {"principals": [{"id": "u1"}], "policies": []}

    collected = await collect_snapshot("azure", "u1", fetcher=_fetch)
    assert "principals" in collected.snapshot


async def test_unknown_provider_returns_empty():
    async def _fetch(connector_id, resource_id, at_ts):  # noqa: ANN001, ARG001
        return {"anything": True}

    assert not await collect_snapshot("mystery", "p", fetcher=_fetch)


async def test_fetch_error_degrades_to_empty():
    async def _boom(connector_id, resource_id, at_ts):  # noqa: ANN001, ARG001
        raise RuntimeError("connectors service down")

    assert not await collect_snapshot("okta", "00u-alice", fetcher=_boom)
    assert not await collect_snapshot("aws", "x", fetcher=_boom)


async def test_empty_cloud_snapshot_returns_empty():
    async def _fetch(connector_id, resource_id, at_ts):  # noqa: ANN001, ARG001
        return {"snapshot": {}}

    assert not await collect_snapshot("gcp", "sa@proj.iam", fetcher=_fetch)


async def test_the_gap_survives_the_hop_from_the_connector():
    """A collector that could not read half the estate says so in the same
    envelope as the data, and that has to reach the caller.

    The earlier shape returned the bare snapshot dict and dropped `partial`
    and the notes on the floor, so a collection that 403'd on a page of role
    assignments was indistinguishable from one that read everything -- and
    the difference is an identity that looks harmless because the policy
    granting it everything was in the page nobody could read.
    """

    async def _fetch(connector_id, resource_id, at_ts):  # noqa: ANN001, ARG001
        return {
            "snapshot": {"principals": [{"id": "u1"}]},
            "partial": True,
            "collection_notes": ["the second page of role assignments returned 403"],
        }

    collected = await collect_snapshot("azure", "u1", fetcher=_fetch)

    assert collected.partial is True
    assert collected.notes == ("the second page of role assignments returned 403",)
    assert collected.snapshot["principals"] == [{"id": "u1"}]


async def test_an_incomplete_collection_that_got_nothing_is_still_nothing():
    """`partial` does not make an empty snapshot answerable.

    Zero principals means the credential lost its read permission far more
    often than it means the estate is empty, so the caller must still 412
    rather than resolve a principal against a document with nothing in it.
    """

    async def _fetch(connector_id, resource_id, at_ts):  # noqa: ANN001, ARG001
        return {"snapshot": {}, "partial": True, "collection_notes": ["every page 403'd"]}

    collected = await collect_snapshot("gcp", "sa@proj.iam", fetcher=_fetch)

    assert not collected, "an empty snapshot is falsy however complete the collector claims it was"
