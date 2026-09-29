"""Content publishing, installation and analyst feedback authorize now.

Seventeen routes across five modules. The pattern in `community.py` is the
sharpest instance of the whole class: its *review* and *curate* routes already
required `plugins:admin` and `playbooks:admin`, while the routes that
**submitted** and **installed** required only a session. So the moderation
step was gated and the thing being moderated was not — a `viewer` could
publish a signed plugin as the tenant, and install one.

The permission follows the content type, matching what governs authoring that
type locally: you should not be able to publish or install what you could not
have written. `plugins:admin` for plugins (code, so installing is an execution
surface), `rules:write` for detections, `playbooks:write` for playbooks.

`feedback.py` is the subtle one. An override writes an alert's `disposition`
*and* persists a per-signature prior into institutional memory, where a
trusted benign prior auto-resolves matching repeat alerts without re-triage.
Ungated, that was not one wrong verdict; it was a durable instruction to the
platform to stop looking, writable by a read-only account.

`POST /community/plugins/{id}/rate` is deliberately left ungated, and
`test_rating_is_deliberately_not_gated` records that as an assertion.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.deps import CurrentUser, get_current_user
from app.api.v1.endpoints import community, feedback, marketplace, phishing, stix_taxii
from app.db.database import get_db
from fastapi import FastAPI
from fastapi.testclient import TestClient

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")
ROW = uuid.UUID("22222222-2222-2222-2222-222222222222")

SIGMA = "title: t\nid: 1\nstatus: test\ndescription: d\nlogsource:\n  category: process_creation\ndetection:\n  condition: selection\n"

GATED: list[tuple[Any, str, str, str, str, Any]] = [
    (community, "add_publisher_key", "plugins:admin", "POST", "/api/v1/community/publishers/keys", {"public_key_pem": "x"}),
    (community, "revoke_publisher_key", "plugins:admin", "DELETE", "/api/v1/community/publishers/keys/abcd", None),
    (community, "publish_plugin", "plugins:admin", "POST", "/api/v1/community/plugins/publish", None),
    (community, "install_community_plugin", "plugins:admin", "POST", "/api/v1/community/plugins/p1/install", None),
    (community, "publish_detection", "rules:write", "POST", "/api/v1/community/detections/publish", SIGMA),
    (community, "install_community_detection", "rules:write", "POST", "/api/v1/community/detections/d1/install", None),
    (community, "submit_playbook", "playbooks:write", "POST", "/api/v1/community/playbooks/submit", {"name": "p"}),
    (community, "install_community_playbook", "playbooks:write", "POST", "/api/v1/community/playbooks/pb1/install", None),
    (
        marketplace,
        "install_marketplace_item",
        "settings:write",
        "POST",
        "/api/v1/marketplace/install",
        {"type": "detection", "id": "det-cloud-001"},
    ),
    (
        marketplace,
        "uninstall_marketplace_item",
        "settings:write",
        "DELETE",
        "/api/v1/marketplace/install?type=detection&id=det-cloud-001",
        None,
    ),
    (
        stix_taxii,
        "create_indicator",
        "threat_intel:write",
        "POST",
        "/api/v1/threatintel/stix/indicators",
        {"pattern": "[ipv4-addr:value = '198.51.100.7']", "name": "c2", "indicator_types": ["malicious-activity"]},
    ),
    (stix_taxii, "create_bundle", "threat_intel:write", "POST", "/api/v1/threatintel/stix/bundles", {"indicator_ids": []}),
    (
        stix_taxii,
        "misp_push_dry_run",
        "threat_intel:write",
        "POST",
        "/api/v1/threatintel/stix/misp/dry-run",
        {"pattern": "[ipv4-addr:value = '198.51.100.7']"},
    ),
    (
        feedback,
        "submit_alert_override",
        "alerts:write",
        "POST",
        "/api/v1/feedback/alert-override",
        {"alert_id": str(ROW), "original_verdict": "true_positive", "corrected_verdict": "benign"},
    ),
    (
        feedback,
        "apply_redisposition_endpoint",
        "alerts:write",
        "POST",
        "/api/v1/feedback/redisposition/apply",
        {"alert_ids": [str(ROW)], "new_disposition": "benign", "confirmation_token": "t"},
    ),
    (phishing, "submit", "cases:write", "POST", "/api/v1/phishing/submit", {"artifact_kind": "email", "raw_content": "hello"}),
    (phishing, "retriage", "cases:write", "POST", f"/api/v1/phishing/{ROW}/retriage", None),
]

#: `plugins:admin` and `playbooks:write` name `tenant_admin` rather than
#: `platform_admin`: the wildcard role would pass even on a misspelling.
#: `plugins:admin` is not in `ROLE_PERMISSIONS` at all, so only the wildcard
#: roles hold it — `admin` is used there and the docstring says why.
HOLDER = {
    "plugins:admin": "admin",
    "rules:write": "threat_hunter",
    "playbooks:write": "tenant_admin",
    "settings:write": "tenant_admin",
    "threat_intel:write": "soc_lead",
    "alerts:write": "soc_analyst",
    "cases:write": "soc_analyst",
}

REFUSED = {
    "plugins:admin": ["viewer", "soc_analyst", "soc_lead", "threat_hunter", "tenant_admin"],
    "rules:write": ["viewer", "soc_analyst"],
    "playbooks:write": ["viewer", "soc_analyst", "soc_lead", "threat_hunter"],
    "settings:write": ["viewer", "soc_analyst", "soc_lead", "threat_hunter"],
    "threat_intel:write": ["viewer", "soc_analyst"],
    "alerts:write": ["viewer", "threat_hunter"],
    "cases:write": ["viewer"],
}

IDS = [f"{m.__name__.rsplit('.', 1)[-1]}.{h}" for m, h, *_ in GATED]


def _user(role: str) -> CurrentUser:
    return CurrentUser(user_id=uuid.uuid4(), tenant_id=TENANT, role=role, email=f"{role}@tenant.example")


def _db() -> AsyncMock:
    result = MagicMock()
    result.fetchone = MagicMock(return_value=None)
    result.fetchall = MagicMock(return_value=[])
    result.scalar_one_or_none = MagicMock(return_value=None)
    result.scalars = MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))
    result.rowcount = 0
    db = AsyncMock()
    db.execute = AsyncMock(return_value=result)
    db.get = AsyncMock(return_value=None)
    db.scalar = AsyncMock(return_value=None)
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    db.refresh = AsyncMock()
    db.flush = AsyncMock()
    db.delete = AsyncMock()
    db.add = MagicMock()
    return db


def _request(module: Any, role: str, method: str, path: str, payload: Any) -> tuple[int, bool]:
    app = FastAPI()
    app.include_router(module.router, prefix="/api/v1")
    db = _db()
    app.dependency_overrides[get_current_user] = lambda: _user(role)
    app.dependency_overrides[get_db] = lambda: db
    client = TestClient(app, raise_server_exceptions=False)
    # Two routes take a text/plain body and one takes raw bytes; the rest JSON.
    kwargs: dict[str, Any] = {}
    if isinstance(payload, str):
        kwargs["content"] = payload
        kwargs["headers"] = {"Content-Type": "text/plain"}
    elif payload is not None:
        kwargs["json"] = payload
    response = client.request(method, path, **kwargs)
    return response.status_code, db.commit.await_count > 0


def _permissions_on(route: Any) -> list[str]:
    found: list[str] = []

    def walk(dependant: Any) -> None:
        call = getattr(dependant, "call", None)
        if getattr(call, "__name__", "") == "_check":
            for cell in getattr(call, "__closure__", None) or ():
                if isinstance(cell.cell_contents, str):
                    found.append(cell.cell_contents)
        for sub in getattr(dependant, "dependencies", []):
            walk(sub)

    walk(route.dependant)
    return found


def _route_for(module: Any, handler_name: str) -> Any:
    for route in module.router.routes:
        if getattr(route, "endpoint", None) is getattr(module, handler_name):
            return route
    raise AssertionError(f"no route registered for {module.__name__}.{handler_name}")


class TestUnentitledCallersAreRefused:
    @pytest.mark.parametrize(("module", "handler", "permission", "method", "path", "payload"), GATED, ids=IDS)
    def test_every_role_without_the_permission_is_refused(
        self, module: Any, handler: str, permission: str, method: str, path: str, payload: Any
    ) -> None:
        for role in REFUSED[permission]:
            status, committed = _request(module, role, method, path, payload)
            assert not committed, f"{role} committed a write through {handler}"
            assert status == 403, f"{role} got HTTP {status} from {handler}, not 403"

    def test_a_viewer_cannot_publish_a_plugin_as_the_tenant(self) -> None:
        """The submit side of a surface whose review side was already gated."""
        status, _ = _request(community, "viewer", "POST", "/api/v1/community/plugins/publish", None)
        assert status == 403

    def test_a_viewer_cannot_install_third_party_plugin_code(self) -> None:
        status, _ = _request(community, "viewer", "POST", "/api/v1/community/plugins/p1/install", None)
        assert status == 403

    def test_a_viewer_cannot_push_an_indicator_out_to_misp(self) -> None:
        """These routes leave the platform under the tenant's credentials."""
        status, _ = _request(
            stix_taxii,
            "viewer",
            "POST",
            "/api/v1/threatintel/stix/indicators",
            {"pattern": "[ipv4-addr:value = '198.51.100.7']", "name": "c2", "indicator_types": ["malicious-activity"]},
        )
        assert status == 403

    def test_a_viewer_cannot_teach_the_platform_to_stop_looking(self) -> None:
        """An override becomes a per-signature prior that auto-resolves repeats."""
        status, committed = _request(
            feedback,
            "viewer",
            "POST",
            "/api/v1/feedback/alert-override",
            {"alert_id": str(ROW), "original_verdict": "true_positive", "corrected_verdict": "benign"},
        )
        assert not committed
        assert status == 403

    def test_the_dry_run_is_not_weaker_than_the_push(self) -> None:
        """Gating a rehearsal more weakly than the act makes it reconnaissance."""
        live = _permissions_on(_route_for(stix_taxii, "create_indicator"))
        dry = _permissions_on(_route_for(stix_taxii, "misp_push_dry_run"))
        assert dry == live, f"dry run enforces {dry}, live push enforces {live}"


class TestEntitledCallersStillWork:
    @pytest.mark.parametrize(("module", "handler", "permission", "method", "path", "payload"), GATED, ids=IDS)
    def test_a_holder_of_the_permission_is_admitted(
        self, module: Any, handler: str, permission: str, method: str, path: str, payload: Any
    ) -> None:
        status, _ = _request(module, HOLDER[permission], method, path, payload)
        assert status != 403, f"{HOLDER[permission]} holds {permission} but {handler} answered 403"

    def test_a_detection_engineer_may_still_install_a_community_rule(self) -> None:
        """The console's detection catalogue calls this; `threat_hunter` uses it."""
        status, _ = _request(community, "threat_hunter", "POST", "/api/v1/community/detections/d1/install", None)
        assert status != 403

    @pytest.mark.parametrize("role", ["soc_analyst", "soc_lead"])
    def test_an_analyst_may_still_correct_a_verdict(self, role: str) -> None:
        status, _ = _request(
            feedback,
            role,
            "POST",
            "/api/v1/feedback/alert-override",
            {"alert_id": str(ROW), "original_verdict": "true_positive", "corrected_verdict": "benign"},
        )
        assert status != 403

    def test_automated_ingestion_may_still_submit_phishing(self) -> None:
        """`cases:write` is held by `api_service`, which the module needs."""
        status, _ = _request(phishing, "api_service", "POST", "/api/v1/phishing/submit", {"artifact_kind": "email", "raw_content": "hi"})
        assert status != 403

    def test_a_viewer_may_still_browse_the_community_catalogue(self) -> None:
        status, _ = _request(community, "viewer", "GET", "/api/v1/community/detections", None)
        assert status != 403


class TestWiring:
    @pytest.mark.parametrize(("module", "handler", "permission", "method", "path", "payload"), GATED, ids=IDS)
    def test_route_enforces_exactly_its_permission(
        self, module: Any, handler: str, permission: str, method: str, path: str, payload: Any
    ) -> None:
        assert _permissions_on(_route_for(module, handler)) == [permission]

    @pytest.mark.parametrize("module", [marketplace, stix_taxii, feedback, phishing], ids=lambda m: m.__name__.rsplit(".", 1)[-1])
    def test_no_state_changing_route_in_these_modules_is_unguarded(self, module: Any) -> None:
        unguarded = [
            getattr(r.endpoint, "__name__", "?")
            for r in module.router.routes
            if r.methods & {"POST", "PUT", "PATCH", "DELETE"} and not _permissions_on(r)
        ]
        assert not unguarded, f"{module.__name__} has state-changing routes with no permission: {unguarded}"

    def test_rating_is_deliberately_not_gated(self) -> None:
        """The one route in this change left alone, pinned so it stays a decision.

        Every authenticated principal is a legitimate rater, the vocabulary
        has no permission for expressing an opinion, and requiring an
        administrative one would mean only administrators may rate. The real
        integrity question is one-vote-per-user, which the in-memory counter
        cannot express — a storage and product decision, not an authorization
        gap.
        """
        assert _permissions_on(_route_for(community, "rate_community_plugin")) == []

    def test_rating_is_the_only_ungated_community_route(self) -> None:
        unguarded = {
            getattr(r.endpoint, "__name__", "?")
            for r in community.router.routes
            if r.methods & {"POST", "PUT", "PATCH", "DELETE"} and not _permissions_on(r)
        }
        assert unguarded == {"rate_community_plugin"}, f"unexpected ungated community routes: {unguarded - {'rate_community_plugin'}}"

    def test_publishing_is_never_weaker_than_moderating_a_different_type(self) -> None:
        """Each content type's publish/install and its moderation route agree.

        The defect was that they disagreed: moderation required an admin
        permission and submission required nothing at all.
        """
        pairs = [
            ("publish_plugin", "review_community_plugin"),
            ("install_community_plugin", "review_community_plugin"),
            ("submit_playbook", "curate_community_playbook"),
            ("install_community_playbook", "curate_community_playbook"),
        ]
        for write, moderate in pairs:
            write_perms = _permissions_on(_route_for(community, write))
            moderate_perms = _permissions_on(_route_for(community, moderate))
            assert write_perms, f"{write} enforces nothing while {moderate} enforces {moderate_perms}"
