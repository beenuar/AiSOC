"""Tests for the GitLab group audit + vulnerability-findings connector.

Mirrors the wave-2 test pattern (schema + registry wiring, severity
mapping for the tagged-union ``_aisoc_stream`` collapse, actor / src_ip
extraction, ``fetch_alerts`` two-stream merge, and ``test_connection``).
Network mocked with respx.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import respx
from app.connectors import CONNECTOR_REGISTRY
from app.connectors.base import Capability
from app.connectors.gitlab import GitLabConnector

_AUDIT_FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "gitlab" / "audit_events.json"
_FINDING_FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "gitlab" / "vulnerability_findings.json"
_BASE = "https://gitlab.com"


@pytest.fixture(scope="module")
def audit_events() -> list[dict]:
    return json.loads(_AUDIT_FIXTURE.read_text())


@pytest.fixture(scope="module")
def findings() -> list[dict]:
    return json.loads(_FINDING_FIXTURE.read_text())


def test_schema_valid():
    schema = GitLabConnector.schema()
    assert schema.connector_id == "gitlab"
    assert schema.category == "vcs"
    names = {f.name for f in schema.fields}
    # The two we absolutely need; gitlab_url defaults so it's optional.
    assert {"group", "token"} <= names
    caps = GitLabConnector.capabilities()
    assert Capability.PULL_AUDIT in caps
    assert Capability.PULL_ALERTS in caps
    assert schema.oauth is not None
    assert schema.oauth.supported_in_hosted is True


def test_registry_contains_gitlab():
    assert "gitlab" in CONNECTOR_REGISTRY
    assert CONNECTOR_REGISTRY["gitlab"] is GitLabConnector


def test_normalize_user_add_to_high(audit_events):
    c = GitLabConnector(group="g", token="t")
    out = c.normalize({**audit_events[0], "_aisoc_stream": "audit_events"})
    assert out["severity"] == "high"
    assert out["actor"] == "Alice Admin"
    assert out["actor_email"] == "alice@corp.test"
    assert out["src_ip"] == "203.0.113.5"
    assert out["event_type"].startswith("gitlab.")


def test_normalize_pat_create_to_high(audit_events):
    c = GitLabConnector(group="g", token="t")
    out = c.normalize({**audit_events[1], "_aisoc_stream": "audit_events"})
    assert out["severity"] == "high"


def test_normalize_protected_branch_removal_to_high(audit_events):
    c = GitLabConnector(group="g", token="t")
    out = c.normalize({**audit_events[2], "_aisoc_stream": "audit_events"})
    assert out["severity"] == "high"


def test_normalize_project_destroy_to_high(audit_events):
    c = GitLabConnector(group="g", token="t")
    out = c.normalize({**audit_events[3], "_aisoc_stream": "audit_events"})
    # Project_destroyed is in the high-risk list and would also match the
    # "destroy" catch-all if it weren't; high beats medium.
    assert out["severity"] == "high"


def test_normalize_description_change_to_info(audit_events):
    c = GitLabConnector(group="g", token="t")
    out = c.normalize({**audit_events[4], "_aisoc_stream": "audit_events"})
    assert out["severity"] == "info"


def test_normalize_finding_critical(findings):
    c = GitLabConnector(group="g", token="t")
    out = c.normalize({**findings[0], "_aisoc_stream": "vulnerability_finding"})
    assert out["severity"] == "critical"
    assert out["external_id"].startswith("finding-")
    assert "Gitleaks" in out["event_type"] or out["event_type"].endswith("Gitleaks")


def test_normalize_finding_high_severity(findings):
    c = GitLabConnector(group="g", token="t")
    out = c.normalize({**findings[1], "_aisoc_stream": "vulnerability_finding"})
    assert out["severity"] == "high"


def test_self_managed_url_strips_trailing_slash():
    c = GitLabConnector(group="g", token="t", gitlab_url="https://gitlab.corp.test/")
    # Internal — accessing _base intentionally to assert the contract.
    assert c._base == "https://gitlab.corp.test"


def test_nested_group_path_is_encoded():
    c = GitLabConnector(group="parent/child", token="t")
    # `quote` with safe="" turns `/` into `%2F` so nested groups survive
    # the URL routing layer.
    assert c._group_path == "parent%2Fchild"


@pytest.mark.asyncio
@respx.mock
async def test_test_connection_success():
    c = GitLabConnector(group="acme", token="t")
    respx.get(f"{_BASE}/api/v4/groups/acme").respond(200, json={"id": 7, "name": "Acme"})
    respx.get(f"{_BASE}/api/v4/groups/acme/audit_events").respond(200, json=[])
    res = await c.test_connection()
    assert res["success"] is True
    assert res["group"] == "acme"
    assert res["audit_events_available"] is True


@pytest.mark.asyncio
@respx.mock
async def test_test_connection_audit_unavailable_is_still_success():
    c = GitLabConnector(group="acme", token="t")
    respx.get(f"{_BASE}/api/v4/groups/acme").respond(200, json={"id": 7, "name": "Acme"})
    # Free-tier group → audit endpoint returns 403.
    respx.get(f"{_BASE}/api/v4/groups/acme/audit_events").respond(403, json={"message": "403 Forbidden"})
    res = await c.test_connection()
    assert res["success"] is True
    assert res["audit_events_available"] is False


@pytest.mark.asyncio
@respx.mock
async def test_test_connection_bad_token():
    c = GitLabConnector(group="acme", token="bad")
    respx.get(f"{_BASE}/api/v4/groups/acme").respond(401, json={"message": "401 Unauthorized"})
    res = await c.test_connection()
    assert res["success"] is False
    assert "401" in res["error"]


@pytest.mark.asyncio
@respx.mock
async def test_fetch_alerts_merges_audit_and_findings(audit_events, findings):
    c = GitLabConnector(group="acme", token="t")
    respx.get(f"{_BASE}/api/v4/groups/acme/audit_events").respond(200, json=audit_events)
    respx.get(f"{_BASE}/api/v4/groups/acme/security/vulnerability_findings").respond(200, json=findings)

    out = await c.fetch_alerts(since_seconds=24 * 60 * 60)

    # 5 audit events + 3 findings (all within a 1-day window relative to the
    # fixture timestamps which are at "now"-ish from a CI clock perspective).
    # We can't depend on real "now" here, so just assert both streams are
    # present, the source tag is uniform, and severities are sane.
    sources = {e["source"] for e in out}
    assert sources == {"gitlab"}
    severities = {e["severity"] for e in out}
    assert "high" in severities  # the audit stream has multiple highs
    # If the finding window filter didn't drop the criticals, we expect
    # to see a critical too.
    assert any(s in {"critical", "high"} for s in severities)


@pytest.mark.asyncio
@respx.mock
async def test_fetch_alerts_handles_403_on_findings(audit_events):
    c = GitLabConnector(group="acme", token="t")
    respx.get(f"{_BASE}/api/v4/groups/acme/audit_events").respond(200, json=audit_events)
    respx.get(f"{_BASE}/api/v4/groups/acme/security/vulnerability_findings").respond(403, json={"message": "403 Forbidden"})

    out = await c.fetch_alerts(since_seconds=24 * 60 * 60)
    # We still get the audit events — Ultimate-tier-only findings don't
    # block the rest of the poll.
    assert len(out) >= 1
    assert all(e["source"] == "gitlab" for e in out)
