"""Tests for the Kubernetes audit log connector.

The connector has two modes (``webhook`` and ``file_tail``) and a
severity heuristic that decides whether an audit event is interesting
enough to bubble up. The tests are grouped accordingly:

* ``test_schema`` / ``test_capabilities`` — surface-area contract.
* ``test_severity_*``                       — the heuristic itself.
* ``test_normalize_*``                      — the audit.k8s.io/v1
                                               -> AiSOC shape mapping.
* ``test_webhook_mode_*``                   — webhook test_connection
                                               + fetch_alerts contract.
* ``test_file_tail_*``                      — file_tail cursor behaviour,
                                               rotation handling, and
                                               partial-line buffering.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from app.connectors.base import Capability
from app.connectors.kubernetes_audit import (
    _MAX_TAIL_BYTES_PER_POLL,
    KubernetesAuditConnector,
    _classify_severity,
)

# ---------------------------------------------------------------------------
# Schema / capabilities contract
# ---------------------------------------------------------------------------


def test_schema_basic_shape():
    schema = KubernetesAuditConnector.schema()
    assert schema.connector_id == "kubernetes_audit"
    assert schema.connector_name == "Kubernetes Audit Logs"
    assert schema.category == "cloud"
    assert schema.docs_url == "/docs/connectors/kubernetes-audit"


def test_schema_field_set():
    schema = KubernetesAuditConnector.schema()
    field_names = {f.name for f in schema.fields}
    assert field_names == {
        "mode",
        "cluster_name",
        "inbox_token",
        "audit_log_path",
        "cursor_path",
    }


def test_schema_mode_field_is_select_with_two_options():
    schema = KubernetesAuditConnector.schema()
    mode = next(f for f in schema.fields if f.name == "mode")
    assert mode.type == "select"
    assert mode.required is True
    assert mode.default == "webhook"
    values = {opt["value"] for opt in (mode.options or [])}
    assert values == {"webhook", "file_tail"}


def test_schema_inbox_token_is_secret():
    schema = KubernetesAuditConnector.schema()
    token = next(f for f in schema.fields if f.name == "inbox_token")
    assert token.type == "secret"
    assert token.required is False


def test_schema_audit_log_path_has_sensible_default():
    schema = KubernetesAuditConnector.schema()
    path = next(f for f in schema.fields if f.name == "audit_log_path")
    assert path.default == "/var/log/kubernetes/audit/audit.log"


def test_capabilities_advertises_pull_audit_and_alerts():
    caps = KubernetesAuditConnector.capabilities()
    assert Capability.PULL_AUDIT in caps
    assert Capability.PULL_ALERTS in caps


# ---------------------------------------------------------------------------
# Severity heuristic
# ---------------------------------------------------------------------------


def test_severity_pod_exec_is_critical():
    # Interactive shell into a pod is functionally equivalent to a
    # P1 incident on that pod — map to AiSOC's ``critical`` tier.
    event = {
        "verb": "create",
        "objectRef": {"resource": "pods", "subresource": "exec"},
        "responseStatus": {"code": 101},
    }
    assert _classify_severity(event) == "critical"


def test_severity_pod_attach_is_critical():
    # ``attach`` is the streaming-IO sibling of ``exec`` — same blast
    # radius, same P1 critical tier.
    event = {
        "verb": "create",
        "objectRef": {"resource": "pods", "subresource": "attach"},
    }
    assert _classify_severity(event) == "critical"


def test_severity_pod_portforward_is_critical():
    # ``portforward`` punches a tunnel to a pod-local port — same
    # P1 blast radius as ``exec`` / ``attach``.
    event = {
        "verb": "create",
        "objectRef": {"resource": "pods", "subresource": "portforward"},
    }
    assert _classify_severity(event) == "critical"


def test_severity_impersonate_is_critical():
    # ``impersonate`` is direct identity hand-off — anyone who can
    # impersonate cluster-admin owns the cluster. Critical / P1.
    event = {
        "verb": "impersonate",
        "objectRef": {"resource": "users"},
    }
    assert _classify_severity(event) == "critical"


def test_severity_clusterrolebinding_create_is_critical():
    # Writes against the RBAC graph itself are the most common
    # post-foothold takeover primitive — P1 critical.
    event = {
        "verb": "create",
        "objectRef": {"resource": "clusterrolebindings"},
    }
    assert _classify_severity(event) == "critical"


def test_severity_secret_create_is_high():
    event = {
        "verb": "create",
        "objectRef": {"resource": "secrets"},
    }
    assert _classify_severity(event) == "high"


def test_severity_serviceaccount_token_create_is_high():
    # ``create`` on ``serviceaccounts`` is the canonical
    # "ServiceAccount token mint" code path. It must trip high.
    event = {
        "verb": "create",
        "objectRef": {"resource": "serviceaccounts", "subresource": "token"},
    }
    assert _classify_severity(event) == "high"


def test_severity_workload_write_is_medium():
    event = {
        "verb": "patch",
        "objectRef": {"resource": "deployments"},
    }
    assert _classify_severity(event) == "medium"


def test_severity_failed_request_is_medium():
    # 403s and 401s during recon / RBAC probing are exactly what
    # we want to surface above floor.
    event = {
        "verb": "get",
        "objectRef": {"resource": "configmaps"},
        "responseStatus": {"code": 403},
    }
    assert _classify_severity(event) == "medium"


def test_severity_sensitive_read_is_low():
    event = {
        "verb": "get",
        "objectRef": {"resource": "secrets"},
        "responseStatus": {"code": 200},
    }
    assert _classify_severity(event) == "low"


def test_severity_steady_state_read_is_info():
    event = {
        "verb": "list",
        "objectRef": {"resource": "pods"},
        "responseStatus": {"code": 200},
    }
    assert _classify_severity(event) == "info"


def test_severity_missing_objectref_does_not_crash():
    # Some audit events (e.g. RequestReceived stage on a malformed
    # request) don't carry an objectRef at all.
    event = {"verb": "get", "responseStatus": {"code": 200}}
    assert _classify_severity(event) == "info"


def test_severity_missing_response_status_does_not_crash():
    event = {"verb": "get", "objectRef": {"resource": "pods"}}
    assert _classify_severity(event) == "info"


# ---------------------------------------------------------------------------
# normalize()
# ---------------------------------------------------------------------------


def _make_connector(**overrides):
    defaults = {
        "mode": "webhook",
        "cluster_name": "prod-eks-us-east-1",
        "inbox_token": "tok-abcdef-1234567890",
    }
    defaults.update(overrides)
    return KubernetesAuditConnector(**defaults)


def test_normalize_extracts_canonical_fields():
    conn = _make_connector()
    raw = {
        "kind": "Event",
        "apiVersion": "audit.k8s.io/v1",
        "level": "RequestResponse",
        "auditID": "00000000-0000-0000-0000-000000000001",
        "stage": "ResponseComplete",
        "requestURI": "/api/v1/namespaces/prod/secrets/db-creds",
        "verb": "get",
        "user": {
            "username": "alice@example.com",
            "groups": ["system:authenticated"],
        },
        "sourceIPs": ["198.51.100.5", "10.0.0.7"],
        "userAgent": "kubectl/v1.29.0",
        "objectRef": {
            "resource": "secrets",
            "namespace": "prod",
            "name": "db-creds",
            "apiVersion": "v1",
        },
        "responseStatus": {"metadata": {}, "code": 200},
        "requestReceivedTimestamp": "2026-05-10T10:00:00.000000Z",
        "stageTimestamp": "2026-05-10T10:00:00.123456Z",
    }
    norm = conn.normalize(raw)
    assert norm["source"] == "kubernetes_audit"
    assert norm["category"] == "cloud"
    assert norm["external_id"] == raw["auditID"]
    assert norm["audit_id"] == raw["auditID"]
    assert norm["k8s_user"] == "alice@example.com"
    assert norm["k8s_user_groups"] == ["system:authenticated"]
    assert norm["k8s_verb"] == "get"
    assert norm["k8s_resource"] == "secrets"
    assert norm["k8s_namespace"] == "prod"
    assert norm["k8s_object_name"] == "db-creds"
    assert norm["k8s_response_code"] == 200
    assert norm["src_ip"] == "198.51.100.5"
    assert norm["source_ips"] == ["198.51.100.5", "10.0.0.7"]
    assert norm["cluster_name"] == "prod-eks-us-east-1"
    assert norm["cloud_platform"] == "kubernetes"
    assert norm["created_at"] == "2026-05-10T10:00:00.123456Z"
    # The full audit event must round-trip — detection content needs it.
    assert norm["raw_event"] is raw
    # Read of a sensitive resource is "low" by the heuristic.
    assert norm["severity"] == "low"


def test_normalize_pod_exec_routes_to_critical_severity_and_clear_title():
    # End-to-end: a pod ``exec`` event must surface as ``critical`` so
    # it lands in the P1 lane (15-minute MTTD SLA).
    conn = _make_connector()
    raw = {
        "auditID": "exec-1",
        "verb": "create",
        "user": {"username": "mallory@example.com"},
        "objectRef": {
            "resource": "pods",
            "subresource": "exec",
            "namespace": "prod",
            "name": "billing-api-7d4b8c-abc",
        },
        "responseStatus": {"code": 101},
        "sourceIPs": ["203.0.113.7"],
        "stageTimestamp": "2026-05-10T11:00:00Z",
    }
    norm = conn.normalize(raw)
    assert norm["severity"] == "critical"
    assert norm["k8s_subresource"] == "exec"
    # The title should be obviously parseable by a human eyeballing
    # the inbox — verb, resource, subresource, target.
    assert "mallory@example.com" in norm["title"]
    assert "exec" in norm["title"]
    assert "billing-api-7d4b8c-abc" in norm["title"]
    assert "prod/" in norm["title"]


def test_normalize_falls_back_to_request_received_timestamp():
    """Older API versions only emit requestReceivedTimestamp."""
    conn = _make_connector()
    raw = {
        "auditID": "old-1",
        "verb": "get",
        "objectRef": {"resource": "pods"},
        "requestReceivedTimestamp": "2026-05-10T09:00:00Z",
    }
    norm = conn.normalize(raw)
    assert norm["created_at"] == "2026-05-10T09:00:00Z"


def test_normalize_handles_impersonation():
    conn = _make_connector()
    raw = {
        "auditID": "imp-1",
        "verb": "get",
        "user": {"username": "ci-bot"},
        "impersonatedUser": {
            "username": "system:masters",
            "groups": ["system:masters"],
        },
        "objectRef": {"resource": "secrets"},
        "responseStatus": {"code": 200},
    }
    norm = conn.normalize(raw)
    assert norm["k8s_user"] == "ci-bot"
    assert norm["k8s_impersonated_user"] == "system:masters"


def test_normalize_missing_optional_fields_does_not_crash():
    """Audit events at the RequestReceived stage are sparse."""
    conn = _make_connector()
    raw = {"auditID": "sparse-1", "verb": "list"}
    norm = conn.normalize(raw)
    assert norm["external_id"] == "sparse-1"
    assert norm["k8s_user"] is None
    assert norm["k8s_resource"] is None
    assert norm["src_ip"] is None
    assert norm["source_ips"] is None


def test_normalize_picks_first_source_ip_as_principal():
    """X-Forwarded-For chain — we want the immediate caller."""
    conn = _make_connector()
    raw = {
        "auditID": "xff-1",
        "verb": "get",
        "sourceIPs": ["198.51.100.99", "10.0.0.1", "10.0.0.2"],
        "objectRef": {"resource": "pods"},
    }
    norm = conn.normalize(raw)
    assert norm["src_ip"] == "198.51.100.99"


def test_normalize_stamps_cluster_name_on_every_event():
    conn = _make_connector(cluster_name="staging-gke-us-central1")
    raw = {"auditID": "c-1", "verb": "list"}
    norm = conn.normalize(raw)
    assert norm["cluster_name"] == "staging-gke-us-central1"


# ---------------------------------------------------------------------------
# webhook mode — test_connection + fetch_alerts
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_webhook_mode_requires_cluster_name():
    conn = KubernetesAuditConnector(
        mode="webhook",
        cluster_name="",
        inbox_token="tok-1",
    )
    result = await conn.test_connection()
    assert result["success"] is False
    assert "cluster_name" in result["error"]


@pytest.mark.asyncio
async def test_webhook_mode_requires_inbox_token():
    conn = KubernetesAuditConnector(
        mode="webhook",
        cluster_name="prod",
        inbox_token="",
    )
    result = await conn.test_connection()
    assert result["success"] is False
    assert "inbox_token" in result["error"]


@pytest.mark.asyncio
async def test_webhook_mode_success_returns_hint_with_truncated_token():
    conn = KubernetesAuditConnector(
        mode="webhook",
        cluster_name="prod-eks-us-east-1",
        inbox_token="tok-superlong-secret-token-value-123",
    )
    result = await conn.test_connection()
    assert result["success"] is True
    assert result["mode"] == "webhook"
    assert result["cluster"] == "prod-eks-us-east-1"
    # The hint must not leak the full token — only a short prefix.
    assert "tok-su" in result["hint"]
    assert "superlong-secret-token-value-123" not in result["hint"]


@pytest.mark.asyncio
async def test_webhook_mode_fetch_alerts_is_empty():
    """Webhook mode pulls nothing on the scheduler tick — events
    arrive on the inbox path instead.
    """
    conn = KubernetesAuditConnector(
        mode="webhook",
        cluster_name="prod",
        inbox_token="tok-1",
    )
    result = await conn.fetch_alerts()
    assert result == []


@pytest.mark.asyncio
async def test_unknown_mode_returns_error():
    conn = KubernetesAuditConnector(
        mode="something-weird",
        cluster_name="prod",
    )
    result = await conn.test_connection()
    assert result["success"] is False
    assert "unknown mode" in result["error"]


# ---------------------------------------------------------------------------
# file_tail mode — test_connection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_file_tail_test_connection_reports_missing_file(tmp_path: Path):
    audit_log = tmp_path / "does-not-exist.log"
    conn = KubernetesAuditConnector(
        mode="file_tail",
        cluster_name="prod",
        audit_log_path=str(audit_log),
    )
    result = await conn.test_connection()
    assert result["success"] is False
    assert "not found" in result["error"]


@pytest.mark.asyncio
async def test_file_tail_test_connection_success(tmp_path: Path):
    audit_log = tmp_path / "audit.log"
    audit_log.write_text("")
    conn = KubernetesAuditConnector(
        mode="file_tail",
        cluster_name="prod",
        audit_log_path=str(audit_log),
    )
    result = await conn.test_connection()
    assert result["success"] is True
    assert result["mode"] == "file_tail"
    assert result["audit_log_path"] == str(audit_log)
    # Default cursor path is right next to the audit log.
    assert result["cursor_path"].endswith(".aisoc-cursor")


@pytest.mark.asyncio
async def test_file_tail_test_connection_reports_unreadable_file(tmp_path: Path):
    audit_log = tmp_path / "audit.log"
    audit_log.write_text("")
    audit_log.chmod(0o000)
    try:
        conn = KubernetesAuditConnector(
            mode="file_tail",
            cluster_name="prod",
            audit_log_path=str(audit_log),
        )
        result = await conn.test_connection()
        # If we happen to be running as root (e.g. in CI), 0o000
        # is still readable and the test isn't meaningful. Skip
        # rather than assert.
        if os.geteuid() == 0:
            pytest.skip("running as root — chmod 000 is not enforceable")
        assert result["success"] is False
        assert "not readable" in result["error"]
    finally:
        audit_log.chmod(0o644)


# ---------------------------------------------------------------------------
# file_tail mode — fetch_alerts + cursor behaviour
# ---------------------------------------------------------------------------


def _write_audit_events(path: Path, events: list[dict]) -> None:
    """Write the apiserver's one-event-per-line JSON format."""
    body = "\n".join(json.dumps(e) for e in events) + "\n"
    path.write_text(body)


def _append_audit_events(path: Path, events: list[dict]) -> None:
    body = "\n".join(json.dumps(e) for e in events) + "\n"
    with open(path, "a") as fh:
        fh.write(body)


@pytest.mark.asyncio
async def test_file_tail_reads_full_file_when_no_cursor(tmp_path: Path):
    audit_log = tmp_path / "audit.log"
    events = [
        {"auditID": "a", "verb": "get", "objectRef": {"resource": "pods"}},
        {"auditID": "b", "verb": "list", "objectRef": {"resource": "pods"}},
    ]
    _write_audit_events(audit_log, events)
    conn = KubernetesAuditConnector(
        mode="file_tail",
        cluster_name="prod",
        audit_log_path=str(audit_log),
    )
    result = await conn.fetch_alerts()
    assert len(result) == 2
    assert result[0]["external_id"] == "a"
    assert result[1]["external_id"] == "b"


@pytest.mark.asyncio
async def test_file_tail_cursor_advances_between_polls(tmp_path: Path):
    audit_log = tmp_path / "audit.log"
    _write_audit_events(audit_log, [{"auditID": "a", "verb": "get"}])
    conn = KubernetesAuditConnector(
        mode="file_tail",
        cluster_name="prod",
        audit_log_path=str(audit_log),
    )
    first = await conn.fetch_alerts()
    assert len(first) == 1
    # Second poll without new bytes should be a no-op.
    second = await conn.fetch_alerts()
    assert second == []
    # Append a new event — only the new one should come back.
    _append_audit_events(audit_log, [{"auditID": "b", "verb": "list"}])
    third = await conn.fetch_alerts()
    assert len(third) == 1
    assert third[0]["external_id"] == "b"


@pytest.mark.asyncio
async def test_file_tail_resets_cursor_after_rotation(tmp_path: Path):
    """If the file shrinks (logrotate truncated it), the cursor
    must reset to 0 rather than seeking past EOF forever.
    """
    audit_log = tmp_path / "audit.log"
    _write_audit_events(
        audit_log,
        [{"auditID": "old-1", "verb": "get"}, {"auditID": "old-2", "verb": "get"}],
    )
    conn = KubernetesAuditConnector(
        mode="file_tail",
        cluster_name="prod",
        audit_log_path=str(audit_log),
    )
    first = await conn.fetch_alerts()
    assert len(first) == 2

    # Simulate logrotate: replace contents with a smaller payload.
    _write_audit_events(audit_log, [{"auditID": "new-1", "verb": "list"}])
    second = await conn.fetch_alerts()
    assert len(second) == 1
    assert second[0]["external_id"] == "new-1"


@pytest.mark.asyncio
async def test_file_tail_buffers_partial_trailing_line(tmp_path: Path):
    """A line without a trailing newline = in-flight write. We
    must not consume it — back the cursor up and wait for the rest.
    """
    audit_log = tmp_path / "audit.log"
    full = {"auditID": "complete", "verb": "get"}
    body = json.dumps(full) + "\n" + '{"auditID": "partial'  # no newline
    audit_log.write_text(body)
    conn = KubernetesAuditConnector(
        mode="file_tail",
        cluster_name="prod",
        audit_log_path=str(audit_log),
    )
    first = await conn.fetch_alerts()
    assert len(first) == 1
    assert first[0]["external_id"] == "complete"

    # Now complete the partial line. Next poll should pick up the
    # newly-completed event.
    completion = '", "verb": "list"}\n'
    with open(audit_log, "a") as fh:
        fh.write(completion)
    second = await conn.fetch_alerts()
    assert len(second) == 1
    assert second[0]["external_id"] == "partial"


@pytest.mark.asyncio
async def test_file_tail_skips_malformed_json_line(tmp_path: Path):
    audit_log = tmp_path / "audit.log"
    body = json.dumps({"auditID": "a", "verb": "get"}) + "\n" + "this-is-not-json\n" + json.dumps({"auditID": "b", "verb": "list"}) + "\n"
    audit_log.write_text(body)
    conn = KubernetesAuditConnector(
        mode="file_tail",
        cluster_name="prod",
        audit_log_path=str(audit_log),
    )
    result = await conn.fetch_alerts()
    assert len(result) == 2
    assert {e["external_id"] for e in result} == {"a", "b"}


@pytest.mark.asyncio
async def test_file_tail_missing_log_returns_empty(tmp_path: Path):
    """No file yet = no events. Must not raise — the apiserver may
    not have started writing yet at connector boot.
    """
    audit_log = tmp_path / "not-yet.log"
    conn = KubernetesAuditConnector(
        mode="file_tail",
        cluster_name="prod",
        audit_log_path=str(audit_log),
    )
    result = await conn.fetch_alerts()
    assert result == []


@pytest.mark.asyncio
async def test_file_tail_respects_custom_cursor_path(tmp_path: Path):
    audit_log = tmp_path / "audit.log"
    cursor = tmp_path / "cursors" / "audit.cursor"
    cursor.parent.mkdir(parents=True)
    _write_audit_events(audit_log, [{"auditID": "a", "verb": "get"}])
    conn = KubernetesAuditConnector(
        mode="file_tail",
        cluster_name="prod",
        audit_log_path=str(audit_log),
        cursor_path=str(cursor),
    )
    await conn.fetch_alerts()
    # The custom cursor file must exist and hold a byte offset > 0.
    assert cursor.exists()
    assert int(cursor.read_text().strip()) > 0


@pytest.mark.asyncio
async def test_file_tail_corrupt_cursor_starts_from_zero(tmp_path: Path):
    audit_log = tmp_path / "audit.log"
    cursor = tmp_path / "audit.log.aisoc-cursor"
    _write_audit_events(audit_log, [{"auditID": "a", "verb": "get"}])
    cursor.write_text("not-an-integer")
    conn = KubernetesAuditConnector(
        mode="file_tail",
        cluster_name="prod",
        audit_log_path=str(audit_log),
    )
    result = await conn.fetch_alerts()
    assert len(result) == 1
    assert result[0]["external_id"] == "a"


@pytest.mark.asyncio
async def test_file_tail_caps_read_size_per_poll(tmp_path: Path, monkeypatch):
    """The per-poll cap exists so a huge backlog doesn't wedge the
    scheduler. Use monkeypatch to shrink the cap so we don't have to
    write 8 MiB of test data.
    """
    monkeypatch.setattr(
        "app.connectors.kubernetes_audit._MAX_TAIL_BYTES_PER_POLL",
        200,  # tiny cap so we can prove the chunking works
    )
    # Now ensure the constant we actually imported also reflects the
    # patch (the connector reads it via module-level reference).
    assert _MAX_TAIL_BYTES_PER_POLL == 8 * 1024 * 1024  # untouched here

    audit_log = tmp_path / "audit.log"
    # Each line is ~80 bytes — 5 lines = ~400 bytes, well over the
    # patched 200 byte cap.
    events = [{"auditID": f"id-{i:03d}", "verb": "get", "objectRef": {"resource": "pods"}} for i in range(5)]
    _write_audit_events(audit_log, events)

    conn = KubernetesAuditConnector(
        mode="file_tail",
        cluster_name="prod",
        audit_log_path=str(audit_log),
    )
    first = await conn.fetch_alerts()
    # We should have read a strict prefix of the events, not all.
    assert 0 < len(first) < 5
    # Drain the rest. Multiple polls are expected — the whole point
    # of the cap is that one poll can't drain a huge backlog.
    all_events = list(first)
    for _ in range(10):
        batch = await conn.fetch_alerts()
        if not batch:
            break
        all_events.extend(batch)
    assert len(all_events) == 5
    assert [e["external_id"] for e in all_events] == [f"id-{i:03d}" for i in range(5)]
