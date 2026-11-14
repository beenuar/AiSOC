"""
Kubernetes audit log connector.

The Kubernetes API server emits an audit log for every authenticated
request hitting the apiserver. Audit logs are the highest-fidelity
detection surface inside a cluster: every ``kubectl exec``, every
service-account token mint, every ``secrets`` GET shows up here.
Almost every detection rule under
``detections/cloud/kubernetes-*.yaml`` and
``detections/identity/kubernetes-*.yaml`` expects events in this
shape.

Why dual-mode (webhook vs file_tail)?

    Kubernetes supports two audit backends:

      * **Webhook backend** — the apiserver POSTs each batch of audit
        events to an HTTP endpoint configured via ``AuditSink`` (v1beta1)
        or via the ``--audit-webhook-config-file`` apiserver flag. This
        is the right pick for managed clusters (EKS / GKE / AKS) where
        operators can't shell onto the control plane to read log files.
        We don't expose a new HTTP route per connector — instead this
        mode tells the operator to drop their audit events at the
        existing ``/v1/inbox/{token}`` endpoint backed by the
        ``k8s-audit`` ingest template. That keeps the auth model
        consistent (token-bound) and reuses the same normalizer the
        rest of the inbox flow uses.

      * **file_tail backend** — many self-hosted clusters publish
        audit events to a local JSON-line file (``--audit-log-path``).
        The polling scheduler reads the file forward from a cursor
        and ships each event up to ingest. This mode is the
        operationally-cheap option for on-prem / Rancher / kubeadm
        clusters, but does require AiSOC's connector pod to be able
        to read the file.

    Both modes emit the same normalized shape — the apiserver writes
    the same ``Event`` JSON schema regardless of backend
    (``audit.k8s.io/v1``), so all the divergence is in *how* we
    receive bytes, not in what's inside them.

What we don't do here:

    The connector deliberately does not run a long-lived listener
    process. ``fetch_alerts`` is called by the polling scheduler on
    a cadence; in file_tail mode we read from the cursor; in webhook
    mode we return an empty list and the events arrive over the
    inbox path instead. That keeps the runtime model identical to
    every other connector and avoids needing connector-instance-aware
    HTTP routes.

Severity heuristic:

    Audit events don't carry an inherent severity — they're a raw
    log of API activity. We bucket using the following heuristic
    so the inbox doesn't fill with low-signal ``get pods`` rows:

      * ``critical`` — ``exec`` / ``attach`` / ``portforward`` into
        a pod, ``impersonate`` verb, or any write against
        ``clusterrolebindings`` / ``rolebindings``.
      * ``high``    — write verbs (``create`` / ``delete`` /
        ``patch``) on ``secrets``, ``serviceaccounts``,
        ``clusterroles``, or ``roles``.
      * ``medium``  — write verbs on workloads (``deployments``,
        ``daemonsets``, ``statefulsets``) or any failed (non-2xx)
        request.
      * ``low``     — read verbs on sensitive resources.
      * ``info``    — anything else (the apiserver chatter floor).
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()


# Verbs that mutate cluster state. Used by the severity heuristic.
_WRITE_VERBS: frozenset[str] = frozenset({"create", "update", "patch", "delete", "deletecollection"})

# Resources we always treat as sensitive (writes are high+).
_SENSITIVE_RESOURCES: frozenset[str] = frozenset(
    {
        "secrets",
        "serviceaccounts",
        "clusterroles",
        "roles",
        "clusterrolebindings",
        "rolebindings",
        "certificatesigningrequests",
    }
)

# Pod subresources that imply interactive access. ``exec`` is the big
# one — it's the kubernetes-native "shell on prod" verb.
_INTERACTIVE_SUBRESOURCES: frozenset[str] = frozenset({"exec", "attach", "portforward", "proxy"})

# Workload resources whose writes deserve medium severity even
# without a sensitive-resource match.
_WORKLOAD_RESOURCES: frozenset[str] = frozenset(
    {
        "deployments",
        "daemonsets",
        "statefulsets",
        "jobs",
        "cronjobs",
        "pods",
        "replicasets",
    }
)

# Hard ceiling on bytes read per poll in file_tail mode. The
# apiserver can produce hundreds of MB per minute on a busy cluster
# — we'd rather drop trailing events from a single poll and catch
# up on the next tick than wedge the scheduler.
_MAX_TAIL_BYTES_PER_POLL = 8 * 1024 * 1024  # 8 MiB


def _classify_severity(event: dict[str, Any]) -> str:
    """Bucket a single audit event into AiSOC's 5-tier severity ladder.

    Reads the standard ``audit.k8s.io/v1`` Event shape:
        objectRef.resource, objectRef.subresource, verb,
        responseStatus.code.

    The ``critical`` tier is reserved for the three signals that map
    directly to standalone P1 SOC incidents on a Kubernetes cluster:
    interactive shell into a pod, ``impersonate`` privilege escalation,
    and writes to the RBAC binding graph itself.
    """
    verb = (event.get("verb") or "").lower()
    obj_ref = event.get("objectRef") or {}
    resource = (obj_ref.get("resource") or "").lower()
    subresource = (obj_ref.get("subresource") or "").lower()
    code = (event.get("responseStatus") or {}).get("code")

    # Interactive shell into a pod is the loudest signal we have —
    # treat it as a standalone critical incident worthy of the P1 SLA.
    if resource == "pods" and subresource in _INTERACTIVE_SUBRESOURCES:
        return "critical"

    # Privilege-escalation primitives — direct hand-off of identity.
    if verb == "impersonate":
        return "critical"

    # Writes against the RBAC graph itself — most common cluster
    # take-over primitive after an initial foothold.
    if verb in _WRITE_VERBS and resource in {"clusterrolebindings", "rolebindings"}:
        return "critical"

    # Writes against any other sensitive resource (Secrets,
    # ServiceAccounts, Roles, etc).
    if verb in _WRITE_VERBS and resource in _SENSITIVE_RESOURCES:
        return "high"

    # Workload writes are medium — operators do these all the time
    # in normal CI/CD flow, so they're not high, but they're not
    # noise floor either.
    if verb in _WRITE_VERBS and resource in _WORKLOAD_RESOURCES:
        return "medium"

    # Failed (non-2xx) requests are worth bumping above floor so
    # bruteforce / probing patterns surface.
    if isinstance(code, int) and code >= 400:
        return "medium"

    # Reads of sensitive resources — useful trail for credential
    # access investigations but not inherently alarming.
    if verb in {"get", "list", "watch"} and resource in _SENSITIVE_RESOURCES:
        return "low"

    return "info"


class KubernetesAuditConnector(BaseConnector):
    """Dual-mode Kubernetes audit log connector.

    Configure exactly one of:
      * ``mode = "webhook"`` — listener configured externally; you
        POST audit events to ``/v1/inbox/{inbox_token}`` with the
        ``k8s-audit`` template attached. ``fetch_alerts`` returns
        an empty list because the events arrive via the inbox path.
      * ``mode = "file_tail"`` — the connector pod reads the local
        audit log file forward from a saved byte cursor.
    """

    connector_id = "kubernetes_audit"
    connector_name = "Kubernetes Audit Logs"
    connector_category = "cloud"

    # File cursor state lives next to the audit log itself so the
    # cursor survives connector restarts. Operators who'd rather
    # store cursors in a different location can override via the
    # ``cursor_path`` field — see schema().
    _DEFAULT_CURSOR_SUFFIX = ".aisoc-cursor"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Kubernetes apiserver audit logs. Supports two delivery "
                "modes: webhook (apiserver pushes events to AiSOC's "
                "inbox) and file_tail (AiSOC tails a local audit log "
                "file forward from a byte cursor). Powers cluster-level "
                "detections under detections/cloud/kubernetes-*.yaml."
            ),
            docs_url="/docs/connectors/kubernetes-audit",
            fields=[
                Field(
                    "mode",
                    "select",
                    "Delivery mode",
                    required=True,
                    default="webhook",
                    options=[
                        {"value": "webhook", "label": "Webhook (apiserver pushes)"},
                        {"value": "file_tail", "label": "File tail (read local audit log)"},
                    ],
                    help_text=(
                        "Webhook is the right choice for managed "
                        "clusters (EKS/GKE/AKS). File tail is the "
                        "right choice for self-hosted clusters where "
                        "you can mount the audit log path into the "
                        "AiSOC connector pod."
                    ),
                ),
                Field(
                    "cluster_name",
                    "string",
                    "Cluster name",
                    required=True,
                    help_text=(
                        "Human-readable cluster name. Surfaced on "
                        "every normalised event so detections and "
                        "investigations can filter to a single cluster."
                    ),
                ),
                Field(
                    "inbox_token",
                    "secret",
                    "Inbox token (webhook mode only)",
                    required=False,
                    help_text=(
                        "Bound inbox token created with the "
                        "``k8s-audit`` template attached. Configure "
                        "your apiserver AuditSink / "
                        "--audit-webhook-config-file to POST to "
                        "``/v1/inbox/<this-token>``."
                    ),
                ),
                Field(
                    "audit_log_path",
                    "string",
                    "Audit log path (file_tail mode only)",
                    required=False,
                    default="/var/log/kubernetes/audit/audit.log",
                    help_text=(
                        "Absolute path to the apiserver audit log "
                        "file inside the connector pod. Mount it "
                        "read-only from the host or from a persistent "
                        "volume the apiserver writes to."
                    ),
                ),
                Field(
                    "cursor_path",
                    "string",
                    "Cursor file path (file_tail mode only)",
                    required=False,
                    help_text=(
                        "Optional override for where AiSOC stores "
                        "its byte-position cursor. Defaults to "
                        "``<audit_log_path>.aisoc-cursor``. Use a "
                        "writeable path — the connector pod needs "
                        "to update this on every successful poll."
                    ),
                ),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        # Audit logs are the canonical PULL_AUDIT surface inside a
        # cluster. They also drive PULL_ALERTS because downstream
        # detections turn them into alerts.
        return (Capability.PULL_AUDIT, Capability.PULL_ALERTS)

    def __init__(
        self,
        mode: str = "webhook",
        cluster_name: str = "",
        inbox_token: str = "",
        audit_log_path: str = "/var/log/kubernetes/audit/audit.log",
        cursor_path: str = "",
    ):
        self._mode = (mode or "webhook").strip().lower()
        self._cluster_name = cluster_name
        self._inbox_token = inbox_token
        self._audit_log_path = audit_log_path
        self._cursor_path = cursor_path or f"{audit_log_path}{self._DEFAULT_CURSOR_SUFFIX}"

    # ------------------------------ helpers ----------------------------------

    def _read_cursor(self) -> int:
        """Read the byte offset for the next file_tail poll.

        Missing cursor file -> 0 (start of file). Corrupt cursor file
        -> 0 with a warning; better to re-ingest than to silently
        wedge on an unreadable cursor.
        """
        try:
            with open(self._cursor_path) as fh:
                raw = fh.read().strip()
            return int(raw) if raw else 0
        except FileNotFoundError:
            return 0
        except (OSError, ValueError) as exc:
            logger.warning(
                "kubernetes_audit.cursor_read_failed",
                cursor_path=self._cursor_path,
                error=str(exc),
            )
            return 0

    def _write_cursor(self, offset: int) -> None:
        try:
            # Atomic write: rename is the only POSIX-portable way to
            # avoid a partially-written cursor on crash.
            tmp = f"{self._cursor_path}.tmp"
            with open(tmp, "w") as fh:
                fh.write(str(offset))
            os.replace(tmp, self._cursor_path)
        except OSError as exc:
            logger.warning(
                "kubernetes_audit.cursor_write_failed",
                cursor_path=self._cursor_path,
                offset=offset,
                error=str(exc),
            )

    def _tail_audit_file(self) -> list[dict[str, Any]]:
        """Read forward from the saved cursor.

        Handles three rotation scenarios:
          * Truncation (file size < cursor) -> reset cursor to 0.
          * Replacement (logrotate copied + truncated, but inode
            unchanged) -> covered by the truncation case.
          * Rename + create (logrotate moved the old file aside) ->
            we re-open the new file and start from 0.
        """
        path = Path(self._audit_log_path)
        if not path.exists():
            logger.warning(
                "kubernetes_audit.audit_log_missing",
                audit_log_path=str(path),
            )
            return []

        try:
            size = path.stat().st_size
        except OSError as exc:
            logger.warning(
                "kubernetes_audit.stat_failed",
                audit_log_path=str(path),
                error=str(exc),
            )
            return []

        cursor = self._read_cursor()
        # File shrank -> rotation/truncation. Start over.
        if cursor > size:
            logger.info(
                "kubernetes_audit.cursor_reset_after_rotation",
                old_cursor=cursor,
                new_size=size,
            )
            cursor = 0

        if cursor >= size:
            # No new bytes since last poll — common, cheap exit.
            return []

        # Cap how much we read in a single poll. Better to fall
        # behind by one poll cycle than to chew the scheduler trying
        # to drain an enormous backlog on the same tick.
        read_end = min(size, cursor + _MAX_TAIL_BYTES_PER_POLL)
        events: list[dict[str, Any]] = []

        try:
            with open(path, "rb") as fh:
                fh.seek(cursor)
                chunk = fh.read(read_end - cursor)
        except OSError as exc:
            logger.warning(
                "kubernetes_audit.read_failed",
                audit_log_path=str(path),
                cursor=cursor,
                error=str(exc),
            )
            return []

        # The apiserver writes one JSON event per line. Split on
        # newline, keeping the trailing partial (if any) for the
        # next poll by adjusting the cursor to the last complete
        # newline.
        last_complete_offset = cursor
        for line in chunk.splitlines(keepends=True):
            last_complete_offset += len(line)
            stripped = line.strip()
            if not stripped:
                continue
            # If this line doesn't end with a newline, we read a
            # partial trailing event — back the cursor up and wait
            # for the rest on the next poll.
            if not line.endswith(b"\n"):
                last_complete_offset -= len(line)
                break
            try:
                events.append(json.loads(stripped))
            except (TypeError, ValueError):
                # A malformed line shouldn't abort the batch — log
                # and skip. This is a high-volume source and we'd
                # rather drop one event than miss everything after it.
                logger.warning(
                    "kubernetes_audit.parse_failed",
                    cursor_offset=last_complete_offset,
                )
                continue

        self._write_cursor(last_complete_offset)
        return events

    # ------------------------------ contract ---------------------------------

    async def test_connection(self) -> dict[str, Any]:
        if not self._cluster_name:
            return {
                "success": False,
                "connector": self.connector_id,
                "error": "cluster_name is required",
            }

        if self._mode == "webhook":
            if not self._inbox_token:
                return {
                    "success": False,
                    "connector": self.connector_id,
                    "error": (
                        "inbox_token is required in webhook mode. Create an inbox token bound to the k8s-audit template and paste it here."
                    ),
                }
            return {
                "success": True,
                "connector": self.connector_id,
                "mode": "webhook",
                "cluster": self._cluster_name,
                "hint": (f"Configure your apiserver AuditSink to POST to /v1/inbox/{self._inbox_token[:6]}…"),
            }

        if self._mode == "file_tail":
            path = Path(self._audit_log_path)
            if not path.exists():
                return {
                    "success": False,
                    "connector": self.connector_id,
                    "error": (
                        f"audit log path {self._audit_log_path} not "
                        "found inside the connector pod. Make sure "
                        "the apiserver audit log is mounted and "
                        "readable."
                    ),
                }
            if not os.access(self._audit_log_path, os.R_OK):
                return {
                    "success": False,
                    "connector": self.connector_id,
                    "error": (f"audit log path {self._audit_log_path} is not readable by the connector pod."),
                }
            return {
                "success": True,
                "connector": self.connector_id,
                "mode": "file_tail",
                "cluster": self._cluster_name,
                "audit_log_path": self._audit_log_path,
                "cursor_path": self._cursor_path,
            }

        return {
            "success": False,
            "connector": self.connector_id,
            "error": (f"unknown mode '{self._mode}'. Expected one of: webhook, file_tail."),
        }

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        # ``since_seconds`` is intentionally ignored in both modes:
        #   * webhook mode pulls nothing on the scheduler tick
        #     because events arrive via the inbox path.
        #   * file_tail mode uses the byte cursor, not a time
        #     window, because the apiserver doesn't timestamp the
        #     trailing partial line we might have stopped on.
        if self._mode == "webhook":
            return []
        if self._mode == "file_tail":
            events = self._tail_audit_file()
            return [self.normalize(e) for e in events]
        return []

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Map an audit.k8s.io/v1 Event to AiSOC's normalised shape.

        See https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
        for the upstream schema. We project the subset detection
        content actually pivots on; the full event lives on
        ``raw_event`` for everything else.
        """
        verb = raw.get("verb")
        user = (raw.get("user") or {}) if isinstance(raw.get("user"), dict) else {}
        username = user.get("username")
        impersonated = raw.get("impersonatedUser") or {}
        impersonated_username = impersonated.get("username") if isinstance(impersonated, dict) else None

        obj_ref = (raw.get("objectRef") or {}) if isinstance(raw.get("objectRef"), dict) else {}
        resource = obj_ref.get("resource")
        subresource = obj_ref.get("subresource")
        namespace = obj_ref.get("namespace")
        name = obj_ref.get("name")

        response_status = (raw.get("responseStatus") or {}) if isinstance(raw.get("responseStatus"), dict) else {}
        response_code = response_status.get("code")

        source_ips_raw = raw.get("sourceIPs") or []
        source_ips: list[str] = [str(ip) for ip in source_ips_raw] if isinstance(source_ips_raw, list) else []
        # The apiserver writes the immediate caller first; the
        # remaining entries are the X-Forwarded-For chain. Pick the
        # first one as the "principal" src_ip so detection content
        # has a single field to match against.
        principal_src_ip = source_ips[0] if source_ips else None

        severity = _classify_severity(raw)

        # The apiserver emits ``stageTimestamp`` (RFC3339) for every
        # event; fall back to ``requestReceivedTimestamp`` if that's
        # the only one present (older API versions).
        stamp = raw.get("stageTimestamp") or raw.get("requestReceivedTimestamp")
        created_at: str | None = None
        if isinstance(stamp, str):
            created_at = stamp
        elif isinstance(stamp, datetime):
            created_at = stamp.astimezone(UTC).isoformat()

        # Human-readable title — operators in the alert inbox should
        # be able to read "what happened" without expanding the row.
        target = name or "(cluster-scope)"
        if namespace:
            target = f"{namespace}/{target}"
        sub = f"/{subresource}" if subresource else ""
        title = f"k8s audit: {username or 'unknown'} {verb or 'request'} {resource or 'resource'}{sub} {target}"

        return {
            "source": self.connector_id,
            "category": "cloud",
            "external_id": raw.get("auditID"),
            "title": title,
            "description": (
                f"verb={verb} resource={resource} subresource={subresource} "
                f"namespace={namespace} name={name} user={username} "
                f"impersonated={impersonated_username} code={response_code}"
            ),
            "severity": severity,
            "cluster_name": self._cluster_name,
            "k8s_user": username,
            "k8s_user_groups": user.get("groups") if isinstance(user, dict) else None,
            "k8s_impersonated_user": impersonated_username,
            "k8s_verb": verb,
            "k8s_resource": resource,
            "k8s_subresource": subresource,
            "k8s_namespace": namespace,
            "k8s_object_name": name,
            "k8s_api_group": obj_ref.get("apiGroup"),
            "k8s_api_version": obj_ref.get("apiVersion"),
            "k8s_response_code": response_code,
            "k8s_user_agent": raw.get("userAgent"),
            "src_ip": principal_src_ip,
            "source_ips": source_ips or None,
            "cloud_platform": "kubernetes",
            "stage": raw.get("stage"),
            "audit_id": raw.get("auditID"),
            "raw_event": raw,
            "created_at": created_at,
        }
