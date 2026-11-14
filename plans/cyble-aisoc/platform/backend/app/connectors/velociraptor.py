"""Velociraptor live endpoint forensics connector.

Implements :class:`BaseForensicsConnector` against `Velociraptor`_'s
gRPC API. Velociraptor is the canonical open-source live-forensics
platform: an agent (``velociraptor.exe``/``velociraptor``) runs on
every endpoint, persistently connected back to a server, and accepts
on-demand artifact collections expressed in VQL (Velociraptor Query
Language). Artifacts read directly from the live OS — registry,
NTFS journal, prefetch, in-memory process maps — answering the
post-containment "what actually happened on this box" question that
EDR telemetry alone cannot.

.. _Velociraptor: https://docs.velociraptor.app

API surface
-----------
Velociraptor exposes two server interfaces:

  * A **GUI** (HTTP/HTTPS) for human analysts.
  * An **API server** speaking gRPC for automation.

This connector targets the **API server** exclusively (the GUI is
not appropriate for service-to-service automation). The API server
authenticates with mutual TLS: the operator runs
``velociraptor --config server.config.yaml config api_client``
which emits a small YAML containing:

  * ``api_connection_string``  ("grpc.velo.example.com:8001")
  * ``ca_certificate``         (PEM)
  * ``client_cert``            (PEM)
  * ``client_private_key``     (PEM)
  * ``name``                   (user/principal the cert is bound to)

We accept that exact YAML — either as a path under
``params.api_config_path`` or inline under ``secrets.api_config_yaml``.

VQL mapping
-----------
All four protocol methods become a single VQL query executed against
the API server. Velociraptor's universal "collect any artifact on
any client" entry-point is ``collect_client(client_id, artifacts)``
and its hunt counterpart is ``hunt(...)``.

``collect_artifact``
    Resolves ``host`` → ``client_id`` via
    ``SELECT client_id FROM clients(search='host:<host>')``, then
    schedules the artifact with ``collect_client``, then polls the
    flow's results table::

        SELECT * FROM flow_results(
            client_id='C.123', flow_id='F.456',
            artifact='Windows.System.Pslist'
        )

``run_hunt``
    ``hunt(description, artifacts, label, condition_label)`` returns
    a ``hunt_id``. We then query ``hunt_flows`` for matched clients
    and ``hunts(hunt_id)`` for status. We do *not* block on full
    completion — hunts often span hours; we return an inflight
    summary the analyst can poll on.

``fetch_file``
    Schedules ``Generic.Forensic.UploadFile`` with the path. Once
    complete, the file lands in the Velociraptor server's
    ``uploads/`` folder; we surface the ``vfs_path`` + sha256 +
    size. The actual bytes stay on the Velociraptor server (chain
    of custody) — the connector does not stream them through the
    AiSOC backend.

``terminate_process``
    Schedules ``Windows.System.KillProcess`` (or
    ``Linux.System.KillProcess`` if the client is Linux) with
    ``Pid`` set. This is the only ``DESTRUCTIVE`` operation here —
    HITL gating in the tool layer enforces a paired approval.

Config (``params``)
-------------------
* ``api_config_path``        — Filesystem path to the
                               ``api_client.config.yaml`` Velociraptor
                               emits. **One of** this OR
                               ``secrets.api_config_yaml`` is required.
* ``poll_interval_s``        — Seconds between flow-status polls.
                               Default ``2``.
* ``poll_max_attempts``      — Cap on flow-status polls before
                               surfacing a timeout. Default ``150``
                               (≈5 minutes default ceiling for
                               collect_artifact).
* ``default_hunt_expiry_h``  — Hunt expiry (hours) when not specified.
                               Default ``24``.
* ``allow_destructive``      — Master switch on
                               ``terminate_process``. If ``False``
                               the connector raises rather than
                               scheduling. Default ``True`` (the
                               *tool layer* still gates via HITL —
                               this is a vendor-level kill switch
                               for forensics-only deployments).

Config (``secrets``)
--------------------
* ``api_config_yaml``        — Inline contents of
                               ``api_client.config.yaml`` (alternative
                               to ``api_config_path`` for managed
                               deployments where mounting files is
                               awkward). Must be the full YAML, not
                               just the cert bytes.

Optional dependency
-------------------
The Velociraptor gRPC client lives in the ``pyvelociraptor`` package,
which pulls in ``grpcio`` + ``protobuf``. We import lazily inside
:meth:`VelociraptorForensicsConnector.__init__` so the rest of the
backend can import this module — and run the *mock* forensics
connector — without ``pyvelociraptor`` installed.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any

import yaml

from app.connectors.sdk.base import (
    ConnectorConfig,
    ConnectorError,
)
from app.connectors.sdk.protocols import BaseForensicsConnector

log = logging.getLogger(__name__)


# ─── constants ───────────────────────────────────────────────────────────

# Velociraptor client IDs always start with "C." followed by 16+ hex.
_CLIENT_ID_RE = re.compile(r"^C\.[0-9a-fA-F]{8,40}$")

# Flow IDs start with "F." and hunt IDs with "H.".
_FLOW_ID_RE = re.compile(r"^F\.[0-9A-Za-z]{6,40}$")
_HUNT_ID_RE = re.compile(r"^H\.[0-9A-Za-z]{6,40}$")

# Artifact identifiers are dotted CamelCase (e.g. ``Windows.System.Pslist``).
# We're permissive: any letters/numbers/dot/underscore/slash, 3-256 chars.
_ARTIFACT_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_./]{2,255}$")

# Reject control chars in host/path/reason values.
_FORBIDDEN_CHARS = re.compile(r"[\x00-\x1f\x7f]")

# Linux kill artifact (case the client is non-Windows).
_LINUX_KILL_ARTIFACT = "Linux.System.KillProcess"
_WINDOWS_KILL_ARTIFACT = "Windows.System.KillProcess"
_UPLOAD_FILE_ARTIFACT = "Generic.Forensic.UploadFile"


# ─── helpers ─────────────────────────────────────────────────────────────


def _check_entity_value(value: str, *, field: str) -> str:
    """Reject empty / non-str / control-char values."""
    if not isinstance(value, str):
        raise ConnectorError(
            f"velociraptor: {field} must be a string "
            f"(got {type(value).__name__})",
            vendor="velociraptor",
        )
    if not value.strip():
        raise ConnectorError(
            f"velociraptor: empty {field} rejected",
            vendor="velociraptor",
        )
    if _FORBIDDEN_CHARS.search(value):
        raise ConnectorError(
            f"velociraptor: {field} {value!r} contains control characters",
            vendor="velociraptor",
        )
    return value


def _check_artifact(artifact: str) -> str:
    """Validate the shape of an artifact identifier."""
    _check_entity_value(artifact, field="artifact")
    if not _ARTIFACT_NAME_RE.match(artifact):
        raise ConnectorError(
            f"velociraptor: invalid artifact name {artifact!r} — expected "
            "dotted identifier like 'Windows.System.Pslist'",
            vendor="velociraptor",
        )
    return artifact


def _vql_quote(value: Any) -> str:
    """Render `value` as a VQL literal safe for string interpolation.

    Velociraptor's VQL parser supports single-quoted strings with
    backslash escapes. Numeric and bool literals are emitted bare.
    Everything else is round-tripped through ``json.dumps`` and then
    re-quoted with single quotes, escaping embedded single quotes.

    We use parameterised queries (``env``) wherever possible — this
    helper is a defence-in-depth fallback for the few spots where the
    VQL grammar requires an inline literal (e.g. artifact names in
    ``collect_client``, which the gRPC binding takes as a separate
    arg anyway).
    """
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, (int, float)):
        return str(value)
    if value is None:
        return "NULL"
    s = str(value)
    if _FORBIDDEN_CHARS.search(s):
        raise ConnectorError(
            f"velociraptor: VQL literal contains control characters: {s!r}",
            vendor="velociraptor",
        )
    escaped = s.replace("\\", "\\\\").replace("'", "\\'")
    return f"'{escaped}'"


def _load_api_config(*, path: str | None, inline: str | None) -> dict[str, Any]:
    """Load the Velociraptor api_client.config.yaml into a dict.

    Validates that the four required keys are present so we fail at
    connector-init time rather than on the first RPC.
    """
    if not path and not inline:
        raise ConnectorError(
            "velociraptor: one of params.api_config_path or "
            "secrets.api_config_yaml is required",
            vendor="velociraptor",
        )
    if path and inline:
        raise ConnectorError(
            "velociraptor: api_config_path and api_config_yaml are "
            "mutually exclusive — pick one",
            vendor="velociraptor",
        )

    raw: str
    if path:
        if not os.path.isfile(path):
            raise ConnectorError(
                f"velociraptor: api_config_path {path!r} does not exist",
                vendor="velociraptor",
            )
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw = fh.read()
        except OSError as exc:
            raise ConnectorError(
                f"velociraptor: failed to read api_config_path {path!r}: "
                f"{exc}",
                vendor="velociraptor",
            ) from exc
    else:
        raw = inline or ""

    try:
        cfg = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ConnectorError(
            f"velociraptor: api_config is not valid YAML: {exc}",
            vendor="velociraptor",
        ) from exc

    if not isinstance(cfg, dict):
        raise ConnectorError(
            "velociraptor: api_config must be a YAML mapping",
            vendor="velociraptor",
        )

    required = (
        "api_connection_string",
        "ca_certificate",
        "client_cert",
        "client_private_key",
    )
    missing = [k for k in required if not cfg.get(k)]
    if missing:
        raise ConnectorError(
            f"velociraptor: api_config missing required keys: "
            f"{', '.join(missing)}",
            vendor="velociraptor",
        )
    return cfg


def _utcnow_iso() -> str:
    """Return a Velociraptor-friendly ISO-8601 timestamp."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ─── connector ───────────────────────────────────────────────────────────


class VelociraptorForensicsConnector(BaseForensicsConnector):
    """Velociraptor connector — VQL over the API server's gRPC interface.

    One instance per ``(tenant_id, FORENSICS)`` pair, cached by the
    registry. The instance owns a gRPC channel + stub; all four
    protocol methods translate to a single VQL query on that stub.
    """

    vendor = "velociraptor"

    def __init__(self, config: ConnectorConfig) -> None:
        super().__init__(config)

        # ── Lazy-import the gRPC stack ──────────────────────────────
        # ``pyvelociraptor`` brings in ``grpcio`` (~30MB) + ``protobuf``.
        # The mock connector and the rest of the backend work without
        # it; we only require it when an operator actually wires up the
        # real Velociraptor connector.
        try:
            from pyvelociraptor import api_pb2, api_pb2_grpc  # type: ignore
            import grpc  # type: ignore
        except ImportError as exc:
            raise ConnectorError(
                "velociraptor: 'pyvelociraptor' is not installed — "
                "run `pip install pyvelociraptor grpcio protobuf` to "
                "enable the real connector. The mock connector "
                "(vendor='mock', kind=FORENSICS) does not require it.",
                vendor="velociraptor",
            ) from exc

        self._api_pb2 = api_pb2
        self._grpc = grpc

        api_cfg = _load_api_config(
            path=config.param("api_config_path") or None,
            inline=config.secret("api_config_yaml", required=False) or None,
        )

        self._connection_string: str = str(api_cfg["api_connection_string"])
        self._poll_interval_s: float = float(
            config.param("poll_interval_s") or 2.0
        )
        self._poll_max_attempts: int = int(
            config.param("poll_max_attempts") or 150
        )
        self._hunt_expiry_h: int = int(
            config.param("default_hunt_expiry_h") or 24
        )
        self._allow_destructive: bool = bool(
            config.param("allow_destructive", True)
        )

        # Build the mTLS credentials + channel. We retain the YAML
        # contents on the cfg dict (not on self) so the cert+key
        # don't leak through __repr__ / logging by accident.
        creds = grpc.ssl_channel_credentials(
            root_certificates=api_cfg["ca_certificate"].encode("utf-8"),
            private_key=api_cfg["client_private_key"].encode("utf-8"),
            certificate_chain=api_cfg["client_cert"].encode("utf-8"),
        )

        # Velociraptor's API server's TLS cert is issued to a stable
        # internal CN ("VelociraptorServer"); override the SSL target
        # name so hostname verification passes when the connection
        # string is an IP / load balancer name.
        options = [
            ("grpc.ssl_target_name_override", "VelociraptorServer"),
            # Sane keepalives — Velociraptor's API server idles
            # otherwise.
            ("grpc.keepalive_time_ms", 30_000),
            ("grpc.keepalive_timeout_ms", 10_000),
            ("grpc.keepalive_permit_without_calls", 1),
        ]
        self._channel = grpc.aio.secure_channel(
            self._connection_string, creds, options=options
        )
        self._stub = api_pb2_grpc.APIStub(self._channel)

    # ------------------------------------------------------------------ #
    # Lifecycle                                                          #
    # ------------------------------------------------------------------ #

    async def aclose(self) -> None:
        try:
            await self._channel.close()
        except Exception:  # noqa: BLE001
            # Channel already torn down — not worth surfacing.
            pass

    # ------------------------------------------------------------------ #
    # Health                                                             #
    # ------------------------------------------------------------------ #

    async def health_check(self) -> dict[str, Any]:
        """Probe with ``SELECT version() FROM scope()``.

        Velociraptor's ``version()`` is a builtin that returns the
        server build string — the smallest possible round-trip that
        proves auth + connectivity. Same pattern as ``SELECT 1`` in
        SQL.
        """
        rows = await self._vql("SELECT version() AS v FROM scope()")
        version = (rows[0] or {}).get("v") if rows else None
        return {
            "ok": True,
            "vendor": self.vendor,
            "kind": self.kind.value,
            "server_version": version,
            "endpoint": self._connection_string,
        }

    # ------------------------------------------------------------------ #
    # Public protocol surface                                            #
    # ------------------------------------------------------------------ #

    async def collect_artifact(
        self,
        *,
        host: str,
        artifact: str,
        parameters: dict[str, Any] | None = None,
        timeout_s: int = 300,
    ) -> dict[str, Any]:
        """Schedule `artifact` on `host` and block until results land.

        Polls ``flow_results`` until the flow's status transitions out
        of ``RUNNING`` or ``timeout_s`` elapses. Returns the rows
        verbatim — the caller (Investigator/Hunter) deals with
        per-artifact field semantics.
        """
        _check_entity_value(host, field="host")
        artifact = _check_artifact(artifact)
        params = _normalise_parameters(parameters)

        client_id = await self._resolve_client_id(host)

        flow_id = await self._schedule_collection(
            client_id=client_id,
            artifacts=[artifact],
            parameters=params,
        )

        started_at = _utcnow_iso()
        max_attempts = min(
            self._poll_max_attempts,
            max(1, int(timeout_s / max(self._poll_interval_s, 0.5))),
        )
        status = "running"
        error: str | None = None
        for _ in range(max_attempts):
            status, error = await self._flow_status(
                client_id=client_id, flow_id=flow_id
            )
            if status != "running":
                break
            await asyncio.sleep(self._poll_interval_s)

        if status == "running":
            return {
                "host": host,
                "artifact": artifact,
                "flow_id": flow_id,
                "client_id": client_id,
                "started_at": started_at,
                "completed_at": None,
                "status": "timeout",
                "rows": [],
                "row_count": 0,
                "total_uploaded_bytes": 0,
                "error": (
                    f"timeout: flow still RUNNING after "
                    f"{timeout_s}s (raise timeout_s or poll_max_attempts)"
                ),
            }

        rows: list[dict[str, Any]] = []
        if status == "completed":
            rows = await self._flow_results(
                client_id=client_id, flow_id=flow_id, artifact=artifact
            )

        return {
            "host": host,
            "artifact": artifact,
            "flow_id": flow_id,
            "client_id": client_id,
            "started_at": started_at,
            "completed_at": _utcnow_iso(),
            "status": status,
            "rows": rows,
            "row_count": len(rows),
            "total_uploaded_bytes": 0,
            "error": error,
        }

    async def run_hunt(
        self,
        *,
        artifact: str,
        label_selector: str | None = None,
        host_ids: list[str] | None = None,
        parameters: dict[str, Any] | None = None,
        timeout_s: int = 600,
    ) -> dict[str, Any]:
        """Fan `artifact` across endpoints via Velociraptor's hunt engine.

        Exactly one of ``label_selector`` / ``host_ids`` must be set.
        We return an inflight snapshot — hunts often run for hours
        and the caller polls separately.
        """
        if (label_selector is None) == (host_ids is None or not host_ids):
            raise ConnectorError(
                "velociraptor: run_hunt requires exactly one of "
                "label_selector or host_ids",
                vendor="velociraptor",
            )
        artifact = _check_artifact(artifact)
        params = _normalise_parameters(parameters)

        # Build the hunt request. Velociraptor's hunt() VQL plugin
        # takes a description, an artifacts list, optional label, and
        # optional condition. ``host_ids`` is a Velociraptor extension
        # we emulate by submitting one collect_client per id — slightly
        # less efficient than a true label-bound hunt but the right
        # shape for the protocol.
        if label_selector is not None:
            _check_entity_value(label_selector, field="label_selector")
            hunt_id = await self._create_hunt(
                artifact=artifact,
                label=label_selector,
                parameters=params,
            )
            matched_hosts: list[str] = []  # filled below from hunt_flows
        else:
            # Per-host fan-out. We still mint a synthetic hunt id so
            # the response shape is consistent.
            hunt_id = f"H.adhoc.{int(datetime.now().timestamp())}"
            matched_hosts = []
            for hid in (host_ids or []):
                _check_entity_value(hid, field="host_ids[]")
                client_id = await self._resolve_client_id(hid)
                await self._schedule_collection(
                    client_id=client_id,
                    artifacts=[artifact],
                    parameters=params,
                )
                matched_hosts.append(hid)

        # For label-driven hunts, ask Velociraptor which clients matched.
        # This is a snapshot — more endpoints may join as the hunt runs.
        if label_selector is not None:
            matched_hosts = await self._hunt_matched_hosts(hunt_id=hunt_id)

        return {
            "hunt_id": hunt_id,
            "artifact": artifact,
            "label_selector": label_selector,
            "started_at": _utcnow_iso(),
            "expiry_h": self._hunt_expiry_h,
            "status": "scheduled",
            "results_summary": {
                "matched_hosts": matched_hosts,
                "match_count": len(matched_hosts),
            },
        }

    async def fetch_file(
        self,
        *,
        host: str,
        path: str,
        max_size_bytes: int = 50 * 1024 * 1024,
    ) -> dict[str, Any]:
        """Pull `path` off `host` via ``Generic.Forensic.UploadFile``.

        Velociraptor uploads the file to the server's ``uploads/``
        VFS — the bytes themselves never traverse the AiSOC backend.
        We return the VFS path + sha256 for the case file.
        """
        _check_entity_value(host, field="host")
        _check_entity_value(path, field="path")
        if not isinstance(max_size_bytes, int) or max_size_bytes <= 0:
            raise ConnectorError(
                f"velociraptor: invalid max_size_bytes "
                f"{max_size_bytes!r}",
                vendor="velociraptor",
            )

        result = await self.collect_artifact(
            host=host,
            artifact=_UPLOAD_FILE_ARTIFACT,
            parameters={"Path": path, "MaxSize": max_size_bytes},
            timeout_s=300,
        )
        first_row = result["rows"][0] if result["rows"] else {}
        return {
            "host": host,
            "path": path,
            "vfs_path": first_row.get("vfs_path")
            or first_row.get("_Path")
            or "",
            "sha256": first_row.get("sha256") or first_row.get("Sha256") or "",
            "size_bytes": int(
                first_row.get("Size") or first_row.get("size") or 0
            ),
            "flow_id": result["flow_id"],
            "status": result["status"],
            "error": result.get("error"),
        }

    async def terminate_process(
        self, *, host: str, pid: int, reason: str
    ) -> dict[str, Any]:
        """Kill `pid` on `host` via the ``*.KillProcess`` artifact.

        Velociraptor's kill artifacts vary by client OS — we resolve
        the OS up front and pick ``Windows`` vs ``Linux``. ``reason``
        is logged in the flow's metadata, never in the payload (it
        would otherwise become a VQL injection sink if mishandled).
        """
        if not self._allow_destructive:
            raise ConnectorError(
                "velociraptor: terminate_process is disabled by "
                "params.allow_destructive=false. Re-enable it on the "
                "tenant's forensics connector config to use this op.",
                vendor="velociraptor",
                status=403,
            )
        _check_entity_value(host, field="host")
        _check_entity_value(reason, field="reason")
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
            raise ConnectorError(
                f"velociraptor: pid must be a positive integer "
                f"(got {pid!r})",
                vendor="velociraptor",
            )

        client_id = await self._resolve_client_id(host)
        os_family = await self._client_os_family(client_id=client_id)
        artifact = (
            _LINUX_KILL_ARTIFACT
            if os_family == "linux"
            else _WINDOWS_KILL_ARTIFACT
        )

        flow_id = await self._schedule_collection(
            client_id=client_id,
            artifacts=[artifact],
            parameters={"Pid": pid},
        )

        # KillProcess is fast — block briefly for the status flip so
        # the caller's audit log records terminated=true|false rather
        # than a "scheduled" pending state.
        status: str = "running"
        error: str | None = None
        for _ in range(15):  # ~30s worst case
            status, error = await self._flow_status(
                client_id=client_id, flow_id=flow_id
            )
            if status != "running":
                break
            await asyncio.sleep(2.0)

        terminated = status == "completed"
        return {
            "host": host,
            "pid": pid,
            "reason": reason,
            "terminated": terminated,
            "flow_id": flow_id,
            "client_id": client_id,
            "ticket": f"FKILL-{pid}",
            "status": status,
            "error": error,
        }

    # ------------------------------------------------------------------ #
    # Internal VQL helpers                                               #
    # ------------------------------------------------------------------ #

    async def _vql(
        self, query: str, *, env: dict[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        """Run a single VQL query, returning rows as dicts.

        Always sends the query inside one ``VQLRequest`` so the server
        can scope arg bindings (``env``) to it. The gRPC stream
        yields one ``VQLResponse`` per page; each has a JSONL
        ``Response`` field containing the row payloads.
        """
        request = self._api_pb2.VQLCollectorArgs(
            max_row=2000,
            max_wait=1,
            Query=[self._api_pb2.VQLRequest(VQL=query, Name="aisoc")],
        )
        if env:
            request.env.extend(
                [
                    self._api_pb2.VQLEnv(key=str(k), value=str(v))
                    for k, v in env.items()
                ]
            )

        rows: list[dict[str, Any]] = []
        try:
            async for response in self._stub.Query(request):
                payload = (response.Response or "").strip()
                if not payload:
                    continue
                try:
                    parsed = json.loads(payload)
                except json.JSONDecodeError as exc:
                    log.warning(
                        "velociraptor: malformed VQL response chunk: %s",
                        exc,
                    )
                    continue
                if isinstance(parsed, list):
                    rows.extend(r for r in parsed if isinstance(r, dict))
                elif isinstance(parsed, dict):
                    rows.append(parsed)
        except self._grpc.aio.AioRpcError as exc:
            raise ConnectorError(
                f"velociraptor: VQL call failed "
                f"({exc.code().name}): {exc.details()}",
                vendor="velociraptor",
            ) from exc
        return rows

    async def _resolve_client_id(self, host: str) -> str:
        """Resolve hostname → Velociraptor ``client_id``.

        If `host` already looks like a client id we trust it (no
        round-trip). Otherwise we run::

            SELECT client_id FROM clients(search='host:<host>')
        """
        _check_entity_value(host, field="host")
        if _CLIENT_ID_RE.match(host):
            return host
        rows = await self._vql(
            f"SELECT client_id FROM clients(search={_vql_quote('host:' + host)})"
        )
        if not rows:
            raise ConnectorError(
                f"velociraptor: host {host!r} not enrolled (no client_id)",
                vendor="velociraptor",
                status=404,
            )
        client_id = str(rows[0].get("client_id") or "").strip()
        if not _CLIENT_ID_RE.match(client_id):
            raise ConnectorError(
                f"velociraptor: malformed client_id in resolve response: "
                f"{client_id!r}",
                vendor="velociraptor",
            )
        return client_id

    async def _client_os_family(self, *, client_id: str) -> str:
        """Return ``'windows' | 'linux' | 'darwin' | 'unknown'`` for `client_id`."""
        rows = await self._vql(
            "SELECT os_info.system AS s FROM clients(client_id="
            + _vql_quote(client_id)
            + ")"
        )
        sys_str = str((rows[0] or {}).get("s") or "").strip().lower()
        if "windows" in sys_str:
            return "windows"
        if "linux" in sys_str:
            return "linux"
        if "darwin" in sys_str or "mac" in sys_str:
            return "darwin"
        return "unknown"

    async def _schedule_collection(
        self,
        *,
        client_id: str,
        artifacts: list[str],
        parameters: dict[str, Any],
    ) -> str:
        """Call ``collect_client`` and return the flow_id.

        Parameters are passed via ``env=...`` to avoid VQL injection
        on operator-supplied artifact arguments.
        """
        # collect_client accepts ``spec`` as a dict mapping artifact
        # name -> parameter map. We render it as a VQL dict literal
        # whose values come from env bindings — safer than inlining
        # untrusted strings into the query.
        spec_obj: dict[str, dict[str, str]] = {}
        env: dict[str, Any] = {"_artifacts": ",".join(artifacts)}
        for art in artifacts:
            spec_obj[art] = {}
            for k, v in parameters.items():
                env_key = f"p_{art.replace('.', '_')}_{k}"
                spec_obj[art][k] = env_key
                env[env_key] = v
        # NOTE: Velociraptor's VQL accepts dict() literals. We render
        # one with placeholder values from env to keep injection
        # surface zero.
        spec_vql = _render_spec_literal(spec_obj)

        rows = await self._vql(
            "SELECT collect_client("
            "client_id=" + _vql_quote(client_id) + ", "
            "artifacts=split(string=env._artifacts, sep=','), "
            f"spec={spec_vql}"
            ") AS flow_id FROM scope()",
            env=env,
        )
        flow_id = str((rows[0] or {}).get("flow_id") or "").strip()
        if not _FLOW_ID_RE.match(flow_id):
            raise ConnectorError(
                f"velociraptor: collect_client returned malformed "
                f"flow_id {flow_id!r}",
                vendor="velociraptor",
            )
        return flow_id

    async def _flow_status(
        self, *, client_id: str, flow_id: str
    ) -> tuple[str, str | None]:
        """Poll a flow's status. Returns ``(state, error)``."""
        rows = await self._vql(
            "SELECT state, status FROM flows(client_id="
            + _vql_quote(client_id)
            + ", flow_id="
            + _vql_quote(flow_id)
            + ")"
        )
        if not rows:
            return "running", None
        state = str(rows[0].get("state") or "").lower().strip()
        # Velociraptor flow states: FINISHED, RUNNING, ERROR.
        if state == "finished":
            return "completed", None
        if state in {"error", "failed"}:
            return "failed", str(rows[0].get("status") or "")
        return "running", None

    async def _flow_results(
        self, *, client_id: str, flow_id: str, artifact: str
    ) -> list[dict[str, Any]]:
        """Pull rows from a completed flow's results table for `artifact`."""
        return await self._vql(
            "SELECT * FROM flow_results(client_id="
            + _vql_quote(client_id)
            + ", flow_id="
            + _vql_quote(flow_id)
            + ", artifact="
            + _vql_quote(artifact)
            + ")"
        )

    async def _create_hunt(
        self,
        *,
        artifact: str,
        label: str,
        parameters: dict[str, Any],
    ) -> str:
        """Schedule a label-bound hunt and return its hunt_id."""
        spec_obj: dict[str, dict[str, str]] = {artifact: {}}
        env: dict[str, Any] = {}
        for k, v in parameters.items():
            env_key = f"p_{k}"
            spec_obj[artifact][k] = env_key
            env[env_key] = v
        spec_vql = _render_spec_literal(spec_obj)

        rows = await self._vql(
            "SELECT hunt("
            "description=" + _vql_quote(f"aisoc:{artifact}") + ", "
            "artifacts=" + _vql_quote(artifact) + ", "
            "condition_label=" + _vql_quote(label) + ", "
            f"spec={spec_vql}, "
            f"expires=now()+{self._hunt_expiry_h*3600}"
            ") AS hunt_id FROM scope()",
            env=env,
        )
        hunt_id = str((rows[0] or {}).get("hunt_id") or "").strip()
        if not _HUNT_ID_RE.match(hunt_id):
            raise ConnectorError(
                f"velociraptor: hunt() returned malformed hunt_id "
                f"{hunt_id!r}",
                vendor="velociraptor",
            )
        return hunt_id

    async def _hunt_matched_hosts(self, *, hunt_id: str) -> list[str]:
        """Resolve a hunt's currently matched client hostnames.

        Joins ``hunt_flows`` (client_ids in this hunt) with
        ``clients`` (hostname per client) so the caller sees
        operator-readable hostnames rather than opaque ``C.xxx`` ids.
        """
        rows = await self._vql(
            "SELECT hf.client_id AS cid, c.os_info.fqdn AS host "
            "FROM hunt_flows(hunt_id="
            + _vql_quote(hunt_id)
            + ") AS hf "
            "LEFT JOIN clients() AS c ON hf.client_id = c.client_id "
            "LIMIT 500"
        )
        hosts: list[str] = []
        for row in rows:
            host = str(row.get("host") or row.get("cid") or "").strip()
            if host:
                hosts.append(host)
        return hosts


# ─── shared helpers ──────────────────────────────────────────────────────


def _normalise_parameters(parameters: dict[str, Any] | None) -> dict[str, Any]:
    """Defensive copy + light validation of artifact parameter maps.

    Velociraptor artifact parameters are exclusively string-keyed and
    JSON-serialisable. We coerce booleans to themselves, ints/floats
    to themselves, everything else to a string — matching the VQL
    binding contract.
    """
    if parameters is None:
        return {}
    if not isinstance(parameters, dict):
        raise ConnectorError(
            f"velociraptor: parameters must be a dict "
            f"(got {type(parameters).__name__})",
            vendor="velociraptor",
        )
    cleaned: dict[str, Any] = {}
    for k, v in parameters.items():
        if not isinstance(k, str) or not k.isidentifier():
            raise ConnectorError(
                f"velociraptor: parameter key {k!r} must be a valid "
                "identifier (letters, digits, underscore; must start "
                "with a letter or underscore)",
                vendor="velociraptor",
            )
        if isinstance(v, (bool, int, float)):
            cleaned[k] = v
        elif v is None:
            continue
        else:
            cleaned[k] = str(v)
    return cleaned


def _render_spec_literal(spec_obj: dict[str, dict[str, str]]) -> str:
    """Render a Velociraptor artifact ``spec`` dict for inline VQL.

    The values are *env-variable names* (e.g. ``p_path``) rather
    than literal strings — the actual values are bound through the
    ``env`` field of the VQLRequest. This keeps the injection
    surface bounded to artifact/parameter *names*, both of which
    are already shape-validated upstream.

    Example output::

        dict(`Windows.System.Pslist`=dict(Pid=env.p_pid))
    """
    parts: list[str] = []
    for art, params in spec_obj.items():
        # Backtick-quote artifact names: VQL identifiers don't allow
        # dots, so we have to escape them as quoted identifiers.
        inner = ", ".join(
            f"{k}=env.{v}" for k, v in params.items()
        )
        parts.append(f"`{art}`=dict({inner})")
    return "dict(" + ", ".join(parts) + ")"


# ─── factory ─────────────────────────────────────────────────────────────


def make_velociraptor_forensics(
    config: ConnectorConfig,
) -> VelociraptorForensicsConnector:
    """Factory entry-point registered in ``app/connectors/sdk/builtin.py``."""
    return VelociraptorForensicsConnector(config)


__all__ = [
    "VelociraptorForensicsConnector",
    "make_velociraptor_forensics",
]
