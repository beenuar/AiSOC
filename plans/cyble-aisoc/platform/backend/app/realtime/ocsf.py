"""OCSF normalization.

The Open Cybersecurity Schema Framework (OCSF) is the cross-vendor
canonical shape for security telemetry. Every connector we own and every
upstream SIEM we federate against speaks a different dialect (Sysmon flat
PascalCase fields, ECS dotted lowercase, raw vendor JSON, half-baked OCSF
from "OCSF-compatible" exporters). The normalizer is the single chokepoint
that translates all of those into one canonical event we can:

* run Sigma rules against (rules expect predictable field names),
* persist into ClickHouse with a stable column layout,
* hash for deduplication,
* and replay through the orchestrator without re-parsing.

Design constraints:

* **Best-effort, never raise.** We will see malformed events in production
  — the normalizer must always return *something*, even if it's mostly
  empty. Sigma evaluation against an under-populated event just doesn't
  match, which is the correct behavior.
* **Dependency-free.** Pure stdlib. The realtime path needs to boot on a
  laptop with no extras installed.
* **Source-tagged.** We always preserve the original payload under
  ``raw`` so downstream forensics can re-parse if we got something wrong.

This is not a 1:1 OCSF library implementation. We model the small subset
the platform actually consumes today (process activity, network activity,
authentication, file activity, generic findings) and leave room to grow
without rewriting consumers.

OCSF reference: https://schema.ocsf.io
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any, Iterable


# ── OCSF taxonomy (subset) ──────────────────────────────────────────────
# We only enumerate the categories and classes we actually emit. Picking
# values out of the OCSF spec rather than inventing our own means a real
# OCSF consumer (e.g. Amazon Security Lake) can ingest these payloads
# directly.


class OcsfCategory(IntEnum):
    """OCSF top-level categories (subset)."""

    SYSTEM_ACTIVITY = 1        # process / file / kernel
    FINDINGS = 2               # generic detection finding
    IDENTITY_ACCESS = 3        # auth, account changes
    NETWORK_ACTIVITY = 4       # connections, DNS, HTTP
    DISCOVERY = 5              # inventory, vuln scan
    APPLICATION_ACTIVITY = 6
    OTHER = 0


class OcsfActivityClass(IntEnum):
    """OCSF event classes (subset).

    Class IDs in OCSF are 4-digit ints where the first digit is the
    category. We only enumerate the classes we project today.
    """

    # System Activity (1xxx)
    FILE_SYSTEM_ACTIVITY = 1001
    PROCESS_ACTIVITY = 1007
    REGISTRY_KEY_ACTIVITY = 1006

    # Findings (2xxx)
    SECURITY_FINDING = 2001

    # Identity & Access (3xxx)
    AUTHENTICATION = 3002
    ACCOUNT_CHANGE = 3001

    # Network Activity (4xxx)
    NETWORK_ACTIVITY = 4001
    DNS_ACTIVITY = 4003
    HTTP_ACTIVITY = 4002

    # Fallback
    BASE_EVENT = 0


# Activity IDs (the verb inside a class) we use frequently. OCSF defines a
# very long enum per class; we only need the verbs that appear in our
# starter Sigma rules.
ACTIVITY_PROCESS_LAUNCH = 1
ACTIVITY_PROCESS_TERMINATE = 2
ACTIVITY_FILE_CREATE = 1
ACTIVITY_FILE_DELETE = 4
ACTIVITY_NETWORK_OPEN = 1
ACTIVITY_NETWORK_CLOSE = 2
ACTIVITY_AUTH_LOGON = 1
ACTIVITY_AUTH_LOGOFF = 2
ACTIVITY_AUTH_FAILED = 99      # OCSF uses class-specific extension IDs


# ── Canonical event ─────────────────────────────────────────────────────


@dataclass
class OcsfEvent:
    """Canonical normalized event.

    This dataclass is the lingua franca for everything downstream of the
    OCSF stage. Sigma rules, ClickHouse rows, dedup hashes, and websocket
    payloads all key off these fields. If a producer doesn't fill a field,
    leave it ``None`` — downstream consumers handle absence gracefully.

    The ``raw`` dict is preserved verbatim so we never lose forensic
    fidelity. Anything we *failed* to normalize lives there.
    """

    # ── Identity / routing ─────────────────────────────────────────
    # ``source`` is the vendor/connector tag (e.g. "splunk", "sentinelone").
    source: str
    # ``external_id`` ties this event back to the upstream system's row id.
    external_id: str | None = None

    # ── OCSF schema fields ─────────────────────────────────────────
    category_uid: int = OcsfCategory.OTHER.value
    class_uid: int = OcsfActivityClass.BASE_EVENT.value
    activity_id: int = 0
    severity_id: int = 1               # 1=Informational..6=Fatal in OCSF
    time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # ── Actor / identity ───────────────────────────────────────────
    actor_user: str | None = None
    actor_process_name: str | None = None
    actor_process_cmdline: str | None = None
    actor_process_pid: int | None = None

    # ── Devices / network ──────────────────────────────────────────
    src_host: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None

    # ── File / hash ────────────────────────────────────────────────
    file_path: str | None = None
    file_hash: str | None = None

    # ── Human-readable summary (rendered into case narrative) ─────
    title: str | None = None
    description: str | None = None

    # ── Original payload — never drop this ────────────────────────
    raw: dict[str, Any] = field(default_factory=dict)

    # ── Diagnostic — which normalization path was taken? ──────────
    # Lets us tell at a glance whether an event was matched by our
    # Sysmon path, ECS path, or pass-through-OCSF path.
    normalization_dialect: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable dict (ISO timestamps, no dataclass internals)."""
        out = asdict(self)
        out["time"] = self.time.astimezone(timezone.utc).isoformat()
        return out


# ── Dialect detection + normalization ──────────────────────────────────
#
# We try dialects in order from most-specific to least-specific so a
# half-OCSF / half-vendor payload still gets normalized down the OCSF
# pass-through path instead of being misparsed as Sysmon.


def normalize_event(
    *,
    source: str,
    event: dict[str, Any],
    external_id: str | None = None,
) -> OcsfEvent:
    """Normalize an arbitrary event payload into an :class:`OcsfEvent`.

    This function never raises. Bad input returns a base event with the
    original payload preserved under ``raw``, so the failure mode is
    "rule doesn't match" rather than "ingest pipeline dies".

    Resolution order:

    1. **Pass-through OCSF** if ``class_uid`` is present (i.e. the upstream
       system already produced OCSF; we just hydrate our dataclass).
    2. **ECS / dotted lowercase** if ``process.name`` / ``host.name``
       style keys exist.
    3. **Sysmon flat** if PascalCase keys like ``Image`` / ``CommandLine``
       / ``Computer`` exist.
    4. **Vendor heuristics**: pick what we can off whatever's left.
    """
    # Guard against accidental coercion at the boundary.
    if not isinstance(event, dict):  # pragma: no cover - defensive
        return OcsfEvent(source=source, raw={"value": event}, normalization_dialect="invalid")

    try:
        if _looks_like_ocsf(event):
            return _from_ocsf(source, event, external_id)
        if _looks_like_ecs(event):
            return _from_ecs(source, event, external_id)
        if _looks_like_sysmon(event):
            return _from_sysmon(source, event, external_id)
        return _from_unknown(source, event, external_id)
    except Exception:  # noqa: BLE001 — last-resort safety net
        # Never crash the realtime pipeline on a single bad event. We
        # return a base event so it still flows downstream and ops can
        # diagnose from the raw payload.
        return OcsfEvent(
            source=source,
            external_id=external_id,
            raw=event,
            normalization_dialect="error",
        )


# ── Dialect probes ─────────────────────────────────────────────────────


def _looks_like_ocsf(ev: dict[str, Any]) -> bool:
    # OCSF requires class_uid; if the producer provided it, trust them.
    return isinstance(ev.get("class_uid"), int) or isinstance(
        ev.get("category_uid"), int
    )


_ECS_KEYS = ("process.name", "host.name", "user.name", "source.ip", "destination.ip")


def _looks_like_ecs(ev: dict[str, Any]) -> bool:
    # ECS uses dotted keys but flatteners often write them as nested dicts.
    if any(k in ev for k in _ECS_KEYS):
        return True
    if isinstance(ev.get("process"), dict) and "name" in ev["process"]:
        return True
    if isinstance(ev.get("host"), dict) and "name" in ev["host"]:
        return True
    return False


_SYSMON_HINT_KEYS = ("Image", "CommandLine", "Computer", "ProcessId", "User", "Hashes")


def _looks_like_sysmon(ev: dict[str, Any]) -> bool:
    return any(k in ev for k in _SYSMON_HINT_KEYS)


# ── Field extraction helpers ───────────────────────────────────────────


def _dig(ev: dict[str, Any], *paths: str) -> Any:
    """Walk dotted paths and return the first scalar value found.

    Mirrors the existing ``_dig`` in ``app/api/routes.py`` but expanded
    so the OCSF normalizer can prefer a typed scalar from the most
    specific path. Returns ``None`` if no path resolves.
    """
    for path in paths:
        cur: Any = ev
        ok = True
        for part in path.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                ok = False
                break
        if ok and cur is not None and not isinstance(cur, (dict, list)):
            return cur
    return None


def _str(ev: dict[str, Any], *paths: str) -> str | None:
    v = _dig(ev, *paths)
    if v is None:
        return None
    s = str(v).strip()
    return s or None


def _int(ev: dict[str, Any], *paths: str) -> int | None:
    v = _dig(ev, *paths)
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _parse_time(ev: dict[str, Any], *paths: str) -> datetime:
    """Best-effort timestamp parse, defaulting to now()."""
    raw = _dig(ev, *paths)
    if raw is None:
        return datetime.now(timezone.utc)
    if isinstance(raw, datetime):
        return raw.astimezone(timezone.utc) if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
    if isinstance(raw, (int, float)):
        # OCSF uses epoch-ms; Sysmon often ships epoch-s. Be forgiving.
        ts = float(raw)
        if ts > 1e12:  # ms
            ts /= 1000.0
        try:
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return datetime.now(timezone.utc)
    if isinstance(raw, str):
        try:
            # Handle Z suffix common in JSON exports
            return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc)
        except ValueError:
            return datetime.now(timezone.utc)
    return datetime.now(timezone.utc)


def _hash_from(ev: dict[str, Any]) -> str | None:
    """Sysmon ships hashes as a single ``MD5=...,SHA256=...`` blob.

    Most rules care about SHA256, fall back to MD5 then SHA1. ECS/OCSF
    use ``process.hash.sha256`` style nested keys which we handle by
    direct path lookup.
    """
    direct = _str(
        ev,
        "process.hash.sha256",
        "process.hash.sha1",
        "process.hash.md5",
        "file.hash.sha256",
        "process_hash_sha256",
    )
    if direct:
        return direct
    blob = ev.get("Hashes")
    if isinstance(blob, str):
        parts = {}
        for chunk in blob.split(","):
            if "=" in chunk:
                k, v = chunk.split("=", 1)
                parts[k.strip().lower()] = v.strip()
        for algo in ("sha256", "sha1", "md5"):
            if algo in parts and parts[algo]:
                return parts[algo]
    return None


# ── Dialect-specific projections ───────────────────────────────────────


def _from_ocsf(source: str, ev: dict[str, Any], ext: str | None) -> OcsfEvent:
    """Pass-through path: the producer already emitted OCSF."""
    return OcsfEvent(
        source=source,
        external_id=ext or _str(ev, "metadata.uid", "uid"),
        category_uid=_int(ev, "category_uid") or OcsfCategory.OTHER.value,
        class_uid=_int(ev, "class_uid") or OcsfActivityClass.BASE_EVENT.value,
        activity_id=_int(ev, "activity_id") or 0,
        severity_id=_int(ev, "severity_id") or 1,
        time=_parse_time(ev, "time", "timestamp", "@timestamp"),
        actor_user=_str(ev, "actor.user.name", "actor.user.full_name"),
        actor_process_name=_str(ev, "actor.process.name", "process.name"),
        actor_process_cmdline=_str(ev, "actor.process.cmd_line", "process.cmd_line"),
        actor_process_pid=_int(ev, "actor.process.pid", "process.pid"),
        src_host=_str(ev, "device.hostname", "device.name", "src_endpoint.hostname"),
        src_ip=_str(ev, "src_endpoint.ip", "source.ip", "src_ip"),
        dst_ip=_str(ev, "dst_endpoint.ip", "destination.ip", "dst_ip"),
        dst_port=_int(ev, "dst_endpoint.port", "destination.port"),
        file_path=_str(ev, "file.path", "file.name"),
        file_hash=_hash_from(ev),
        title=_str(ev, "type_name", "activity_name", "class_name"),
        description=_str(ev, "message", "description"),
        raw=ev,
        normalization_dialect="ocsf",
    )


def _from_ecs(source: str, ev: dict[str, Any], ext: str | None) -> OcsfEvent:
    """ECS (Elastic Common Schema) — Splunk Add-on / Filebeat default."""
    class_uid = OcsfActivityClass.BASE_EVENT
    activity_id = 0
    category = _str(ev, "event.category", "event.kind") or ""
    action = (_str(ev, "event.action", "event.type") or "").lower()

    if "process" in category or _str(ev, "process.name"):
        class_uid = OcsfActivityClass.PROCESS_ACTIVITY
        activity_id = (
            ACTIVITY_PROCESS_TERMINATE if "end" in action or "terminate" in action
            else ACTIVITY_PROCESS_LAUNCH
        )
    elif "network" in category or _str(ev, "destination.ip"):
        class_uid = OcsfActivityClass.NETWORK_ACTIVITY
        activity_id = ACTIVITY_NETWORK_OPEN
    elif "authentication" in category or _str(ev, "user.name"):
        class_uid = OcsfActivityClass.AUTHENTICATION
        activity_id = (
            ACTIVITY_AUTH_FAILED if "failure" in action or "failed" in action
            else ACTIVITY_AUTH_LOGON
        )
    elif "file" in category:
        class_uid = OcsfActivityClass.FILE_SYSTEM_ACTIVITY
        activity_id = ACTIVITY_FILE_CREATE

    return OcsfEvent(
        source=source,
        external_id=ext or _str(ev, "event.id"),
        category_uid=class_uid.value // 1000,
        class_uid=class_uid.value,
        activity_id=activity_id,
        severity_id=_int(ev, "event.severity") or 1,
        time=_parse_time(ev, "@timestamp", "event.created", "timestamp"),
        actor_user=_str(ev, "user.name", "process.user.name"),
        actor_process_name=_str(ev, "process.name", "process.executable"),
        actor_process_cmdline=_str(ev, "process.command_line", "process.args"),
        actor_process_pid=_int(ev, "process.pid"),
        src_host=_str(ev, "host.name", "host.hostname", "agent.hostname"),
        src_ip=_str(ev, "source.ip", "client.ip", "host.ip"),
        dst_ip=_str(ev, "destination.ip", "server.ip"),
        dst_port=_int(ev, "destination.port", "server.port"),
        file_path=_str(ev, "file.path", "file.name"),
        file_hash=_hash_from(ev),
        title=_str(ev, "event.action", "rule.name"),
        description=_str(ev, "message"),
        raw=ev,
        normalization_dialect="ecs",
    )


def _from_sysmon(source: str, ev: dict[str, Any], ext: str | None) -> OcsfEvent:
    """Sysmon EventLog flat schema (PascalCase keys).

    We map ``EventID`` to OCSF class/activity since that's the most
    reliable signal in Sysmon. EventID 1 = process create, 3 = network
    connect, 11 = file create, etc.
    """
    event_id = _int(ev, "EventID", "event_id") or 0
    if event_id == 1:
        class_uid = OcsfActivityClass.PROCESS_ACTIVITY
        activity_id = ACTIVITY_PROCESS_LAUNCH
    elif event_id == 5:
        class_uid = OcsfActivityClass.PROCESS_ACTIVITY
        activity_id = ACTIVITY_PROCESS_TERMINATE
    elif event_id == 3:
        class_uid = OcsfActivityClass.NETWORK_ACTIVITY
        activity_id = ACTIVITY_NETWORK_OPEN
    elif event_id == 11:
        class_uid = OcsfActivityClass.FILE_SYSTEM_ACTIVITY
        activity_id = ACTIVITY_FILE_CREATE
    elif event_id in (12, 13, 14):
        class_uid = OcsfActivityClass.REGISTRY_KEY_ACTIVITY
        activity_id = 1
    elif event_id == 22:
        class_uid = OcsfActivityClass.DNS_ACTIVITY
        activity_id = 1
    else:
        class_uid = OcsfActivityClass.PROCESS_ACTIVITY
        activity_id = ACTIVITY_PROCESS_LAUNCH

    image = _str(ev, "Image", "ImagePath")
    process_name = None
    if image:
        # Sysmon ships full path; tools that watch process.name want the
        # basename. Keep the full path under raw for forensics.
        process_name = image.replace("\\", "/").rsplit("/", 1)[-1]

    return OcsfEvent(
        source=source,
        external_id=ext or _str(ev, "RecordID", "EventRecordID"),
        category_uid=class_uid.value // 1000,
        class_uid=class_uid.value,
        activity_id=activity_id,
        severity_id=_int(ev, "Level") or 1,
        time=_parse_time(ev, "UtcTime", "TimeCreated", "@timestamp"),
        actor_user=_str(ev, "User", "SourceUser"),
        actor_process_name=process_name,
        actor_process_cmdline=_str(ev, "CommandLine"),
        actor_process_pid=_int(ev, "ProcessId", "PID"),
        src_host=_str(ev, "Computer", "ComputerName", "Hostname"),
        src_ip=_str(ev, "SourceIp"),
        dst_ip=_str(ev, "DestinationIp"),
        dst_port=_int(ev, "DestinationPort"),
        file_path=_str(ev, "TargetFilename", "Image"),
        file_hash=_hash_from(ev),
        title=_str(ev, "RuleName") or f"sysmon_eid_{event_id}",
        description=_str(ev, "Description"),
        raw=ev,
        normalization_dialect="sysmon",
    )


def _from_unknown(source: str, ev: dict[str, Any], ext: str | None) -> OcsfEvent:
    """Fallback path — pick what we can off arbitrary vendor JSON.

    This is the bucket every CrowdStrike-style "Falcon EDR" connector
    initially lands in. We harvest the most common scalar keys, leave
    everything else under ``raw``, and trust Sigma rules to either match
    on a generic pattern or just not match.
    """
    return OcsfEvent(
        source=source,
        external_id=ext or _str(ev, "id", "_id", "uuid"),
        category_uid=OcsfCategory.OTHER.value,
        class_uid=OcsfActivityClass.SECURITY_FINDING.value,
        activity_id=0,
        severity_id=_int(ev, "severity") or 1,
        time=_parse_time(ev, "timestamp", "time", "@timestamp", "created_at"),
        actor_user=_str(ev, "user", "username", "user_name"),
        actor_process_name=_str(ev, "process_name", "process"),
        actor_process_cmdline=_str(ev, "cmdline", "command_line"),
        actor_process_pid=_int(ev, "pid", "process_id"),
        src_host=_str(ev, "host", "hostname", "computer", "device_name"),
        src_ip=_str(ev, "src_ip", "source_ip", "ip"),
        dst_ip=_str(ev, "dst_ip", "destination_ip"),
        dst_port=_int(ev, "dst_port", "destination_port"),
        file_path=_str(ev, "file", "file_path", "filename"),
        file_hash=_hash_from(ev),
        title=_str(ev, "title", "name", "rule"),
        description=_str(ev, "description", "message"),
        raw=ev,
        normalization_dialect="unknown",
    )


# ── Helpers for consumers ──────────────────────────────────────────────


def ocsf_to_sigma_payload(oe: OcsfEvent) -> dict[str, Any]:
    """Project an OCSF event into the flat dict Sigma rules expect.

    The Sigma engine in ``app/detections/runtime`` matches on flat field
    names. We give it both OCSF-canonical keys (``process.name``) and the
    common aliases the starter rulepack uses (``Image``, ``CommandLine``,
    ``ProcessName``) so rules written against either dialect light up.
    """
    payload: dict[str, Any] = {}
    if oe.actor_user:
        payload["user.name"] = oe.actor_user
        payload["User"] = oe.actor_user
    if oe.actor_process_name:
        payload["process.name"] = oe.actor_process_name
        payload["ProcessName"] = oe.actor_process_name
        payload["Image"] = oe.actor_process_name
    if oe.actor_process_cmdline:
        payload["process.command_line"] = oe.actor_process_cmdline
        payload["CommandLine"] = oe.actor_process_cmdline
    if oe.actor_process_pid is not None:
        payload["process.pid"] = oe.actor_process_pid
        payload["ProcessId"] = oe.actor_process_pid
    if oe.src_host:
        payload["host.name"] = oe.src_host
        payload["Computer"] = oe.src_host
    if oe.src_ip:
        payload["source.ip"] = oe.src_ip
        payload["SourceIp"] = oe.src_ip
    if oe.dst_ip:
        payload["destination.ip"] = oe.dst_ip
        payload["DestinationIp"] = oe.dst_ip
    if oe.dst_port is not None:
        payload["destination.port"] = oe.dst_port
        payload["DestinationPort"] = oe.dst_port
    if oe.file_path:
        payload["file.path"] = oe.file_path
        payload["TargetFilename"] = oe.file_path
    if oe.file_hash:
        payload["file.hash"] = oe.file_hash
        payload["process.hash.sha256"] = oe.file_hash
    # Keep the original raw payload so rules written against vendor
    # idiosyncrasies (e.g. ``EventID``) still match.
    for k, v in oe.raw.items():
        payload.setdefault(k, v)
    return payload


def iter_ocsf(events: Iterable[dict[str, Any]], *, source: str) -> Iterable[OcsfEvent]:
    """Convenience: normalize a stream of events lazily."""
    for ev in events:
        yield normalize_event(source=source, event=ev)
