"""Tests for the Linux ``auditd`` file_tail connector.

The connector ships in three layers and the tests are grouped to
match:

* ``test_schema_*`` / ``test_capabilities_*`` — surface-area contract.
* ``test_parse_*`` / ``test_assemble_*``       — multi-record event
                                                 reassembly. This is the
                                                 hard part of the
                                                 connector and gets the
                                                 most coverage.
* ``test_severity_*``                          — the ``aisoc_*`` key
                                                 prefix mapping plus the
                                                 fall-back path/exec
                                                 heuristics.
* ``test_normalize_*``                         — the reassembled event
                                                 -> AiSOC shape mapping
                                                 (must match what
                                                 ``detections/endpoint/
                                                 linux-*.yaml`` rules
                                                 pivot on).
* ``test_file_tail_*``                         — file_tail cursor
                                                 behaviour, rotation,
                                                 partial-line buffering,
                                                 corrupt-cursor recovery.
* ``test_test_connection_*``                   — the test_connection
                                                 contract.

Real-world auditd output is a pile of edge cases (hex-encoded
proctitles, missing PATH records, multi-PATH events for ``rename``,
quoted/unquoted values, partial trailing lines) and every one is
exercised here so refactoring this connector cannot silently break
detection content.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from app.connectors.auditd import (
    _HIGH_RISK_EXEC_DIRS,
    _MAX_EVENTS_PER_POLL,
    _MAX_TAIL_BYTES_PER_POLL,
    AuditdConnector,
    _assemble_events,
    _decode_hex_string,
    _extract_argv,
    _parse_record,
    _severity_from_event,
)
from app.connectors.base import Capability

# ---------------------------------------------------------------------------
# Schema / capabilities contract
# ---------------------------------------------------------------------------


def test_schema_basic_shape():
    schema = AuditdConnector.schema()
    assert schema.connector_id == "auditd"
    assert schema.connector_name == "Linux Auditd"
    assert schema.category == "edr"
    assert schema.docs_url == "/docs/connectors/auditd"


def test_schema_field_set():
    schema = AuditdConnector.schema()
    field_names = {f.name for f in schema.fields}
    assert field_names == {"host_label", "audit_log_path", "cursor_path"}


def test_schema_host_label_is_required():
    schema = AuditdConnector.schema()
    host = next(f for f in schema.fields if f.name == "host_label")
    assert host.required is True


def test_schema_audit_log_path_has_sensible_default():
    schema = AuditdConnector.schema()
    path = next(f for f in schema.fields if f.name == "audit_log_path")
    assert path.required is True
    assert path.default == "/var/log/audit/audit.log"


def test_schema_cursor_path_is_optional():
    schema = AuditdConnector.schema()
    cursor = next(f for f in schema.fields if f.name == "cursor_path")
    assert cursor.required is False


def test_capabilities_advertises_pull_audit_and_alerts():
    caps = AuditdConnector.capabilities()
    assert Capability.PULL_AUDIT in caps
    assert Capability.PULL_ALERTS in caps


# ---------------------------------------------------------------------------
# _parse_record — single-line parsing primitives
# ---------------------------------------------------------------------------


def test_parse_record_extracts_event_id_type_and_fields():
    line = (
        "type=SYSCALL msg=audit(1715520000.123:9876): arch=c000003e "
        'syscall=59 success=yes exit=0 uid=1000 auid=1000 comm="bash" '
        'exe="/usr/bin/bash" key="aisoc_exec"'
    )
    event_id, record_type, fields = _parse_record(line)
    assert event_id == ("1715520000.123", "9876")
    assert record_type == "SYSCALL"
    assert fields["syscall"] == "59"
    assert fields["uid"] == "1000"
    assert fields["exe"] == "/usr/bin/bash"
    assert fields["key"] == "aisoc_exec"
    assert fields["success"] == "yes"


def test_parse_record_handles_quoted_values_with_spaces():
    """Quoted values can contain spaces — the splitter must not break."""
    line = 'type=USER_CMD msg=audit(1.0:1): cmd="ls -la /etc"'
    _, _, fields = _parse_record(line)
    assert fields["cmd"] == "ls -la /etc"


def test_parse_record_handles_unquoted_hex_values():
    """proctitle is hex-encoded as a bareword (no quotes)."""
    line = "type=PROCTITLE msg=audit(1.0:1): proctitle=626173680A2D63"
    _, record_type, fields = _parse_record(line)
    assert record_type == "PROCTITLE"
    assert fields["proctitle"] == "626173680A2D63"


def test_parse_record_returns_empty_for_malformed_line():
    """No msg=audit(...) -> caller drops the line cleanly."""
    line = "this is not an audit record"
    event_id, record_type, fields = _parse_record(line)
    assert event_id is None
    assert record_type is None
    assert fields == {}


def test_parse_record_extracts_argv_slot_keys():
    line = 'type=EXECVE msg=audit(1.0:1): argc=3 a0="bash" a1="-c" a2="curl http://evil/"'
    _, record_type, fields = _parse_record(line)
    assert record_type == "EXECVE"
    assert fields["a0"] == "bash"
    assert fields["a1"] == "-c"
    assert fields["a2"] == "curl http://evil/"


# ---------------------------------------------------------------------------
# _decode_hex_string — proctitle decoding
# ---------------------------------------------------------------------------


def test_decode_hex_string_replaces_nuls_with_spaces():
    # "bash\x00-c" -> "bash -c". "bash" = 62 61 73 68.
    out = _decode_hex_string("62617368002D63")
    assert "\x00" not in out
    assert "bash" in out
    assert "-c" in out


def test_decode_hex_string_returns_input_for_invalid_hex():
    assert _decode_hex_string("not-hex-at-all") == "not-hex-at-all"


def test_decode_hex_string_handles_known_argv_blob():
    # "bash\x00-c\x00ls" = 62 61 73 68 00 2d 63 00 6c 73
    out = _decode_hex_string("62617368002D63006C73")
    # We expect "bash -c ls" (NULs replaced by spaces).
    assert "bash" in out
    assert "ls" in out
    assert "-c" in out


# ---------------------------------------------------------------------------
# _extract_argv — argv reassembly
# ---------------------------------------------------------------------------


def test_extract_argv_walks_a0_a1_a2_in_order():
    fields = {"argc": "3", "a0": "bash", "a1": "-c", "a2": "id"}
    assert _extract_argv(fields) == ["bash", "-c", "id"]


def test_extract_argv_stops_at_first_gap():
    """auditd should always emit contiguous slots, but defensively
    we stop at the first missing index rather than scanning forever.
    """
    fields = {"a0": "bash", "a1": "-c", "a3": "skipped"}
    # a2 is missing -> we stop after a1.
    assert _extract_argv(fields) == ["bash", "-c"]


def test_extract_argv_returns_empty_list_when_no_slots():
    assert _extract_argv({"argc": "0"}) == []


# ---------------------------------------------------------------------------
# _assemble_events — multi-record reassembly (the hard part)
# ---------------------------------------------------------------------------


def _make_records(*lines: str) -> list:
    """Helper: parse a batch of raw lines into the input shape that
    _assemble_events expects.
    """
    return [_parse_record(line) for line in lines]


def test_assemble_groups_records_by_event_id():
    """SYSCALL + EXECVE + CWD + PATH + PROCTITLE -> one event."""
    records = _make_records(
        "type=SYSCALL msg=audit(1.0:1): arch=c000003e syscall=59 "
        'success=yes exit=0 uid=1000 auid=1000 comm="bash" '
        'exe="/usr/bin/bash" key="aisoc_exec"',
        'type=EXECVE msg=audit(1.0:1): argc=3 a0="bash" a1="-c" a2="id"',
        'type=CWD msg=audit(1.0:1): cwd="/tmp"',
        'type=PATH msg=audit(1.0:1): item=0 name="/usr/bin/bash"',
        "type=PROCTITLE msg=audit(1.0:1): proctitle=626173002D630069",
    )
    events = _assemble_events(records)
    assert len(events) == 1
    event = events[0]
    assert event["event_id"] == "1.0:1"
    assert event["timestamp"] == "1.0"
    assert event["serial"] == "1"
    assert event["syscall"] == "execve"  # 59 -> execve via the table
    assert event["exe"] == "/usr/bin/bash"
    assert event["argv"] == ["bash", "-c", "id"]
    assert event["cwd"] == "/tmp"
    assert event["path"] == "/usr/bin/bash"
    assert event["paths"] == ["/usr/bin/bash"]
    assert event["actor_uid"] == "1000"
    assert event["key"] == "aisoc_exec"
    assert event["comm"] == "bash"


def test_assemble_resolves_syscall_number_to_name():
    """Detection rules pivot on string syscall names (``execve``)
    rather than kernel-architecture-dependent numbers.
    """
    records = _make_records(
        "type=SYSCALL msg=audit(1.0:1): arch=c000003e syscall=59",
        "type=SYSCALL msg=audit(2.0:2): arch=c000003e syscall=257",
        "type=SYSCALL msg=audit(3.0:3): arch=c000003e syscall=175",
        "type=SYSCALL msg=audit(4.0:4): arch=c000003e syscall=313",
    )
    events = {e["serial"]: e for e in _assemble_events(records)}
    assert events["1"]["syscall"] == "execve"
    assert events["2"]["syscall"] == "openat"
    assert events["3"]["syscall"] == "init_module"
    assert events["4"]["syscall"] == "finit_module"


def test_assemble_falls_back_to_raw_syscall_number_when_unknown():
    """Unknown syscall numbers should still surface as something — we
    drop them through unchanged rather than emitting None.
    """
    records = _make_records(
        "type=SYSCALL msg=audit(1.0:1): arch=c000003e syscall=999999",
    )
    events = _assemble_events(records)
    assert events[0]["syscall"] == "999999"


def test_assemble_keeps_multiple_path_records_for_rename():
    """``rename`` emits two PATH records. We collect both into ``paths``
    and promote the first to the singular ``path`` for the common case.
    """
    records = _make_records(
        'type=SYSCALL msg=audit(1.0:1): arch=c000003e syscall=82 comm="mv" exe="/usr/bin/mv"',  # 82 = rename
        'type=PATH msg=audit(1.0:1): item=0 name="/etc/passwd.bak"',
        'type=PATH msg=audit(1.0:1): item=1 name="/etc/passwd"',
    )
    events = _assemble_events(records)
    assert len(events) == 1
    event = events[0]
    assert event["paths"] == ["/etc/passwd.bak", "/etc/passwd"]
    # First one is promoted as the singular "path" for the common case.
    assert event["path"] == "/etc/passwd.bak"


def test_assemble_decodes_hex_proctitle():
    # "bash\x00-c\x00id" -> "bash -c id"
    # bash = 62 61 73 68, -c = 2d 63, id = 69 64
    records = _make_records(
        "type=SYSCALL msg=audit(1.0:1): syscall=59",
        "type=PROCTITLE msg=audit(1.0:1): proctitle=62617368002D63006964",
    )
    events = _assemble_events(records)
    proctitle = events[0]["proctitle"]
    assert "\x00" not in proctitle
    assert "bash" in proctitle


def test_assemble_keeps_quoted_proctitle_unchanged():
    """Quoted proctitle (no NULs in the original) should not be hex-decoded."""
    records = _make_records(
        "type=SYSCALL msg=audit(1.0:1): syscall=59",
        'type=PROCTITLE msg=audit(1.0:1): proctitle="bash"',
    )
    events = _assemble_events(records)
    assert events[0]["proctitle"] == "bash"


def test_assemble_produces_one_event_per_id_pair():
    """Two distinct (timestamp, serial) tuples = two distinct events."""
    records = _make_records(
        "type=SYSCALL msg=audit(1.0:1): syscall=59 uid=1000",
        "type=SYSCALL msg=audit(2.0:2): syscall=59 uid=2000",
    )
    events = _assemble_events(records)
    assert len(events) == 2
    by_serial = {e["serial"]: e for e in events}
    assert by_serial["1"]["actor_uid"] == "1000"
    assert by_serial["2"]["actor_uid"] == "2000"


def test_assemble_deduplicates_repeated_path_names():
    """Some kernel paths can repeat (parent + child PATH for an openat).
    The list should not duplicate entries.
    """
    records = _make_records(
        "type=SYSCALL msg=audit(1.0:1): syscall=257",
        'type=PATH msg=audit(1.0:1): item=0 name="/etc/passwd"',
        'type=PATH msg=audit(1.0:1): item=1 name="/etc/passwd"',
    )
    events = _assemble_events(records)
    assert events[0]["paths"] == ["/etc/passwd"]


def test_assemble_preserves_raw_records_per_type():
    """Detections occasionally need to walk back to a specific record
    type — keep ``raw_records`` populated.
    """
    records = _make_records(
        "type=SYSCALL msg=audit(1.0:1): syscall=59",
        'type=EXECVE msg=audit(1.0:1): argc=1 a0="ls"',
        'type=PATH msg=audit(1.0:1): item=0 name="/usr/bin/ls"',
    )
    events = _assemble_events(records)
    raw = events[0]["raw_records"]
    assert "SYSCALL" in raw
    assert "EXECVE" in raw
    # PATH is a list because it can repeat.
    assert isinstance(raw["PATH"], list)
    assert raw["PATH"][0]["name"] == "/usr/bin/ls"


def test_assemble_drops_records_with_no_msg_id():
    """Lines with no msg=audit(...) header should be silently dropped
    rather than crashing the batch.
    """
    records = [(None, None, {})] + _make_records(
        "type=SYSCALL msg=audit(1.0:1): syscall=59",
    )
    events = _assemble_events(records)
    assert len(events) == 1


def test_assemble_event_with_no_paths_has_path_none():
    records = _make_records(
        "type=SYSCALL msg=audit(1.0:1): syscall=59",
    )
    events = _assemble_events(records)
    assert events[0]["path"] is None
    assert events[0]["paths"] == []


# ---------------------------------------------------------------------------
# _severity_from_event — the bucket assignment
# ---------------------------------------------------------------------------


def test_severity_critical_key_prefix_is_critical():
    # ``aisoc_critical_*`` keys mark the irreversible-or-equivalent
    # mutations to host trust (sudoers, ssh keys, sshd config). In
    # the 5-tier ladder these map directly to ``critical`` — the P1
    # SLA tier — rather than collapsing to ``high``.
    assert _severity_from_event({"key": "aisoc_critical_sudoers_write"}) == "critical"
    assert _severity_from_event({"key": "aisoc_critical_ssh_config"}) == "critical"
    assert _severity_from_event({"key": "aisoc_critical_authorized_keys"}) == "critical"


def test_severity_priv_esc_key_prefix_is_high():
    # Priv-esc primitives (module load, ptrace) are loud-but-survivable
    # — ``high`` rather than ``critical``, which is reserved for
    # full host-trust compromise.
    assert _severity_from_event({"key": "aisoc_priv_esc_module_load"}) == "high"
    assert _severity_from_event({"key": "aisoc_priv_esc_ptrace"}) == "high"


def test_severity_persistence_key_prefix_is_medium():
    assert _severity_from_event({"key": "aisoc_persistence_systemd"}) == "medium"
    assert _severity_from_event({"key": "aisoc_persistence_cron"}) == "medium"


def test_severity_aisoc_exec_key_is_medium():
    assert _severity_from_event({"key": "aisoc_exec"}) == "medium"


def test_severity_watch_key_prefix_is_low():
    assert _severity_from_event({"key": "aisoc_watch_hosts"}) == "low"


def test_severity_audit_self_tampering_key_prefix_is_low():
    assert _severity_from_event({"key": "aisoc_audit_subsystem"}) == "low"


def test_severity_critical_prefix_wins_over_exec():
    """A critical key should outrank the generic ``aisoc_exec`` bucket
    even though both are AiSOC-prefixed. Order in the prefix table
    matters.
    """
    assert _severity_from_event({"key": "aisoc_critical_sudoers_write"}) == "critical"


def test_severity_falls_back_to_path_heuristic_when_no_key():
    """Operators not using the AiSOC profile still get coverage via
    path-based heuristics on canonical sensitive files.
    """
    assert _severity_from_event({"path": "/etc/shadow"}) == "high"
    assert _severity_from_event({"path": "/etc/passwd"}) == "high"
    assert _severity_from_event({"path": "/etc/sudoers"}) == "high"
    assert _severity_from_event({"path": "/etc/ssh/sshd_config"}) == "high"


def test_severity_falls_back_to_exec_from_temp_heuristic():
    """An ``execve`` from a temp dir is almost always malicious."""
    for tmp_dir in _HIGH_RISK_EXEC_DIRS:
        assert (
            _severity_from_event(
                {"syscall": "execve", "exe": f"{tmp_dir}payload"},
            )
            == "high"
        )


def test_severity_exec_from_legitimate_path_is_info():
    """An ``execve`` from /usr/bin should not trip the exec-from-temp
    heuristic — that's normal user activity.
    """
    assert _severity_from_event({"syscall": "execve", "exe": "/usr/bin/ls"}) == "info"


def test_severity_unknown_key_falls_through_to_info():
    """Custom CIS / STIG key that AiSOC doesn't recognise -> info floor
    (we don't surface unknown keys as alerts).
    """
    assert _severity_from_event({"key": "cis_benchmark_5_1_2"}) == "info"


def test_severity_handles_missing_key_path_and_syscall():
    assert _severity_from_event({}) == "info"


def test_severity_strips_quotes_around_key():
    """auditd lines have quoted keys (``key="aisoc_exec"``) — the parser
    strips the quotes, but defensively the severity helper also handles
    a stray quote prefix/suffix.
    """
    assert _severity_from_event({"key": '"aisoc_critical_sudoers_write"'}) == "critical"


# ---------------------------------------------------------------------------
# AuditdConnector.normalize() — the AiSOC field shape
# ---------------------------------------------------------------------------


def _make_connector(**overrides):
    defaults = {
        "host_label": "prod-web-01",
        "audit_log_path": "/var/log/audit/audit.log",
    }
    defaults.update(overrides)
    return AuditdConnector(**defaults)


def test_normalize_emits_canonical_endpoint_fields():
    """The field names below are the contract every existing
    ``detections/endpoint/linux-*.yaml`` rule pivots on. Renaming
    any of them is a breaking change for detection content.
    """
    conn = _make_connector()
    raw = {
        "event_id": "1.0:1",
        "timestamp": "1.0",
        "serial": "1",
        "syscall": "execve",
        "exe": "/usr/bin/bash",
        "argv": ["bash", "-c", "curl http://evil/"],
        "path": "/usr/bin/bash",
        "paths": ["/usr/bin/bash"],
        "cwd": "/tmp",
        "comm": "bash",
        "proctitle": "bash -c curl",
        "actor_uid": "1000",
        "actor_auid": "1000",
        "actor_euid": "0",
        "actor_gid": "1000",
        "actor_pid": "12345",
        "actor_ppid": "1234",
        "tty": "pts0",
        "session": "5",
        "arch": "c000003e",
        "key": "aisoc_exec",
        "success": "yes",
        "exit": "0",
        "raw_records": {"SYSCALL": {}, "EXECVE": {}},
    }
    norm = conn.normalize(raw)
    # Top-level identity / housekeeping
    assert norm["source"] == "auditd"
    assert norm["category"] == "endpoint"
    assert norm["external_id"] == "1.0:1"
    assert norm["event_id"] == "1.0:1"
    # Host stamping
    assert norm["host"] == "prod-web-01"
    assert norm["hostname"] == "prod-web-01"
    # Detection-pivoted fields
    assert norm["syscall"] == "execve"
    assert norm["exe"] == "/usr/bin/bash"
    assert norm["argv"] == ["bash", "-c", "curl http://evil/"]
    assert norm["path"] == "/usr/bin/bash"
    assert norm["paths"] == ["/usr/bin/bash"]
    assert norm["cwd"] == "/tmp"
    assert norm["comm"] == "bash"
    assert norm["proctitle"] == "bash -c curl"
    assert norm["actor_uid"] == "1000"
    assert norm["actor_pid"] == "12345"
    assert norm["actor_ppid"] == "1234"
    assert norm["tty"] == "pts0"
    assert norm["session"] == "5"
    assert norm["arch"] == "c000003e"
    # Both ``key`` and ``auditd_key`` must be present — the latter is
    # the canonical detection pivot field, the former preserves the raw
    # auditd vocabulary for users who pivoted on it before.
    assert norm["key"] == "aisoc_exec"
    assert norm["auditd_key"] == "aisoc_exec"
    assert norm["success"] == "yes"
    assert norm["exit"] == "0"
    # raw_records must round-trip so detections can walk back.
    assert norm["raw_records"] == {"SYSCALL": {}, "EXECVE": {}}


def test_normalize_severity_uses_key_prefix_mapping():
    conn = _make_connector()
    raw = {"key": "aisoc_critical_sudoers_write"}
    # The five-tier ladder mirrors aisoc_critical_* → ``critical`` so
    # genuine P1 host-trust events fire the 15-minute MTTD SLA.
    assert conn.normalize(raw)["severity"] == "critical"


def test_normalize_severity_falls_back_to_path_when_no_key():
    conn = _make_connector()
    raw = {"path": "/etc/shadow", "syscall": "openat"}
    assert conn.normalize(raw)["severity"] == "high"


def test_normalize_severity_floor_is_info():
    conn = _make_connector()
    raw = {"syscall": "openat", "path": "/var/log/uneventful.log"}
    assert conn.normalize(raw)["severity"] == "info"


def test_normalize_title_for_execve_includes_argv_preview():
    conn = _make_connector()
    raw = {
        "syscall": "execve",
        "exe": "/usr/bin/bash",
        "argv": ["bash", "-c", "id"],
    }
    norm = conn.normalize(raw)
    assert "execve" in norm["title"]
    assert "/usr/bin/bash" in norm["title"]
    assert "-c" in norm["title"]


def test_normalize_title_for_path_event_uses_syscall_and_path():
    conn = _make_connector()
    raw = {"syscall": "openat", "path": "/etc/sudoers"}
    norm = conn.normalize(raw)
    assert "openat" in norm["title"]
    assert "/etc/sudoers" in norm["title"]


def test_normalize_title_falls_back_to_key_when_no_path_or_exec():
    conn = _make_connector()
    raw = {"syscall": "kill", "key": "aisoc_priv_esc_kill"}
    norm = conn.normalize(raw)
    assert "kill" in norm["title"]
    assert "aisoc_priv_esc_kill" in norm["title"]


def test_normalize_handles_missing_optional_fields():
    """Audit events from rules without an EXECVE/PATH companion are sparse."""
    conn = _make_connector()
    raw = {"event_id": "1.0:1", "syscall": "kill"}
    norm = conn.normalize(raw)
    assert norm["external_id"] == "1.0:1"
    assert norm["argv"] == []
    assert norm["paths"] == []
    assert norm["path"] is None
    assert norm["exe"] is None


def test_normalize_stamps_host_label_on_every_event():
    conn = _make_connector(host_label="staging-edge-04")
    raw = {"event_id": "1.0:1", "syscall": "openat"}
    norm = conn.normalize(raw)
    assert norm["host"] == "staging-edge-04"
    assert norm["hostname"] == "staging-edge-04"


# ---------------------------------------------------------------------------
# test_connection contract
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_test_connection_requires_host_label(tmp_path: Path):
    audit_log = tmp_path / "audit.log"
    audit_log.write_text("")
    conn = AuditdConnector(
        host_label="",
        audit_log_path=str(audit_log),
    )
    result = await conn.test_connection()
    assert result["success"] is False
    assert "host_label" in result["error"]


@pytest.mark.asyncio
async def test_test_connection_reports_missing_audit_log(tmp_path: Path):
    audit_log = tmp_path / "does-not-exist.log"
    conn = AuditdConnector(
        host_label="prod-web-01",
        audit_log_path=str(audit_log),
    )
    result = await conn.test_connection()
    assert result["success"] is False
    assert "not found" in result["error"]


@pytest.mark.asyncio
async def test_test_connection_reports_unreadable_audit_log(tmp_path: Path):
    audit_log = tmp_path / "audit.log"
    audit_log.write_text("")
    audit_log.chmod(0o000)
    try:
        conn = AuditdConnector(
            host_label="prod-web-01",
            audit_log_path=str(audit_log),
        )
        result = await conn.test_connection()
        if os.geteuid() == 0:
            pytest.skip("running as root — chmod 000 is not enforceable")
        assert result["success"] is False
        assert "not readable" in result["error"]
    finally:
        audit_log.chmod(0o644)


@pytest.mark.asyncio
async def test_test_connection_success_returns_paths(tmp_path: Path):
    audit_log = tmp_path / "audit.log"
    audit_log.write_text("")
    conn = AuditdConnector(
        host_label="prod-web-01",
        audit_log_path=str(audit_log),
    )
    result = await conn.test_connection()
    assert result["success"] is True
    assert result["host"] == "prod-web-01"
    assert result["audit_log_path"] == str(audit_log)
    assert result["cursor_path"].endswith(".aisoc-cursor")


@pytest.mark.asyncio
async def test_test_connection_respects_custom_cursor_path(tmp_path: Path):
    audit_log = tmp_path / "audit.log"
    audit_log.write_text("")
    cursor = tmp_path / "custom" / "audit.cursor"
    conn = AuditdConnector(
        host_label="prod-web-01",
        audit_log_path=str(audit_log),
        cursor_path=str(cursor),
    )
    result = await conn.test_connection()
    assert result["success"] is True
    assert result["cursor_path"] == str(cursor)


# ---------------------------------------------------------------------------
# file_tail mode — fetch_alerts + cursor behaviour
# ---------------------------------------------------------------------------


# A minimal three-record execve event we can paste into log files for
# end-to-end tests. Designed to round-trip cleanly through parsing,
# assembly, and normalization.
_EXECVE_BLOCK_TEMPLATE = (
    "type=SYSCALL msg=audit({ts}:{serial}): arch=c000003e syscall=59 "
    'success=yes exit=0 uid=1000 auid=1000 comm="bash" '
    'exe="/usr/bin/bash" key="aisoc_exec"\n'
    'type=EXECVE msg=audit({ts}:{serial}): argc=2 a0="bash" a1="-c"\n'
    'type=PATH msg=audit({ts}:{serial}): item=0 name="/usr/bin/bash"\n'
)


def _execve_block(ts: str, serial: str) -> str:
    return _EXECVE_BLOCK_TEMPLATE.format(ts=ts, serial=serial)


def _write_log(path: Path, body: str) -> None:
    path.write_text(body)


def _append_log(path: Path, body: str) -> None:
    with open(path, "a") as fh:
        fh.write(body)


@pytest.mark.asyncio
async def test_fetch_alerts_returns_empty_when_log_missing(tmp_path: Path):
    """No file = no events. Connector boots before auditd writes."""
    conn = AuditdConnector(
        host_label="prod-web-01",
        audit_log_path=str(tmp_path / "missing.log"),
    )
    result = await conn.fetch_alerts()
    assert result == []


@pytest.mark.asyncio
async def test_fetch_alerts_reads_full_log_when_no_cursor(tmp_path: Path):
    audit_log = tmp_path / "audit.log"
    _write_log(audit_log, _execve_block("1.0", "1") + _execve_block("2.0", "2"))
    conn = AuditdConnector(
        host_label="prod-web-01",
        audit_log_path=str(audit_log),
    )
    result = await conn.fetch_alerts()
    assert len(result) == 2
    assert {e["external_id"] for e in result} == {"1.0:1", "2.0:2"}
    # Sanity-check the normalised shape on at least one event.
    e = next(e for e in result if e["external_id"] == "1.0:1")
    assert e["syscall"] == "execve"
    assert e["exe"] == "/usr/bin/bash"
    assert e["host"] == "prod-web-01"
    assert e["auditd_key"] == "aisoc_exec"
    assert e["severity"] == "medium"  # aisoc_exec -> medium


@pytest.mark.asyncio
async def test_fetch_alerts_cursor_advances_between_polls(tmp_path: Path):
    audit_log = tmp_path / "audit.log"
    _write_log(audit_log, _execve_block("1.0", "1"))
    conn = AuditdConnector(
        host_label="prod-web-01",
        audit_log_path=str(audit_log),
    )
    first = await conn.fetch_alerts()
    assert len(first) == 1
    # No new bytes since last poll -> empty.
    second = await conn.fetch_alerts()
    assert second == []
    # New event appended -> only the new one comes back.
    _append_log(audit_log, _execve_block("2.0", "2"))
    third = await conn.fetch_alerts()
    assert len(third) == 1
    assert third[0]["external_id"] == "2.0:2"


@pytest.mark.asyncio
async def test_fetch_alerts_resets_cursor_after_rotation(tmp_path: Path):
    """If the file shrinks (logrotate), the cursor must reset to 0."""
    audit_log = tmp_path / "audit.log"
    _write_log(audit_log, _execve_block("1.0", "1") + _execve_block("2.0", "2"))
    conn = AuditdConnector(
        host_label="prod-web-01",
        audit_log_path=str(audit_log),
    )
    first = await conn.fetch_alerts()
    assert len(first) == 2
    # Simulate rotation: replace contents with a smaller payload.
    _write_log(audit_log, _execve_block("3.0", "3"))
    second = await conn.fetch_alerts()
    assert len(second) == 1
    assert second[0]["external_id"] == "3.0:3"


@pytest.mark.asyncio
async def test_fetch_alerts_buffers_partial_trailing_line(tmp_path: Path):
    """Trailing line without ``\\n`` is mid-write — must be left for
    the next poll, not consumed.
    """
    audit_log = tmp_path / "audit.log"
    full = _execve_block("1.0", "1")
    partial = "type=SYSCALL msg=audit(2.0:2): arch=c000003e syscall=59"  # no \n
    audit_log.write_text(full + partial)
    conn = AuditdConnector(
        host_label="prod-web-01",
        audit_log_path=str(audit_log),
    )
    first = await conn.fetch_alerts()
    # Only the complete event came through.
    assert len(first) == 1
    assert first[0]["external_id"] == "1.0:1"

    # Complete the partial line + add the rest of the records.
    completion = (
        ' success=yes uid=1000 comm="ls" exe="/usr/bin/ls" key="aisoc_exec"\n'
        'type=EXECVE msg=audit(2.0:2): argc=1 a0="ls"\n'
        'type=PATH msg=audit(2.0:2): item=0 name="/usr/bin/ls"\n'
    )
    _append_log(audit_log, completion)
    second = await conn.fetch_alerts()
    assert len(second) == 1
    assert second[0]["external_id"] == "2.0:2"
    assert second[0]["exe"] == "/usr/bin/ls"


@pytest.mark.asyncio
async def test_fetch_alerts_skips_malformed_lines(tmp_path: Path):
    """A garbage line (no msg=audit(...) header) must not abort the
    batch — it's silently dropped and surrounding events round-trip.
    """
    audit_log = tmp_path / "audit.log"
    body = _execve_block("1.0", "1") + "this line is not an audit record\n" + _execve_block("2.0", "2")
    _write_log(audit_log, body)
    conn = AuditdConnector(
        host_label="prod-web-01",
        audit_log_path=str(audit_log),
    )
    result = await conn.fetch_alerts()
    assert {e["external_id"] for e in result} == {"1.0:1", "2.0:2"}


@pytest.mark.asyncio
async def test_fetch_alerts_corrupt_cursor_starts_from_zero(tmp_path: Path):
    """A non-integer cursor file is treated as 0 (re-ingest) rather
    than wedging the connector.
    """
    audit_log = tmp_path / "audit.log"
    _write_log(audit_log, _execve_block("1.0", "1"))
    cursor = Path(f"{audit_log}.aisoc-cursor")
    cursor.write_text("not-an-integer")
    conn = AuditdConnector(
        host_label="prod-web-01",
        audit_log_path=str(audit_log),
    )
    result = await conn.fetch_alerts()
    assert len(result) == 1
    assert result[0]["external_id"] == "1.0:1"


@pytest.mark.asyncio
async def test_fetch_alerts_respects_custom_cursor_path(tmp_path: Path):
    """Cursor path override must be honoured and the cursor file must
    actually exist after the first poll.
    """
    audit_log = tmp_path / "audit.log"
    cursor = tmp_path / "cursors" / "audit.cursor"
    cursor.parent.mkdir(parents=True)
    _write_log(audit_log, _execve_block("1.0", "1"))
    conn = AuditdConnector(
        host_label="prod-web-01",
        audit_log_path=str(audit_log),
        cursor_path=str(cursor),
    )
    await conn.fetch_alerts()
    assert cursor.exists()
    assert int(cursor.read_text().strip()) > 0


@pytest.mark.asyncio
async def test_fetch_alerts_caps_read_size_per_poll(tmp_path: Path, monkeypatch):
    """A huge backlog must not be drained in a single poll — the cap
    ensures one busy host can't wedge the scheduler.
    """
    monkeypatch.setattr(
        "app.connectors.auditd._MAX_TAIL_BYTES_PER_POLL",
        300,  # tiny cap
    )
    # Sanity check the imported constant is the real one (not patched
    # in this module).
    assert _MAX_TAIL_BYTES_PER_POLL == 8 * 1024 * 1024
    audit_log = tmp_path / "audit.log"
    body = "".join(_execve_block("1.0", str(i)) for i in range(1, 6))
    _write_log(audit_log, body)
    conn = AuditdConnector(
        host_label="prod-web-01",
        audit_log_path=str(audit_log),
    )
    first = await conn.fetch_alerts()
    # Strict prefix — cap should kick in.
    assert 0 < len(first) < 5
    # Drain the rest across multiple polls.
    all_events = list(first)
    for _ in range(20):
        batch = await conn.fetch_alerts()
        if not batch:
            break
        all_events.extend(batch)
    assert {e["external_id"] for e in all_events} == {f"1.0:{i}" for i in range(1, 6)}


@pytest.mark.asyncio
async def test_fetch_alerts_caps_event_count_per_poll(tmp_path: Path, monkeypatch):
    """Event-storm protection: a runaway exec storm gets truncated."""
    monkeypatch.setattr(
        "app.connectors.auditd._MAX_EVENTS_PER_POLL",
        3,
    )
    # Sanity check the imported constant is unmodified at module level.
    assert _MAX_EVENTS_PER_POLL == 50_000
    audit_log = tmp_path / "audit.log"
    body = "".join(_execve_block("1.0", str(i)) for i in range(1, 11))
    _write_log(audit_log, body)
    conn = AuditdConnector(
        host_label="prod-web-01",
        audit_log_path=str(audit_log),
    )
    result = await conn.fetch_alerts()
    assert len(result) == 3


@pytest.mark.asyncio
async def test_fetch_alerts_ignores_since_seconds(tmp_path: Path):
    """``since_seconds`` is documented as a no-op (cursor handles
    exactly-once-ish semantics). Passing a value must not change behaviour.
    """
    audit_log = tmp_path / "audit.log"
    _write_log(audit_log, _execve_block("1.0", "1"))
    conn = AuditdConnector(
        host_label="prod-web-01",
        audit_log_path=str(audit_log),
    )
    a = await conn.fetch_alerts(since_seconds=60)
    assert len(a) == 1
    # Second call should still be empty regardless of since_seconds.
    b = await conn.fetch_alerts(since_seconds=99999)
    assert b == []


# ---------------------------------------------------------------------------
# Integration sanity check — end-to-end auditd_key pivot
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_end_to_end_aisoc_critical_event_surfaces_as_critical(tmp_path: Path):
    """A sudoers-write event using the AiSOC profile key must come
    out the other side as a critical-severity event with auditd_key set,
    so the new ``linux-auditd-sudoers-tampering`` detection rule can
    fire on it. In the 5-tier ladder, sudoers tamper is a P1 incident.
    """
    audit_log = tmp_path / "audit.log"
    body = (
        "type=SYSCALL msg=audit(1.0:1): arch=c000003e syscall=257 "
        'success=yes exit=0 uid=1000 auid=1000 comm="vi" '
        'exe="/usr/bin/vi" key="aisoc_critical_sudoers_write"\n'
        'type=PATH msg=audit(1.0:1): item=0 name="/etc/sudoers"\n'
    )
    _write_log(audit_log, body)
    conn = AuditdConnector(
        host_label="prod-web-01",
        audit_log_path=str(audit_log),
    )
    result = await conn.fetch_alerts()
    assert len(result) == 1
    event = result[0]
    assert event["severity"] == "critical"
    assert event["auditd_key"] == "aisoc_critical_sudoers_write"
    assert event["path"] == "/etc/sudoers"
    assert event["host"] == "prod-web-01"
    assert event["source"] == "auditd"
    assert event["category"] == "endpoint"


@pytest.mark.asyncio
async def test_end_to_end_module_load_event_surfaces_as_high(tmp_path: Path):
    """Kernel module load via syscall=175 (init_module) tagged with
    ``aisoc_priv_esc_module_load`` should come out as ``high`` so
    the ``linux-auditd-kernel-module-load`` rule catches it. Priv-esc
    primitives are high (analyst-eyes) rather than critical (P1).
    """
    audit_log = tmp_path / "audit.log"
    body = (
        "type=SYSCALL msg=audit(1.0:1): arch=c000003e syscall=175 "
        'success=yes exit=0 uid=0 auid=1000 comm="insmod" '
        'exe="/sbin/insmod" key="aisoc_priv_esc_module_load"\n'
    )
    _write_log(audit_log, body)
    conn = AuditdConnector(
        host_label="prod-web-01",
        audit_log_path=str(audit_log),
    )
    result = await conn.fetch_alerts()
    assert len(result) == 1
    event = result[0]
    assert event["severity"] == "high"
    assert event["syscall"] == "init_module"
    assert event["auditd_key"] == "aisoc_priv_esc_module_load"
    assert event["exe"] == "/sbin/insmod"
