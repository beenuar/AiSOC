"""Phase D1 — network/endpoint/NDR connector expansion tests.

Covers Netskope (SASE), Windows Event/Sysmon (WEF), Zeek/Suricata (NDR), and
the generic syslog/CEF listener — schema, registry, severity mapping, and the
CEF parser.
"""

from __future__ import annotations

import pytest
from app.connectors import CONNECTOR_REGISTRY
from app.connectors.netskope import NetskopeConnector
from app.connectors.syslog_cef import SyslogCefConnector, parse_cef
from app.connectors.windows_event import WindowsEventConnector
from app.connectors.zeek_suricata import ZeekSuricataConnector

# ── Netskope ──────────────────────────────────────────────────────────────────


def test_netskope_registered():
    assert CONNECTOR_REGISTRY["netskope"] is NetskopeConnector
    assert NetskopeConnector.schema().category == "network"


def test_netskope_malware_floored_to_high():
    c = NetskopeConnector(tenant_url="https://n", api_token="t")
    out = c.normalize({"alert_type": "malware", "severity": "low", "user": "alice", "srcip": "10.0.0.1"})
    assert out["severity"] == "high"  # malware floored up from low
    assert out["username"] == "alice"


def test_netskope_preserves_native_severity():
    c = NetskopeConnector(tenant_url="https://n", api_token="t")
    out = c.normalize({"alert_type": "anomaly", "severity": "critical"})
    assert out["severity"] == "critical"


# ── Windows Event / Sysmon ────────────────────────────────────────────────────


def test_windows_event_registered_edr():
    assert CONNECTOR_REGISTRY["windows_event"] is WindowsEventConnector
    assert WindowsEventConnector.schema().category == "edr"


def test_windows_log_clear_is_high():
    c = WindowsEventConnector(collector_url="https://w", api_token="t")
    out = c.normalize({"EventID": 1102, "Channel": "Security", "Computer": "DC01", "EventData": {}})
    assert out["severity"] == "high"
    assert out["hostname"] == "DC01"


def test_windows_sysmon_injection_is_high():
    c = WindowsEventConnector(collector_url="https://w", api_token="t")
    out = c.normalize({"EventID": 8, "Channel": "Microsoft-Windows-Sysmon/Operational", "EventData": {"Image": "evil.exe"}})
    assert out["severity"] == "high"
    assert out["process_name"] == "evil.exe"


def test_windows_unknown_event_is_info():
    c = WindowsEventConnector(collector_url="https://w", api_token="t")
    out = c.normalize({"EventID": 4624, "Channel": "Security", "EventData": {}})
    assert out["severity"] == "info"


# ── Zeek / Suricata NDR ───────────────────────────────────────────────────────


def test_zeek_suricata_registered_ndr():
    assert CONNECTOR_REGISTRY["zeek_suricata"] is ZeekSuricataConnector
    assert ZeekSuricataConnector.schema().category == "ndr"


def test_zeek_suricata_bad_engine_rejected():
    with pytest.raises(ValueError):
        ZeekSuricataConnector(engine="bogus", spool_url="https://s", api_token="t")


def test_suricata_priority_one_is_high():
    c = ZeekSuricataConnector(engine="suricata", spool_url="https://s", api_token="t")
    out = c.normalize({"flow_id": 1, "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2", "alert": {"severity": 1, "signature": "ET EXPLOIT"}})
    assert out["severity"] == "high"
    assert out["src_ip"] == "1.1.1.1"
    assert out["stream"] == "suricata"


def test_zeek_intel_notice_is_medium():
    c = ZeekSuricataConnector(engine="zeek", spool_url="https://s", api_token="t")
    out = c.normalize({"uid": "C1", "note": "Intel::Notice", "msg": "hit", "id.orig_h": "3.3.3.3"})
    assert out["severity"] == "medium"
    assert out["stream"] == "zeek"


# ── Generic syslog / CEF ──────────────────────────────────────────────────────


def test_syslog_cef_registered():
    assert CONNECTOR_REGISTRY["syslog_cef"] is SyslogCefConnector


def test_parse_cef_extracts_header_and_extension():
    line = "CEF:0|Fortinet|FortiGate|7.0|13|IPS Signature Matched|8|src=10.0.0.5 dst=8.8.8.8 suser=alice"
    parsed = parse_cef(line)
    assert parsed is not None
    assert parsed["device_vendor"] == "Fortinet"
    assert parsed["device_product"] == "FortiGate"
    assert parsed["name"] == "IPS Signature Matched"
    assert parsed["ext"]["src"] == "10.0.0.5"
    assert parsed["ext"]["suser"] == "alice"


def test_parse_cef_returns_none_for_plain_syslog():
    assert parse_cef("<134>Jul 12 08:00:00 host sshd[1]: accepted password for root") is None


def test_syslog_cef_severity_mapping():
    c = SyslogCefConnector(spool_url="https://s", api_token="t")
    out = c.normalize({"message": "CEF:0|V|P|1|1|Bad|9|src=1.2.3.4 dst=5.6.7.8"})
    assert out["severity"] == "critical"  # CEF sev 9 → critical
    assert out["src_ip"] == "1.2.3.4"


def test_syslog_cef_raw_line_is_info():
    c = SyslogCefConnector(spool_url="https://s", api_token="t")
    out = c.normalize({"message": "plain non-cef syslog line"})
    assert out["severity"] == "info"
    assert out["event_type"] == "syslog_cef.raw"
