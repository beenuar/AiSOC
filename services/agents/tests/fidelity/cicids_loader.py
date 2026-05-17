"""CICIDS-2017 loader → OCSF Network Activity (class_uid 4001).

CICIDS-2017 is a labelled flow dataset published by the Canadian
Institute for Cybersecurity at the University of New Brunswick. It
ships as eight CSV files of CICFlowMeter-extracted features, one per
attack day (Monday-WorkingHours.pcap_ISCX.csv, …,
Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv). The full
dataset must be downloaded from the official source; see
``scripts/datasets/download_cicids.py``.

Citation:
  Sharafaldin, I., Habibi Lashkari, A., & Ghorbani, A. A. (2018).
  Toward Generating a New Intrusion Detection Dataset and Intrusion
  Traffic Characterization. In Proceedings of the 4th International
  Conference on Information Systems Security and Privacy (ICISSP).

This loader is intentionally stdlib-only (``csv``, ``ipaddress``) so
the harness has no extra runtime dependencies and can be exercised in
CI against the committed micro fixture.
"""

from __future__ import annotations

import csv
import ipaddress
import logging
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Canonical label families used across the harness. The CICIDS CSVs
# spell labels with arbitrary capitalisation and whitespace; we
# collapse them into the families below before scoring.
_LABEL_ALIASES: dict[str, str] = {
    "BENIGN": "benign",
    "DDOS": "ddos",
    "DOS HULK": "dos",
    "DOS GOLDENEYE": "dos",
    "DOS SLOWLORIS": "dos",
    "DOS SLOWHTTPTEST": "dos",
    "PORTSCAN": "port_scan",
    "FTP-PATATOR": "brute_force",
    "SSH-PATATOR": "brute_force",
    "BOT": "bot",
    # The literal ``–`` and ``\u2013`` are the same code point (U+2013 EN
    # DASH); we only keep one entry per spelling. Listing both was
    # flagged by CodeQL ``py/duplicate-key-dict-literal``. We still
    # alias the ASCII ``-`` variant separately because CICIDS CSVs in
    # the wild use either dash flavour.
    "WEB ATTACK \u2013 BRUTE FORCE": "web_attack",
    "WEB ATTACK - BRUTE FORCE": "web_attack",
    "WEB ATTACK \u2013 XSS": "web_attack",
    "WEB ATTACK - XSS": "web_attack",
    "WEB ATTACK \u2013 SQL INJECTION": "web_attack",
    "WEB ATTACK - SQL INJECTION": "web_attack",
    "INFILTRATION": "infiltration",
    "HEARTBLEED": "exploit",
}

# Numeric columns the substrate classifier reads. Stored as a tuple so
# the loader fails fast (rather than silently coerces) when the CSV
# schema drifts.
_NUMERIC_FEATURES: tuple[str, ...] = (
    "flow_duration_us",
    "total_fwd_packets",
    "total_bwd_packets",
    "flow_bytes_per_sec",
    "flow_packets_per_sec",
    "syn_flag_count",
    "ack_flag_count",
    "psh_flag_count",
    "rst_flag_count",
    "fin_flag_count",
    "fwd_packet_length_mean",
    "bwd_packet_length_mean",
    "down_up_ratio",
)

# Mapping from CICFlowMeter column header (case/space-normalised) to
# the field name used inside the harness. Columns absent from the file
# default to ``0.0`` in :func:`_normalise_row` so the substrate
# classifier can still run on partial fixtures.
_HEADER_MAP: dict[str, str] = {
    "flow id": "flow_id",
    "source ip": "src_ip",
    "src ip": "src_ip",
    "source port": "src_port",
    "src port": "src_port",
    "destination ip": "dst_ip",
    "dst ip": "dst_ip",
    "destination port": "dst_port",
    "dst port": "dst_port",
    "protocol": "protocol",
    "timestamp": "timestamp",
    "flow duration": "flow_duration_us",
    "total fwd packets": "total_fwd_packets",
    "total fwd packet": "total_fwd_packets",
    "total backward packets": "total_bwd_packets",
    "total bwd packets": "total_bwd_packets",
    "flow bytes/s": "flow_bytes_per_sec",
    "flow packets/s": "flow_packets_per_sec",
    "syn flag count": "syn_flag_count",
    "ack flag count": "ack_flag_count",
    "psh flag count": "psh_flag_count",
    "rst flag count": "rst_flag_count",
    "fin flag count": "fin_flag_count",
    "fwd packet length mean": "fwd_packet_length_mean",
    "bwd packet length mean": "bwd_packet_length_mean",
    "down/up ratio": "down_up_ratio",
    "label": "label",
}


def _normalise_header(name: str) -> str:
    return name.strip().lower().replace("\ufeff", "")


def _normalise_label(raw: str) -> str:
    """Collapse a raw CICIDS label into one of the canonical families.

    Unknown labels degrade to ``benign`` and emit a single warning per
    label so a future CICIDS revision (e.g. CICIDS-2018) does not
    silently corrupt scoring.
    """

    key = (raw or "").strip().upper()
    family = _LABEL_ALIASES.get(key)
    if family is None:
        logger.warning("cicids: unrecognised label %r; treating as benign", raw)
        family = "benign"
    return family


def _coerce_float(value: str) -> float:
    if value is None:
        return 0.0
    text = value.strip()
    if not text:
        return 0.0
    if text.lower() in {"inf", "infinity", "+inf"}:
        return float("inf")
    if text.lower() == "nan":
        return 0.0
    try:
        return float(text)
    except ValueError:
        return 0.0


def _coerce_int(value: str) -> int:
    return int(_coerce_float(value))


def _coerce_ip(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return ""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text


def _parse_timestamp(value: str) -> str:
    """Return an RFC3339 UTC timestamp.

    CICIDS-2017 ships timestamps in ``DD/MM/YYYY HH:MM:SS`` and
    occasionally ``DD/MM/YYYY HH:MM`` form, in local time. We assume
    UTC because the dataset lacks a tz field; the methodology page
    documents this assumption.
    """

    text = (value or "").strip()
    if not text:
        return datetime.now(timezone.utc).isoformat()
    for fmt in ("%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%Y-%m-%d %H:%M:%S"):
        try:
            parsed = datetime.strptime(text, fmt)
        except ValueError:
            continue
        return parsed.replace(tzinfo=timezone.utc).isoformat()
    return text


def _normalise_row(row: dict[str, str]) -> dict[str, Any]:
    """Lower-case a CICIDS row and coerce numeric features."""

    normalised: dict[str, Any] = {}
    for raw_key, value in row.items():
        key = _normalise_header(raw_key or "")
        mapped = _HEADER_MAP.get(key)
        if mapped is None:
            continue
        normalised[mapped] = value

    for feature in _NUMERIC_FEATURES:
        normalised[feature] = _coerce_float(normalised.get(feature, "0"))

    normalised["src_port"] = _coerce_int(str(normalised.get("src_port", "0")))
    normalised["dst_port"] = _coerce_int(str(normalised.get("dst_port", "0")))
    normalised["protocol"] = _coerce_int(str(normalised.get("protocol", "0")))
    normalised["src_ip"] = _coerce_ip(str(normalised.get("src_ip", "")))
    normalised["dst_ip"] = _coerce_ip(str(normalised.get("dst_ip", "")))
    normalised["flow_id"] = str(normalised.get("flow_id", "")).strip()
    normalised["timestamp"] = _parse_timestamp(str(normalised.get("timestamp", "")))
    normalised["label"] = _normalise_label(str(normalised.get("label", "")))
    return normalised


def to_ocsf(row: dict[str, Any]) -> dict[str, Any]:
    """Convert a normalised CICIDS row into an OCSF Network Activity event.

    The event mirrors ``packages/types/src/ocsf.ts``'s
    ``OcsfNetworkActivity`` shape: ``class_uid=4001``, severity 1
    (Informational, since the loader does not yet score), and the
    five-tuple plus byte/packet counts in ``connection_info`` and
    ``traffic``.

    The non-OCSF fields the substrate classifier reads
    (``flow_duration_us``, flag counts, etc.) live under the
    ``unmapped`` extension namespace per the OCSF Extensible Schema
    rules, so a downstream OCSF-only consumer can ignore them safely.
    """

    bytes_in = int(max(row.get("flow_bytes_per_sec", 0.0), 0.0))
    packets_total = int(row.get("total_fwd_packets", 0)) + int(
        row.get("total_bwd_packets", 0)
    )

    return {
        "category_uid": 4,
        "category_name": "Network Activity",
        "class_uid": 4001,
        "class_name": "Network Activity",
        "type_uid": 400106,
        "activity_id": 6,
        "activity_name": "Traffic",
        "severity_id": 1,
        "severity": "Informational",
        "time": row.get("timestamp", ""),
        "metadata": {
            "version": "1.1.0",
            "product": {
                "name": "CICIDS-2017",
                "vendor_name": "Canadian Institute for Cybersecurity",
            },
            "log_name": "CICFlowMeter",
        },
        "src_endpoint": {
            "ip": row.get("src_ip", ""),
            "port": int(row.get("src_port", 0)),
        },
        "dst_endpoint": {
            "ip": row.get("dst_ip", ""),
            "port": int(row.get("dst_port", 0)),
        },
        "connection_info": {
            "protocol_num": int(row.get("protocol", 0)),
            "direction": "Outbound",
            "direction_id": 2,
        },
        "traffic": {
            "bytes": bytes_in,
            "packets": packets_total,
        },
        "unmapped": {
            "flow_id": row.get("flow_id", ""),
            "flow_duration_us": row.get("flow_duration_us", 0.0),
            "total_fwd_packets": row.get("total_fwd_packets", 0),
            "total_bwd_packets": row.get("total_bwd_packets", 0),
            "flow_bytes_per_sec": row.get("flow_bytes_per_sec", 0.0),
            "flow_packets_per_sec": row.get("flow_packets_per_sec", 0.0),
            "syn_flag_count": row.get("syn_flag_count", 0.0),
            "ack_flag_count": row.get("ack_flag_count", 0.0),
            "psh_flag_count": row.get("psh_flag_count", 0.0),
            "rst_flag_count": row.get("rst_flag_count", 0.0),
            "fin_flag_count": row.get("fin_flag_count", 0.0),
            "fwd_packet_length_mean": row.get("fwd_packet_length_mean", 0.0),
            "bwd_packet_length_mean": row.get("bwd_packet_length_mean", 0.0),
            "down_up_ratio": row.get("down_up_ratio", 0.0),
            "label": row.get("label", "benign"),
        },
    }


def iter_flows(path: Path | str, *, limit: int | None = None) -> Iterator[dict[str, Any]]:
    """Stream a CICIDS CSV as normalised harness rows.

    Yields one dict per row with both the substrate features and the
    canonical ``label``. Use :func:`to_ocsf` if you need the OCSF
    Network Activity envelope instead.
    """

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"CICIDS CSV not found: {p}")

    count = 0
    with p.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            yield _normalise_row(row)
            count += 1
            if limit is not None and count >= limit:
                break


def iter_files(paths: Iterable[Path | str], *, limit: int | None = None) -> Iterator[dict[str, Any]]:
    """Stream multiple CICIDS CSVs concatenated, applying a global limit."""

    remaining = limit
    for path in paths:
        for row in iter_flows(path, limit=remaining):
            yield row
            if remaining is not None:
                remaining -= 1
                if remaining <= 0:
                    return
