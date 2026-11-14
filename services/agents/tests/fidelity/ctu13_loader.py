"""CTU-13 loader → OCSF Network Activity (class_uid 4001).

CTU-13 is the Stratosphere Lab botnet capture corpus published by the
Czech Technical University. It ships as 13 ``.binetflow`` Argus-format
files (capture-1.binetflow, …, capture-13.binetflow), one per
botnet-infected scenario, plus a Background label for unrelated
traffic.

Citation:
  Garcia, S., Grill, M., Stiborek, J., & Zunino, A. (2014). An
  empirical comparison of botnet detection methods. Computers &
  Security, 45, 100-123.

Each scenario typically contains a few thousand to a few million
flows with three top-level label families: ``Background``, ``Normal``
and ``Botnet`` (the latter further specialised, e.g. ``Botnet-V47``).
Per the CTU-13 evaluation protocol, ``Background`` flows are excluded
from scoring because they were not curated.
"""

from __future__ import annotations

import csv
import ipaddress
import logging
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Argus protocol → IANA protocol number, for the small subset CTU-13
# captures use. Anything outside this map gets a 0 to keep the OCSF
# event well-formed; the substrate classifier does not key off
# protocol number for CTU-13.
_PROTO_TO_NUM: dict[str, int] = {
    "tcp": 6,
    "udp": 17,
    "icmp": 1,
    "icmp6": 58,
    "ipv6-icmp": 58,
    "igmp": 2,
    "arp": 0,
    "rtp": 0,
    "rarp": 0,
    "pim": 103,
}


def _normalise_label(raw: str) -> str:
    """Collapse a raw CTU-13 label into one of three families.

    Returns ``background``, ``benign`` or ``bot``. ``background`` is a
    sentinel — the runner skips it during scoring per the dataset
    authors' protocol.
    """

    text = (raw or "").strip().lower()
    if not text:
        return "background"
    if "background" in text:
        return "background"
    if "botnet" in text or text.startswith("malware") or "bot" == text:
        return "bot"
    if text.startswith("normal") or text == "legitimate":
        return "benign"
    logger.warning("ctu13: unrecognised label %r; treating as background", raw)
    return "background"


def _coerce_int(value: str) -> int:
    text = (value or "").strip()
    if not text or text.lower() == "nan":
        return 0
    try:
        return int(float(text))
    except ValueError:
        return 0


def _coerce_float(value: str) -> float:
    text = (value or "").strip()
    if not text or text.lower() == "nan":
        return 0.0
    try:
        return float(text)
    except ValueError:
        return 0.0


def _coerce_ip(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return ""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text


def _parse_timestamp(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return datetime.now(UTC).isoformat()
    for fmt in (
        "%Y/%m/%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
    ):
        try:
            parsed = datetime.strptime(text, fmt)
        except ValueError:
            continue
        return parsed.replace(tzinfo=UTC).isoformat()
    return text


def _proto_num(value: str) -> int:
    return _PROTO_TO_NUM.get((value or "").strip().lower(), 0)


def _coerce_port(value: str) -> int:
    text = (value or "").strip()
    if not text:
        return 0
    if text.startswith("0x") or text.startswith("0X"):
        try:
            return int(text, 16)
        except ValueError:
            return 0
    return _coerce_int(text)


def _normalise_row(row: dict[str, str]) -> dict[str, Any]:
    """Lower-case a CTU-13 binetflow row and coerce numerics."""

    src_bytes = _coerce_int(row.get("SrcBytes", "0"))
    tot_bytes = _coerce_int(row.get("TotBytes", "0"))
    dst_bytes = max(tot_bytes - src_bytes, 0)
    return {
        "timestamp": _parse_timestamp(row.get("StartTime", "")),
        "duration_sec": _coerce_float(row.get("Dur", "0")),
        "protocol": _proto_num(row.get("Proto", "")),
        "protocol_name": (row.get("Proto", "") or "").strip().lower(),
        "src_ip": _coerce_ip(row.get("SrcAddr", "")),
        "src_port": _coerce_port(row.get("Sport", "")),
        "direction": (row.get("Dir", "") or "").strip(),
        "dst_ip": _coerce_ip(row.get("DstAddr", "")),
        "dst_port": _coerce_port(row.get("Dport", "")),
        "state": (row.get("State", "") or "").strip(),
        "tot_packets": _coerce_int(row.get("TotPkts", "0")),
        "tot_bytes": tot_bytes,
        "src_bytes": src_bytes,
        "dst_bytes": dst_bytes,
        "label": _normalise_label(row.get("Label", "")),
    }


def to_ocsf(row: dict[str, Any]) -> dict[str, Any]:
    """Convert a normalised CTU-13 row into an OCSF Network Activity event."""

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
                "name": "CTU-13",
                "vendor_name": "Stratosphere Lab, Czech Technical University",
            },
            "log_name": "Argus binetflow",
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
            "protocol_name": row.get("protocol_name", ""),
            "direction": "Outbound",
            "direction_id": 2,
        },
        "traffic": {
            "bytes": int(row.get("tot_bytes", 0)),
            "bytes_in": int(row.get("dst_bytes", 0)),
            "bytes_out": int(row.get("src_bytes", 0)),
            "packets": int(row.get("tot_packets", 0)),
        },
        "unmapped": {
            "duration_sec": row.get("duration_sec", 0.0),
            "state": row.get("state", ""),
            "direction": row.get("direction", ""),
            "label": row.get("label", "background"),
        },
    }


def iter_flows(path: Path | str, *, limit: int | None = None) -> Iterator[dict[str, Any]]:
    """Stream a CTU-13 ``.binetflow`` file as normalised harness rows."""

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"CTU-13 binetflow not found: {p}")
    count = 0
    with p.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            yield _normalise_row(row)
            count += 1
            if limit is not None and count >= limit:
                break
