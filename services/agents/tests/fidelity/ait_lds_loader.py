"""AIT-LDS loader → OCSF Web Resources Activity (class_uid 6002).

AIT-LDS (Austrian Institute of Technology Log Data Set) is a labelled,
multi-source security log corpus published by AIT GmbH. It ships as a
collection of host log directories, each containing Apache `access.log`,
`auth.log`, Suricata `eve.json`, OpenVPN logs, and audit/labels CSVs.
The corpus contains both benign daily activity and four
attack-scenario windows (`scenario-1` … `scenario-4`) covering
phishing → web-shell upload → lateral movement → privilege escalation.

Citation:
  Landauer, M., Skopik, F., Frank, M., Hotwagner, W., Wurzenberger, M.,
  & Rauber, A. (2023). Maintainable Log Datasets for Evaluation of
  Intrusion Detection Systems. IEEE TDSC.

For the AiSOC fidelity harness we focus on the **Apache access log**
surface because it is the most stable across releases and covers the
phishing-and-web-shell phase end-to-end. The companion `labels.csv`
ships side-by-side with each `access.log` and uses a one-line-per-event
schema:

    timestamp,line_no,label

…where `label` is one of `normal`, `recon`, `web_attack`, `webshell`,
`exfil`, or an attack-specific tag like `scenario-1.phishing.callback`.
We collapse those into the harness's canonical four-tier ladder:

  * `benign`  — `normal`
  * `recon`   — `recon`, `scan`
  * `web_attack` — `web_attack`, `xss`, `sqli`, `webshell.*`,
                   `scenario-*.*.web*`
  * `lateral` — `exfil`, `c2`, `scenario-*.*.callback`, `scenario-*.*.lateral`

The loader is stdlib-only so CI can run it against the committed
micro fixture without adding a runtime dependency. When the full corpus
is downloaded, the same code path runs against it; the micro fixture
mirrors the full file format byte-for-byte (10 lines + 10 labels).
"""

from __future__ import annotations

import csv
import logging
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Canonical label families used in the AIT loader. The benchmark runner
# uses the same families across all datasets so confusion matrices are
# comparable. The mapping below collapses AIT's verbose tags into the
# four canonical families.
_LABEL_ALIASES: dict[str, str] = {
    "normal": "benign",
    "benign": "benign",
    "ok": "benign",
    "recon": "recon",
    "scan": "recon",
    "portscan": "recon",
    "dirbust": "recon",
    "web_attack": "web_attack",
    "webattack": "web_attack",
    "xss": "web_attack",
    "sqli": "web_attack",
    "sql_injection": "web_attack",
    "rce": "web_attack",
    "exfil": "lateral",
    "exfiltration": "lateral",
    "c2": "lateral",
    "callback": "lateral",
    "lateral": "lateral",
    "privesc": "lateral",
}

# Substring rules applied when a tag does not appear in _LABEL_ALIASES.
# AIT-LDS encodes scenario phases as dotted tags such as
# ``scenario-2.foothold.webshell``; we map by the *terminal* phase.
_LABEL_SUBSTRING_RULES: tuple[tuple[str, str], ...] = (
    ("webshell", "web_attack"),
    ("phishing", "lateral"),
    ("callback", "lateral"),
    ("exfil", "lateral"),
    ("lateral", "lateral"),
    ("recon", "recon"),
    ("scan", "recon"),
    ("web", "web_attack"),
)

# Apache combined-log-format regex. The AIT corpus uses the standard
# combined format (CLF + Referer + User-Agent + optional %D microseconds).
_APACHE_CLF_RE = re.compile(
    r"^(?P<host>\S+)\s+\S+\s+(?P<user>\S+)\s+"
    r"\[(?P<time>[^\]]+)\]\s+"
    r'"(?P<request>[^"]*)"\s+'
    r"(?P<status>\d{3})\s+(?P<size>\S+)"
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
    r"(?:\s+(?P<duration_us>\d+))?\s*$"
)


def _normalise_label(raw: str) -> str:
    """Collapse a raw AIT-LDS label into one of the canonical families.

    Unknown labels degrade to ``benign`` with a single warning per
    label so a future AIT-LDS revision (or operator-authored tag) does
    not silently corrupt the score.
    """

    key = (raw or "").strip().lower()
    if not key:
        return "benign"
    family = _LABEL_ALIASES.get(key)
    if family is not None:
        return family
    for token, fam in _LABEL_SUBSTRING_RULES:
        if token in key:
            return fam
    logger.warning("ait_lds: unrecognised label %r; treating as benign", raw)
    return "benign"


def _parse_apache_time(raw: str) -> str:
    """Apache CLF time → RFC3339 UTC. Returns the input unchanged on
    parse failure so the runner does not bail on a malformed minority."""

    text = (raw or "").strip()
    if not text:
        return datetime.now(UTC).isoformat()
    # Apache CLF: "08/Jul/2024:13:45:01 +0000"
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S"):
        try:
            parsed = datetime.strptime(text, fmt)
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC).isoformat()
    return text


def _split_request(request: str) -> tuple[str, str, str]:
    """Split a "METHOD path proto" request-line. Returns ("", "", "")
    on a malformed line — Apache occasionally logs partial requests
    (`-` for the whole field) and we don't want a `IndexError` to
    poison the score."""

    parts = (request or "").split()
    if len(parts) >= 3:
        return parts[0], parts[1], parts[2]
    if len(parts) == 2:
        return parts[0], parts[1], ""
    if len(parts) == 1:
        return parts[0], "", ""
    return "", "", ""


def _coerce_int(value: str) -> int:
    text = (value or "").strip()
    if not text or text == "-":
        return 0
    try:
        return int(text)
    except ValueError:
        return 0


def _parse_access_line(line: str) -> dict[str, Any] | None:
    """Parse a single Apache CLF line. Returns ``None`` on a no-match
    (the caller drops it from the harness stream)."""

    m = _APACHE_CLF_RE.match(line.rstrip("\n"))
    if not m:
        return None
    method, path, _proto = _split_request(m.group("request"))
    return {
        "timestamp": _parse_apache_time(m.group("time")),
        "host_ip": m.group("host"),
        "user": m.group("user") if m.group("user") != "-" else "",
        "method": method,
        "path": path,
        "status": _coerce_int(m.group("status")),
        "size": _coerce_int(m.group("size")),
        "referer": (m.group("referer") or "") if m.group("referer") and m.group("referer") != "-" else "",
        "user_agent": (m.group("ua") or "") if m.group("ua") and m.group("ua") != "-" else "",
        "duration_us": _coerce_int(m.group("duration_us") or "0"),
    }


def _load_labels(label_path: Path) -> dict[int, str]:
    """Read the labels.csv side-file and return ``{line_no: family}``.

    The AIT labels file is a 3-column CSV with header
    ``timestamp,line_no,label``. ``line_no`` is 1-indexed and matches
    the line number of the corresponding entry in ``access.log``.
    """

    out: dict[int, str] = {}
    if not label_path.exists():
        return out
    with label_path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            try:
                line_no = int((row.get("line_no") or "").strip())
            except ValueError:
                continue
            label = _normalise_label(row.get("label") or "")
            out[line_no] = label
    return out


def to_ocsf(row: dict[str, Any]) -> dict[str, Any]:
    """Convert a normalised AIT row into an OCSF Web Resources Activity
    event (class_uid 6002).

    The Web Resources Activity class is the natural OCSF home for an
    Apache access-log line. The fields the substrate classifier needs
    (`method`, `path`, `status`, `size`, `user_agent`, the canonical
    `label`) all live under the ``unmapped`` extension namespace so an
    OCSF-strict consumer can ignore them.
    """

    method = row.get("method", "") or "GET"
    return {
        "category_uid": 6,
        "category_name": "Application Activity",
        "class_uid": 6002,
        "class_name": "Web Resources Activity",
        "type_uid": 600201,
        "activity_id": 1,
        "activity_name": "Access",
        "severity_id": 1,
        "severity": "Informational",
        "time": row.get("timestamp", ""),
        "metadata": {
            "version": "1.1.0",
            "product": {
                "name": "AIT-LDS",
                "vendor_name": "Austrian Institute of Technology",
            },
            "log_name": "apache.access",
        },
        "src_endpoint": {
            "ip": row.get("host_ip", ""),
        },
        "http_request": {
            "http_method": method,
            "url": {
                "path": row.get("path", ""),
            },
            "user_agent": row.get("user_agent", ""),
            "referrer": row.get("referer", ""),
        },
        "http_response": {
            "code": int(row.get("status", 0)),
            "length": int(row.get("size", 0)),
        },
        "unmapped": {
            "user": row.get("user", ""),
            "duration_us": int(row.get("duration_us", 0)),
            "label": row.get("label", "benign"),
        },
    }


def iter_flows(path: Path | str, *, limit: int | None = None) -> Iterator[dict[str, Any]]:
    """Stream an AIT-LDS Apache access log as normalised harness rows.

    Looks for a sibling ``labels.csv`` in the same directory; if
    present, each row carries the matching canonical family on the
    ``label`` key. If the labels file is missing, every row is
    labelled ``benign`` (the dataset authors document this as the
    expected behaviour for the benign-day captures).

    Lines that fail to parse as Apache CLF are silently dropped — the
    AIT corpus contains a small number of partial-write lines at log
    rotation boundaries and the harness should not stop scoring on
    them.
    """

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"AIT-LDS access log not found: {p}")
    labels = _load_labels(p.parent / "labels.csv")

    count = 0
    with p.open("r", encoding="utf-8", errors="replace") as fh:
        for line_no, line in enumerate(fh, start=1):
            row = _parse_access_line(line)
            if row is None:
                continue
            row["label"] = labels.get(line_no, "benign")
            row["line_no"] = line_no
            yield row
            count += 1
            if limit is not None and count >= limit:
                break
