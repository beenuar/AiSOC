"""
Synthetic Telemetry Schema & Coverage Gate
==========================================
Schema and coverage gate for `eval_data/synthetic_telemetry.jsonl`.

Each line is one event from a real-world log source (Sysmon, M365 audit,
CloudTrail, Azure AD sign-in, EDR, auditd, journald, DNS, web access,
Kubernetes, GitHub audit, VPN, DB audit) annotated with the
`incident_id` and `template_id` of the synthetic incident it backs.

This file is consumed by:

  * Connector PRs — to validate field coverage end-to-end against a
    realistic event payload without standing up a live tenant.
  * Sigma / detection-rule PRs — so authors have a fixed corpus to
    pattern-match against.
  * The OCSF mapper — to spot field drift before it reaches a customer.

What we gate here:

  1. Every event is well-formed JSON with at minimum an `incident_id`,
     `template_id`, `event_index`, and `source`.
  2. Every incident in `synthetic_incidents.json` has at least one
     backing telemetry event.
  3. The set of telemetry sources covers the connector matrix promised
     by the README (M365, CloudTrail, Sysmon, Azure AD, EDR, auditd,
     web/DNS, k8s, GitHub).
  4. Source-specific required fields are present (e.g. Sysmon must have
     `EventID` and `Computer`; CloudTrail must have `eventName` and
     `userIdentity`; M365 must have `Workload` and `Operation`; etc.).
  5. Placeholders have been resolved — no event still contains
     unresolved `{user}` / `{host}` / `{ip}` / `{campaign}` strings.

See `apps/docs/docs/benchmark.md` for what each suite measures.

Run:
    pytest services/agents/tests/test_synthetic_telemetry.py -v
"""

from __future__ import annotations

import json
import re
import unittest
from collections import Counter
from pathlib import Path
from typing import Any

_TESTS_DIR = Path(__file__).parent
_INCIDENTS_PATH = _TESTS_DIR / "eval_data" / "synthetic_incidents.json"
_TELEMETRY_PATH = _TESTS_DIR / "eval_data" / "synthetic_telemetry.jsonl"


def _load_incidents() -> list[dict[str, Any]]:
    if not _INCIDENTS_PATH.exists():
        raise FileNotFoundError(
            f"Missing {_INCIDENTS_PATH}. Run `python3 scripts/generate_eval_incidents.py`."
        )
    with _INCIDENTS_PATH.open() as f:
        return json.load(f)


def _load_telemetry() -> list[dict[str, Any]]:
    if not _TELEMETRY_PATH.exists():
        raise FileNotFoundError(
            f"Missing {_TELEMETRY_PATH}. Run `python3 scripts/generate_eval_incidents.py`."
        )
    events: list[dict[str, Any]] = []
    with _TELEMETRY_PATH.open() as f:
        for i, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:  # pragma: no cover
                raise AssertionError(
                    f"{_TELEMETRY_PATH.name}: line {i} is not valid JSON ({exc})"
                ) from exc
    return events


INCIDENTS: list[dict[str, Any]] = _load_incidents()
TELEMETRY: list[dict[str, Any]] = _load_telemetry()


# ---------------------------------------------------------------------------
# Source matrix the README / docs promise.
# ---------------------------------------------------------------------------

# Sources we expect to see at least once across the corpus.
EXPECTED_SOURCES: set[str] = {
    "sysmon",
    "windows_security",
    "m365_audit",
    "azure_signin",
    "cloudtrail",
    "linux_auditd",
    "linux_journald",
    "edr",
    "dns",
    "web_access",
    "k8s_audit",
    "github_audit",
    "vpn",
    "db_audit",
}

# Per-source required fields.  These are the fields a connector PR or a
# Sigma-style detection would actually pivot on, so we keep the bar
# tight enough that field drift breaks the build.
REQUIRED_FIELDS_BY_SOURCE: dict[str, set[str]] = {
    "sysmon": {"channel", "Provider", "EventID", "Computer"},
    "windows_security": {"channel", "Provider", "EventID"},
    "m365_audit": {"Workload", "Operation"},
    "azure_signin": {"category", "userPrincipalName", "resultType"},
    "cloudtrail": {"eventName", "userIdentity", "awsRegion"},
    "linux_auditd": {"type", "syscall"},
    "linux_journald": {"_SYSTEMD_UNIT", "MESSAGE"},
    "edr": {"rule", "severity"},
    "dns": {"query_name", "query_type"},
    "web_access": {"http_method", "url", "status_code"},
    "k8s_audit": {"verb", "objectRef"},
    "github_audit": {"action", "actor"},
    "vpn": {"action", "user"},
    "db_audit": {"user", "operation"},
}

# Anything that looks like an unresolved Python-style placeholder.
_PLACEHOLDER_RE = re.compile(r"\{(user|host|ip|campaign)\b[^}]*\}")


def _walk_strings(obj: Any) -> list[str]:
    """Yield every string value in a nested dict/list (used for placeholder scan)."""
    out: list[str] = []
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            out.extend(_walk_strings(v))
    elif isinstance(obj, list):
        for v in obj:
            out.extend(_walk_strings(v))
    return out


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestSyntheticTelemetrySchema(unittest.TestCase):
    """Schema, coverage, and field-level invariants for synthetic_telemetry.jsonl."""

    def test_jsonl_is_non_empty(self) -> None:
        self.assertGreater(
            len(TELEMETRY),
            0,
            f"{_TELEMETRY_PATH.name} is empty — generator did not emit telemetry.",
        )

    def test_every_event_has_required_envelope(self) -> None:
        """Every line must carry incident_id, template_id, event_index, and source."""
        required = {"incident_id", "template_id", "event_index", "source"}
        bad: list[tuple[int, set[str]]] = []
        for i, event in enumerate(TELEMETRY):
            missing = required - event.keys()
            if missing:
                bad.append((i, missing))
        self.assertEqual(
            bad,
            [],
            f"{len(bad)} events missing envelope fields (sample: {bad[:3]}).",
        )

    def test_event_index_is_zero_based_per_incident(self) -> None:
        """event_index restarts at 0 per incident and is contiguous."""
        by_incident: dict[str, list[int]] = {}
        for event in TELEMETRY:
            by_incident.setdefault(event["incident_id"], []).append(event["event_index"])
        bad: list[tuple[str, list[int]]] = []
        for incident_id, indexes in by_incident.items():
            indexes_sorted = sorted(indexes)
            expected = list(range(len(indexes_sorted)))
            if indexes_sorted != expected:
                bad.append((incident_id, indexes_sorted))
        self.assertEqual(
            bad,
            [],
            f"Non-contiguous event_index for {len(bad)} incidents (sample: {bad[:3]}).",
        )

    def test_every_incident_has_telemetry(self) -> None:
        """Every synthetic incident must have at least one backing event.

        This is what makes the dataset valuable to connector / Sigma
        PRs — if an incident has no telemetry, there is nothing for a
        detection rule to fire on.
        """
        with_telemetry = {event["incident_id"] for event in TELEMETRY}
        all_ids = {inc["id"] for inc in INCIDENTS}
        missing = sorted(all_ids - with_telemetry)
        self.assertEqual(
            missing,
            [],
            f"{len(missing)} incidents have no backing telemetry (sample: {missing[:5]}).",
        )

    def test_source_matrix_covers_promised_connectors(self) -> None:
        """The source set must cover every connector advertised in docs."""
        seen = {event["source"] for event in TELEMETRY}
        missing = sorted(EXPECTED_SOURCES - seen)
        self.assertEqual(
            missing,
            [],
            "synthetic_telemetry.jsonl is missing events for the following "
            f"advertised sources: {missing}",
        )

    def test_per_source_required_fields(self) -> None:
        """Each event must carry the fields a real connector pivots on."""
        bad: list[tuple[str, str, set[str]]] = []  # (source, incident_id, missing)
        for event in TELEMETRY:
            source = event["source"]
            required = REQUIRED_FIELDS_BY_SOURCE.get(source)
            if required is None:
                # Unknown source; surface it explicitly so we don't silently drop coverage.
                bad.append((source, event.get("incident_id", "?"), {"<unknown source>"}))
                continue
            missing = required - event.keys()
            if missing:
                bad.append((source, event.get("incident_id", "?"), missing))
        self.assertEqual(
            bad,
            [],
            f"{len(bad)} events missing per-source required fields "
            f"(sample: {bad[:3]}). See REQUIRED_FIELDS_BY_SOURCE.",
        )

    def test_no_unresolved_placeholders(self) -> None:
        """The recursive resolver must have substituted all `{user}/{host}/{ip}/{campaign}`."""
        bad: list[tuple[str, int, str]] = []
        for event in TELEMETRY:
            for s in _walk_strings(event):
                m = _PLACEHOLDER_RE.search(s)
                if m:
                    bad.append((event["incident_id"], event["event_index"], s))
                    break
        self.assertEqual(
            bad,
            [],
            f"{len(bad)} events still contain unresolved placeholders "
            f"(sample: {bad[:3]}).",
        )

    def test_template_telemetry_is_not_concentrated(self) -> None:
        """No single template should monopolize the corpus.

        With ~55 templates each cycled ~3-4×, the most-frequent template
        should account for ≤ 5% of events. Anything higher means the
        dataset has skewed and per-template metrics are misleading.
        """
        counts = Counter(event["template_id"] for event in TELEMETRY)
        total = sum(counts.values())
        top_template, top_count = counts.most_common(1)[0]
        share = top_count / total if total else 0.0
        self.assertLessEqual(
            share,
            0.05,
            f"Template '{top_template}' accounts for {share:.1%} of telemetry — "
            "dataset has skewed; rebalance the templates.",
        )

    def test_telemetry_template_ids_match_incident_template_ids(self) -> None:
        """Every (incident_id, template_id) pair must agree with synthetic_incidents.json."""
        incident_template_by_id = {inc["id"]: inc.get("template_id") for inc in INCIDENTS}
        bad: list[tuple[str, str, str]] = []
        for event in TELEMETRY:
            inc_id = event["incident_id"]
            expected = incident_template_by_id.get(inc_id)
            actual = event["template_id"]
            if expected is None:
                bad.append((inc_id, "<missing-incident>", actual))
            elif expected != actual:
                bad.append((inc_id, expected, actual))
        self.assertEqual(
            bad,
            [],
            f"{len(bad)} events disagree with the incident dataset on template_id "
            f"(sample: {bad[:3]}).",
        )


if __name__ == "__main__":
    counts = Counter(event["source"] for event in TELEMETRY)
    template_counts = Counter(event["template_id"] for event in TELEMETRY)
    print(
        json.dumps(
            {
                "events": len(TELEMETRY),
                "incidents_with_telemetry": len({e["incident_id"] for e in TELEMETRY}),
                "source_counts": dict(counts.most_common()),
                "template_count": len(template_counts),
                "top_templates": template_counts.most_common(5),
            },
            indent=2,
        )
    )
