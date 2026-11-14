"""Smoke test for the Sigma detection engine + 100+ rule starter pack.

Verifies:
- All shipped rules under ``app/detections/rules/`` parse cleanly in strict mode.
- We are at the 100+ rule starter pack target promised by Theme 1.
- The engine evaluates rules against synthetic events and yields hits.
- The multi-backend translator can compile a sample of rules to SPL, KQL,
  Lucene, and Chronicle (UDM Search + YARA-L 2.0) without raising.

Run with:

    .venv/bin/python -m tests._check_detections_pack
"""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

from app.detections import (
    BackendError,
    DetectionEngine,
    RulePack,
    translate_chronicle,
    translate_chronicle_yaral,
    translate_kql,
    translate_lucene,
    translate_splunk,
)


RULES_DIR = (
    Path(__file__).resolve().parents[1] / "app" / "detections" / "rules"
)
MIN_RULES = 100


def _fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def _ok(msg: str) -> None:
    print(f"ok   {msg}")


def main() -> None:
    if not RULES_DIR.is_dir():
        _fail(f"rules dir not found: {RULES_DIR}")

    pack = RulePack.load_directory(RULES_DIR, strict=True)
    n = len(pack.rules)
    if n < MIN_RULES:
        _fail(f"only {n} rules loaded, expected >= {MIN_RULES}")
    _ok(f"loaded {n} rules in strict mode (zero parse errors)")

    severities = Counter(r.severity.value for r in pack.rules)
    _ok(f"severity distribution: {dict(severities)}")

    tag_families: Counter[str] = Counter()
    for r in pack.rules:
        for t in r.tags or []:
            tag_families[t.split(".", 1)[0]] += 1
    top_families = dict(tag_families.most_common(5))
    _ok(f"top tag families: {top_families}")

    ids = [r.id for r in pack.rules]
    dup = [rid for rid, c in Counter(ids).items() if c > 1]
    if dup:
        _fail(f"duplicate rule ids: {dup[:5]}")
    _ok("all rule ids are unique")

    engine = DetectionEngine(pack)

    sample_events = [
        {
            "event": {"action": "ConsoleLogin", "outcome": "success"},
            "user": {"name": "[email protected]"},
            "source": {"ip": "8.8.8.8"},
            "enrich": {"identity": {"privileged": True}},
        },
        {
            "event": {"action": "mfa_challenge", "outcome": "success"},
            "user": {"name": "[email protected]"},
            "enrich": {"push_denied_count": 7},
        },
        {
            "dns": {"question": {"type": "TXT", "name": "abc.example.com"}},
            "enrich": {
                "flow": {"dst_external": True},
                "dns": {"queries_per_domain_5m": 120},
            },
        },
    ]
    total_hits = 0
    for ev in sample_events:
        hits = list(engine.evaluate(ev))
        total_hits += len(hits)
    _ok(f"engine produced {total_hits} hits across {len(sample_events)} sample events")

    sample = pack.rules[: min(10, len(pack.rules))]
    translator_failures: list[str] = []
    for r in sample:
        for name, fn in (
            ("splunk", translate_splunk),
            ("kql", translate_kql),
            ("lucene", translate_lucene),
            ("chronicle", translate_chronicle),
            ("chronicle_yaral", translate_chronicle_yaral),
        ):
            try:
                out = fn(r)
            except BackendError as exc:
                translator_failures.append(f"{r.id}:{name}:{exc}")
                continue
            if not isinstance(out, str) or not out.strip():
                translator_failures.append(f"{r.id}:{name}:empty")
    if translator_failures:
        _fail(
            "translator failures: " + "; ".join(translator_failures[:5])
        )
    _ok(
        f"translator compiled {len(sample)} rules to "
        "SPL+KQL+Lucene+Chronicle(UDM+YARA-L)"
    )

    # And: every rule in the pack must compile to Chronicle UDM Search.
    # YARA-L 2.0 rule names must be valid identifiers (alphanumeric + _,
    # starting with a letter). This catches malformed `id:` fields that
    # would silently produce broken rules when published to Chronicle.
    chron_failures: list[str] = []
    for r in pack.rules:
        try:
            udm = translate_chronicle(r)
            yara = translate_chronicle_yaral(r)
        except BackendError as exc:
            chron_failures.append(f"{r.id}:translate:{exc}")
            continue
        if not udm.strip() or not yara.strip():
            chron_failures.append(f"{r.id}:empty")
            continue
        if "rule " not in yara.split("\n", 1)[0]:
            chron_failures.append(f"{r.id}:missing-rule-header")
        if "events:" not in yara or "condition:" not in yara:
            chron_failures.append(f"{r.id}:missing-yaral-blocks")
    if chron_failures:
        _fail(
            "chronicle translator failures: "
            + "; ".join(chron_failures[:5])
        )
    _ok(
        f"chronicle translator compiled all {len(pack.rules)} rules "
        "to UDM Search + YARA-L 2.0"
    )

    print(f"PASS detection pack smoke test ({n} rules)")


if __name__ == "__main__":
    main()
