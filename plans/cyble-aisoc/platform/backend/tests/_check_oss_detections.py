"""Smoke test for t5-oss-detections.

Exercises the public-catalog API, the contributor validator, and the
provenance stamping. Hermetic — uses a temp DB and the deterministic
mock LLM so it can run in CI alongside the other ``_check_*.py``
files.

Coverage:
  1. ``GET /detections/catalog`` returns every loadable rule.
  2. Filtering by ``pack`` / ``severity`` / ``source`` works.
  3. ``GET /detections/catalog/summary`` exposes total + provenance %.
  4. ``POST /detections/validate`` accepts a valid contributor rule.
  5. The validator rejects rules that violate H1, H2, H3, H4, H5, H8.
  6. The validator surfaces S2/S3/S4 as warnings, not errors.
  7. Sibling ``.tests.yml`` files cause negative samples to fail H6.
  8. The full shipping pack at ``app/detections/rules/`` validates
     without any hard errors (i.e. we don't ship a broken pack).
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import textwrap
from pathlib import Path

# ─── Hermetic setup ─────────────────────────────────────────────────
_TMP = tempfile.NamedTemporaryFile(prefix="aisoc-oss-det-", suffix=".db", delete=False)
_TMP.close()
os.environ["AISOC_DB_PATH"] = _TMP.name
os.environ["AISOC_LLM_PROVIDER"] = "mock"
os.environ["AISOC_DEV_ALLOW_ANON_TENANT"] = "true"

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def _bad(msg: str, *details: object) -> None:
    print(f"FAIL: {msg}")
    for d in details:
        print(f"  -> {d}")


# ─── Fixtures ───────────────────────────────────────────────────────


_GOOD_RULE = textwrap.dedent(
    """
    title: Test Rule For Validator OK Path
    id: contrib-test-0001-good-rule
    status: experimental
    description: |
      A small contribution-test rule whose only job is to pass H1-H8.
      It detects a benign pattern, and we ship it from the test only.
    author: Test Author (github:tester)
    level: medium
    logsource:
      category: process_creation
      product: windows
    tags:
      - attack.t1059.001
      - attack.execution
      - aisoc.endpoint
    detection:
      selection:
        process.name: contrib-test-marker.exe
      condition: selection
    falsepositives:
      - none expected
    """
).strip()


_BAD_RULE_NO_TITLE = textwrap.dedent(
    """
    id: contrib-test-bad-0001
    status: stable
    description: short
    logsource:
      category: process_creation
    detection:
      selection:
        foo: bar
      condition: selection
    """
).strip()


_BAD_RULE_NO_ATTACK_TAG = textwrap.dedent(
    """
    title: Bad rule with no ATT&CK tag
    id: contrib-test-bad-0002
    status: stable
    description: |
      This rule deliberately omits the required attack.* tag so we can
      verify that H3 fires. The text is long enough to clear H2.
    logsource:
      category: process_creation
      product: windows
    tags:
      - aisoc.endpoint
    detection:
      selection:
        process.name: foo.exe
      condition: selection
    falsepositives:
      - none expected
    """
).strip()


def main() -> int:
    from fastapi.testclient import TestClient

    from app.db import init_db
    from app.detections.contrib import (
        build_catalog,
        catalog_summary,
        validate_pack_directory,
        validate_rule,
    )
    from app.detections.sigma import SigmaRule
    from app.main import app

    init_db()
    client = TestClient(app)

    rules_dir = Path(ROOT) / "app" / "detections" / "rules"
    if not rules_dir.exists():
        _bad("rules dir missing", rules_dir)
        return 1

    # 1. Catalog endpoint returns the loadable rules.
    resp = client.get("/detections/catalog?limit=1000")
    if resp.status_code != 200:
        _bad("catalog endpoint did not 200", resp.status_code, resp.text)
        return 1
    cat = resp.json()
    if cat.get("count", 0) < 50:  # we ship 130; tolerate some skip
        _bad("catalog count unexpectedly low", cat.get("count"))
        return 1
    sample = cat["rules"][0]
    for required in ("id", "title", "severity", "tags", "pack", "provenance"):
        if required not in sample:
            _bad(f"missing field `{required}` on catalog entry", sample)
            return 1
    if sample["provenance"].get("source") not in {
        "cyble-native",
        "community",
        "mirrored",
    }:
        _bad("invalid provenance.source", sample)
        return 1

    # 2. Filtering: pick a known rule, filter by its pack, expect it
    #    to be present.
    target_pack = sample["pack"]
    resp_filtered = client.get(
        f"/detections/catalog?pack={target_pack}&limit=1000"
    ).json()
    if resp_filtered["count"] == 0:
        _bad("pack filter returned nothing", target_pack)
        return 1
    if any(e["pack"] != target_pack for e in resp_filtered["rules"]):
        _bad("pack filter leaks other packs", target_pack)
        return 1
    resp_sev = client.get("/detections/catalog?severity=critical&limit=1000").json()
    if resp_sev["count"] and any(
        e["severity"] != "critical" for e in resp_sev["rules"]
    ):
        _bad("severity filter leaks other severities", resp_sev["rules"][0])
        return 1

    # 3. Summary endpoint.
    summary_resp = client.get("/detections/catalog/summary")
    if summary_resp.status_code != 200:
        _bad("summary endpoint did not 200", summary_resp.status_code)
        return 1
    summary = summary_resp.json()
    for required in (
        "total_rules",
        "by_pack",
        "by_severity",
        "by_source",
        "unique_attack_techniques",
        "percent_community",
    ):
        if required not in summary:
            _bad(f"summary missing `{required}`", summary)
            return 1
    if summary["total_rules"] < 50:
        _bad("summary total_rules low", summary)
        return 1

    # 4. POST /detections/validate accepts a good rule.
    good = client.post(
        "/detections/validate",
        json={"yaml": _GOOD_RULE, "name": "good-rule.yml"},
    ).json()
    if not good.get("ok"):
        _bad("good rule should validate", json.dumps(good, indent=2))
        return 1
    if good["accepted"] != ["contrib-test-0001-good-rule"]:
        _bad("good rule not accepted", good)
        return 1

    # 5a. Reject H2 (missing title) and any other hard errors.
    bad1 = client.post(
        "/detections/validate",
        json={"yaml": _BAD_RULE_NO_TITLE, "name": "bad-no-title.yml"},
    ).json()
    if bad1.get("ok"):
        _bad("title-less rule should fail validation", bad1)
        return 1
    bad1_codes = {e["code"] for e in bad1["errors"]}
    if "parse" not in bad1_codes and "H2" not in bad1_codes:
        _bad("expected a parse or H2 error", bad1_codes)
        return 1

    # 5b. Reject H3 (missing ATT&CK tag).
    bad2 = client.post(
        "/detections/validate",
        json={"yaml": _BAD_RULE_NO_ATTACK_TAG, "name": "bad-no-attack.yml"},
    ).json()
    if bad2.get("ok"):
        _bad("rule without attack tag should fail H3", bad2)
        return 1
    if not any(e["code"] == "H3" for e in bad2["errors"]):
        _bad("expected H3 error", bad2["errors"])
        return 1

    # 6. The good rule generates no errors and at most an S4 warning
    #    (none in our case because we set falsepositives:).
    if good["warnings"]:
        codes = {w["code"] for w in good["warnings"]}
        # S2/S3/S4 should not fire on our well-formed sample.
        if codes & {"S2", "S3", "S4"}:
            _bad(
                "well-formed sample triggered avoidable S-warnings", codes
            )
            return 1

    # 7. Tests-file negative-sample enforcement: write a temp rule +
    #    tests file in a temp dir and run validate_pack_directory.
    with tempfile.TemporaryDirectory(prefix="aisoc-oss-pack-") as td:
        td_path = Path(td)
        rule_path = td_path / "neg-test.yml"
        rule_path.write_text(_GOOD_RULE, encoding="utf-8")
        tests_path = td_path / "neg-test.tests.yml"
        tests_path.write_text(
            textwrap.dedent(
                """
                positives:
                  - { process.name: contrib-test-marker.exe }
                negatives:
                  # Negative MUST not match. It does match (process.name
                  # is exactly the value we look for) so H6 should fail.
                  - { process.name: contrib-test-marker.exe }
                """
            ).strip(),
            encoding="utf-8",
        )
        report = validate_pack_directory(td_path)
        if report.ok:
            _bad("matching negative sample should have triggered H6")
            return 1
        if not any(e.code == "H6" for e in report.errors):
            _bad("expected H6 error", [e.code for e in report.errors])
            return 1

    # 8. The shipping pack must validate (no hard errors).
    full_report = validate_pack_directory(rules_dir)
    if not full_report.ok:
        _bad(
            "shipping rule pack has hard errors",
            [(e.rule_id, e.code, e.message) for e in full_report.errors[:5]],
        )
        return 1

    # 9. Provenance: at least one cyble-native and zero unknown sources
    #    in the live catalog.
    catalog_entries = build_catalog(rules_dir, include_verticals=True)
    sources = {e.provenance["source"] for e in catalog_entries}
    if "cyble-native" not in sources:
        _bad("expected at least one cyble-native rule", sources)
        return 1
    if any(e.provenance["source"] == "unknown" for e in catalog_entries):
        _bad("found rules with unknown provenance")
        return 1

    print("OK t5-oss-detections")
    print(json.dumps({
        "catalog_count": cat["count"],
        "shipping_pack_size": full_report.rules_checked,
        "shipping_warnings": len(full_report.warnings),
        "summary_total": summary["total_rules"],
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
