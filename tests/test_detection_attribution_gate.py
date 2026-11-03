"""The DRL-1.1 attribution obligation, held by tests rather than by a caveat.

Issue #1680, reported by Florian Roth (SigmaHQ): rules imported from SigmaHQ
shipped with no author. DRL-1.1 permits redistribution in modified form — the
translation into this engine's matcher language is exactly that — on condition
that author identification travels with the copy *and* appears in messages
produced by a match.

The gap had been documented in the compiler's generated report under a heading
that called it a known gap, which is how it survived: a caveat reads as
modesty and functions as an exemption. These tests are the replacement, and
they assert on the corpus and the rendered alert rather than on the presence
of a note about them.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tools"))

GATE = ROOT / "scripts" / "check_detection_attribution.py"
LICENCE = "DRL-1.1"

#: His example, named explicitly. A corpus-wide count can be satisfied by a
#: backfill that got one rule wrong, and this is the one rule whose answer is
#: published in a public issue thread.
HIS_EXAMPLE_ID = "002bdb95-0cf1-46a6-9e08-d38c128a6127"
HIS_EXAMPLE_AUTHOR = "Tim Shelton"

COMPILED = (
    ROOT / "services" / "fusion" / "app" / "data" / "detection_ruleset_imported.json",
    ROOT / "services" / "api" / "app" / "data" / "detections" / "detection_ruleset_imported.json",
)
MARKETPLACES = (
    ROOT / "marketplace" / "index.json",
    ROOT / "apps" / "web" / "public" / "marketplace" / "index.json",
    ROOT / "services" / "api" / "app" / "data" / "marketplace" / "index.json",
)


def _rules(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("rules") or data.get("items") or []


def _drl(items: list[dict]) -> list[dict]:
    return [i for i in items if (i.get("provenance") or {}).get("license") == LICENCE]


@pytest.mark.parametrize("path", COMPILED, ids=lambda p: p.parent.parent.parent.name)
def test_every_compiled_drl_rule_names_its_author(path: Path) -> None:
    drl = _drl(_rules(path))
    assert drl, f"no {LICENCE} rules in {path} — the corpus moved and this test is now vacuous"
    unattributed = [r["id"] for r in drl if not str((r["provenance"]).get("author") or "").strip()]
    assert not unattributed, (
        f"{len(unattributed)} of {len(drl)} {LICENCE} rules carry no author. "
        "DRL-1.1 requires author identification to travel with a shared copy."
    )


@pytest.mark.parametrize("path", MARKETPLACES, ids=lambda p: str(p.relative_to(ROOT)).replace("/", "_"))
def test_catalogue_credits_the_upstream_author_and_not_this_project(path: Path) -> None:
    """The sharpest form of the defect: not omission, but substitution.

    The builder projected provenance without the author and defaulted the
    item-level ``author`` to ``AiSOC``, so the console showed a rule written
    by Tim Shelton credited to this project.
    """
    drl = _drl(_rules(path))
    assert drl, f"no {LICENCE} items in {path} — this test would pass vacuously"
    missing = [i["id"] for i in drl if not str((i["provenance"]).get("author") or "").strip()]
    ours = [i["id"] for i in drl if str(i.get("author") or "").strip().lower() in {"aisoc", ""}]
    assert not missing, f"{len(missing)} {LICENCE} items carry no provenance author"
    assert not ours, f"{len(ours)} {LICENCE} items are credited to this project rather than their author"


def test_his_reported_example_credits_tim_shelton() -> None:
    for path in COMPILED:
        match = [r for r in _rules(path) if (r.get("provenance") or {}).get("source_id") == HIS_EXAMPLE_ID]
        assert match, f"the rule reported in #1680 is not in {path}"
        assert match[0]["provenance"]["author"] == HIS_EXAMPLE_AUTHOR


def test_the_alert_a_match_produces_names_the_author() -> None:
    """DRL-1.1 is explicit that *messages produced by a match* identify the author.

    Driven through the real engine rather than by asserting on the rendering
    helper, because the clause is about what an operator reads.
    """
    sys.path.insert(0, str(ROOT / "services" / "fusion"))
    from app.services.detection_engine import (  # noqa: PLC0415
        DetectionEngine,
        DetectionHit,
        _attribution,
    )

    rules = _rules(COMPILED[0])
    rule = next(r for r in rules if (r.get("provenance") or {}).get("source_id") == HIS_EXAMPLE_ID)

    hit = DetectionHit(
        rule_id=rule["id"],
        name=rule["name"],
        severity=rule["severity"],
        category=rule["category"],
        mitre=list(rule.get("mitre") or []),
        attribution=_attribution(rule),
    )
    alert = DetectionEngine().build_alert({"tenant_id": "00000000-0000-0000-0000-000000000001", "ocsf_event": {}}, hit)
    assert alert is not None
    assert HIS_EXAMPLE_AUTHOR in alert.description
    assert LICENCE in alert.description


def test_an_author_upstream_does_not_credit_is_recorded_not_invented() -> None:
    """A rule upstream credits to nobody must not acquire a fabricated author.

    Naming the publisher in place of the person is the exact substitution the
    licence does not accept, and an empty string is indistinguishable from the
    defect this closes.
    """
    from detection_import.sigma_importer import AUTHOR_ABSENT, _author_of  # noqa: PLC0415

    assert _author_of({}) == AUTHOR_ABSENT
    assert _author_of({"author": ""}) == AUTHOR_ABSENT
    assert _author_of({"author": None}) == AUTHOR_ABSENT
    assert "SigmaHQ" not in AUTHOR_ABSENT
    assert AUTHOR_ABSENT.strip() != ""


def test_multi_author_rules_keep_upstreams_own_spelling() -> None:
    """1,098 of the imported rules name more than one person.

    Upstream's comma-separated string is preserved rather than normalised into
    a shape this project invented; a co-author lost to tidying is the same
    licence defect at smaller scale.
    """
    from detection_import.sigma_importer import _author_of  # noqa: PLC0415

    verbatim = "frack113, Nasreddine Bencherchali (Nextron Systems)"
    assert _author_of({"author": verbatim}) == verbatim
    assert _author_of({"author": ["Alice", "Bob"]}) == "Alice, Bob"
    # Authors carrying quotes round-trip intact; a hand-rolled de-quoter
    # truncated 90 of these during the backfill.
    quoted = "Mark Morowczynski '@markmorow'"
    assert _author_of({"author": quoted}) == quoted

    corpus = _drl(_rules(COMPILED[0]))
    multi = [r for r in corpus if "," in str(r["provenance"].get("author") or "")]
    assert multi, "no multi-author rules found — the corpus or the import changed shape"


def test_gate_passes_on_the_current_tree() -> None:
    result = subprocess.run([sys.executable, str(GATE)], capture_output=True, text=True, cwd=ROOT, check=False)
    assert result.returncode == 0, result.stdout + result.stderr


def test_gate_self_test_passes() -> None:
    """The gate's own proof that it detects each shape of the defect."""
    result = subprocess.run([sys.executable, str(GATE), "--self-test"], capture_output=True, text=True, cwd=ROOT, check=False)
    assert result.returncode == 0, result.stdout + result.stderr


def test_gate_goes_red_when_an_author_is_removed(tmp_path: Path) -> None:
    """The negative control, run rather than asserted.

    A gate that has never been observed to fail is indistinguishable from one
    that cannot. The compiled ruleset is copied aside, blanked, and the gate is
    required to exit 1 and name the surface — then the original is restored and
    checked byte-identical, because a control that corrupts the tree it proves
    is worse than no control.
    """
    target = COMPILED[0]
    original = target.read_bytes()
    backup = tmp_path / "ruleset.json"
    backup.write_bytes(original)
    try:
        data = json.loads(original)
        for rule in data["rules"]:
            if rule.get("provenance"):
                rule["provenance"]["author"] = ""
        target.write_text(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n")

        result = subprocess.run([sys.executable, str(GATE)], capture_output=True, text=True, cwd=ROOT, check=False)
        assert result.returncode == 1, "the gate passed a corpus with every author removed"
        assert "with no author" in result.stdout
    finally:
        target.write_bytes(original)
    assert target.read_bytes() == original
