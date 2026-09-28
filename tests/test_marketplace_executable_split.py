"""The catalogue must say which of its entries can actually fire.

`marketplace/index.json` holds 7,155 entries and the detection engine loads
2,767 of them. The other 4,388 are on disk and cannot fire. They were
disclosed by one field — `verified: false` — which says something else
entirely: 1,770 imported Sigma rules are compiled, proven to fire and loaded,
and they are not "verified" either.

Three specific dishonesties, all fixed here and all asserted below:

* **`stats.quarantined` counted the wrong thing.** It summed rows carrying a
  `quarantine_reason`, which was 4,213 — while 4,388 rules the engine does
  not load. Nothing compared it to `docs/detections/truth-table.md`, which
  has published the right split all along.
* **Rows were disabled with no stated reason.** `quarantine_reason` was
  written only on the quarantine branch, so a rule the engine skips for any
  other cause arrived indistinguishable from an executable one.
* **`enabled` is not the capability signal and reading it as one understates
  the corpus.** 1,724 rules carry `enabled: false` in their file and the
  engine loads every one — the Sigma compiler began translating rules in
  place without rewriting the flag. `executable` is membership of the
  engine's loaded set, the same question the truth table asks.

The counts here are deliberately not hard-coded. This corpus moves every time
the Sigma compiler reaches further, and a pinned number would be a second
figure to keep in step. What is asserted is the *relationship*: the two
halves partition the catalogue, every disabled entry states why, and the
published figure equals the count it claims to be.
"""

from __future__ import annotations

import json
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
COPIES = (
    REPO / "marketplace" / "index.json",
    REPO / "apps" / "web" / "public" / "marketplace" / "index.json",
    REPO / "services" / "api" / "app" / "data" / "marketplace" / "index.json",
)


@pytest.fixture(scope="module")
def index() -> dict:
    payload = json.loads(COPIES[0].read_text(encoding="utf-8"))
    assert payload.get("items"), "the marketplace index is empty — nothing below would mean anything"
    return payload


def _executable(items: list[dict]) -> list[dict]:
    return [i for i in items if i.get("executable", True)]


def _reference_only(items: list[dict]) -> list[dict]:
    return [i for i in items if not i.get("executable", True)]


class TestThePublishedSplitIsTheRealOne:
    def test_the_two_halves_partition_the_catalogue(self, index: dict) -> None:
        items = index["items"]
        assert len(_executable(items)) + len(_reference_only(items)) == len(items)

    def test_both_halves_are_non_empty(self, index: dict) -> None:
        """A partition where one side is empty makes every other assertion
        vacuous — and would also mean the engine loads everything or nothing,
        neither of which is true."""
        items = index["items"]
        assert _executable(items), "nothing in the catalogue is executable"
        assert _reference_only(items), "nothing in the catalogue is reference-only"

    def test_the_stats_match_the_items(self, index: dict) -> None:
        """`stats.quarantined` was 4,213 against the 4,388 rules the engine
        does not load, because it counted rows carrying a reason rather than
        rows outside the engine's loaded set."""
        stats, items = index["stats"], index["items"]
        assert stats["executable"] == len(_executable(items))
        assert stats["quarantined"] == len(_reference_only(items))
        assert stats["executable"] + stats["quarantined"] == stats["total"] == len(items)

    def test_every_entry_that_cannot_fire_says_why(self, index: dict) -> None:
        silent = [i["id"] for i in _reference_only(index["items"]) if not (i.get("quarantine_reason") or "").strip()]
        assert not silent, (
            f"{len(silent)} entries are not loaded by the engine and state no reason, "
            f"e.g. {silent[:5]}. A reader cannot tell those from executable content."
        )

    def test_the_split_matches_the_engine_and_the_truth_table(self, index: dict) -> None:
        """The figure the README publishes, read from the artefact the engine
        loads rather than from this file.

        `enabled` was tried as the signal and was wrong by 1,724 rules in the
        direction that understates the corpus. Comparing against the engine's
        own ruleset is what stops that recurring.
        """
        # Both compiled rulesets, because the engine loads both: the native
        # corpus and the translated Sigma imports. Reading only the first
        # accounts for 833 of the 2,603 and would fail this by 1,770.
        data = REPO / "services" / "fusion" / "app" / "data"
        loaded: set[str] = set()
        for name in ("detection_ruleset.json", "detection_ruleset_imported.json"):
            path = data / name
            assert path.is_file(), f"{path} is missing — the catalogue's claim rests on it"
            loaded |= {str(r["id"]) for r in json.loads(path.read_text(encoding="utf-8")).get("rules") or [] if r.get("id")}
        assert loaded, "the engine rulesets are empty — nothing here would mean anything"

        detections = [i for i in index["items"] if i["type"] == "detection"]
        marked = {i["id"] for i in detections if i.get("executable")}
        assert marked == loaded, (
            f"the catalogue marks {len(marked)} detections executable and the engine loads {len(loaded)}; "
            f"only in catalogue: {sorted(marked - loaded)[:3]}, only in engine: {sorted(loaded - marked)[:3]}"
        )

    def test_enabled_is_not_the_capability_signal(self, index: dict) -> None:
        """Pinned. Reading `enabled` is the mistake, and it is not a
        hypothetical one — it is true of 1,724 rules right now."""
        detections = [i for i in index["items"] if i["type"] == "detection"]
        loaded_but_flagged_off = [i["id"] for i in detections if i.get("executable") and i.get("enabled") is False]
        assert loaded_but_flagged_off, (
            "no rule is `enabled: false` yet loaded by the engine. If the compiler now rewrites the flag, "
            "delete this test and say so — until then it is what stops `enabled` being read as capability."
        )

    def test_verified_is_not_a_proxy_for_executable(self, index: dict) -> None:
        """Pinned, because `verified: false` was the only disclosure and it
        answers a different question. If these two ever became the same set,
        the separate field would be redundant — and the reason to keep them
        apart is that imported rules the engine *does* load are not verified."""
        items = index["items"]
        executable_ids = {i["id"] for i in _executable(items)}
        verified_ids = {i["id"] for i in items if i.get("verified")}
        assert executable_ids != verified_ids, "`enabled` and `verified` have collapsed into one signal"
        assert executable_ids - verified_ids, "no executable entry is unverified — check the engine's loaded set"


class TestTheThreeCopiesAgree:
    """The index ships in three build contexts that cannot see one another.
    `check_marketplace_index_parity.py` asserts they are byte-identical; this
    asserts the property that matters if that ever relaxes."""

    @pytest.mark.parametrize("path", COPIES[1:], ids=lambda p: str(p.relative_to(REPO)))
    def test_the_split_is_the_same_everywhere(self, index: dict, path: pathlib.Path) -> None:
        assert path.is_file(), f"{path} is missing"
        other = json.loads(path.read_text(encoding="utf-8"))
        assert other["stats"]["executable"] == index["stats"]["executable"]
        assert other["stats"]["quarantined"] == index["stats"]["quarantined"]
