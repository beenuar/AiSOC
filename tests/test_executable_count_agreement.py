"""Two surfaces must not publish different numbers under the same word.

The marketplace stat card read **2,767 Executable** under a tooltip saying
"loaded by the detection engine", while the truth table, the corpus stats and
the README all publish **2,603** for that claim. Both numbers were correct
about what they counted and the word was wrong about one of them: the
marketplace figure is every installable entry, which is the 2,603 rules the
engine loads *plus* 87 playbooks and 77 plugins that are not engine rules at
all and carry no `executable` field.

    2603 + 87 + 77 = 2767

So 164 entries were being described as loaded by an engine that has never
seen them, and a reader comparing the marketplace with the detections page
found a 164-rule discrepancy with nothing explaining it.

This gate does not force the two figures to be equal — they measure different
things and should. It forces the arithmetic between them to hold, so if the
catalogue grows the relationship is checked rather than assumed, and it
refuses the label that caused the confusion.
"""

from __future__ import annotations

import json
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
INDEX = REPO / "marketplace" / "index.json"
VIEW = REPO / "apps" / "web" / "src" / "components" / "marketplace" / "MarketplaceView.tsx"


@pytest.fixture(scope="module")
def stats() -> dict:
    return json.loads(INDEX.read_text(encoding="utf-8"))["stats"]


class TestTheTwoFiguresReconcile:
    def test_installable_is_rules_plus_playbooks_and_plugins(self, stats: dict) -> None:
        """The relationship, asserted rather than assumed.

        `executable` in the index counts every entry the engine loads plus the
        content that is installable but is not a rule. If that stops being
        true the two published figures have drifted apart for a new reason,
        and this says so instead of leaving a reader to find it.
        """
        from_engine = stats["executable"] - stats["playbooks"] - stats["plugins"]
        truth_table = REPO / "docs" / "detections" / "truth-table.md"
        if not truth_table.is_file():
            pytest.skip("no truth table to reconcile against")
        published = re.search(r"(\d[\d,]*)\s+executable", truth_table.read_text(encoding="utf-8"))
        assert published, "the truth table no longer publishes an executable count in a form this reads"
        assert from_engine == int(published.group(1).replace(",", "")), (
            f"the marketplace's installable figure implies {from_engine} engine rules, but the truth table publishes {published.group(1)}"
        )

    def test_the_partition_still_sums(self, stats: dict) -> None:
        assert stats["executable"] + stats["quarantined"] == stats["total"]


class TestTheLabelMatchesWhatItCounts:
    def test_the_card_does_not_call_non_rules_executable(self) -> None:
        """`Installable`, not `Executable`.

        The number includes playbooks and plugins, so a label promising the
        detection engine loaded them is false for 164 entries — and reads as
        contradicting the figure every other surface publishes.
        """
        source = VIEW.read_text(encoding="utf-8")
        # Matches the identifier in either spelling, so this fails on the
        # *label* against the pre-fix tree rather than on the rename — a test
        # that only knows the new name reports "symbol absent", which proves
        # nothing about the defect.
        card = re.search(r"\{\s*label:\s*'([^']+)',\s*value:\s*(?:installableCount|executableCount)", source)
        assert card, "the mixed-count stat card is gone; re-point this gate"
        assert card.group(1) == "Installable", f"the card counting playbooks and plugins is labelled {card.group(1)!r}"

    def test_no_tooltip_claims_the_engine_loads_all_of_them(self) -> None:
        source = VIEW.read_text(encoding="utf-8")
        # The phrase is fine beside `Detections`, which really is rules only.
        offending = re.findall(r"title:\s*'Loaded by the detection engine[^']*'", source)
        assert not offending, f"a tooltip still claims engine execution for the mixed count: {offending}"
