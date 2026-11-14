"""A case's evidence chain records custody, and says when it was edited.

Wave 0. `aisoc_cases.evidence_chain` had three readers and no writer, so
`GET /cases/{id}/evidence` returned `[]` under a heading reading
"Evidence Chain" — which an auditor reads as "no evidence was handled",
not as "this product does not record custody".
"""

from __future__ import annotations

import uuid

import pytest
from app.services.evidence_custody import (
    CUSTODY_ACTIONS,
    append_entry,
    build_entry,
    compute_entry_hash,
    verify_chain,
)

ACTOR = uuid.UUID("11111111-1111-1111-1111-111111111111")


def _chain(n: int = 3) -> list[dict]:
    chain: list[dict] = []
    for i in range(n):
        chain = append_entry(
            chain,
            action="alert_linked",
            actor_id=ACTOR,
            actor_email="analyst@example.com",
            item=f"alert-{i}",
        )
    return chain


class TestAnEntryRecordsCustody:
    def test_it_records_what_who_and_when(self) -> None:
        """The four things a chain of custody is for."""
        entry = build_entry(action="alert_linked", actor_id=ACTOR, actor_email="a@example.com", item="alert-1")

        assert entry["action"] == "alert_linked"
        assert entry["actor_id"] == str(ACTOR)
        assert entry["actor_email"] == "a@example.com"
        assert entry["item"] == "alert-1"
        assert entry["at"]

    def test_an_unknown_action_is_refused(self) -> None:
        """A typo'd verb would store happily and never match a filter —
        the quiet failure this module exists to stop repeating."""
        with pytest.raises(ValueError, match="unknown custody action"):
            build_entry(action="alrt_linkd", actor_id=ACTOR)

    def test_every_declared_action_is_accepted(self) -> None:
        """The negative control for the test above: without it, a guard
        that refused everything would pass."""
        for action in CUSTODY_ACTIONS:
            assert build_entry(action=action, actor_id=ACTOR)["action"] == action


class TestTheChainIsTamperEvident:
    def test_an_untouched_chain_verifies(self) -> None:
        report = verify_chain(_chain())
        assert report["intact"] is True
        assert report["entries"] == 3
        assert report["broken_at"] is None

    def test_an_empty_chain_is_intact_not_broken(self) -> None:
        """A case nobody has touched has an empty chain, which is a
        different fact from a chain that was emptied."""
        assert verify_chain([])["intact"] is True
        assert verify_chain(None)["intact"] is True

    def test_editing_an_entry_is_caught(self) -> None:
        chain = _chain()
        chain[1]["item"] = "alert-substituted"

        report = verify_chain(chain)
        assert report["intact"] is False
        assert report["broken_at"] == 1
        assert "edited after it was written" in report["reason"]

    def test_removing_an_entry_is_caught(self) -> None:
        """The gap breaks the link across it, which is the whole reason
        each entry carries its predecessor's hash."""
        chain = _chain(4)
        del chain[1]

        report = verify_chain(chain)
        assert report["intact"] is False
        assert report["broken_at"] == 1
        assert "removed, reordered or inserted" in report["reason"]

    def test_reordering_is_caught(self) -> None:
        chain = _chain(3)
        chain[1], chain[2] = chain[2], chain[1]
        assert verify_chain(chain)["intact"] is False

    def test_it_names_the_entry_rather_than_returning_a_boolean(self) -> None:
        """ "The chain is broken" sends an auditor to read all of it;
        "entry 1 of 3 does not match" sends them to the row that changed."""
        chain = _chain(3)
        chain[1]["actor_email"] = "someone.else@example.com"

        report = verify_chain(chain)
        assert report["broken_at"] == 1
        assert report["entries"] == 3
        assert isinstance(report["reason"], str) and report["reason"]

    def test_rewriting_the_whole_chain_is_not_detected_and_that_is_stated(self) -> None:
        """Tamper *evidence*, not tamper proofing. Anyone who can write
        the column can rewrite every link consistently, and a reader who
        assumes otherwise has been misled by us."""
        forged = _chain(3)
        forged[1]["item"] = "alert-substituted"
        forged[1]["entry_hash"] = compute_entry_hash(forged[1], forged[1]["prev_hash"])
        forged[2]["prev_hash"] = forged[1]["entry_hash"]
        forged[2]["entry_hash"] = compute_entry_hash(forged[2], forged[2]["prev_hash"])

        assert verify_chain(forged)["intact"] is True


class TestAppending:
    def test_each_entry_links_to_the_one_before(self) -> None:
        chain = _chain(3)
        assert chain[0]["prev_hash"] is None
        assert chain[1]["prev_hash"] == chain[0]["entry_hash"]
        assert chain[2]["prev_hash"] == chain[1]["entry_hash"]

    def test_appending_to_none_starts_a_chain(self) -> None:
        chain = append_entry(None, action="case_opened", actor_id=ACTOR)
        assert len(chain) == 1
        assert verify_chain(chain)["intact"] is True

    def test_entries_have_distinct_ids(self) -> None:
        chain = _chain(5)
        assert len({e["id"] for e in chain}) == 5
