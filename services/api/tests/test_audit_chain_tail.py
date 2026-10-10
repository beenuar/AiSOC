"""verify_chain_tail: truncation of the newest audit rows must be visible."""

from app.services.audit_hash import verify_chain_tail


def _rows(n):
    return [{"chain_index": i, "entry_hash": f"h{i}"} for i in range(n)]


def test_intact_tail_is_not_a_break():
    assert verify_chain_tail(_rows(3), {"next_index": 3, "head_hash": "h2"}) is None


def test_deleting_the_newest_row_is_a_break():
    # Observed on v17.1: rows 0..2 written, row 2 deleted with the immutability
    # trigger disabled, /health/audit-chain still reported replay_intact=true.
    brk = verify_chain_tail(_rows(2), {"next_index": 3, "head_hash": "h2"})
    assert brk is not None and brk["missing"] == 1


def test_deleting_every_row_is_a_break():
    brk = verify_chain_tail([], {"next_index": 3, "head_hash": "h2"})
    assert brk is not None and brk["missing"] == 3


def test_append_after_the_head_was_read_is_not_a_break():
    assert verify_chain_tail(_rows(4), {"next_index": 3, "head_hash": "h2"}) is None


def test_replaced_newest_row_is_a_break():
    rows = _rows(3)
    rows[-1]["entry_hash"] = "forged"
    brk = verify_chain_tail(rows, {"next_index": 3, "head_hash": "h2"})
    assert brk is not None and brk["missing"] == 0


def test_no_head_yet_is_not_a_break():
    assert verify_chain_tail([], None) is None
    assert verify_chain_tail([], {"next_index": 0, "head_hash": None}) is None


def test_legacy_unindexed_rows_are_ignored():
    rows = [{"chain_index": None, "entry_hash": "x"}, *_rows(2)]
    assert verify_chain_tail(rows, {"next_index": 2, "head_hash": "h1"}) is None
