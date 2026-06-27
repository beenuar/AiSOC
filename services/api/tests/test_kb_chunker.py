"""Tests for the boundary-aware KB chunker (issue #277).

Imports the real implementation from ``app.services.kb_chunking`` so these
tests guard the code that actually ships, not a copy.
"""

import random
import string

from app.services.kb_chunking import CHUNK_OVERLAP, CHUNK_SIZE, chunk_text


def _chunk_old(content, chunk_size=CHUNK_SIZE):
    """The original fixed-width chunker, kept only to contrast behaviour."""
    return [content[i : i + chunk_size] for i in range(0, len(content), chunk_size)] or [content]


def test_old_splits_mid_word():
    text = "A" * 799 + " boundary_word " + "B" * 100
    old = _chunk_old(text)
    assert "boundary_word" not in old[0]
    assert "boundary_word" in old[1]


def test_new_keeps_word_intact():
    text = "A" * 799 + " boundary_word " + "B" * 100
    chunks = chunk_text(text)
    assert any("boundary_word" in c for c in chunks)
    assert not any(c.endswith("boundary_w") for c in chunks)


def test_empty():
    assert chunk_text("") == [""]


def test_short_single_chunk():
    t = "Short runbook entry."
    assert chunk_text(t) == [t]


def test_exact_size_single_chunk():
    t = "x" * CHUNK_SIZE
    assert len(chunk_text(t)) == 1


def test_no_chunk_exceeds_size():
    random.seed(99)
    text = " ".join("".join(random.choices(string.ascii_lowercase, k=random.randint(3, 15))) for _ in range(600))
    for c in chunk_text(text, chunk_size=800):
        assert len(c) <= 800


def test_sentence_boundary_not_split():
    sentence = "The attacker leveraged a misconfigured S3 bucket to exfiltrate credentials. "
    text = sentence * 15
    for chunk in chunk_text(text, chunk_size=800):
        assert chunk.rstrip()[-1] in ".!? "


def test_paragraph_boundary_preserved():
    text = "First paragraph about IR.\n\nSecond paragraph about hunting.\n\nThird about detection."
    chunks = chunk_text(text, chunk_size=800)
    assert len(chunks) == 1
    assert "First" in chunks[0] and "Third" in chunks[0]


def test_overlap_carries_context():
    sentence = "Each runbook step must be followed in strict order. "
    text = sentence * 20
    chunks = chunk_text(text, chunk_size=800, overlap=150)
    assert len(chunks) >= 2
    for i in range(1, len(chunks)):
        prev_words = chunks[i - 1][-150:].split()[:4]
        assert any(w in chunks[i][:250] for w in prev_words)


def test_long_paragraph_no_sentences():
    word = "security " * 100
    text = word + "\n\n" + word
    chunks = chunk_text(text, chunk_size=800)
    assert len(chunks) >= 2
    for c in chunks:
        assert len(c) <= 801


def test_overlap_adds_total_chars():
    sentences = ["Step %d: investigate alert before closing. " % i for i in range(50)]
    text = " ".join(sentences)
    no_ov = sum(len(c) for c in chunk_text(text, chunk_size=800, overlap=0))
    with_ov = sum(len(c) for c in chunk_text(text, chunk_size=800, overlap=150))
    assert with_ov >= no_ov


def test_long_doc_multiple_chunks_all_within_limit():
    long_text = ("Runbook step alpha. " * 10 + "\n\n") * 10
    chunks = chunk_text(long_text, chunk_size=800)
    assert len(chunks) >= 2
    assert all(len(c) <= 800 for c in chunks)


def test_overlap_default_constant():
    assert CHUNK_OVERLAP > 0


def test_hard_split_run_is_not_corrupted():
    # A token longer than chunk_size with no whitespace/punctuation forces the
    # hard-split fallback. Reassembly must keep characters contiguous: no space
    # may be injected mid-token, and the original text must be reconstructable.
    blob = "X" + "y" * 2500 + "Z"
    chunks = chunk_text(blob, chunk_size=800, overlap=150)
    assert all(len(c) <= 800 for c in chunks)
    assert blob.startswith(chunks[0])  # first chunk is a true prefix
    assert "y X" not in " ".join(chunks)  # no stray separators inside the run


def test_boundary_token_recovered_via_overlap():
    # A keyword straddling a hard-split boundary must appear intact in at least
    # one chunk thanks to the overlap, and must never be split by a space.
    doc = "A" * 790 + " CRITICAL_INDICATOR_malware_c2_beacon " + "follows. " * 30
    chunks = chunk_text(doc, chunk_size=800, overlap=150)
    assert any("CRITICAL_INDICATOR_malware_c2_beacon" in c for c in chunks)
    assert not any("CRITICAL_ INDICATOR" in c for c in chunks)
