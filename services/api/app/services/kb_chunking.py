"""Knowledge-base document chunking.

Pure, dependency-free text-chunking helpers used by the KB ingest endpoint
(``POST /kb/ingest``).  Kept separate from the endpoint module so the logic
can be unit-tested without importing FastAPI / auth / DB dependencies.
"""

from __future__ import annotations

import re

CHUNK_SIZE = 800  # characters per chunk
CHUNK_OVERLAP = 150  # overlap between consecutive chunks


def chunk_text(
    content: str,
    chunk_size: int = CHUNK_SIZE,
    overlap: int = CHUNK_OVERLAP,
) -> list[str]:
    """Sentence/paragraph-boundary-aware chunker with configurable overlap.

    Strategy (recursive):
      1. Split on double-newlines (paragraph breaks) first.
      2. If a paragraph still exceeds chunk_size, split on sentence endings.
      3. If a sentence exceeds chunk_size, fall back to hard character split.

    Each chunk overlaps the previous one by ``overlap`` characters so context
    spans chunk boundaries and PostgreSQL ``to_tsvector`` stems complete words
    rather than truncated fragments.

    All produced units are guaranteed to be <= chunk_size characters before
    the overlap tail is prepended, so no chunk can grow beyond
    chunk_size + overlap in the worst case.
    """
    if not content:
        return [content]

    # ── Step 1: split into paragraphs ────────────────────────────────────
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", content) if p.strip()]
    if not paragraphs:
        paragraphs = [content.strip()]

    # Build atomic units, each guaranteed <= chunk_size.  ``glue`` marks a
    # unit that is a continuation of a hard-split run and therefore must be
    # concatenated to its predecessor *without* an inserted space, so a token
    # split across the boundary is reconstructed verbatim instead of corrupted
    # (e.g. "CRITICAL_INDICATOR" must not become "CRITICAL_ INDICATOR").
    units: list[tuple[str, bool]] = []
    for para in paragraphs:
        if len(para) <= chunk_size:
            units.append((para, False))
        else:
            # Step 2: split on sentence boundaries (.  !  ?)
            sentences = re.split(r"(?<=[.!?])\s+", para)
            for sent in sentences:
                if len(sent) <= chunk_size:
                    units.append((sent, False))
                else:
                    # Step 3: hard character split as last resort. Pieces are
                    # contiguous slices of the same run, so all but the first
                    # are glued to keep the original characters intact.
                    for piece_idx, i in enumerate(range(0, len(sent), chunk_size)):
                        units.append((sent[i : i + chunk_size], piece_idx > 0))

    # ── Merge units into chunks with overlap ─────────────────────────────
    chunks: list[str] = []
    current = ""
    for unit, glue in units:
        sep = "" if glue or not current else " "
        candidate = current + sep + unit
        if len(candidate) <= chunk_size:
            current = candidate
        else:
            if current:
                chunks.append(current)
            tail = current[-overlap:] if overlap and current else ""
            # Re-seed with the overlap tail. A glued unit is contiguous with
            # that tail, so no separator is inserted; otherwise a space is.
            if tail:
                new_current = tail + ("" if glue else " ") + unit
            else:
                new_current = unit
            # If tail + unit still exceeds the limit (unit is near chunk_size),
            # drop the tail — unit alone is always <= chunk_size (see above).
            current = new_current if len(new_current) <= chunk_size else unit

    if current:
        chunks.append(current)

    return chunks or [content]
