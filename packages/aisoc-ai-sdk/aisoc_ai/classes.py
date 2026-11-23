"""Sensitive-class counts for prompts — local, opt-in, counts only (WS5.6).

The SDK's standing privacy claim is that prompt content never leaves the
customer's process by default, and this module is written to keep that
claim exactly true while still answering the governance question "what
KINDS of data do our prompts carry?":

* **Local**: plain regex/keyword heuristics, no model call, no network.
* **Opt-in**: nothing runs unless the client was constructed with
  ``classify_prompt_classes=True``.
* **Counts only**: the emitted field is ``{"personal": 2, "payment": 1}``
  — match COUNTS per class. No match text, no offsets, no excerpts, so the
  field cannot reconstruct any part of the prompt.

The classes are deliberately coarse and the heuristics say so: a
four-digit-grouped number is *payment-shaped*, a word from the health list
is *health-adjacent*. These are governance signals, not detections; the
platform never treats a class count as a verdict.
"""

from __future__ import annotations

import re

#: class name -> patterns. Payment reuses the card shape `redaction.py`
#: scrubs; the rest are the smallest honest spellings of each class.
CLASS_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    "personal": (
        re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b"),  # email address
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),  # SSN-shaped
        re.compile(r"\b(?:\+?\d{1,3}[ .-]?)?(?:\(\d{3}\)|\d{3})[ .-]?\d{3}[ .-]?\d{4}\b"),  # phone-shaped
    ),
    "health": (
        re.compile(
            r"\b(?:diagnos\w+|prescri\w+|medication|icd-?10|patient\s+record|lab\s+result|hipaa)\b",
            re.I,
        ),
    ),
    "payment": (
        re.compile(r"\b(?:\d[ -]*?){13,16}\b"),  # card-shaped (redaction.py's shape)
        re.compile(r"\b(?:iban|swift|routing\s+number|account\s+number)\b", re.I),
    ),
    "source_code": (
        re.compile(r"^\s*(?:def |class |import |from \w+ import |func |package |#include)", re.M),
        re.compile(r"```[a-z]*\n"),  # fenced code block
    ),
}


def classify_text(text: str) -> dict[str, int]:
    """Match counts per class. Empty dict for a prompt matching nothing —
    an absent field, not a confident zero for every class."""
    counts: dict[str, int] = {}
    for class_name, patterns in CLASS_PATTERNS.items():
        total = sum(len(pattern.findall(text or "")) for pattern in patterns)
        if total:
            counts[class_name] = total
    return counts
