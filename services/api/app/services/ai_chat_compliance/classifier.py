"""Classify AI-chat content into labels without keeping the content.

Depth plan wave 2, Phase 7.1.

What this module is for
-----------------------
An enterprise AI-chat compliance API hands back whole conversations. A SOC
wants to know whether any of them carried a credential, a person's data, a
regulated identifier or payment data. It does not want, and under most
customers' own policies must not keep, the conversations themselves.

So this runs in-process over text that is never persisted and returns four
things: which of the four classes matched, which shapes matched by name, one
bounded snippet, and how many messages were examined. The text it read is
discarded with the call.

Why a snippet at all
--------------------
Because a bare label is unactionable. "This chat contained a secret" sends a
reviewer to read the conversation, which is the outcome this feature exists
to avoid. A short window around the match is usually enough to tell a pasted
``.env`` file from a sentence about how to rotate a key.

Why the snippet is masked, which is the part that is easy to get wrong
----------------------------------------------------------------------
A verbatim window around a match would store precisely the value the label
says is present — a "minimised" row containing the AWS key. Every matched
span is therefore replaced by its shape name *before* the window is cut, so
the row records "an AWS access key appeared here" at a position in the text
and never the key. ``test_classifier.py`` asserts the secret value is absent
from the snippet for every pattern, which is the assertion that has to hold
for this table to be safe to keep.

Where the patterns come from
----------------------------
``SECRET_PATTERNS`` is the AI SDK's own list, vendored by
``scripts/sync_vendored_ai_redaction.py`` and held byte-identical by its
``--check`` mode. A prompt and a chat message that both contain an AWS key
must produce the same shape name on both surfaces; a second hand-written
copy is how two surfaces come to disagree about the same rows.

The SDK's list is a *transmission* question ("what must not leave"), so it
groups e-mail addresses and card numbers in with credentials. This module
asks a *classification* question, where those are personal data and
financial data rather than secrets, so ``_SDK_LABEL`` maps each shape to one
of the plan's four classes instead of relabelling the shared list.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app._vendor.ai_redaction import _SECRET_PATTERNS as SECRET_PATTERNS

#: Maximum snippet length. Mirrors the ``VARCHAR(280)`` bound in migration
#: 146. The column is the backstop for a caller that forgets; this is where
#: the cut actually happens.
SNIPPET_MAX = 280

#: The four classes the plan names, and the CHECK constraint's vocabulary in
#: migration 146. A label invented here fails at the write rather than
#: appearing in the console as a value nothing can filter on.
LABELS = ("secrets", "personal_data", "regulated", "financial")

#: Which class each shared SDK shape belongs to. Every name in
#: ``SECRET_PATTERNS`` must appear here; ``test_classifier.py`` asserts it,
#: so a shape added to the SDK cannot arrive silently unclassified and be
#: dropped on the floor.
_SDK_LABEL: dict[str, str] = {
    "aws_access_key": "secrets",
    "github_token": "secrets",
    "openai_key": "secrets",
    "slack_token": "secrets",
    "private_key": "secrets",
    "jwt": "secrets",
    "email": "personal_data",
    "credit_card": "financial",
}

#: Personal data beyond the shared list. Deliberately narrow: an address and
#: a phone number have a shape, where "a name" does not, and a loose rule
#: would label every conversation and make the signal worthless.
_PERSONAL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("phone_number", re.compile(r"(?<![\d-])\+?\d{1,3}[\s.-]\(?\d{2,4}\)?[\s.-]\d{3,4}[\s.-]\d{3,4}(?![\d-])")),
    ("postal_address", re.compile(r"\b\d{1,5}\s+[A-Z][a-z]+\s+(?:Street|St|Avenue|Ave|Road|Rd|Lane|Ln|Boulevard|Blvd)\b")),
)

#: Regulated identifiers, whose presence in an AI chat is a compliance event
#: on its own.
_REGULATED_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("us_ssn", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")),
    ("nhs_number", re.compile(r"\bNHS\s*(?:no\.?|number)?\s*:?\s*\d{3}\s?\d{3}\s?\d{4}\b", re.I)),
    ("passport_number", re.compile(r"\bpassport\s*(?:no\.?|number)?\s*:?\s*[A-Z0-9]{6,9}\b", re.I)),
    ("medical_record_number", re.compile(r"\b(?:MRN|medical\s+record\s+(?:no\.?|number))\s*:?\s*[A-Z0-9-]{4,16}\b", re.I)),
)

#: Financial beyond the shared card shape.
_FINANCIAL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")),
    ("us_bank_routing", re.compile(r"\b(?:routing|ABA)\s*(?:no\.?|number)?\s*:?\s*\d{9}\b", re.I)),
)

_EXTRA_PATTERNS: tuple[tuple[str, tuple[tuple[str, re.Pattern[str]], ...]], ...] = (
    ("personal_data", _PERSONAL_PATTERNS),
    ("regulated", _REGULATED_PATTERNS),
    ("financial", _FINANCIAL_PATTERNS),
)


@dataclass(frozen=True)
class Classification:
    """What one chat evidenced, and nothing of what it said."""

    labels: tuple[str, ...] = ()
    #: Shape names only, never values. Same vocabulary the AI SDK emits for
    #: a prompt, so the two surfaces agree.
    shapes: tuple[str, ...] = ()
    snippet: str | None = None
    snippet_truncated: bool = False
    #: Counted here rather than re-derived by a caller. A meter asserted
    #: against a second call to the thing being measured measures nothing.
    messages_examined: int = 0
    messages_matched: int = 0

    @property
    def secret_kinds(self) -> tuple[str, ...]:
        """The subset of shapes that are credentials."""
        return tuple(s for s in self.shapes if _SDK_LABEL.get(s) == "secrets")


def _luhn(digits: str) -> bool:
    total, parity = 0, len(digits) % 2
    for index, char in enumerate(digits):
        value = int(char)
        if index % 2 == parity:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def classify_message(text: str) -> tuple[set[str], set[str], list[tuple[int, int, str]]]:
    """Labels, shape names, and the spans to mask, for one message."""
    labels: set[str] = set()
    shapes: set[str] = set()
    spans: list[tuple[int, int, str]] = []

    for name, pattern in SECRET_PATTERNS:
        label = _SDK_LABEL.get(name)
        if label is None:
            # A shape the SDK added and this module has not classified.
            # Skipped rather than guessed, and the test above fails so it
            # cannot stay skipped. Guessing would put a credential in the
            # personal-data bucket, or worse, leave it unmasked.
            continue
        for match in pattern.finditer(text):
            # The SDK's card shape is digits-only, so it also matches order
            # ids and phone numbers. Luhn is what makes the financial label
            # believable; without it the classifier labels everything.
            if name == "credit_card" and not _luhn(re.sub(r"[ -]", "", match.group(0))):
                continue
            labels.add(label)
            shapes.add(name)
            spans.append((match.start(), match.end(), name))

    for label, patterns in _EXTRA_PATTERNS:
        for name, pattern in patterns:
            for match in pattern.finditer(text):
                labels.add(label)
                shapes.add(name)
                spans.append((match.start(), match.end(), name))

    return labels, shapes, spans


def _mask(text: str, spans: list[tuple[int, int, str]]) -> str:
    """Replace every matched span with its shape name.

    Overlaps resolve to the longest span at each start, because an e-mail
    address inside a longer connection string must mask the string rather
    than leave half of it visible.
    """
    if not spans:
        return text
    ordered = sorted(spans, key=lambda s: (s[0], -(s[1] - s[0])))
    out: list[str] = []
    cursor = 0
    for start, end, name in ordered:
        if start < cursor:
            continue
        out.append(text[cursor:start])
        out.append(f"[{name}]")
        cursor = end
    out.append(text[cursor:])
    return "".join(out)


def classify_chat(messages: list[str]) -> Classification:
    """Classify a conversation, keeping only labels, shapes and a snippet.

    ``messages`` is read and discarded. Nothing in the returned object can
    reconstruct it: every match is masked before the snippet is cut.
    """
    labels: set[str] = set()
    shapes: set[str] = set()
    snippet: str | None = None
    truncated = False
    examined = 0
    matched = 0

    for message in messages:
        examined += 1
        if not isinstance(message, str) or not message:
            continue
        message_labels, message_shapes, spans = classify_message(message)
        if not message_labels:
            continue
        matched += 1
        labels |= message_labels
        shapes |= message_shapes
        if snippet is None:
            masked = _mask(message, spans)
            # Centre the window on the first match so the cut keeps the
            # evidence rather than the greeting that preceded it. The
            # offset is measured in the *masked* string, since masking
            # changes every position after the first match.
            first = min(s[0] for s in spans)
            masked_offset = len(_mask(message[:first], [s for s in spans if s[1] <= first]))
            start = max(0, masked_offset - SNIPPET_MAX // 3)
            window = masked[start : start + SNIPPET_MAX]
            truncated = len(window) < len(masked)
            snippet = window

    return Classification(
        labels=tuple(sorted(labels)),
        shapes=tuple(sorted(shapes)),
        snippet=snippet,
        snippet_truncated=truncated,
        messages_examined=examined,
        messages_matched=matched,
    )
