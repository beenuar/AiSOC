"""Redaction for AI telemetry, applied before anything leaves the process.

Prompts and model responses are the most sensitive payload in an AI estate.
They routinely contain whatever the user pasted in, whatever a retrieval step
pulled out of an internal store, and whatever the model then said about it. A
SOC needs to detect abuse of the AI without becoming the largest single
collection of that text in the organisation.

So the default is to send a hash and a length, never the content. That is
enough to answer the questions detection actually asks — is this the same
prompt we saw fifty times in the last minute, did the response body change
after an injection attempt, is this prompt anomalously long for this agent —
without retaining the text.

Full capture exists because incident response sometimes genuinely needs the
words, but it is opt-in per call site and per deployment, and even then the
common secret shapes are masked first. Opting in is a decision someone should
have to make deliberately rather than inherit from a default.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import Enum


class CaptureMode(str, Enum):
    """How much of a prompt or response leaves the process."""

    #: Hash and length only. The default.
    HASHED = "hashed"
    #: Content included, with secret-shaped substrings masked.
    MASKED = "masked"
    #: Content included verbatim. Requires an explicit opt-in.
    FULL = "full"


#: Patterns masked before any content is sent, in MASKED mode.
#:
#: Deliberately narrow and high-confidence. A greedy redactor that mangles
#: ordinary prose trains people to turn redaction off, which is a worse
#: outcome than a narrow one that they leave on.
#: The declared type used to be
#: ``tuple[tuple[str, re.Pattern[str]], None | str] | tuple``, whose first
#: member is a two-element tuple — structurally impossible for the eight-pair
#: value below, so it only ever matched through the bare ``| tuple``. That
#: erases the element type to ``Any``, which is why nothing objected to
#: ``pattern.subn`` on something typed as possibly a ``str``. In a masking
#: path, a checker that has been silently switched off is worse than none.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("email", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b")),
    ("credit_card", re.compile(r"\b(?:\d[ -]*?){13,16}\b")),
)


@dataclass(frozen=True)
class RedactedText:
    """What the SDK will actually transmit for a prompt or response."""

    sha256: str
    length: int
    #: Present only when the caller opted into MASKED or FULL.
    content: str | None = None
    #: Names of the secret patterns that matched, in MASKED mode. Useful on
    #: its own: "this prompt contained an AWS key" is a finding even when the
    #: key itself is never sent.
    redacted_kinds: tuple[str, ...] = ()


def redact(text: str | None, mode: CaptureMode = CaptureMode.HASHED) -> RedactedText:
    """Reduce `text` to what may leave the process under `mode`."""
    if text is None:
        return RedactedText(sha256="", length=0)

    digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()

    if mode is CaptureMode.HASHED:
        return RedactedText(sha256=digest, length=len(text))

    if mode is CaptureMode.FULL:
        return RedactedText(sha256=digest, length=len(text), content=text)

    masked = text
    kinds: list[str] = []
    for name, pattern in _SECRET_PATTERNS:
        masked, count = pattern.subn(f"[redacted:{name}]", masked)
        if count:
            kinds.append(name)
    return RedactedText(sha256=digest, length=len(text), content=masked, redacted_kinds=tuple(kinds))


def secret_kinds(text: str | None) -> tuple[str, ...]:
    """Which secret shapes appear in `text`, without returning any of it.

    Callable in HASHED mode, where the content is never transmitted: knowing a
    prompt contained a private key is actionable even if the SOC never sees it.
    """
    if not text:
        return ()
    return tuple(name for name, pattern in _SECRET_PATTERNS if pattern.search(text))
