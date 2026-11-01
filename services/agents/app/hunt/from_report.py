"""Turn a threat report into a reviewable hunt.

Wave 2, Phase 5.1.

An analyst pastes the URL of a vendor write-up. The platform fetches it,
pulls out the indicators and techniques **with where in the source each one
came from**, and the model drafts those into the existing closed hunt schema.
Nothing is executed and nothing is hunted until a person has looked at the
list.

Five constraints, and each one is a thing that goes wrong otherwise
-------------------------------------------------------------------
* **Off by default, per tenant.** Fetching a URL is outbound traffic from a
  security platform, and a deployment that never wants that must not acquire
  it by upgrading.
* **The URL goes through the existing guard, which is a validator and not a
  fetcher.** `validate_outbound_url` resolves the host and refuses private
  and metadata addresses; it does not bound a response, so the size cap and
  the timeout are this module's job. An unbounded read of an attacker-chosen
  URL is a memory exhaustion with extra steps.
* **The fetched text is untrusted and is fenced like runbook content**, in a
  per-run nonce envelope. It is somebody else's prose arriving over the
  network specifically so a model can read it, which is the most directly
  attacker-aimed channel in the product.
* **Indicators are extracted to a reviewable list carrying their location.**
  A bare list of forty strings cannot be checked; "line 212, in the
  Infrastructure section" can. The extraction is deterministic — regexes over
  the text — so the list a reviewer approves is not itself model output.
* **The model drafts into the closed schema, and values are bound as
  parameters.** It chooses fields and operators from fixed sets and supplies
  values; it never writes query text. `validate_plan` is the authority and
  refuses anything else.

Defanging, which a real report always uses
------------------------------------------
Vendor write-ups print `1.2.3[.]4` and `hxxps://` so a reader cannot click
them. Extraction refangs before matching, or it finds nothing in exactly the
documents this feature exists for — and the refanged value is recorded
alongside the literal text that appeared, so a reviewer sees both.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.playbook.ssrf_guard import SSRFError, validate_outbound_url
from app.prompting.envelope import EvidenceEnvelope

#: Hard ceiling on a fetched report. A vendor write-up is prose; anything
#: past this is not one, and the guard cannot bound a body it never reads.
MAX_REPORT_BYTES = 2 * 1024 * 1024

#: Whole-request deadline. Separate from the read loop's bound because a slow
#: trickle under the size cap is still a request that never ends.
FETCH_TIMEOUT_SECONDS = 20.0

#: How many indicators are offered for review. A report with four hundred is
#: a feed, not a report, and a reviewer cannot check four hundred strings.
MAX_INDICATORS = 60


class ReportFetchError(RuntimeError):
    """The report could not be fetched, with a reason an analyst can act on."""


class ReportDisabled(ReportFetchError):
    """This tenant has not enabled fetching reports.

    Its own class so a caller renders "your administrator has not enabled
    this" rather than a network error, which would send somebody to debug
    connectivity that was never attempted.
    """


@dataclass(frozen=True)
class Indicator:
    """One extracted indicator, and where it was found.

    ``literal`` is the text exactly as the report printed it, ``value`` is
    the refanged form. Both are kept: a reviewer checking the source needs
    the string they will actually see on the page.
    """

    kind: str
    value: str
    literal: str
    line: int
    excerpt: str


@dataclass
class ReportDraft:
    """What a reviewer is shown before anything is hunted."""

    url: str
    byte_size: int
    content_sha256: str
    indicators: list[Indicator] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    truncated: bool = False
    skipped_indicators: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "byte_size": self.byte_size,
            "content_sha256": self.content_sha256,
            "indicators": [
                {"kind": i.kind, "value": i.value, "literal": i.literal, "line": i.line, "excerpt": i.excerpt} for i in self.indicators
            ],
            "techniques": list(self.techniques),
            "truncated": self.truncated,
            "skipped_indicators": self.skipped_indicators,
        }


# ── Fetching ────────────────────────────────────────────────────────────────


async def fetch_report(
    url: str,
    *,
    enabled: bool,
    max_bytes: int = MAX_REPORT_BYTES,
    timeout: float = FETCH_TIMEOUT_SECONDS,
    client: httpx.AsyncClient | None = None,
) -> tuple[str, bool]:
    """Fetch ``url`` under the SSRF guard and a hard size bound.

    Returns ``(text, truncated)``. ``enabled`` is the per-tenant switch and
    is a required keyword rather than a default, so a caller cannot acquire
    outbound fetching by forgetting to pass it.

    The body is read in chunks and abandoned the moment it passes
    ``max_bytes``; a `Content-Length` is **not** trusted for this, because it
    is a claim by the server being fetched.
    """
    if not enabled:
        raise ReportDisabled(
            "fetching threat reports is not enabled for this tenant. An administrator "
            "turns it on in Settings; it is off by default because it is outbound traffic."
        )

    try:
        safe_url = validate_outbound_url(url)
    except SSRFError as exc:
        raise ReportFetchError(f"refusing to fetch that URL: {exc}") from exc

    owns_client = client is None
    client = client or httpx.AsyncClient(timeout=timeout, follow_redirects=False)
    try:
        chunks: list[bytes] = []
        total = 0
        truncated = False
        # `follow_redirects` is off deliberately: a redirect is a second URL
        # the guard never saw, which is the standard way past an allowlist.
        async with client.stream("GET", safe_url, timeout=timeout) as response:
            if response.status_code >= 400:
                raise ReportFetchError(f"the report URL answered {response.status_code}")
            async for chunk in response.aiter_bytes():
                if total + len(chunk) > max_bytes:
                    chunks.append(chunk[: max_bytes - total])
                    truncated = True
                    break
                chunks.append(chunk)
                total += len(chunk)
    except httpx.HTTPError as exc:
        raise ReportFetchError(f"could not fetch the report: {exc}") from exc
    finally:
        if owns_client:
            await client.aclose()

    return b"".join(chunks).decode("utf-8", errors="replace"), truncated


# ── Extraction ──────────────────────────────────────────────────────────────

_REFANG = (
    ("[.]", "."),
    ("(.)", "."),
    ("[:]", ":"),
    ("[//]", "//"),
    ("hxxp", "http"),
    ("hXXp", "http"),
)

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("sha256", re.compile(r"\b[a-fA-F0-9]{64}\b")),
    ("sha1", re.compile(r"\b[a-fA-F0-9]{40}\b")),
    ("md5", re.compile(r"\b[a-fA-F0-9]{32}\b")),
    ("ipv4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")),
    ("cve", re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)),
    ("domain", re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b")),
)

_TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

#: Domains that appear in every write-up and are nobody's indicator. Hunting
#: on one would match the whole estate, which reads as a confirmed compromise.
_DOMAIN_NOISE = frozenset(
    {
        "example.com",
        "github.com",
        "twitter.com",
        "x.com",
        "linkedin.com",
        "microsoft.com",
        "google.com",
        "mitre.org",
        "attack.mitre.org",
        "wikipedia.org",
        "virustotal.com",
    }
)

#: File extensions a domain regex matches but which are filenames.
_NOT_A_DOMAIN = re.compile(r"\.(?:exe|dll|ps1|sh|py|js|zip|rar|docx?|xlsx?|pdf|png|jpe?g|html?|txt|json|yaml|yml)$", re.IGNORECASE)


def _refang(text: str) -> str:
    out = text
    for needle, replacement in _REFANG:
        out = out.replace(needle, replacement)
    return out


def _excerpt(line_text: str, limit: int = 160) -> str:
    collapsed = " ".join(line_text.split())
    return collapsed if len(collapsed) <= limit else collapsed[: limit - 1] + "…"


def extract_indicators(text: str, *, limit: int = MAX_INDICATORS) -> tuple[list[Indicator], list[str], int]:
    """Pull indicators and ATT&CK techniques out of report text.

    Deterministic by construction — regexes, not a model — so the list a
    reviewer approves is not itself model output. Returns
    ``(indicators, techniques, skipped)``; ``skipped`` is reported rather
    than silently dropped, because a reviewer told "here are 60" would
    otherwise believe that was all of them.
    """
    found: list[Indicator] = []
    seen: set[tuple[str, str]] = set()
    techniques: list[str] = []
    skipped = 0

    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        refanged = _refang(raw_line)
        for technique in _TECHNIQUE.findall(refanged):
            upper = technique.upper()
            if upper not in techniques:
                techniques.append(upper)

        for kind, pattern in _PATTERNS:
            for match in pattern.finditer(refanged):
                value = match.group(0)
                if kind == "domain":
                    lowered = value.lower()
                    if lowered in _DOMAIN_NOISE or _NOT_A_DOMAIN.search(lowered):
                        continue
                    value = lowered
                elif kind in {"sha256", "sha1", "md5", "cve"}:
                    value = value.upper() if kind == "cve" else value.lower()

                key = (kind, value)
                if key in seen:
                    continue
                seen.add(key)
                if len(found) >= limit:
                    skipped += 1
                    continue
                found.append(
                    Indicator(
                        kind=kind,
                        value=value,
                        literal=match.group(0) if refanged == raw_line else value,
                        line=line_no,
                        excerpt=_excerpt(raw_line),
                    )
                )

    return found, techniques, skipped


# ── Fencing ─────────────────────────────────────────────────────────────────


def fence_report(text: str, *, nonce: str, max_chars: int = 20_000) -> str:
    """Fence report text for a prompt, exactly as runbook content is fenced.

    Uses :class:`EvidenceEnvelope` rather than the plain wrapper so the block
    carries the run's nonce: this is prose fetched from the open internet
    specifically so a model can read it, which makes it the most directly
    attacker-aimed channel in the product.
    """
    return EvidenceEnvelope.wrap(
        text,
        nonce=nonce,
        source="threat_report",
        max_body_chars=max_chars,
    ).render()


# ── Drafting ────────────────────────────────────────────────────────────────

#: Which hunt field an indicator kind belongs in. A closed map: an indicator
#: whose kind has no field is **not** hunted on a guessed one, because a
#: hash searched as a hostname matches nothing and reads as "clean".
INDICATOR_FIELDS: dict[str, str] = {
    "ipv4": "destination_ip",
    "domain": "destination_domain",
    "sha256": "file_hash",
    "sha1": "file_hash",
    "md5": "file_hash",
}


def draft_clauses(indicators: list[Indicator], *, allowed_fields: frozenset[str]) -> tuple[list[dict[str, str]], list[str]]:
    """Turn approved indicators into closed-schema clauses.

    Returns ``(clauses, refusals)``. Values are carried as *values* — the
    platform binds them as parameters when it compiles — and the operator is
    always `equals`, because an indicator is an exact match and anything
    looser is a different hunt from the one the reviewer approved.

    `allowed_fields` is passed in rather than imported so the caller supplies
    whatever the configured schema actually accepts; a field this module
    believed in but the schema does not would produce a plan that fails
    validation after a human approved it.
    """
    clauses: list[dict[str, str]] = []
    refusals: list[str] = []
    for indicator in indicators:
        field_name = INDICATOR_FIELDS.get(indicator.kind)
        if field_name is None:
            refusals.append(f"{indicator.kind} {indicator.value!r}: no hunt field carries this kind of indicator")
            continue
        if field_name not in allowed_fields:
            refusals.append(f"{indicator.kind} {indicator.value!r}: the hunt schema has no {field_name!r} field on this deployment")
            continue
        clauses.append({"field": field_name, "operator": "equals", "value": indicator.value})
    return clauses, refusals


__all__ = [
    "FETCH_TIMEOUT_SECONDS",
    "INDICATOR_FIELDS",
    "MAX_INDICATORS",
    "MAX_REPORT_BYTES",
    "Indicator",
    "ReportDisabled",
    "ReportDraft",
    "ReportFetchError",
    "draft_clauses",
    "extract_indicators",
    "fence_report",
    "fetch_report",
]
