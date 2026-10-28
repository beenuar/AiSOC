"""What the headers of a reported message say, and what they refuse to say.

Depth 7.2: "headers, sender authentication results, URLs and attachments go
through the existing sandbox providers and enrichment, cited in the ledger".
This module is the headers-and-authentication half.

The one rule that shapes everything here
-----------------------------------------
**An absent header is not a passing one.** SPF, DKIM and DMARC each have a
third state that matters more than the other two put together: *nobody
checked*. A message with no ``Authentication-Results`` has not passed SPF — it
has not been evaluated, usually because it never crossed a boundary that
evaluates it. Rendering that as a green tick is the same defect as a phishing
verdict carrying no attachment indicator, which the submit path already
refuses to produce.

So every finding here carries a three-valued result, ``pass`` / ``fail`` /
``not_evaluated``, and the summary counts the third separately rather than
folding it into either side.

What is parsed, and why each one
---------------------------------
* **Authentication-Results** (RFC 8601) — the receiving boundary's own verdict
  on SPF, DKIM and DMARC. The most load-bearing header in a phishing triage
  and the one most often missing.
* **Received-SPF** — a second, older statement of the SPF result. Read as a
  fallback only, because when the two disagree the ``Authentication-Results``
  one is the boundary's considered answer.
* **Return-Path against From** — a mismatch is how the envelope sender and the
  displayed sender come apart, which is most of what SPF alignment is about.
  Common and benign on mailing lists, which is why it is `informational`
  rather than a finding on its own.
* **Reply-To against From** — the shape of a reply-to-me redirect, and the one
  an analyst asks about first in a business-email-compromise case.
* **Display name against address** — a display name containing an address that
  is not the sender's is impersonation with no ambiguity about intent.
* **Received hop count** — not a verdict, a *measurement*. One hop on a
  message claiming to be from a large provider is odd; so are twelve.

Severity is deliberately not computed here
-------------------------------------------
This module answers "what do the headers say". Deciding what that is worth is
the triage path's job, and a module that both measured and judged would make
the judgement unauditable. The caller gets findings and a count.

Nothing here reaches the network. Header analysis on a reported message must
work on a deployment with no provider configured and no outbound access, and
it does.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email.utils import parseaddr
from enum import Enum
from typing import Any

__all__ = [
    "AuthMethod",
    "AuthResult",
    "HeaderAnalysis",
    "HeaderFinding",
    "analyse_headers",
]


class AuthResult(str, Enum):
    """Three values, and the third is the point.

    ``NOT_EVALUATED`` is not a failure and it is emphatically not a pass. It
    means no receiving boundary recorded a verdict, which on a forwarded
    report is common and on a direct delivery is itself worth noticing.
    """

    PASS = "pass"
    FAIL = "fail"
    NOT_EVALUATED = "not_evaluated"


class AuthMethod(str, Enum):
    SPF = "spf"
    DKIM = "dkim"
    DMARC = "dmarc"


#: Result tokens RFC 8601 defines, mapped onto the three states. ``neutral``,
#: ``none``, ``policy``, ``permerror`` and ``temperror`` are **not** passes:
#: each one means the check did not reach a verdict, and treating them as
#: passes is how a message with a broken SPF record reads as authenticated.
_RESULT_TOKENS: dict[str, AuthResult] = {
    "pass": AuthResult.PASS,
    "fail": AuthResult.FAIL,
    "softfail": AuthResult.FAIL,
    "hardfail": AuthResult.FAIL,
    "none": AuthResult.NOT_EVALUATED,
    "neutral": AuthResult.NOT_EVALUATED,
    "policy": AuthResult.NOT_EVALUATED,
    "permerror": AuthResult.NOT_EVALUATED,
    "temperror": AuthResult.NOT_EVALUATED,
}

_AUTH_CLAUSE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)
_RECEIVED_SPF = re.compile(r"^\s*([a-z]+)", re.IGNORECASE)
#: An address embedded in a display name. Deliberately narrow: it must look
#: like an address, because "Billing (accounts)" is not impersonation.
#:
#: The lookbehind pins every match attempt to the *start* of a local-part
#: run. Without it the unanchored scan retried from each interior position
#: of a long run and re-consumed the tail every time — quadratic, measured
#: at 33 s for a 128 KB display name, which an authenticated reporter
#: controls and which this module processes synchronously on the event
#: loop (GHSA-9m2j-23jf-gg3p). Interior starts now fail in O(1), the same
#: property the leading ``\b`` already gives the other scans in this
#: package. No match changes: an interior start could only ever find an
#: address the run-start attempt also finds, because the suffix after the
#: ``@`` decides both.
_ADDRESS_IN_NAME = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+\.[\w.-]+")

#: A display name is analysed on its first kilobyte only. RFC 5322 caps a
#: header line at 998 octets, so a display name beyond this is already
#: pathological; the cap bounds the scan independently of the pattern's
#: complexity and keeps the impersonation finding's ``evidence`` — which
#: embeds the display name verbatim, and is stored and rendered — out of
#: the megabyte range on a crafted report.
_MAX_DISPLAY_LEN = 1024


@dataclass(frozen=True)
class HeaderFinding:
    """One observation. ``kind`` is stable; ``detail`` is for a human."""

    kind: str
    detail: str
    #: ``finding`` means something is wrong; ``informational`` means something
    #: is worth knowing and is routinely benign. Separated so a console can
    #: show the first without burying it in the second.
    severity_hint: str = "finding"
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class HeaderAnalysis:
    authentication: dict[str, str]
    findings: tuple[HeaderFinding, ...]
    hop_count: int
    #: Headers that were not present at all. Published rather than inferred
    #: from an empty value, because "the header said nothing" and "there was
    #: no header" send an analyst to different places: the first is a
    #: boundary that evaluated and declined, the second is a message that
    #: crossed no boundary which evaluates.
    missing_headers: tuple[str, ...]

    @property
    def failed_methods(self) -> tuple[str, ...]:
        return tuple(sorted(m for m, r in self.authentication.items() if r == AuthResult.FAIL.value))

    @property
    def unevaluated_methods(self) -> tuple[str, ...]:
        return tuple(sorted(m for m, r in self.authentication.items() if r == AuthResult.NOT_EVALUATED.value))

    def as_indicators(self) -> list[dict[str, Any]]:
        """The shape ``aisoc_phishing_submissions.indicators`` already holds.

        Produced here rather than in the endpoint so the wording an analyst
        reads is beside the logic that earned it. Every unevaluated method
        produces an indicator of its own: silence about a check nobody ran is
        the thing this module exists to prevent.
        """
        out: list[dict[str, Any]] = []
        for method, result in sorted(self.authentication.items()):
            if result == AuthResult.FAIL.value:
                note = f"{method.upper()} failed at the receiving boundary"
            elif result == AuthResult.NOT_EVALUATED.value:
                note = f"{method.upper()} was not evaluated: no receiving boundary recorded a verdict. This is not a pass."
            else:
                note = f"{method.upper()} passed at the receiving boundary"
            out.append({"kind": "header", "value": f"{method}={result}", "note": note})
        for finding in self.findings:
            out.append(
                {
                    "kind": "header",
                    "value": finding.kind,
                    "note": finding.detail,
                    "severity_hint": finding.severity_hint,
                    **({"evidence": finding.evidence} if finding.evidence else {}),
                }
            )
        return out

    def summary(self) -> str:
        if not self.authentication:
            return (
                "No sender-authentication results are present in this message's headers. "
                "Nothing was checked, which is not the same as nothing being wrong."
            )
        parts = [f"{m.upper()} {r}" for m, r in sorted(self.authentication.items())]
        return "; ".join(parts) + f"; {len(self.findings)} header finding(s) across {self.hop_count} delivery hop(s)"


def _first_address(raw: str) -> str:
    _name, addr = parseaddr(raw or "")
    return addr.strip().lower()


def _display_name(raw: str) -> str:
    name, _addr = parseaddr(raw or "")
    return name.strip()


def _domain_of(address: str) -> str:
    return address.rsplit("@", 1)[-1].lower() if "@" in address else ""


def _parse_authentication(headers: dict[str, str]) -> tuple[dict[str, str], list[str]]:
    """``{method: result}`` plus the headers that were absent.

    Both ``Authentication-Results`` and its ARC-sealed sibling are read, in
    that order. ARC carries a *forwarder's* record of what an earlier boundary
    concluded, which is exactly the case a reported forward presents and which
    a reader of the plain header alone would see as "not evaluated".
    """
    results: dict[str, str] = {}
    missing: list[str] = []

    combined = "\n".join(filter(None, (headers.get("authentication-results", ""), headers.get("arc-authentication-results", ""))))
    if not combined:
        missing.append("Authentication-Results")
    for method, token in _AUTH_CLAUSE.findall(combined):
        key = method.lower()
        value = _RESULT_TOKENS.get(token.lower(), AuthResult.NOT_EVALUATED).value
        # First statement wins. A multi-hop header lists the outermost
        # boundary first, and that is the one whose verdict the recipient's
        # mail system acted on.
        results.setdefault(key, value)

    received_spf = headers.get("received-spf", "")
    if AuthMethod.SPF.value not in results:
        if received_spf:
            match = _RECEIVED_SPF.match(received_spf)
            token = match.group(1).lower() if match else ""
            results[AuthMethod.SPF.value] = _RESULT_TOKENS.get(token, AuthResult.NOT_EVALUATED).value
        else:
            missing.append("Received-SPF")

    # Every method the product reports on gets an entry, so a console cannot
    # render "SPF fail" and silently omit DMARC because no clause mentioned
    # it. Absent is `not_evaluated`, which is the honest word for it.
    for method in (AuthMethod.SPF, AuthMethod.DKIM, AuthMethod.DMARC):
        results.setdefault(method.value, AuthResult.NOT_EVALUATED.value)
    return results, missing


def analyse_headers(headers: dict[str, str], *, reported_sender: str = "") -> HeaderAnalysis:
    """Read a reported message's headers. No network, no provider, no model.

    ``headers`` is the lowercased name → value mapping
    :class:`app.services.phishing.intake.ReportedMessage` carries. Repeated
    headers arrive newline-joined, which is how the hop count is recovered.
    """
    normalised = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    authentication, missing = _parse_authentication(normalised)
    findings: list[HeaderFinding] = []

    from_header = normalised.get("from", "")
    from_address = _first_address(from_header) or reported_sender.lower()
    from_domain = _domain_of(from_address)

    return_path = _first_address(normalised.get("return-path", ""))
    if return_path and from_address and _domain_of(return_path) != from_domain:
        findings.append(
            HeaderFinding(
                kind="return_path_mismatch",
                detail=(
                    f"The envelope sender ({return_path}) is on a different domain from the displayed "
                    f"sender ({from_address}). Routine on mailing lists and bulk senders; it is also the "
                    f"shape SPF alignment exists to catch."
                ),
                severity_hint="informational",
                evidence={"return_path": return_path, "from": from_address},
            )
        )

    reply_to = _first_address(normalised.get("reply-to", ""))
    if reply_to and from_address and reply_to != from_address and _domain_of(reply_to) != from_domain:
        findings.append(
            HeaderFinding(
                kind="reply_to_redirect",
                detail=(
                    f"Replies go to {reply_to}, on a different domain from the sender ({from_address}). "
                    f"This is the mechanism of a reply-chain redirect."
                ),
                evidence={"reply_to": reply_to, "from": from_address},
            )
        )

    display = _display_name(from_header)[:_MAX_DISPLAY_LEN]
    embedded = _ADDRESS_IN_NAME.findall(display)
    impersonated = [a.lower() for a in embedded if a.lower() != from_address]
    if impersonated:
        findings.append(
            HeaderFinding(
                kind="display_name_impersonation",
                detail=(
                    f"The display name contains {impersonated[0]}, which is not the sending address "
                    f"({from_address}). A mail client shows the display name."
                ),
                evidence={"display_name": display, "claimed": impersonated[0], "actual": from_address},
            )
        )

    received = normalised.get("received", "")
    hop_count = len([line for line in received.split("\n") if line.strip()]) if received else 0
    if hop_count == 0:
        missing.append("Received")
        findings.append(
            HeaderFinding(
                kind="no_received_chain",
                detail=(
                    "No Received headers are present, so the delivery path cannot be reconstructed. On a "
                    "report that arrived as an attachment or through an API this is expected; on a direct "
                    "delivery it is not."
                ),
                severity_hint="informational",
            )
        )

    for method in sorted(authentication):
        if authentication[method] == AuthResult.FAIL.value:
            findings.append(
                HeaderFinding(
                    kind=f"{method}_fail",
                    detail=f"{method.upper()} failed at the receiving boundary for {from_domain or 'the sending domain'}.",
                    evidence={"method": method, "domain": from_domain},
                )
            )

    return HeaderAnalysis(
        authentication=authentication,
        findings=tuple(findings),
        hop_count=hop_count,
        missing_headers=tuple(dict.fromkeys(missing)),
    )
