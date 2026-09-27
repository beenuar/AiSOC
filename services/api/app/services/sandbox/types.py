"""The vocabulary every file and URL analysis provider is translated into.

Why a vocabulary and not a payload
----------------------------------
A sandbox report is the most vendor-shaped object in this product. One vendor
calls its judgement ``verdict``, another ``score``, another ``malscore``; one
returns ATT&CK under ``ttps``, another under ``attackTechniques``, another not
at all. Passing any one of those through to the console and to the agent makes
the first provider wired the de-facto interface, and the second adapter then
gets written to imitate it.

So the interface owns the words. A verdict, a score, signatures, IOCs and an
ATT&CK mapping are what a caller may ask for, and each provider maps its own
payload onto them. Nothing here is named after a vendor, and nothing here
exists because one vendor happened to return it.

Absent is not zero
------------------
The rule that makes this usable is :data:`UNAVAILABLE`. Three states have to
stay distinguishable and two of them look identical if the type is a list:

``[]`` / ``0``
    The provider computed this and the answer is none. The sample contacted no
    domains.
:data:`UNAVAILABLE`
    The provider does not compute this, or the stage that would have computed
    it did not run. Nothing is known either way.
``None`` on an optional field
    Reserved for "this provider has no such concept at all".

Collapsing the middle one into the first is how a sandbox report turns into a
clean bill of health for a sample nobody detonated. A concrete instance is in
the tree: the first commercial adapter returns an empty ATT&CK list alongside
``behavior.analyzed = false``, because the file type could not be identified
and no guest was ever chosen. The techniques are absent because the stage did
not run, and reporting that as "no techniques" would be an invented negative.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Final, Literal, TypeVar

__all__ = [
    "UNAVAILABLE",
    "AnalysisState",
    "AttackTechnique",
    "Maybe",
    "ProviderCapabilities",
    "SandboxError",
    "SandboxIocs",
    "SandboxReport",
    "SandboxUnavailable",
    "SandboxVerdict",
    "Signature",
    "SubmissionReceipt",
    "Unavailable",
    "is_available",
]


class Unavailable:
    """Singleton for "not known", distinct from an empty result.

    Falsy on purpose, so ``if report.attack:`` is never accidentally true, but
    never equal to ``[]``, ``0`` or ``None``, so a caller that cares about the
    difference can ask for it.
    """

    _instance: Unavailable | None = None

    def __new__(cls) -> Unavailable:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __bool__(self) -> bool:
        return False

    def __repr__(self) -> str:
        return "UNAVAILABLE"

    def __reduce__(self) -> tuple[type[Unavailable], tuple[()]]:
        return (Unavailable, ())


UNAVAILABLE: Final[Unavailable] = Unavailable()

_T = TypeVar("_T")
#: A value the provider supplied, or :data:`UNAVAILABLE`.
Maybe = _T | Unavailable


def is_available(value: Maybe[_T]) -> bool:
    """True when ``value`` came from the provider rather than standing in for it."""
    return not isinstance(value, Unavailable)


class SandboxVerdict(str, enum.Enum):
    """The judgement, normalised across providers.

    ``UNKNOWN`` is a judgement the provider reached; a provider that reached no
    judgement returns :data:`UNAVAILABLE` for the field instead.
    """

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"


class AnalysisState(str, enum.Enum):
    """Where an analysis has got to.

    ``PENDING`` and ``RUNNING`` both mean "ask again later"; they are separate
    because a caller that has not yet been scheduled and one that is executing
    deserve different wording in front of an analyst. ``NOT_FOUND`` is the
    hash-lookup miss, which is a normal answer and not an error.
    """

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    NOT_FOUND = "not_found"

    @property
    def terminal(self) -> bool:
        return self in (AnalysisState.COMPLETED, AnalysisState.FAILED, AnalysisState.NOT_FOUND)


@dataclass(frozen=True, slots=True)
class Signature:
    """One named thing a provider observed or matched.

    Deliberately flat. A YARA hit, a behavioural signature and an engine
    detection are the same shape to a reader deciding whether to care, and
    keeping them one type is what stops the console growing a section per
    provider. ``source`` carries the provenance ("yara", "capa", "behaviour",
    an engine name) so nothing is lost by the flattening.
    """

    identifier: str
    source: str
    description: str = ""
    severity: str | None = None
    confidence: float | None = None


@dataclass(frozen=True, slots=True)
class AttackTechnique:
    technique_id: str
    name: str | None = None
    tactic: str | None = None


@dataclass(frozen=True, slots=True)
class SandboxIocs:
    """Indicators the analysis extracted.

    Every list is independently :data:`UNAVAILABLE`-able: a static-only pass
    can produce embedded URLs while knowing nothing about mutexes, and saying
    "no mutexes" there would be a claim it never made.
    """

    urls: Maybe[tuple[str, ...]] = UNAVAILABLE
    domains: Maybe[tuple[str, ...]] = UNAVAILABLE
    ipv4: Maybe[tuple[str, ...]] = UNAVAILABLE
    ipv6: Maybe[tuple[str, ...]] = UNAVAILABLE
    emails: Maybe[tuple[str, ...]] = UNAVAILABLE
    file_hashes: Maybe[tuple[str, ...]] = UNAVAILABLE
    file_paths: Maybe[tuple[str, ...]] = UNAVAILABLE
    registry_keys: Maybe[tuple[str, ...]] = UNAVAILABLE
    mutexes: Maybe[tuple[str, ...]] = UNAVAILABLE
    cves: Maybe[tuple[str, ...]] = UNAVAILABLE


@dataclass(frozen=True, slots=True)
class ProviderCapabilities:
    """What a provider can do, so a caller never offers what it cannot.

    ``local`` is the air-gap predicate and is a property of where the analysis
    runs, not of who wrote the adapter: a self-hosted open-source sandbox on
    the operator's own network is local, and a hosted service is not, however
    the credential is configured.
    """

    name: str
    local: bool
    supports_hash_lookup: bool = True
    supports_file_submission: bool = False
    supports_url_submission: bool = False
    #: True when a submitted sample is visible beyond the operator and the
    #: vendor. Drives the consent text, so it is a declared fact about the
    #: provider rather than something the upload path infers.
    submissions_are_public_by_default: bool = False
    description: str = ""


@dataclass(frozen=True, slots=True)
class SubmissionReceipt:
    """What a caller needs to come back for a result.

    ``handle`` is opaque and provider-scoped. It is deliberately not called a
    task id, a scan uuid or a job id, because it is all three depending on who
    answered, and giving it one vendor's name is how the next adapter ends up
    fabricating one.
    """

    provider: str
    handle: str
    state: AnalysisState
    #: What the analysis will be visible to once it completes, when the
    #: provider says. Recorded on the audit row, so an operator can answer
    #: "where did this file go" later.
    visibility: str | None = None
    poll_after_seconds: int = 15
    submitted_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class SandboxReport:
    """A provider's answer, in the interface's words.

    ``state`` leads because it is what a caller must branch on. A report whose
    state is ``PENDING`` carries no verdict and is not a benign one.
    """

    provider: str
    state: AnalysisState
    verdict: Maybe[SandboxVerdict] = UNAVAILABLE
    #: 0-100, higher is worse. ``UNAVAILABLE`` when the provider publishes no
    #: score; a provider with a different range normalises here rather than
    #: leaking its own.
    score: Maybe[int] = UNAVAILABLE
    signatures: Maybe[tuple[Signature, ...]] = UNAVAILABLE
    iocs: SandboxIocs = field(default_factory=SandboxIocs)
    attack: Maybe[tuple[AttackTechnique, ...]] = UNAVAILABLE
    sha256: str | None = None
    file_name: str | None = None
    file_type: str | None = None
    #: Where a human can read the full report, when there is such a place.
    report_url: str | None = None
    #: Who the completed analysis is visible to, in the provider's own words.
    visibility: str | None = None
    analyzed_at: datetime | None = None
    #: Why a section is missing, keyed by field name, e.g.
    #: ``{"attack": "behavioural stage did not run: unidentified_file_type"}``.
    #: An analyst asking "why is this blank" gets an answer instead of a guess.
    unavailable_reasons: dict[str, str] = field(default_factory=dict)

    def summary(self) -> dict[str, Any]:
        """A compact, JSON-safe projection for a prompt or an API response.

        Unavailable fields are rendered as the string ``"unavailable"`` rather
        than dropped, because a key that is simply missing reads to a model as
        a field it may infer.
        """

        def render(value: Maybe[Any]) -> Any:
            if isinstance(value, Unavailable):
                return "unavailable"
            if isinstance(value, enum.Enum):
                return value.value
            return value

        return {
            "provider": self.provider,
            "state": self.state.value,
            "verdict": render(self.verdict),
            "score": render(self.score),
            "signatures": (
                "unavailable"
                if isinstance(self.signatures, Unavailable)
                else [{"id": s.identifier, "source": s.source, "description": s.description} for s in self.signatures[:25]]
            ),
            "attack": (
                "unavailable"
                if isinstance(self.attack, Unavailable)
                else [{"technique_id": t.technique_id, "name": t.name} for t in self.attack]
            ),
            "iocs": {
                name: ("unavailable" if isinstance(value, Unavailable) else list(value[:50]))
                for name, value in (
                    ("urls", self.iocs.urls),
                    ("domains", self.iocs.domains),
                    ("ipv4", self.iocs.ipv4),
                    ("ipv6", self.iocs.ipv6),
                    ("emails", self.iocs.emails),
                    ("file_hashes", self.iocs.file_hashes),
                    ("file_paths", self.iocs.file_paths),
                    ("registry_keys", self.iocs.registry_keys),
                    ("mutexes", self.iocs.mutexes),
                    ("cves", self.iocs.cves),
                )
            },
            "sha256": self.sha256,
            "file_name": self.file_name,
            "report_url": self.report_url,
            "visibility": self.visibility,
            "unavailable_reasons": dict(self.unavailable_reasons),
        }


class SandboxError(RuntimeError):
    """Base class for every failure a provider can raise."""


class SandboxUnavailable(SandboxError):
    """The provider could not be reached, or refused to answer.

    Raised rather than returning a report, so no call site can mistake a
    failed check for a clean one. Callers that face a model or an analyst
    catch it and say "could not check"; see
    :mod:`app.services.sandbox.service`.
    """

    def __init__(self, provider: str, reason: str, *, kind: Literal["network", "auth", "rate_limit", "bad_response"] = "network") -> None:
        super().__init__(f"{provider}: {reason}")
        self.provider = provider
        self.reason = reason
        self.kind = kind
