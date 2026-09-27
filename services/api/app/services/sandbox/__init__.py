"""File and URL analysis behind one provider contract.

``types`` owns the vocabulary, ``base`` the contract, ``policy`` the decision
about whether a customer file may leave, ``service`` the hash-first sequencing
and the "could not check" rule, and ``providers/`` the adapters.
"""

from app.services.sandbox.base import SandboxProvider, guard_outbound_url
from app.services.sandbox.policy import (
    CONSENT_TEXT_VERSION,
    UploadDecision,
    UploadRefusal,
    consent_text_for,
    evaluate_upload,
)
from app.services.sandbox.registry import SandboxRegistry, build_registry
from app.services.sandbox.service import (
    SandboxOutcome,
    SandboxResult,
    analyse_file,
    analyse_url,
    lookup_hash,
    poll,
    sha256_of,
)
from app.services.sandbox.types import (
    UNAVAILABLE,
    AnalysisState,
    AttackTechnique,
    ProviderCapabilities,
    SandboxError,
    SandboxIocs,
    SandboxReport,
    SandboxUnavailable,
    SandboxVerdict,
    Signature,
    SubmissionReceipt,
    Unavailable,
    is_available,
)

__all__ = [
    "CONSENT_TEXT_VERSION",
    "UNAVAILABLE",
    "AnalysisState",
    "AttackTechnique",
    "ProviderCapabilities",
    "SandboxError",
    "SandboxIocs",
    "SandboxOutcome",
    "SandboxProvider",
    "SandboxRegistry",
    "SandboxReport",
    "SandboxResult",
    "SandboxUnavailable",
    "SandboxVerdict",
    "Signature",
    "SubmissionReceipt",
    "Unavailable",
    "UploadDecision",
    "UploadRefusal",
    "analyse_file",
    "analyse_url",
    "build_registry",
    "consent_text_for",
    "evaluate_upload",
    "guard_outbound_url",
    "is_available",
    "lookup_hash",
    "poll",
    "sha256_of",
]
