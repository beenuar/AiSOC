"""When a customer file may leave the deployment, and what the operator agreed to.

Uploading a customer file to a third party is a disclosure. Not a lookup with a
side effect, not a cache miss: the file leaves, and for at least one provider
in this tree it then becomes readable by anyone. So the decision is modelled as
a decision, with four refusals that are checked in a fixed order and an audit
row written whichever way it goes.

The order is load-bearing:

1. **Air-gap.** A deployment that declares itself air-gapped may use local
   providers only. Checked first because no amount of tenant consent overrides
   it, and because the answer does not depend on the tenant.
2. **Can the provider even take it.** A provider that accepts no uploads is a
   refusal with a different meaning from a policy refusal, and conflating them
   would have an operator hunting for a consent screen that would not help.
3. **Hash first.** A digest discloses nothing, so it is always tried, and a hit
   means the upload is unnecessary rather than forbidden. This is the case the
   plan puts first and it is also the common one.
4. **Tenant consent.** Off by default, per tenant *and* per provider, recorded
   with who agreed and to what text.

Per tenant per provider, not per tenant
---------------------------------------
Consent is about where the file goes. An operator who is content to send a
sample to a sandbox they run in their own rack has agreed to nothing about a
hosted service, and a single per-tenant flag would treat those as the same
question. The pair ``(tenant, provider)`` is the key for that reason.

Consent text is versioned
-------------------------
:data:`CONSENT_TEXT_VERSION` travels onto the row. If the disclosure changes,
what a tenant previously agreed to did not, and a stored boolean with no record
of the sentence behind it cannot tell anyone which one it was.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

from app.services.sandbox.types import ProviderCapabilities

__all__ = [
    "CONSENT_TEXT_VERSION",
    "UploadDecision",
    "UploadRefusal",
    "consent_text_for",
    "evaluate_upload",
]

#: Bump when any wording in :func:`consent_text_for` changes. Stored on every
#: consent row so an audit can say which text was agreed to.
CONSENT_TEXT_VERSION = "2026-09-26.1"


class UploadRefusal(str, enum.Enum):
    """Why an upload was refused. The console renders a different remedy for each."""

    AIRGAPPED = "airgapped"
    PROVIDER_CANNOT_UPLOAD = "provider_cannot_upload"
    ALREADY_KNOWN = "already_known"
    TENANT_NOT_CONSENTED = "tenant_not_consented"


@dataclass(frozen=True, slots=True)
class UploadDecision:
    """The answer, and enough of the reasoning to log and to render.

    ``allowed`` is never ``True`` by omission: every construction site sets it
    explicitly, and the only place it becomes ``True`` is :func:`evaluate_upload`
    after all four checks have passed.
    """

    allowed: bool
    reason: str
    refusal: UploadRefusal | None = None
    provider: str = ""
    #: Set when the decision was reached because a hash lookup already
    #: answered the question. Carries the disclosure count to zero.
    satisfied_by_hash_lookup: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "refusal": self.refusal.value if self.refusal else None,
            "provider": self.provider,
            "satisfied_by_hash_lookup": self.satisfied_by_hash_lookup,
        }


def consent_text_for(capabilities: ProviderCapabilities) -> str:
    """The sentence an operator has to agree to before files go to this provider.

    Written to be read by the person clicking it, which means saying what
    happens rather than naming a policy. The first commercial adapter in this
    tree returns ``visibility: "public"`` and ``tlp: "clear"`` on a stored
    report, so for a provider that declares
    ``submissions_are_public_by_default`` the text says *public* in those
    words. "Shared with the vendor" would be true and would also be the wrong
    impression.
    """
    lines = [
        f"Enabling uploads lets AiSOC send files from this tenant to {capabilities.name} for analysis.",
        "A file may contain customer data, credentials, personal data or intellectual property. "
        "AiSOC cannot inspect a file to decide whether it does.",
    ]
    if capabilities.submissions_are_public_by_default:
        lines.append(
            f"{capabilities.name} publishes submitted samples by default: an uploaded file and its report become "
            "readable by anyone on the internet, not only by the vendor. Treat every upload as a public disclosure "
            "that cannot be recalled."
        )
    elif not capabilities.local:
        lines.append(
            f"{capabilities.name} runs outside this deployment. An uploaded file leaves your infrastructure and is "
            "retained under that vendor's terms."
        )
    else:
        lines.append(
            f"{capabilities.name} runs inside your own network, so an uploaded file does not leave your "
            "infrastructure. It is still written to that system's storage."
        )
    lines.append(
        "AiSOC always looks a file's SHA-256 up first and only uploads when the provider has not seen it. "
        "Every upload and every refusal is recorded against this tenant."
    )
    return " ".join(lines)


def evaluate_upload(
    *,
    capabilities: ProviderCapabilities,
    airgapped: bool,
    tenant_uploads_enabled: bool,
    hash_already_known: bool,
) -> UploadDecision:
    """Decide whether one file may be sent to one provider for one tenant.

    Pure, and takes the tenant's setting as an argument rather than reading it,
    so the gate and the tests can drive every combination without a database.
    The caller is responsible for having *done* the hash lookup: passing
    ``hash_already_known=False`` without having looked is how the hash-first
    rule would get skipped, which is why the route helper in
    :mod:`app.services.sandbox.service` owns both steps rather than exposing
    them separately.
    """
    provider = capabilities.name

    if airgapped and not capabilities.local:
        return UploadDecision(
            allowed=False,
            reason=(f"Air-gapped mode is on and {provider} runs outside this deployment. Only local analysis providers are permitted."),
            refusal=UploadRefusal.AIRGAPPED,
            provider=provider,
        )

    if not capabilities.supports_file_submission:
        return UploadDecision(
            allowed=False,
            reason=f"{provider} does not accept file submissions; it can only answer hash lookups.",
            refusal=UploadRefusal.PROVIDER_CANNOT_UPLOAD,
            provider=provider,
        )

    if hash_already_known:
        return UploadDecision(
            allowed=False,
            reason=f"{provider} has already analysed this file. The existing report was used and nothing was uploaded.",
            refusal=UploadRefusal.ALREADY_KNOWN,
            provider=provider,
            satisfied_by_hash_lookup=True,
        )

    if not tenant_uploads_enabled:
        return UploadDecision(
            allowed=False,
            reason=(
                f"Uploading files to {provider} is disabled for this tenant. An administrator must enable it in "
                "Settings, which records who agreed to the disclosure."
            ),
            refusal=UploadRefusal.TENANT_NOT_CONSENTED,
            provider=provider,
        )

    return UploadDecision(allowed=True, reason=f"Tenant policy permits uploads to {provider}.", provider=provider)
