"""File and URL analysis, exposed to the model as a callable tool.

Lookup only. The model can ask whether a hash is already known to a configured
analysis provider; it cannot cause a file to be uploaded. That is not a
limitation of the transport, it is the point: an upload is a disclosure of
customer data, it is governed by a per-tenant consent the operator records
deliberately, and a decision that consequential does not belong behind a
sentence a model chose to emit. Prompt injection into an attachment name would
otherwise be one step from exfiltrating the attachment.

Execution goes through the API, which owns the provider registry, the tenant's
consent and the audit trail. The agent passes no tenant: it authenticates with
its own API key and the API takes the tenant from that credential, because a
tool argument named ``tenant_id`` is the most valuable thing on this surface to
inject.

A failure reaches the model as "could not check"
------------------------------------------------
Every error path returns ``available: false`` with wording that says so. A
sandbox is slow and failure-prone by nature, and the failure that matters is
not the outage: it is a model reading a timeout as "the file is not known to be
malicious" and writing a benign verdict on that basis.
"""

from __future__ import annotations

import os
import re
from typing import Any

import httpx
import structlog

logger = structlog.get_logger()

__all__ = ["TOOL_DESCRIPTION", "TOOL_NAME", "TOOL_PARAMETERS", "lookup_file_hash"]

#: A hash lookup is a single indexed read at every provider in the tree, but it
#: may cross the public internet. Short enough that a stalled provider cannot
#: hold a tool loop open, long enough for a cold cache.
TOOL_TIMEOUT_SECONDS = 15.0

_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")


def _api_url() -> str:
    return os.getenv("AISOC_API_URL", "http://api:8000").rstrip("/")


TENANT_HEADER = "X-AiSOC-Tenant-ID"


def _service_token() -> str:
    """The agents service's own API key. Empty means the tool cannot run.

    The tenant is named beside it rather than implied by it. One shared key
    meant one tenant, so every tenant's lookup would have read that tenant's
    credential, so a compromised prompt cannot redirect the lookup, and cannot
    read another tenant's analysis history.
    """
    specific = (os.getenv("AISOC_API_SERVICE_TOKEN") or "").strip()
    return specific or (os.getenv("AISOC_SERVICE_TOKEN") or "").strip()


def _could_not_check(reason: str, sha256: str = "") -> dict[str, Any]:
    """The one shape every failure takes.

    The wording is for the model, and the second sentence is the load-bearing
    one. "No result" and "the lookup failed" must never read the same, or the
    second becomes evidence of absence.
    """
    return {
        "available": False,
        "outcome": "could_not_check",
        "sha256": sha256,
        "reason": (
            f"{reason} This is a lookup failure, not a clean result: the file has NOT been assessed. "
            "Do not treat this as evidence that the file is benign."
        ),
    }


async def lookup_file_hash(sha256: str, *, tenant_id: str = "") -> dict[str, Any]:
    """Ask the configured analysis provider whether it has seen this file."""
    digest = (sha256 or "").strip().lower()
    if not _SHA256.match(digest):
        return {
            "available": False,
            "outcome": "invalid_input",
            "reason": "Not a SHA-256 digest. Provide 64 hexadecimal characters.",
        }
    key = _service_token()
    if not key:
        # A loud skip. Without the credential the API refuses by design, so
        # this would be a guaranteed 401 on every lookup; an operator needs to
        # see why rather than find an empty result.
        logger.warning("sandbox_tool.no_service_token", reason="AISOC_SERVICE_TOKEN is unset")
        return _could_not_check("No file-analysis credential is configured for the agent service.", digest)

    try:
        async with httpx.AsyncClient(timeout=TOOL_TIMEOUT_SECONDS) as client:
            response = await client.post(
                f"{_api_url()}/api/v1/sandbox/lookup",
                json={"sha256": digest},
                headers={"Authorization": f"Bearer {key}", TENANT_HEADER: tenant_id},
            )
    except Exception as exc:  # noqa: BLE001 - every failure becomes data for the model
        logger.warning("sandbox_tool.unreachable", error=type(exc).__name__)
        return _could_not_check(f"Could not reach the file-analysis service ({type(exc).__name__}).", digest)

    if response.status_code == 404:
        return _could_not_check("No file-analysis provider is configured for this deployment.", digest)
    if response.status_code == 403:
        # Deliberately does not name air-gap mode. A 403 is equally an expired
        # service token, a revoked scope, or a tenant policy that forbids file
        # analysis, and naming the deployment's networking posture sends an
        # analyst to debug a network while the fix is a credential. Say what is
        # known -- the request was refused -- and name the candidates.
        return _could_not_check(
            "The file-analysis service refused the request (HTTP 403). That is an authorisation "
            "problem: an expired or unscoped service token, a tenant policy forbidding file "
            "analysis, or an air-gapped deployment with no local provider configured.",
            digest,
        )
    if response.status_code >= 400:
        logger.warning("sandbox_tool.refused", status_code=response.status_code)
        return _could_not_check(f"The file-analysis service returned HTTP {response.status_code}.", digest)

    try:
        body = response.json()
    except ValueError:
        return _could_not_check("The file-analysis service returned an unreadable response.", digest)

    outcome = body.get("outcome")
    if outcome == "could_not_check":
        return _could_not_check(str(body.get("detail") or "The provider could not be reached."), digest)
    if outcome == "known":
        return {
            "available": True,
            "outcome": "known",
            "sha256": digest,
            "provider": body.get("provider"),
            # Passed through whole: fields the provider does not publish read
            # "unavailable" here rather than being absent, so the model is
            # never invited to infer one.
            "report": body.get("report"),
            "detail": body.get("detail"),
        }
    if outcome == "pending":
        return {
            "available": False,
            "outcome": "pending",
            "sha256": digest,
            "provider": body.get("provider"),
            "reason": (
                "An analysis of this file is still running, so there is no verdict yet. "
                "This is not a clean result. Continue the investigation on other evidence and "
                "say the file analysis was incomplete."
            ),
        }
    # not_seen and upload_refused both mean no provider holds a report. Said
    # plainly, because "no provider has analysed this file" is genuinely
    # different from "a provider analysed it and found nothing".
    return {
        "available": True,
        "outcome": "not_seen",
        "sha256": digest,
        "provider": body.get("provider"),
        "reason": (
            "No configured analysis provider has ever analysed this file. That is an absence of prior "
            "analysis, not a verdict: an unknown hash is common for targeted malware and says nothing "
            "either way. Uploading the file is a disclosure and is not available to this tool."
        ),
        "detail": body.get("detail"),
    }


# The registry wraps these into its own ``Tool`` rather than this module
# importing that dataclass. The import would run tool module -> registry while
# ``default_registry`` already runs registry -> tool module, and a cycle that
# happens to work because one side defers its import is still a cycle. Keeping
# the schema here as plain data also means a tool module knows nothing about
# how tools are registered.
TOOL_NAME = "lookup_file_hash"

TOOL_DESCRIPTION = (
    "Check whether a configured malware-analysis provider has already analysed a file, by its "
    "SHA-256 hash. Returns a verdict, score, signatures and any ATT&CK techniques when a report "
    "exists. Never uploads the file. An unknown hash is not a clean verdict, and a failed lookup "
    "is not a clean verdict either: check the 'outcome' field."
)

TOOL_PARAMETERS: dict[str, Any] = {
    "type": "object",
    "properties": {
        "sha256": {
            "type": "string",
            "description": "The file's SHA-256 digest, 64 hexadecimal characters.",
        }
    },
    "required": ["sha256"],
}
