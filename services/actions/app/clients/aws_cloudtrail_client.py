"""AWS CloudTrail ``LookupEvents``, for investigation rather than response.

Gap-closure Phase 4.2.

Why this is not boto3
---------------------
``aws_security_groups.py`` in this directory uses boto3 and degrades to
"boto3 not installed in actions service" on every live call, because **boto3
is not a dependency of this service**. Measured on the published image:
``import boto3`` raises ``ModuleNotFoundError`` in ``aisoc-actions`` and
succeeds in ``aisoc-connectors`` at 1.43.101. So the choice was to add boto3
here or to sign one request by hand.

boto3 plus botocore is tens of megabytes of wheel, and ADR-0007 has just
moved this service into the CORE profile on the strength of a 539 MB image
and 48 MiB resident. Paying that for one read verb would be trading a
published number for a convenience. ``LookupEvents`` is a single JSON POST
with a SigV4 ``Authorization`` header; the signing is about sixty lines of
``hmac`` and ``hashlib`` and needs nothing outside the standard library.

What is and is not verified
---------------------------
The canonical request, the string to sign, the derived signing key and the
header set are pinned by tests against fixed inputs, so the algorithm cannot
drift silently, and the response parsing and projection run against a
recorded CloudTrail payload through ``httpx.MockTransport``.

**No call has been made against live AWS from this repository.** There is no
funded AWS account here, so the live path is unverified and the documentation
says so rather than implying otherwise. That is the same position the plan
takes for vendor MCP servers: shipped, documented, and marked unverified
until somebody runs it.

Read-only by construction
-------------------------
``LookupEvents`` is the only action this client can name. The target header
is built from a constant, not from an argument, so there is no argument any
caller can pass that reaches a different CloudTrail API.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
from typing import Any

import httpx
import structlog

logger = structlog.get_logger()

_SERVICE = "cloudtrail"
_ALGORITHM = "AWS4-HMAC-SHA256"

#: The one API this client can call. A constant rather than a parameter: an
#: argument here would be the difference between a read client and a
#: general-purpose AWS client wearing a read client's name.
_TARGET = "CloudTrail_20131101.LookupEvents"

#: CloudTrail's own attribute vocabulary for LookupEvents, which is a closed
#: set the API defines. Named here so an unsupported key is refused with the
#: supported list rather than sent and rejected by AWS as a 400 that reads
#: like an outage.
LOOKUP_ATTRIBUTES: frozenset[str] = frozenset(
    {
        "AccessKeyId",
        "EventId",
        "EventName",
        "EventSource",
        "ReadOnly",
        "ResourceName",
        "ResourceType",
        "Username",
    }
)


class CloudTrailLookupError(RuntimeError):
    """The lookup could not be performed. Never an empty result."""


def _sign(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def _signing_key(secret_access_key: str, date_stamp: str, region: str) -> bytes:
    """Derive the SigV4 signing key.

    Four chained HMACs over date, region, service and the fixed terminator,
    in that order, per the SigV4 specification. Split out so a test can pin
    the derivation itself rather than only the header it ends up in.
    """
    k_date = _sign(f"AWS4{secret_access_key}".encode(), date_stamp)
    k_region = _sign(k_date, region)
    k_service = _sign(k_region, _SERVICE)
    return _sign(k_service, "aws4_request")


class AWSCloudTrailClient:
    """Sign and issue one CloudTrail ``LookupEvents`` request.

    Credentials are request-scoped, like every other client in this
    directory: the dispatcher treats a credential as belonging to the call so
    a multi-tenant deployment can route two tenants to two AWS accounts in
    one process.

    ``session_token`` is accepted so a deployment using short-lived
    credentials works. Minting them is not this client's job: STS is a
    different API with its own signing, and a half-implemented assume-role
    would be a capability that works on the operator's laptop and not in
    their account.
    """

    def __init__(
        self,
        access_key_id: str,
        secret_access_key: str,
        *,
        region: str = "us-east-1",
        session_token: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._access_key_id = access_key_id
        self._secret_access_key = secret_access_key
        self._region = region
        self._session_token = session_token
        # Injected only by tests. A real caller leaves it None and httpx uses
        # its own transport; this is here so the recorded-payload tests drive
        # the same signing and parsing code a live call would.
        self._transport = transport

    @property
    def endpoint(self) -> str:
        return f"https://{_SERVICE}.{self._region}.amazonaws.com/"

    @property
    def host(self) -> str:
        return f"{_SERVICE}.{self._region}.amazonaws.com"

    def _headers_to_sign(self, amz_date: str) -> dict[str, str]:
        """The headers SigV4 covers, lowercased because the spec signs them so.

        Sent to httpx in this same lowercase form rather than title-cased. HTTP
        header names are case-insensitive, and sending exactly the bytes that
        were signed removes any chance of the signature covering one spelling
        while the wire carries another.
        """
        headers = {
            "content-type": "application/x-amz-json-1.1",
            "host": self.host,
            "x-amz-date": amz_date,
            "x-amz-target": _TARGET,
        }
        if self._session_token:
            headers["x-amz-security-token"] = self._session_token
        return headers

    def canonical_parts(self, payload: str, amz_date: str, date_stamp: str) -> tuple[str, str, str]:
        """The canonical request, the string to sign, and the signed-header list.

        Public and returned as data so the tests can pin the algorithm itself
        rather than only the header it ends up inside. ``_authorization``
        calls **this**: a second copy of the canonical-request construction
        for the tests to read would be the one-directional gate this
        repository keeps finding, where a test compares a producer against a
        copy of itself and prints OK.
        """
        headers = self._headers_to_sign(amz_date)
        # Signed headers are the header names lowercased and sorted, and the
        # canonical headers are those same names with their values in the
        # same order. Both are derived from one sorted list so they cannot
        # disagree.
        signed_names = sorted(headers)
        canonical_headers = "".join(f"{name}:{headers[name].strip()}\n" for name in signed_names)
        signed_headers = ";".join(signed_names)

        canonical_request = "\n".join(
            [
                "POST",
                "/",
                "",
                canonical_headers,
                signed_headers,
                hashlib.sha256(payload.encode("utf-8")).hexdigest(),
            ]
        )
        string_to_sign = "\n".join(
            [
                _ALGORITHM,
                amz_date,
                f"{date_stamp}/{self._region}/{_SERVICE}/aws4_request",
                hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
            ]
        )
        return canonical_request, string_to_sign, signed_headers

    def _authorization(self, payload: str, amz_date: str, date_stamp: str) -> dict[str, str]:
        """The full header set for one signed POST."""
        _, string_to_sign, signed_headers = self.canonical_parts(payload, amz_date, date_stamp)
        signature = hmac.new(
            _signing_key(self._secret_access_key, date_stamp, self._region),
            string_to_sign.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        credential_scope = f"{date_stamp}/{self._region}/{_SERVICE}/aws4_request"
        return {
            **self._headers_to_sign(amz_date),
            "authorization": (
                f"{_ALGORITHM} Credential={self._access_key_id}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
            ),
        }

    async def lookup_events(
        self,
        *,
        attribute_key: str,
        attribute_value: str,
        hours: int = 24,
        limit: int = 50,
        now: dt.datetime | None = None,
    ) -> list[dict[str, Any]]:
        """Look up CloudTrail management events matching one attribute.

        ``attribute_key`` is checked against CloudTrail's own closed
        vocabulary rather than forwarded, so an unsupported key is refused
        here with the supported set named.

        Raises ``CloudTrailLookupError`` on any failure. It never returns an
        empty list to mean "the lookup did not work": an empty CloudTrail
        window is a real and common answer, and a caller that cannot tell the
        two apart will conclude a principal did nothing when in fact nobody
        looked.
        """
        if attribute_key not in LOOKUP_ATTRIBUTES:
            raise CloudTrailLookupError(
                f"{attribute_key!r} is not a CloudTrail lookup attribute; CloudTrail accepts {', '.join(sorted(LOOKUP_ATTRIBUTES))}"
            )
        if not str(attribute_value).strip():
            raise CloudTrailLookupError(f"a {attribute_key} value is required; an empty lookup would match the whole window")

        moment = now or dt.datetime.now(dt.UTC)
        window = max(1, min(hours, 720))
        payload = json.dumps(
            {
                "LookupAttributes": [{"AttributeKey": attribute_key, "AttributeValue": str(attribute_value)}],
                "StartTime": (moment - dt.timedelta(hours=window)).timestamp(),
                "EndTime": moment.timestamp(),
                "MaxResults": min(max(1, limit), 50),
            },
            separators=(",", ":"),
        )
        amz_date = moment.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = moment.strftime("%Y%m%d")

        try:
            async with httpx.AsyncClient(timeout=30.0, transport=self._transport) as client:
                response = await client.post(
                    self.endpoint,
                    headers=self._authorization(payload, amz_date, date_stamp),
                    content=payload,
                )
        except httpx.HTTPError as exc:
            raise CloudTrailLookupError(f"CloudTrail was unreachable: {type(exc).__name__}") from exc

        if response.status_code >= 400:
            # AWS returns its error type in a JSON body. Surfaced because the
            # difference between "these credentials cannot LookupEvents" and
            # "CloudTrail is down" is the difference between a configuration
            # fix and a wait, and both look the same as a bare 400.
            detail = ""
            try:
                body = response.json()
                detail = str(body.get("__type") or body.get("message") or "")
            except ValueError:
                detail = response.text[:200]
            raise CloudTrailLookupError(f"CloudTrail returned HTTP {response.status_code}: {detail or 'no detail'}")

        try:
            body = response.json()
        except ValueError as exc:
            raise CloudTrailLookupError("CloudTrail returned a body that is not JSON") from exc

        events = body.get("Events") or []
        projected = [_project_event(entry) for entry in events if isinstance(entry, dict)]
        logger.info("cloudtrail.lookup", attribute=attribute_key, count=len(projected))
        return projected


def _mfa_authenticated(identity: dict[str, Any]) -> Any:
    """Whether the session was MFA-authenticated, or ``None`` if not stated.

    Pulled out rather than inlined as a chained conditional. Three levels of
    `.get(...) or {}` in one expression is unreadable, and the inline form
    re-fetched `sessionContext` so the value the guard inspected was not the
    value that was used.
    """
    session = identity.get("sessionContext")
    if not isinstance(session, dict):
        return None
    attributes = session.get("attributes")
    if not isinstance(attributes, dict):
        return None
    return attributes.get("mfaAuthenticated")


def _project_event(entry: dict[str, Any]) -> dict[str, Any]:
    """Reduce one CloudTrail event to what an investigation reads.

    ``CloudTrailEvent`` is a JSON *string* holding the full record, which for
    a single API call routinely runs to several kilobytes of request
    parameters, response elements and TLS details. The nine fields below are
    the ones an analyst reads; the rest is token cost with a bounded amount of
    signal, and it is where injected text in a resource name would otherwise
    travel unexamined into a prompt.
    """
    detail: dict[str, Any] = {}
    raw = entry.get("CloudTrailEvent")
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                detail = parsed
        except ValueError:
            # A malformed record is not a failed lookup. The envelope fields
            # below still answer the question; the detail is simply absent.
            logger.warning("cloudtrail.event_detail_unparseable", event_id=entry.get("EventId"))

    raw_identity = detail.get("userIdentity")
    identity: dict[str, Any] = raw_identity if isinstance(raw_identity, dict) else {}
    return {
        "event_id": entry.get("EventId"),
        "event_name": entry.get("EventName"),
        "event_source": entry.get("EventSource"),
        "event_time": entry.get("EventTime"),
        "username": entry.get("Username"),
        "read_only": entry.get("ReadOnly"),
        "region": detail.get("awsRegion"),
        "source_ip": detail.get("sourceIPAddress"),
        "user_agent": detail.get("userAgent"),
        "error_code": detail.get("errorCode"),
        "principal_type": identity.get("type"),
        "principal_arn": identity.get("arn"),
        "mfa_authenticated": _mfa_authenticated(identity),
    }
