"""AWS IAM / STS / EC2 client for cloud-identity and instance containment.

Depth 5.5's first three named gaps are all AWS and all absent: deactivating
an access key, revoking the sessions an assumed role has already issued, and
quarantining an instance. The tree had one AWS client and it edits security
group rules for an IP block, which is a different question from "this role's
credentials are in an attacker's hands".

API references, each fetched before this module was written:

* ``UpdateAccessKey`` — https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateAccessKey.html
* ``ListAccessKeys`` — https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListAccessKeys.html
* ``PutRolePolicy`` — https://docs.aws.amazon.com/IAM/latest/APIReference/API_PutRolePolicy.html
* ``ModifyInstanceAttribute`` — https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ModifyInstanceAttribute.html
* ``DescribeInstances`` — https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html

Why httpx and a hand-written SigV4 rather than boto3
----------------------------------------------------
``aws_security_groups.py`` calls boto3, which is not in this service's
dependency set: every method there degrades to a ``note`` saying boto3 is
absent, so the arm reports a structured non-failure and changes nothing. An
executor whose only observed behaviour is its own fallback is not an
integration. Signing here keeps the transport ``httpx``, which is what every
other client in this service uses and what the mock-vendor tests drive, so
the request that reaches a recorded AWS shape in a test is byte-for-byte the
request that reaches AWS.

Session revocation, specifically
--------------------------------
There is no "revoke these STS sessions" API. The documented mechanism — and
what the IAM console's own "Revoke active sessions" button does — is to put
an inline policy on the role that denies everything for credentials issued
before a cut-off, keyed on ``aws:TokenIssueTime``. Sessions issued after the
cut-off keep working, which is what makes this usable during an incident:
the role is not broken, only the credentials already in circulation.

That shape has a consequence worth stating because it decides the contract:
the revocation *is* an inline policy, so the rollback is deleting that
policy, and the verification probe is reading it back. Both are real, which
is why this verb is not one of the recorded verification gaps.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import urllib.parse
import xml.etree.ElementTree as ET
from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)

#: Inline policy name the IAM console uses for the same operation. Matching
#: it means an operator who later looks at the role in the console sees the
#: control they already know, rather than a policy named after this product
#: that they have to go and ask somebody about.
REVOKE_POLICY_NAME = "AWSRevokeOlderSessions"

_IAM_API_VERSION = "2010-05-08"
_EC2_API_VERSION = "2016-11-15"
_ALGORITHM = "AWS4-HMAC-SHA256"


class AWSAPIError(RuntimeError):
    """AWS answered, and the answer was a refusal.

    Separated from a transport error on purpose: "the credentials cannot
    reach AWS" and "AWS declined this call" send an operator to different
    places, and the executors above report them differently.
    """


def _sign(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def _signing_key(secret: str, date_stamp: str, region: str, service: str) -> bytes:
    k_date = _sign(f"AWS4{secret}".encode(), date_stamp)
    k_region = _sign(k_date, region)
    k_service = _sign(k_region, service)
    return _sign(k_service, "aws4_request")


class AWSIAMClient:
    """Signed calls to the IAM and EC2 query APIs.

    ``region`` applies to EC2; IAM is a global service signed against
    ``us-east-1`` whatever the caller's region is, which is a signing rule
    rather than a preference — signing IAM against another region is
    rejected.
    """

    def __init__(
        self,
        *,
        access_key_id: str,
        secret_access_key: str,
        session_token: str | None = None,
        region: str = "us-east-1",
        iam_endpoint: str | None = None,
        ec2_endpoint: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._access_key_id = access_key_id
        self._secret_access_key = secret_access_key
        self._session_token = session_token
        self._region = region
        # Endpoint overrides exist so the mock-vendor tests drive the real
        # signing and the real parser against a recorded AWS shape. They are
        # not a production affordance and nothing resolves them from tenant
        # input.
        self._iam_endpoint = (iam_endpoint or "https://iam.amazonaws.com").rstrip("/")
        self._ec2_endpoint = (ec2_endpoint or f"https://ec2.{region}.amazonaws.com").rstrip("/")
        self._timeout = timeout

    # ------------------------------------------------------------------
    # Transport
    # ------------------------------------------------------------------

    def _headers(self, *, host: str, service: str, region: str, body: str, now: dt.datetime) -> dict[str, str]:
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")

        payload_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
        signed_headers = "content-type;host;x-amz-date"
        canonical_headers = f"content-type:application/x-www-form-urlencoded; charset=utf-8\nhost:{host}\nx-amz-date:{amz_date}\n"
        if self._session_token:
            signed_headers = "content-type;host;x-amz-date;x-amz-security-token"
            canonical_headers += f"x-amz-security-token:{self._session_token}\n"

        canonical_request = "\n".join(["POST", "/", "", canonical_headers, signed_headers, payload_hash])
        credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
        string_to_sign = "\n".join(
            [
                _ALGORITHM,
                amz_date,
                credential_scope,
                hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
            ]
        )
        signature = hmac.new(
            _signing_key(self._secret_access_key, date_stamp, region, service),
            string_to_sign.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        headers = {
            "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
            "X-Amz-Date": amz_date,
            "Authorization": (f"{_ALGORITHM} Credential={self._access_key_id}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"),
        }
        if self._session_token:
            headers["X-Amz-Security-Token"] = self._session_token
        return headers

    async def _call(self, *, service: str, params: dict[str, str]) -> ET.Element:
        if service == "iam":
            endpoint, region, version = self._iam_endpoint, "us-east-1", _IAM_API_VERSION
        else:
            endpoint, region, version = self._ec2_endpoint, self._region, _EC2_API_VERSION

        body = urllib.parse.urlencode({**params, "Version": version})
        host = httpx.URL(endpoint).host
        headers = self._headers(
            host=host,
            service=service,
            region=region,
            body=body,
            now=dt.datetime.now(dt.UTC),
        )

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.post(endpoint + "/", content=body, headers=headers)

        if response.status_code >= 400:
            raise AWSAPIError(f"{service} {params.get('Action')} failed with HTTP {response.status_code}: {_error_message(response.text)}")
        try:
            return ET.fromstring(response.text)  # noqa: S314 - AWS response, not attacker-controlled document
        except ET.ParseError as exc:
            raise AWSAPIError(f"{service} {params.get('Action')} returned a body that is not XML: {exc}") from exc

    # ------------------------------------------------------------------
    # Access keys
    # ------------------------------------------------------------------

    async def update_access_key_status(self, *, user_name: str, access_key_id: str, status: str) -> dict[str, Any]:
        """``UpdateAccessKey``. ``status`` is ``Active`` or ``Inactive``."""
        if status not in ("Active", "Inactive"):
            raise ValueError(f"status must be Active or Inactive, got {status!r}")
        await self._call(
            service="iam",
            params={
                "Action": "UpdateAccessKey",
                "UserName": user_name,
                "AccessKeyId": access_key_id,
                "Status": status,
            },
        )
        return {"user_name": user_name, "access_key_id": access_key_id, "status": status}

    async def deactivate_access_key(self, *, user_name: str, access_key_id: str) -> dict[str, Any]:
        return await self.update_access_key_status(user_name=user_name, access_key_id=access_key_id, status="Inactive")

    async def activate_access_key(self, *, user_name: str, access_key_id: str) -> dict[str, Any]:
        return await self.update_access_key_status(user_name=user_name, access_key_id=access_key_id, status="Active")

    async def list_access_keys(self, *, user_name: str) -> list[dict[str, str]]:
        """``ListAccessKeys``. The read the key-deactivation probe uses."""
        root = await self._call(service="iam", params={"Action": "ListAccessKeys", "UserName": user_name})
        keys: list[dict[str, str]] = []
        for member in root.iter():
            if _local(member.tag) != "member":
                continue
            entry = {_local(child.tag): (child.text or "") for child in member}
            if "AccessKeyId" in entry:
                keys.append(entry)
        return keys

    # ------------------------------------------------------------------
    # Role sessions
    # ------------------------------------------------------------------

    @staticmethod
    def revoke_policy_document(issued_before: dt.datetime) -> str:
        """The deny-everything-issued-before policy, as a JSON string.

        Kept as a function so the executor, the probe and the test all read
        one definition. ``issued_before`` is rendered in the exact format
        ``aws:TokenIssueTime`` compares against; a local-time or
        offset-bearing stamp here silently widens or narrows the revocation.
        """
        stamp = issued_before.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        return json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Action": ["*"],
                        "Resource": ["*"],
                        "Condition": {"DateLessThan": {"aws:TokenIssueTime": stamp}},
                    }
                ],
            },
            separators=(",", ":"),
        )

    async def revoke_role_sessions(self, *, role_name: str, issued_before: dt.datetime) -> dict[str, Any]:
        """``PutRolePolicy`` with the console's own revocation policy."""
        document = self.revoke_policy_document(issued_before)
        await self._call(
            service="iam",
            params={
                "Action": "PutRolePolicy",
                "RoleName": role_name,
                "PolicyName": REVOKE_POLICY_NAME,
                "PolicyDocument": document,
            },
        )
        return {
            "role_name": role_name,
            "policy_name": REVOKE_POLICY_NAME,
            "issued_before": issued_before.astimezone(dt.UTC).isoformat(),
        }

    async def restore_role_sessions(self, *, role_name: str) -> dict[str, Any]:
        """``DeleteRolePolicy``: lift the revocation this client applied.

        Scoped to the policy name above rather than taking one from the
        caller. A rollback that can delete any inline policy on any role is
        a privilege-escalation primitive wearing a rollback's clothes.
        """
        await self._call(
            service="iam",
            params={
                "Action": "DeleteRolePolicy",
                "RoleName": role_name,
                "PolicyName": REVOKE_POLICY_NAME,
            },
        )
        return {"role_name": role_name, "policy_name": REVOKE_POLICY_NAME, "removed": True}

    async def get_role_revocation(self, *, role_name: str) -> dict[str, Any] | None:
        """``GetRolePolicy`` for the revocation policy, or ``None`` if absent."""
        try:
            root = await self._call(
                service="iam",
                params={
                    "Action": "GetRolePolicy",
                    "RoleName": role_name,
                    "PolicyName": REVOKE_POLICY_NAME,
                },
            )
        except AWSAPIError as exc:
            if "NoSuchEntity" in str(exc):
                return None
            raise
        document = _first_text(root, "PolicyDocument")
        return {
            "role_name": role_name,
            "policy_name": REVOKE_POLICY_NAME,
            "policy_document": urllib.parse.unquote(document) if document else "",
        }

    # ------------------------------------------------------------------
    # Instance quarantine
    # ------------------------------------------------------------------

    async def describe_instance_security_groups(self, *, instance_id: str) -> list[str]:
        """``DescribeInstances`` reduced to the attached security-group ids.

        Both the probe and the rollback need this: quarantine replaces the
        instance's groups, so the only record of what they were is the read
        taken before the replacement.
        """
        root = await self._call(
            service="ec2",
            params={"Action": "DescribeInstances", "InstanceId.1": instance_id},
        )
        return [text for element in root.iter() if _local(element.tag) == "groupId" and (text := (element.text or "").strip())]

    async def set_instance_security_groups(self, *, instance_id: str, group_ids: list[str]) -> dict[str, Any]:
        """``ModifyInstanceAttribute`` replacing the instance's groups.

        Quarantine and release are the same call with different groups, so
        they share one method rather than drifting apart.
        """
        if not group_ids:
            raise ValueError("at least one security group id is required; EC2 refuses an empty group set")
        params: dict[str, str] = {"Action": "ModifyInstanceAttribute", "InstanceId": instance_id}
        for index, group_id in enumerate(group_ids, start=1):
            params[f"GroupId.{index}"] = group_id
        await self._call(service="ec2", params=params)
        return {"instance_id": instance_id, "security_groups": list(group_ids)}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _first_text(root: ET.Element, name: str) -> str | None:
    for element in root.iter():
        if _local(element.tag) == name:
            return element.text
    return None


def _error_message(body: str) -> str:
    """Pull AWS's own ``<Message>`` out of an error body.

    Returning the raw body would put a few hundred bytes of XML in front of
    an operator at the moment they are least able to read it.
    """
    try:
        root = ET.fromstring(body)  # noqa: S314 - AWS error body
    except ET.ParseError:
        return body[:300]
    code = _first_text(root, "Code") or ""
    message = _first_text(root, "Message") or body[:300]
    return f"{code}: {message}" if code else message
