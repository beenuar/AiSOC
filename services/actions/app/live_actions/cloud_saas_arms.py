"""Cloud, SaaS, code-platform and gateway response arms (wave-2 Phase 6.1).

Depth 5.5's finding, re-measured on this tree: 89 arms over 39 verbs, and
the containment surface stopped at endpoints, identity sessions and email.
There was no AWS key or role-session containment, no GCP or Azure
service-identity containment, no GitHub, Slack, Salesforce, Snowflake or
1Password containment, and no gateway verb for a single URL. An incident in
any of those ended with "open a ticket for the cloud team".

Shape, inherited from ``vendor_breadth.py`` and kept deliberately identical
--------------------------------------------------------------------------
``_run`` short-circuits ``dry_run`` **before** the client factory is
called, so a preview cannot reach a vendor by construction rather than by
remembering to strip the right credential keys. That is the stronger half
of the lesson this repository learned twice: once when a strip list named
``splunk_host`` while the factory read ``splunk_url``, so a "dry run"
called production Splunk, and once in the mirror image, when a credential
strip pushed ``NotifySlackExecutor`` into a simulation branch it does not
have and every dry run reported ``message_sent: true`` on a send that never
happened.

Each arm still declares ``_credential_keys``. The tuple is graded two ways
in ``tests/test_cloud_saas_arms.py``: against the keys its factory actually
reads, re-derived from the factory's source, and behaviourally, by asserting
the factory returns ``None`` once they are stripped. The declaration and
the structural short-circuit are belt and braces on purpose — either alone
has already failed here.

Three rules every arm follows, all inherited:

**A failure is reported, never absorbed.** An executor returns FAILED with
the vendor's own message rather than a success meaning "we asked".

**Credentials absent is not the action failing.** "We could not reach the
vendor" and "the vendor refused" send an operator to different places.

**A missing parameter is its own answer.** A verb that needs an
organisation name and was given none did not fail at the vendor; saying so
stops an operator debugging their GitHub token.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Awaitable, Callable
from typing import Any

import structlog

from app.clients.factories import (
    AWS_IAM_CLIENT_PARAM_KEYS,
    GCP_IAM_CLIENT_PARAM_KEYS,
    GITHUB_CLIENT_PARAM_KEYS,
    NETSKOPE_CLIENT_PARAM_KEYS,
    ONEPASSWORD_CLIENT_PARAM_KEYS,
    SALESFORCE_CLIENT_PARAM_KEYS,
    SLACK_ADMIN_CLIENT_PARAM_KEYS,
    SNOWFLAKE_CLIENT_PARAM_KEYS,
    ZSCALER_CLIENT_PARAM_KEYS,
    _aws_iam_client,
    _cloudflare_client,
    _entra_client,
    _gcp_iam_client,
    _github_client,
    _gws_client,
    _netskope_client,
    _okta_client,
    _onepassword_client,
    _salesforce_client,
    _slack_admin_client,
    _snowflake_client,
    _zscaler_client,
)
from app.clients.github_client import GitHubClient
from app.live_actions.capability_contracts import apply_contract
from app.live_actions.executor import LiveActionExecutor
from app.live_actions.models import LiveActionRequest, LiveActionResult, LiveActionStatus

logger = structlog.get_logger(__name__)

#: Credential keys the Cloudflare, Entra, Workspace and Okta factories read.
#: Declared here beside the arms that use them so every arm in this module
#: has a tuple the dry-run test can grade, including the ones whose client
#: predates this phase.
CLOUDFLARE_CLIENT_PARAM_KEYS = ("cf_api_token",)
ENTRA_CLIENT_PARAM_KEYS = ("azure_tenant_id", "azure_client_id", "azure_client_secret")
GWS_CLIENT_PARAM_KEYS = ("gws_service_account_key", "gws_subject_email")
OKTA_CLIENT_PARAM_KEYS = ("okta_domain", "okta_api_token")


class MissingParameter(ValueError):
    """A verb was dispatched without an argument it cannot work without."""


def _require(params: dict[str, Any], name: str) -> Any:
    value = params.get(name)
    if value in (None, "", [], {}):
        raise MissingParameter(name)
    return value


def _result(
    executor: LiveActionExecutor,
    request: LiveActionRequest,
    status: LiveActionStatus,
    summary: str,
    *,
    details: dict[str, Any] | None = None,
    error: str | None = None,
) -> LiveActionResult:
    return LiveActionResult(
        request_id=request.request_id,
        status=status,
        capability=executor.capability,
        vendor_id=executor.vendor_id,
        summary=summary,
        details=details or {},
        error=error,
    )


async def _run(
    executor: LiveActionExecutor,
    request: LiveActionRequest,
    vendor: str,
    factory: Callable[[dict[str, Any]], Any],
    call: Callable[[Any, str, dict[str, Any]], Awaitable[Any]],
    summary: str,
) -> LiveActionResult:
    """Shared execute body: dry-run, credentials, call, error handling.

    The ordering is the design. ``dry_run`` returns before ``factory`` is
    reached, so a preview cannot construct a client, which means it cannot
    reach a vendor whatever the credential bag contains.
    """
    params: dict[str, Any] = request.params or {}
    target = str(request.target or "")

    if request.dry_run:
        return _result(
            executor,
            request,
            LiveActionStatus.SIMULATED,
            f"would {executor.capability} {target} on {vendor}",
            details={
                "would_run": executor.capability,
                "target": target,
                "vendor": vendor,
                # Named in the result so a reviewer reading a preview can
                # see which credentials the live call would have used, and
                # so the per-arm dry-run test has something to assert
                # against beyond "it said simulated".
                "credential_keys": list(getattr(executor, "_credential_keys", ())),
            },
        )

    client = factory(params)
    if client is None:
        return _result(
            executor,
            request,
            LiveActionStatus.FAILED,
            f"{vendor} credentials not configured",
            error=(f"{vendor} credentials are not configured, so {executor.capability} was not attempted. This is not a statement about the target."),
        )

    try:
        response = await call(client, target, params)
    except MissingParameter as exc:
        return _result(
            executor,
            request,
            LiveActionStatus.FAILED,
            f"{executor.capability} needs a {exc.args[0]}",
            error=(
                f"{executor.capability} was dispatched without {exc.args[0]!r}, "
                f"which it cannot work without. The vendor was not called, so "
                f"this says nothing about {vendor} or about the target."
            ),
        )
    except Exception as exc:  # noqa: BLE001 - a vendor error is FAILED, never silent
        logger.warning("cloud_saas_action.failed", vendor=executor.vendor_id, capability=executor.capability, error=str(exc))
        return _result(
            executor,
            request,
            LiveActionStatus.FAILED,
            f"{vendor} {executor.capability} failed",
            error=f"{vendor} {executor.capability} failed: {exc}",
        )

    return _result(
        executor,
        request,
        LiveActionStatus.SUCCEEDED,
        summary.format(target=target),
        details={"target": target, "vendor_response": response},
    )


def _issued_before(params: dict[str, Any]) -> dt.datetime:
    """Resolve the session-revocation cut-off.

    Defaults to now, which revokes every session in flight. A caller that
    knows when the compromise started passes ``issued_before`` and revokes
    only what was minted before it, which is the narrower action.
    """
    raw = params.get("issued_before")
    if not raw:
        return dt.datetime.now(dt.UTC)
    if isinstance(raw, dt.datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=dt.UTC)
    parsed = dt.datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.UTC)


# ─── AWS ─────────────────────────────────────────────────────────────────────
#
# Depth 5.5's first three named gaps, plus the IAM-user containment that has
# no API of its own: AWS offers no "disable this user", and the documented
# answer is the managed AWSDenyAll policy, whose detach is an exact rollback.


@apply_contract
class AwsDeactivateAccessKey(LiveActionExecutor):
    vendor_id = "aws"
    capability = "deactivate_access_key"
    description = "Set an IAM access key to Inactive. The key is kept, so the reverse is exact."
    requires_credentials = True
    _credential_keys = AWS_IAM_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "AWS",
            _aws_iam_client,
            lambda c, t, p: c.deactivate_access_key(user_name=_require(p, "user_name"), access_key_id=t),
            "access key {target} deactivated",
        )


@apply_contract
class AwsReactivateAccessKey(LiveActionExecutor):
    vendor_id = "aws"
    capability = "reactivate_access_key"
    description = "Set an IAM access key back to Active."
    requires_credentials = True
    _credential_keys = AWS_IAM_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "AWS",
            _aws_iam_client,
            lambda c, t, p: c.activate_access_key(user_name=_require(p, "user_name"), access_key_id=t),
            "access key {target} reactivated",
        )


@apply_contract
class AwsRevokeRoleSessions(LiveActionExecutor):
    vendor_id = "aws"
    capability = "revoke_role_sessions"
    description = "Deny every credential a role issued before a cut-off, keyed on aws:TokenIssueTime."
    requires_credentials = True
    _credential_keys = AWS_IAM_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "AWS",
            _aws_iam_client,
            lambda c, t, p: c.revoke_role_sessions(role_name=t, issued_before=_issued_before(p)),
            "sessions issued before the cut-off revoked on role {target}",
        )


@apply_contract
class AwsRestoreRoleSessions(LiveActionExecutor):
    vendor_id = "aws"
    capability = "restore_role_sessions"
    description = "Remove the session-revocation policy this platform wrote on a role."
    requires_credentials = True
    _credential_keys = AWS_IAM_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "AWS",
            _aws_iam_client,
            lambda c, t, p: c.restore_role_sessions(role_name=t),
            "session revocation lifted on role {target}",
        )


@apply_contract
class AwsQuarantineInstance(LiveActionExecutor):
    vendor_id = "aws"
    capability = "quarantine_instance"
    description = "Replace an instance's security groups with a quarantine group."
    requires_credentials = True
    _credential_keys = AWS_IAM_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        async def _quarantine(client: Any, target: str, params: dict[str, Any]) -> dict[str, Any]:
            quarantine_group = _require(params, "quarantine_security_group_id")
            # Read first. The groups being replaced are the only record of
            # what to put back, and after the write they are gone.
            previous = await client.describe_instance_security_groups(instance_id=target)
            result = await client.set_instance_security_groups(instance_id=target, group_ids=[quarantine_group])
            return {**result, "previous_security_groups": previous}

        return await _run(self, request, "AWS", _aws_iam_client, _quarantine, "instance {target} moved to the quarantine security group")


@apply_contract
class AwsReleaseInstance(LiveActionExecutor):
    vendor_id = "aws"
    capability = "release_instance"
    description = "Restore an instance's named security groups after a quarantine."
    requires_credentials = True
    _credential_keys = AWS_IAM_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "AWS",
            _aws_iam_client,
            lambda c, t, p: c.set_instance_security_groups(instance_id=t, group_ids=list(_require(p, "security_group_ids"))),
            "instance {target} released to its named security groups",
        )


@apply_contract
class AwsDisableUser(LiveActionExecutor):
    vendor_id = "aws"
    capability = "disable_user"
    description = "Attach the AWS-managed AWSDenyAll policy to an IAM user."
    requires_credentials = True
    _credential_keys = AWS_IAM_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(self, request, "AWS", _aws_iam_client, lambda c, t, p: c.attach_deny_all(user_name=t), "AWSDenyAll attached to IAM user {target}")


@apply_contract
class AwsEnableUser(LiveActionExecutor):
    vendor_id = "aws"
    capability = "enable_user"
    description = "Detach AWSDenyAll from an IAM user. The user's own policies were never touched."
    requires_credentials = True
    _credential_keys = AWS_IAM_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(self, request, "AWS", _aws_iam_client, lambda c, t, p: c.detach_deny_all(user_name=t), "AWSDenyAll detached from IAM user {target}")


@apply_contract
class AwsGetCloudIdentity(LiveActionExecutor):
    vendor_id = "aws"
    capability = "get_cloud_identity"
    description = "Access keys and attached policies for one IAM user."
    requires_credentials = True
    _credential_keys = AWS_IAM_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        async def _read(client: Any, target: str, _params: dict[str, Any]) -> dict[str, Any]:
            return {
                "user_name": target,
                "access_keys": await client.list_access_keys(user_name=target),
                "attached_policies": await client.list_attached_user_policies(user_name=target),
            }

        return await _run(self, request, "AWS", _aws_iam_client, _read, "read IAM credentials for {target}")


# ─── GCP ─────────────────────────────────────────────────────────────────────


@apply_contract
class GcpDisableServiceIdentity(LiveActionExecutor):
    vendor_id = "gcp"
    capability = "disable_service_identity"
    description = "Disable a GCP service account."
    requires_credentials = True
    _credential_keys = GCP_IAM_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "GCP",
            _gcp_iam_client,
            lambda c, t, p: c.disable_service_account(t, project_id=p.get("project_id")),
            "service account {target} disabled",
        )


@apply_contract
class GcpEnableServiceIdentity(LiveActionExecutor):
    vendor_id = "gcp"
    capability = "enable_service_identity"
    description = "Re-enable a GCP service account."
    requires_credentials = True
    _credential_keys = GCP_IAM_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "GCP",
            _gcp_iam_client,
            lambda c, t, p: c.enable_service_account(t, project_id=p.get("project_id")),
            "service account {target} enabled",
        )


@apply_contract
class GcpRevokeToken(LiveActionExecutor):
    vendor_id = "gcp"
    capability = "revoke_token"
    description = "Disable one service-account key. The workload keeps running on its other keys."
    requires_credentials = True
    _credential_keys = GCP_IAM_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "GCP",
            _gcp_iam_client,
            lambda c, t, p: c.disable_service_account_key(t, service_account=p.get("service_account"), project_id=p.get("project_id")),
            "service-account key {target} disabled",
        )


@apply_contract
class GcpRestoreToken(LiveActionExecutor):
    vendor_id = "gcp"
    capability = "restore_token"
    description = "Re-enable a disabled service-account key. GCP disables rather than destroys, which is why this verb can exist here and nowhere else."
    requires_credentials = True
    _credential_keys = GCP_IAM_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "GCP",
            _gcp_iam_client,
            lambda c, t, p: c.enable_service_account_key(t, service_account=p.get("service_account"), project_id=p.get("project_id")),
            "service-account key {target} re-enabled",
        )


@apply_contract
class GcpGetCloudIdentity(LiveActionExecutor):
    vendor_id = "gcp"
    capability = "get_cloud_identity"
    description = "State and keys of one GCP service account."
    requires_credentials = True
    _credential_keys = GCP_IAM_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        async def _read(client: Any, target: str, params: dict[str, Any]) -> dict[str, Any]:
            account = await client.get_service_account(target, project_id=params.get("project_id"))
            return {**account, "keys": await client.list_service_account_keys(target, project_id=params.get("project_id"))}

        return await _run(self, request, "GCP", _gcp_iam_client, _read, "read service account {target}")


# ─── Microsoft Entra ─────────────────────────────────────────────────────────


@apply_contract
class EntraDisableServiceIdentity(LiveActionExecutor):
    vendor_id = "azure_entra"
    capability = "disable_service_identity"
    description = "Set accountEnabled=false on a service principal."
    requires_credentials = True
    _credential_keys = ENTRA_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(self, request, "Entra", _entra_client, lambda c, t, p: c.disable_service_principal(t), "service principal {target} disabled")


@apply_contract
class EntraEnableServiceIdentity(LiveActionExecutor):
    vendor_id = "azure_entra"
    capability = "enable_service_identity"
    description = "Set accountEnabled=true on a service principal."
    requires_credentials = True
    _credential_keys = ENTRA_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(self, request, "Entra", _entra_client, lambda c, t, p: c.enable_service_principal(t), "service principal {target} enabled")


@apply_contract
class EntraRevokeOAuthGrant(LiveActionExecutor):
    vendor_id = "azure_entra"
    capability = "revoke_oauth_grant"
    description = "Delete one delegated permission grant."
    requires_credentials = True
    _credential_keys = ENTRA_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(self, request, "Entra", _entra_client, lambda c, t, p: c.delete_oauth2_permission_grant(t), "OAuth grant {target} revoked")


@apply_contract
class EntraGetOAuthGrants(LiveActionExecutor):
    vendor_id = "azure_entra"
    capability = "get_oauth_grants"
    description = "Delegated permission grants, optionally for one principal."
    requires_credentials = True
    _credential_keys = ENTRA_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Entra",
            _entra_client,
            lambda c, t, p: c.list_oauth2_permission_grants(principal_id=t or None),
            "read OAuth grants for {target}",
        )


@apply_contract
class EntraGetCloudIdentity(LiveActionExecutor):
    vendor_id = "azure_entra"
    capability = "get_cloud_identity"
    description = "Service-principal record: app id, type and whether the account is enabled."
    requires_credentials = True
    _credential_keys = ENTRA_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(self, request, "Entra", _entra_client, lambda c, t, p: c.get_service_principal(t), "read service principal {target}")


@apply_contract
class EntraRevokeToken(LiveActionExecutor):
    vendor_id = "azure_entra"
    capability = "revoke_token"
    description = "Remove one client secret from a service principal. The identity keeps working on its other credentials."
    requires_credentials = True
    _credential_keys = ENTRA_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Entra",
            _entra_client,
            lambda c, t, p: c.remove_service_principal_password(t, _require(p, "key_id")),
            "client secret removed from service principal {target}",
        )


# ─── Google Workspace ────────────────────────────────────────────────────────


@apply_contract
class GoogleWorkspaceRevokeOAuthGrant(LiveActionExecutor):
    vendor_id = "google_workspace"
    capability = "revoke_oauth_grant"
    description = "Delete one third-party application's token for a user."
    requires_credentials = True
    _credential_keys = GWS_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Google Workspace",
            _gws_client,
            lambda c, t, p: c.revoke_oauth_token(t, _require(p, "client_id")),
            "OAuth grant revoked for {target}",
        )


@apply_contract
class GoogleWorkspaceGetOAuthGrants(LiveActionExecutor):
    vendor_id = "google_workspace"
    capability = "get_oauth_grants"
    description = "Third-party applications holding a token for a user."
    requires_credentials = True
    _credential_keys = GWS_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(self, request, "Google Workspace", _gws_client, lambda c, t, p: c.list_oauth_tokens(t), "read OAuth grants for {target}")


@apply_contract
class GoogleWorkspaceRevokeToken(LiveActionExecutor):
    vendor_id = "google_workspace"
    capability = "revoke_token"
    description = "Delete a user's application-specific passwords — the credential that survives a suspension because it predates 2-step verification."
    requires_credentials = True
    _credential_keys = GWS_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Google Workspace",
            _gws_client,
            lambda c, t, p: c.revoke_app_passwords(t, code_id=p.get("code_id")),
            "application passwords revoked for {target}",
        )


@apply_contract
class GoogleWorkspaceGetCloudIdentity(LiveActionExecutor):
    vendor_id = "google_workspace"
    capability = "get_cloud_identity"
    description = "Directory record for one account: suspended, admin, 2SV enforcement, last login."
    requires_credentials = True
    _credential_keys = GWS_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(self, request, "Google Workspace", _gws_client, lambda c, t, p: c.get_user(t), "read directory record for {target}")


# ─── Okta ────────────────────────────────────────────────────────────────────


@apply_contract
class OktaRevokeOAuthGrant(LiveActionExecutor):
    vendor_id = "okta"
    capability = "revoke_oauth_grant"
    description = "Revoke one OAuth grant, or every grant a user holds."
    requires_credentials = True
    _credential_keys = OKTA_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Okta",
            _okta_client,
            lambda c, t, p: c.revoke_grants(t, grant_id=p.get("grant_id")),
            "OAuth grants revoked for {target}",
        )


@apply_contract
class OktaGetOAuthGrants(LiveActionExecutor):
    vendor_id = "okta"
    capability = "get_oauth_grants"
    description = "OAuth grants a user has consented to."
    requires_credentials = True
    _credential_keys = OKTA_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(self, request, "Okta", _okta_client, lambda c, t, p: c.list_grants(t), "read OAuth grants for {target}")


@apply_contract
class OktaRevokeToken(LiveActionExecutor):
    vendor_id = "okta"
    capability = "revoke_token"
    description = "Revoke a user's refresh tokens for one application, leaving the consent in place."
    requires_credentials = True
    _credential_keys = OKTA_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Okta",
            _okta_client,
            lambda c, t, p: c.revoke_refresh_tokens(t, _require(p, "client_id")),
            "refresh tokens revoked for {target}",
        )


@apply_contract
class OktaGetCloudIdentity(LiveActionExecutor):
    vendor_id = "okta"
    capability = "get_cloud_identity"
    description = "Lifecycle status of one Okta user."
    requires_credentials = True
    _credential_keys = OKTA_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Okta",
            _okta_client,
            lambda c, t, p: _as_status(c, t),
            "read Okta status for {target}",
        )


async def _as_status(client: Any, login_or_id: str) -> dict[str, Any]:
    return {"user": login_or_id, "status": await client.get_user_status(login_or_id)}


# ─── GitHub ──────────────────────────────────────────────────────────────────


@apply_contract
class GitHubRemoveOrgMember(LiveActionExecutor):
    vendor_id = "github"
    capability = "remove_org_member"
    description = "Remove a user from an organisation and all its teams."
    requires_credentials = True
    _credential_keys = GITHUB_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "GitHub",
            _github_client,
            lambda c, t, p: c.remove_org_member(_require(p, "org"), t),
            "{target} removed from the organisation",
        )


@apply_contract
class GitHubRestoreOrgMember(LiveActionExecutor):
    vendor_id = "github"
    capability = "restore_org_member"
    description = "Re-invite a user to an organisation, at member role unless told otherwise."
    requires_credentials = True
    _credential_keys = GITHUB_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "GitHub",
            _github_client,
            lambda c, t, p: c.set_org_membership(_require(p, "org"), t, role=p.get("role", "member")),
            "{target} re-invited to the organisation",
        )


@apply_contract
class GitHubRevokeDeployKey(LiveActionExecutor):
    vendor_id = "github"
    capability = "revoke_deploy_key"
    description = "Delete a repository deploy key."
    requires_credentials = True
    _credential_keys = GITHUB_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "GitHub",
            _github_client,
            lambda c, t, p: c.delete_deploy_key(_require(p, "owner"), _require(p, "repo"), t),
            "deploy key {target} deleted",
        )


@apply_contract
class GitHubDisableWorkflow(LiveActionExecutor):
    vendor_id = "github"
    capability = "disable_workflow"
    description = "Disable one Actions workflow by id or file name."
    requires_credentials = True
    _credential_keys = GITHUB_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "GitHub",
            _github_client,
            lambda c, t, p: c.set_workflow_enabled(_require(p, "owner"), _require(p, "repo"), t, enabled=False),
            "workflow {target} disabled",
        )


@apply_contract
class GitHubEnableWorkflow(LiveActionExecutor):
    vendor_id = "github"
    capability = "enable_workflow"
    description = "Re-enable one Actions workflow."
    requires_credentials = True
    _credential_keys = GITHUB_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "GitHub",
            _github_client,
            lambda c, t, p: c.set_workflow_enabled(_require(p, "owner"), _require(p, "repo"), t, enabled=True),
            "workflow {target} enabled",
        )


def _github_revocation_client(params: dict[str, Any]) -> GitHubClient:
    """A client for the one GitHub endpoint that takes no credentials.

    ``POST /credentials/revoke`` is unauthenticated by design and answers
    403 to an authenticated caller, so this arm needs no token and must not
    send one. Returning a client unconditionally — rather than ``None`` on
    a missing token — is correct here and is why this arm declares
    ``requires_credentials = False``: "credentials not configured" would be
    the wrong answer to a verb that needs none.
    """
    return GitHubClient(token=str(params.get("github_token") or ""))


@apply_contract
class GitHubRevokeToken(LiveActionExecutor):
    vendor_id = "github"
    capability = "revoke_token"
    description = "Revoke leaked GitHub credentials through the platform's revocation API. Irreversible: GitHub cannot reactivate a revoked credential."
    requires_credentials = False
    #: Empty, and deliberately so. The endpoint this arm calls refuses an
    #: authenticated request, so there is no credential to strip — and a
    #: tuple naming one would make the dry-run test assert a property this
    #: arm does not have.
    _credential_keys = ()

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "GitHub",
            _github_revocation_client,
            lambda c, t, p: c.revoke_credentials(list(p.get("credentials") or ([t] if t else []))),
            "credential revocation submitted to GitHub",
        )


@apply_contract
class GitHubGetSecretScanningAlerts(LiveActionExecutor):
    vendor_id = "github"
    capability = "get_secret_scanning_alerts"
    description = "Open secret-scanning alerts for an organisation or one repository."
    requires_credentials = True
    _credential_keys = GITHUB_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "GitHub",
            _github_client,
            lambda c, t, p: c.list_secret_scanning_alerts(
                org=(t if t and "/" not in t and not p.get("repo") else None),
                owner=(p.get("owner") or (t.split("/", 1)[0] if t and "/" in t else None)),
                repo=(p.get("repo") or (t.split("/", 1)[1] if t and "/" in t else None)),
                state=p.get("state", "open"),
            ),
            "read secret-scanning alerts for {target}",
        )


@apply_contract
class GitHubGetCloudIdentity(LiveActionExecutor):
    vendor_id = "github"
    capability = "get_cloud_identity"
    description = "Organisation membership state and role for one user."
    requires_credentials = True
    _credential_keys = GITHUB_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "GitHub",
            _github_client,
            lambda c, t, p: c.get_org_membership(_require(p, "org"), t),
            "read organisation membership for {target}",
        )


# ─── Slack ───────────────────────────────────────────────────────────────────


@apply_contract
class SlackDisableUser(LiveActionExecutor):
    vendor_id = "slack"
    capability = "disable_user"
    description = "Remove a user from a Slack workspace. Slack offers no soft deactivation; this is the pair that exists."
    requires_credentials = True
    _credential_keys = SLACK_ADMIN_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Slack",
            _slack_admin_client,
            lambda c, t, p: c.remove_user(t, team_id=p.get("team_id")),
            "{target} removed from the Slack workspace",
        )


@apply_contract
class SlackEnableUser(LiveActionExecutor):
    vendor_id = "slack"
    capability = "enable_user"
    description = "Assign a user back to a Slack workspace."
    requires_credentials = True
    _credential_keys = SLACK_ADMIN_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Slack",
            _slack_admin_client,
            lambda c, t, p: c.assign_user(t, team_id=p.get("team_id")),
            "{target} reassigned to the Slack workspace",
        )


@apply_contract
class SlackRevokeSession(LiveActionExecutor):
    vendor_id = "slack"
    capability = "revoke_session"
    description = "Wipe every Slack session a user holds, on every device."
    requires_credentials = True
    _credential_keys = SLACK_ADMIN_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Slack",
            _slack_admin_client,
            lambda c, t, p: c.reset_sessions(t, mobile_only=bool(p.get("mobile_only")), web_only=bool(p.get("web_only"))),
            "Slack sessions wiped for {target}",
        )


@apply_contract
class SlackGetCloudIdentity(LiveActionExecutor):
    vendor_id = "slack"
    capability = "get_cloud_identity"
    description = "Slack user record, including whether the account has been removed."
    requires_credentials = True
    _credential_keys = SLACK_ADMIN_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(self, request, "Slack", _slack_admin_client, lambda c, t, p: c.get_user(t), "read Slack user {target}")


# ─── Salesforce ──────────────────────────────────────────────────────────────


@apply_contract
class SalesforceDisableUser(LiveActionExecutor):
    vendor_id = "salesforce"
    capability = "disable_user"
    description = "Freeze a Salesforce user. Freeze rather than deactivate: deactivating releases the licence and breaks record ownership."
    requires_credentials = True
    _credential_keys = SALESFORCE_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(self, request, "Salesforce", _salesforce_client, lambda c, t, p: c.freeze_user(t), "{target} frozen")


@apply_contract
class SalesforceEnableUser(LiveActionExecutor):
    vendor_id = "salesforce"
    capability = "enable_user"
    description = "Unfreeze a Salesforce user."
    requires_credentials = True
    _credential_keys = SALESFORCE_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(self, request, "Salesforce", _salesforce_client, lambda c, t, p: c.unfreeze_user(t), "{target} unfrozen")


@apply_contract
class SalesforceRevokeToken(LiveActionExecutor):
    vendor_id = "salesforce"
    capability = "revoke_token"
    description = "Revoke one Salesforce OAuth token. Revoking a refresh token takes its access tokens with it."
    requires_credentials = True
    _credential_keys = SALESFORCE_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(self, request, "Salesforce", _salesforce_client, lambda c, t, p: c.revoke_oauth_token(t), "OAuth token revoked")


@apply_contract
class SalesforceRevokeSession(LiveActionExecutor):
    vendor_id = "salesforce"
    capability = "revoke_session"
    description = "Delete every AuthSession a Salesforce user holds."
    requires_credentials = True
    _credential_keys = SALESFORCE_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(self, request, "Salesforce", _salesforce_client, lambda c, t, p: c.revoke_sessions(t), "sessions revoked for {target}")


@apply_contract
class SalesforceGetCloudIdentity(LiveActionExecutor):
    vendor_id = "salesforce"
    capability = "get_cloud_identity"
    description = "User and UserLogin state, including whether the account is frozen."
    requires_credentials = True
    _credential_keys = SALESFORCE_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(self, request, "Salesforce", _salesforce_client, lambda c, t, p: c.resolve_user_login(t), "read Salesforce login state for {target}")


# ─── Snowflake ───────────────────────────────────────────────────────────────


@apply_contract
class SnowflakeDisableUser(LiveActionExecutor):
    vendor_id = "snowflake"
    capability = "disable_user"
    description = "ALTER USER … SET DISABLED = TRUE."
    requires_credentials = True
    _credential_keys = SNOWFLAKE_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(self, request, "Snowflake", _snowflake_client, lambda c, t, p: c.disable_user(t), "{target} disabled")


@apply_contract
class SnowflakeEnableUser(LiveActionExecutor):
    vendor_id = "snowflake"
    capability = "enable_user"
    description = "ALTER USER … SET DISABLED = FALSE."
    requires_credentials = True
    _credential_keys = SNOWFLAKE_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(self, request, "Snowflake", _snowflake_client, lambda c, t, p: c.enable_user(t), "{target} enabled")


@apply_contract
class SnowflakeRevokeSession(LiveActionExecutor):
    vendor_id = "snowflake"
    capability = "revoke_session"
    description = "Abort one live Snowflake session by id, without disabling the account."
    requires_credentials = True
    _credential_keys = SNOWFLAKE_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(self, request, "Snowflake", _snowflake_client, lambda c, t, p: c.abort_session(t), "session {target} aborted")


@apply_contract
class SnowflakeGetCloudIdentity(LiveActionExecutor):
    vendor_id = "snowflake"
    capability = "get_cloud_identity"
    description = "DESCRIBE USER, reduced to the properties a containment decision needs."
    requires_credentials = True
    _credential_keys = SNOWFLAKE_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(self, request, "Snowflake", _snowflake_client, lambda c, t, p: c.describe_user(t), "read Snowflake user {target}")


# ─── 1Password ───────────────────────────────────────────────────────────────


@apply_contract
class OnePasswordDisableUser(LiveActionExecutor):
    vendor_id = "onepassword"
    capability = "disable_user"
    description = "Suspend a 1Password account through the SCIM bridge."
    requires_credentials = True
    _credential_keys = ONEPASSWORD_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(self, request, "1Password", _onepassword_client, lambda c, t, p: c.suspend_user(t), "{target} suspended")


@apply_contract
class OnePasswordEnableUser(LiveActionExecutor):
    vendor_id = "onepassword"
    capability = "enable_user"
    description = "Restore a suspended 1Password account."
    requires_credentials = True
    _credential_keys = ONEPASSWORD_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(self, request, "1Password", _onepassword_client, lambda c, t, p: c.restore_user(t), "{target} restored")


@apply_contract
class OnePasswordGetCloudIdentity(LiveActionExecutor):
    vendor_id = "onepassword"
    capability = "get_cloud_identity"
    description = "SCIM record for one 1Password account, including whether it is active."
    requires_credentials = True
    _credential_keys = ONEPASSWORD_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(self, request, "1Password", _onepassword_client, lambda c, t, p: c.get_user(t), "read 1Password account {target}")


# ─── Secure web gateways ─────────────────────────────────────────────────────


@apply_contract
class CloudflareBlockURL(LiveActionExecutor):
    vendor_id = "cloudflare"
    capability = "block_url"
    description = "Append a URL to a Cloudflare Gateway list the customer's own block policy points at."
    requires_credentials = True
    _credential_keys = CLOUDFLARE_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Cloudflare",
            _cloudflare_client,
            lambda c, t, p: c.block_url(t, _require(p, "account_id"), _require(p, "list_id")),
            "{target} added to the Gateway block list",
        )


@apply_contract
class CloudflareAllowURL(LiveActionExecutor):
    vendor_id = "cloudflare"
    capability = "allow_url"
    description = "Remove a URL from a Cloudflare Gateway list."
    requires_credentials = True
    _credential_keys = CLOUDFLARE_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Cloudflare",
            _cloudflare_client,
            lambda c, t, p: c.allow_url(t, _require(p, "account_id"), _require(p, "list_id")),
            "{target} removed from the Gateway block list",
        )


@apply_contract
class ZscalerBlockURL(LiveActionExecutor):
    vendor_id = "zscaler"
    capability = "block_url"
    description = "Add a URL to a Zscaler custom URL category."
    requires_credentials = True
    _credential_keys = ZSCALER_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Zscaler",
            _zscaler_client,
            lambda c, t, p: c.block_url(t, category_id=_require(p, "category_id")),
            "{target} added to the Zscaler category",
        )


@apply_contract
class ZscalerAllowURL(LiveActionExecutor):
    vendor_id = "zscaler"
    capability = "allow_url"
    description = "Remove a URL from a Zscaler custom URL category."
    requires_credentials = True
    _credential_keys = ZSCALER_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Zscaler",
            _zscaler_client,
            lambda c, t, p: c.allow_url(t, category_id=_require(p, "category_id")),
            "{target} removed from the Zscaler category",
        )


@apply_contract
class ZscalerBlockDomain(LiveActionExecutor):
    vendor_id = "zscaler"
    capability = "block_domain"
    description = "Add a domain to a Zscaler custom URL category."
    requires_credentials = True
    _credential_keys = ZSCALER_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Zscaler",
            _zscaler_client,
            lambda c, t, p: c.block_domain(t, category_id=_require(p, "category_id")),
            "{target} added to the Zscaler category",
        )


@apply_contract
class ZscalerAllowDomain(LiveActionExecutor):
    vendor_id = "zscaler"
    capability = "allow_domain"
    description = "Remove a domain from a Zscaler custom URL category."
    requires_credentials = True
    _credential_keys = ZSCALER_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Zscaler",
            _zscaler_client,
            lambda c, t, p: c.allow_domain(t, category_id=_require(p, "category_id")),
            "{target} removed from the Zscaler category",
        )


@apply_contract
class NetskopeBlockURL(LiveActionExecutor):
    vendor_id = "netskope"
    capability = "block_url"
    description = "Append a URL to a Netskope URL list."
    requires_credentials = True
    _credential_keys = NETSKOPE_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Netskope",
            _netskope_client,
            lambda c, t, p: c.block_url(t, list_id=_require(p, "list_id")),
            "{target} added to the Netskope list",
        )


@apply_contract
class NetskopeAllowURL(LiveActionExecutor):
    vendor_id = "netskope"
    capability = "allow_url"
    description = "Remove a URL from a Netskope URL list."
    requires_credentials = True
    _credential_keys = NETSKOPE_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Netskope",
            _netskope_client,
            lambda c, t, p: c.allow_url(t, list_id=_require(p, "list_id")),
            "{target} removed from the Netskope list",
        )


@apply_contract
class NetskopeBlockDomain(LiveActionExecutor):
    vendor_id = "netskope"
    capability = "block_domain"
    description = "Append a domain to a Netskope URL list."
    requires_credentials = True
    _credential_keys = NETSKOPE_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Netskope",
            _netskope_client,
            lambda c, t, p: c.block_domain(t, list_id=_require(p, "list_id")),
            "{target} added to the Netskope list",
        )


@apply_contract
class NetskopeAllowDomain(LiveActionExecutor):
    vendor_id = "netskope"
    capability = "allow_domain"
    description = "Remove a domain from a Netskope URL list."
    requires_credentials = True
    _credential_keys = NETSKOPE_CLIENT_PARAM_KEYS

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return await _run(
            self,
            request,
            "Netskope",
            _netskope_client,
            lambda c, t, p: c.allow_domain(t, list_id=_require(p, "list_id")),
            "{target} removed from the Netskope list",
        )


#: Every arm this module adds, in the order the registry sees them.
CLOUD_SAAS_EXECUTORS: tuple[type[LiveActionExecutor], ...] = (
    AwsDeactivateAccessKey,
    AwsReactivateAccessKey,
    AwsRevokeRoleSessions,
    AwsRestoreRoleSessions,
    AwsQuarantineInstance,
    AwsReleaseInstance,
    AwsDisableUser,
    AwsEnableUser,
    AwsGetCloudIdentity,
    GcpDisableServiceIdentity,
    GcpEnableServiceIdentity,
    GcpRevokeToken,
    GcpRestoreToken,
    GcpGetCloudIdentity,
    EntraDisableServiceIdentity,
    EntraEnableServiceIdentity,
    EntraRevokeOAuthGrant,
    EntraGetOAuthGrants,
    EntraGetCloudIdentity,
    EntraRevokeToken,
    GoogleWorkspaceRevokeOAuthGrant,
    GoogleWorkspaceGetOAuthGrants,
    GoogleWorkspaceRevokeToken,
    GoogleWorkspaceGetCloudIdentity,
    OktaRevokeOAuthGrant,
    OktaGetOAuthGrants,
    OktaRevokeToken,
    OktaGetCloudIdentity,
    GitHubRemoveOrgMember,
    GitHubRestoreOrgMember,
    GitHubRevokeDeployKey,
    GitHubDisableWorkflow,
    GitHubEnableWorkflow,
    GitHubRevokeToken,
    GitHubGetSecretScanningAlerts,
    GitHubGetCloudIdentity,
    SlackDisableUser,
    SlackEnableUser,
    SlackRevokeSession,
    SlackGetCloudIdentity,
    SalesforceDisableUser,
    SalesforceEnableUser,
    SalesforceRevokeToken,
    SalesforceRevokeSession,
    SalesforceGetCloudIdentity,
    SnowflakeDisableUser,
    SnowflakeEnableUser,
    SnowflakeRevokeSession,
    SnowflakeGetCloudIdentity,
    OnePasswordDisableUser,
    OnePasswordEnableUser,
    OnePasswordGetCloudIdentity,
    CloudflareBlockURL,
    CloudflareAllowURL,
    ZscalerBlockURL,
    ZscalerAllowURL,
    ZscalerBlockDomain,
    ZscalerAllowDomain,
    NetskopeBlockURL,
    NetskopeAllowURL,
    NetskopeBlockDomain,
    NetskopeAllowDomain,
)
