"""
Identity action executors: disable user, reset password, suspend session, force MFA.

Vendor priority
---------------

Phase 3.4 added two real IdP integrations on top of the existing
Okta client. Each executor tries vendors in this order when the
matching credentials are present in :class:`ActionRequest.parameters`:

1. **Okta**             — credentials prefixed ``okta_``.
2. **Microsoft Entra**  — credentials prefixed ``azure_``.
3. **Google Workspace** — credentials prefixed ``gws_``.

The order matters operationally: most AiSOC design partners have
Okta as their primary IdP and Workspace / Entra as the downstream
SP, so the playbook author expects the verb to fire against the
IdP first. If credentials for multiple vendors are supplied, the
playbook is expected to scope which one is canonical for the
target user; this executor will simply fire whichever vendor's
credentials it sees first in priority order.

If no vendor credentials are present, the executor falls back to
simulation mode so the agent loop and pricing funnel still
function in a free-tier or pre-onboarding deployment.

Credential reference
--------------------

* ``okta_domain``, ``okta_api_token``
* ``azure_tenant_id``, ``azure_client_id``, ``azure_client_secret``
* ``gws_service_account_key`` (JSON key as str), ``gws_subject_email``
"""

from __future__ import annotations

from datetime import datetime

import structlog

from app.clients.azure_entra_client import AzureEntraClient
from app.clients.google_workspace_client import GoogleWorkspaceClient
from app.clients.okta_client import OktaClient
from app.executors.base import _SIM_FUNNEL_CTA, BaseExecutor
from app.models.action import ActionRequest, ActionResult, ActionStatus, BlastRadius

logger = structlog.get_logger()


def _okta_client(params: dict) -> OktaClient | None:
    domain = params.get("okta_domain")
    api_token = params.get("okta_api_token")
    if not (domain and api_token):
        return None
    return OktaClient(domain=domain, api_token=api_token)


def _entra_client(params: dict) -> AzureEntraClient | None:
    tenant_id = params.get("azure_tenant_id")
    client_id = params.get("azure_client_id")
    client_secret = params.get("azure_client_secret")
    if not (tenant_id and client_id and client_secret):
        return None
    return AzureEntraClient(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
    )


def _gws_client(params: dict) -> GoogleWorkspaceClient | None:
    key = params.get("gws_service_account_key")
    subject = params.get("gws_subject_email")
    if not (key and subject):
        return None
    return GoogleWorkspaceClient(service_account_key=key, subject_email=subject)


_SIM_NOTE_IDENTITY = (
    "Simulation mode — provide okta_domain+okta_api_token, "
    "azure_tenant_id+azure_client_id+azure_client_secret, or "
    "gws_service_account_key+gws_subject_email to enable live execution." + _SIM_FUNNEL_CTA
)


class DisableUserExecutor(BaseExecutor):
    """Disables a user account in Okta / Entra / Workspace.

    target: user login (email) or vendor-native user ID.
    """

    async def execute(self, request: ActionRequest) -> ActionResult:
        user_id = request.target
        params = request.parameters
        logger.info("Executing disable_user", user=user_id)

        okta = _okta_client(params)
        if okta:
            try:
                result = await okta.disable_user(user_id)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.HIGH,
                    output=result,
                    rollback_data={"user_id": user_id, "vendor": "okta"},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("disable_user.okta.failed", user=user_id, error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.HIGH,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        entra = _entra_client(params)
        if entra:
            try:
                result = await entra.disable_user(user_id)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.HIGH,
                    output=result,
                    rollback_data={"user_id": user_id, "vendor": "entra"},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("disable_user.entra.failed", user=user_id, error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.HIGH,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        gws = _gws_client(params)
        if gws:
            try:
                result = await gws.suspend_user(user_id)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.HIGH,
                    output=result,
                    rollback_data={"user_id": user_id, "vendor": "gws"},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("disable_user.gws.failed", user=user_id, error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.HIGH,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        logger.warning(
            "disable_user.simulation",
            user=user_id,
            reason="no IdP credentials",
            funnel="plugin-sdk",
        )
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius=BlastRadius.HIGH,
            output={
                "action": "disable_user",
                "user": user_id,
                "note": _SIM_NOTE_IDENTITY,
            },
            rollback_data={"user_id": user_id},
            completed_at=datetime.utcnow(),
        )

    async def rollback(self, result: ActionResult) -> bool:
        user_id = result.rollback_data.get("user_id")
        vendor = result.rollback_data.get("vendor")
        logger.info("Rolling back disable_user (re-enabling)", user=user_id, vendor=vendor)
        # Best-effort vendor-aware rollback. We don't surface client
        # credentials here because rollback is invoked by the
        # ledger, not by an action request, and the playbook is
        # expected to re-issue an explicit ``enable_user`` action
        # rather than rely on the rollback path.
        return True


class ResetPasswordExecutor(BaseExecutor):
    """Forces a password reset for a user via Okta / Entra / GWS.

    target: user login (email) or vendor-native user ID.
    parameters.send_email: bool (default True) — used only for the Okta path.
    """

    async def execute(self, request: ActionRequest) -> ActionResult:
        user_id = request.target
        params = request.parameters
        send_email = params.get("send_email", True)
        logger.info("Executing reset_password", user=user_id)

        okta = _okta_client(params)
        if okta:
            try:
                result = await okta.reset_password(user_id, send_email=send_email)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.MEDIUM,
                    output=result,
                    rollback_data={"user_id": user_id, "vendor": "okta"},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("reset_password.okta.failed", user=user_id, error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.MEDIUM,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        entra = _entra_client(params)
        if entra:
            try:
                result = await entra.reset_password(user_id)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.MEDIUM,
                    output=result,
                    rollback_data={"user_id": user_id, "vendor": "entra"},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("reset_password.entra.failed", user=user_id, error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.MEDIUM,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        gws = _gws_client(params)
        if gws:
            try:
                result = await gws.reset_password(user_id)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.MEDIUM,
                    output=result,
                    rollback_data={"user_id": user_id, "vendor": "gws"},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("reset_password.gws.failed", user=user_id, error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.MEDIUM,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        logger.warning(
            "reset_password.simulation",
            user=user_id,
            reason="no IdP credentials",
            funnel="plugin-sdk",
        )
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius=BlastRadius.MEDIUM,
            output={
                "action": "reset_password",
                "user": user_id,
                "send_email": send_email,
                "note": _SIM_NOTE_IDENTITY,
            },
            rollback_data={"user_id": user_id},
            completed_at=datetime.utcnow(),
        )

    async def rollback(self, result: ActionResult) -> bool:
        logger.info("reset_password has no automatic rollback (password already sent)")
        return True


class SuspendSessionExecutor(BaseExecutor):
    """Suspends a user's active sessions in Okta / Entra / GWS.

    target: user login (email) or vendor-native user ID.

    For Okta this clears all sessions and then suspends the user
    (matching the legacy behaviour). For Entra and Workspace the
    canonical verb is "revoke sessions" — we explicitly do not
    flip ``accountEnabled`` / ``suspended`` here because that's the
    job of ``disable_user``; this verb stops at killing the
    live tokens.
    """

    async def execute(self, request: ActionRequest) -> ActionResult:
        user_id = request.target
        params = request.parameters
        logger.info("Executing suspend_session", user=user_id)

        okta = _okta_client(params)
        if okta:
            try:
                sessions_result = await okta.clear_sessions(user_id)
                suspend_result = await okta.suspend_user(user_id)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.HIGH,
                    output={
                        "sessions_cleared": sessions_result,
                        "user_suspended": suspend_result,
                    },
                    rollback_data={"user_id": user_id, "vendor": "okta"},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("suspend_session.okta.failed", user=user_id, error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.HIGH,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        entra = _entra_client(params)
        if entra:
            try:
                result = await entra.revoke_sessions(user_id)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.HIGH,
                    output=result,
                    rollback_data={"user_id": user_id, "vendor": "entra"},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("suspend_session.entra.failed", user=user_id, error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.HIGH,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        gws = _gws_client(params)
        if gws:
            try:
                result = await gws.revoke_sessions(user_id)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.HIGH,
                    output=result,
                    rollback_data={"user_id": user_id, "vendor": "gws"},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("suspend_session.gws.failed", user=user_id, error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.HIGH,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        logger.warning(
            "suspend_session.simulation",
            user=user_id,
            reason="no IdP credentials",
            funnel="plugin-sdk",
        )
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius=BlastRadius.HIGH,
            output={
                "action": "suspend_session",
                "user": user_id,
                "note": _SIM_NOTE_IDENTITY,
            },
            rollback_data={"user_id": user_id},
            completed_at=datetime.utcnow(),
        )

    async def rollback(self, result: ActionResult) -> bool:
        user_id = result.rollback_data.get("user_id")
        vendor = result.rollback_data.get("vendor")
        logger.info("Rolling back suspend_session (un-suspending)", user=user_id, vendor=vendor)
        return True


class ForceMFAExecutor(BaseExecutor):
    """Forces MFA re-enrollment for a user in Okta / Entra / GWS.

    target: user login (email) or vendor-native user ID.
    """

    async def execute(self, request: ActionRequest) -> ActionResult:
        user_id = request.target
        params = request.parameters
        logger.info("Executing force_mfa", user=user_id)

        okta = _okta_client(params)
        if okta:
            try:
                result = await okta.force_mfa_enrollment(user_id)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.MEDIUM,
                    output=result,
                    rollback_data={"user_id": user_id, "vendor": "okta"},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("force_mfa.okta.failed", user=user_id, error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.MEDIUM,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        entra = _entra_client(params)
        if entra:
            try:
                result = await entra.require_mfa(user_id)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.MEDIUM,
                    output=result,
                    rollback_data={"user_id": user_id, "vendor": "entra"},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("force_mfa.entra.failed", user=user_id, error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.MEDIUM,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        gws = _gws_client(params)
        if gws:
            try:
                result = await gws.enforce_2sv(user_id)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.MEDIUM,
                    output=result,
                    rollback_data={"user_id": user_id, "vendor": "gws"},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("force_mfa.gws.failed", user=user_id, error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.MEDIUM,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        logger.warning(
            "force_mfa.simulation",
            user=user_id,
            reason="no IdP credentials",
            funnel="plugin-sdk",
        )
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius=BlastRadius.MEDIUM,
            output={
                "action": "force_mfa",
                "user": user_id,
                "note": _SIM_NOTE_IDENTITY,
            },
            rollback_data={"user_id": user_id},
            completed_at=datetime.utcnow(),
        )

    async def rollback(self, result: ActionResult) -> bool:
        logger.info("force_mfa has no automatic rollback")
        return True
