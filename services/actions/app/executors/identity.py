"""
Identity action executors: disable user, reset password, suspend session, force MFA.

Live integration via Okta Management API when credentials are provided:
    okta_domain: str     e.g. "https://yourorg.okta.com"
    okta_api_token: str

Falls back to simulation mode if credentials are absent.
"""

from __future__ import annotations

from datetime import datetime

import structlog

from app.clients.okta_client import OktaClient
from app.executors.base import BaseExecutor, _SIM_FUNNEL_CTA
from app.models.action import ActionRequest, ActionResult, ActionStatus, BlastRadius

logger = structlog.get_logger()


def _okta_client(params: dict) -> OktaClient | None:
    domain = params.get("okta_domain")
    api_token = params.get("okta_api_token")
    if not (domain and api_token):
        return None
    return OktaClient(domain=domain, api_token=api_token)


class DisableUserExecutor(BaseExecutor):
    """Disables (deactivates) a user account in Okta.

    target: Okta user login (email) or user ID.
    Requires: okta_domain, okta_api_token in parameters.
    """

    async def execute(self, request: ActionRequest) -> ActionResult:
        user_id = request.target
        logger.info("Executing disable_user", user=user_id)

        okta = _okta_client(request.parameters)
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

        logger.warning(
            "disable_user.simulation",
            user=user_id,
            reason="no Okta credentials",
            funnel="plugin-sdk",
        )
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius=BlastRadius.HIGH,
            output={
                "action": "disable_user",
                "user": user_id,
                "note": (
                    "Simulation mode — provide okta_domain and okta_api_token to enable live execution."
                    + _SIM_FUNNEL_CTA
                ),
            },
            rollback_data={"user_id": user_id},
            completed_at=datetime.utcnow(),
        )

    async def rollback(self, result: ActionResult) -> bool:
        user_id = result.rollback_data.get("user_id")
        logger.info("Rolling back disable_user (re-enabling)", user=user_id)
        return True


class ResetPasswordExecutor(BaseExecutor):
    """Forces a password reset for a user via Okta.

    target: Okta user login (email) or user ID.
    Requires: okta_domain, okta_api_token in parameters.
    parameters.send_email: bool (default True) — send reset email to user.
    """

    async def execute(self, request: ActionRequest) -> ActionResult:
        user_id = request.target
        send_email = request.parameters.get("send_email", True)
        logger.info("Executing reset_password", user=user_id)

        okta = _okta_client(request.parameters)
        if okta:
            try:
                result = await okta.reset_password(user_id, send_email=send_email)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.MEDIUM,
                    output=result,
                    rollback_data={"user_id": user_id},
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

        logger.warning(
            "reset_password.simulation",
            user=user_id,
            reason="no Okta credentials",
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
                "note": (
                    "Simulation mode — provide okta_domain and okta_api_token to enable live execution."
                    + _SIM_FUNNEL_CTA
                ),
            },
            rollback_data={"user_id": user_id},
            completed_at=datetime.utcnow(),
        )

    async def rollback(self, result: ActionResult) -> bool:
        logger.info("reset_password has no automatic rollback (password already sent)")
        return True


class SuspendSessionExecutor(BaseExecutor):
    """Suspends a user's active sessions in Okta (clears all sessions).

    target: Okta user login (email) or user ID.
    Requires: okta_domain, okta_api_token in parameters.
    """

    async def execute(self, request: ActionRequest) -> ActionResult:
        user_id = request.target
        logger.info("Executing suspend_session", user=user_id)

        okta = _okta_client(request.parameters)
        if okta:
            try:
                # Clear active sessions, then suspend
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

        logger.warning(
            "suspend_session.simulation",
            user=user_id,
            reason="no Okta credentials",
            funnel="plugin-sdk",
        )
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius=BlastRadius.HIGH,
            output={
                "action": "suspend_session",
                "user": user_id,
                "note": (
                    "Simulation mode — provide okta_domain and okta_api_token to enable live execution."
                    + _SIM_FUNNEL_CTA
                ),
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
    """Forces MFA re-enrollment for a user in Okta.

    target: Okta user login (email) or user ID.
    Requires: okta_domain, okta_api_token in parameters.
    """

    async def execute(self, request: ActionRequest) -> ActionResult:
        user_id = request.target
        logger.info("Executing force_mfa", user=user_id)

        okta = _okta_client(request.parameters)
        if okta:
            try:
                result = await okta.force_mfa_enrollment(user_id)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.MEDIUM,
                    output=result,
                    rollback_data={"user_id": user_id},
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

        logger.warning(
            "force_mfa.simulation",
            user=user_id,
            reason="no Okta credentials",
            funnel="plugin-sdk",
        )
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius=BlastRadius.MEDIUM,
            output={
                "action": "force_mfa",
                "user": user_id,
                "note": (
                    "Simulation mode — provide okta_domain and okta_api_token to enable live execution."
                    + _SIM_FUNNEL_CTA
                ),
            },
            rollback_data={"user_id": user_id},
            completed_at=datetime.utcnow(),
        )

    async def rollback(self, result: ActionResult) -> bool:
        logger.info("force_mfa has no automatic rollback")
        return True
