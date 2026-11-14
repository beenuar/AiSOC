"""Human-in-the-Loop (HITL) approval gateway.

Replaces the prior demo-auto-approve stub in BaseAgent.call_tool. Every risky
tool call (per autonomy + risk policy) creates a HitlRequest row, fans out
notifications to console / Slack / Teams, and blocks the agent coroutine until
either an analyst decision is recorded or the SLA timer expires.

On SLA expiry the action is DENIED (never auto-approved), and an escalation
record is written for the on-call handoff.
"""
from app.hitl.gateway import HitlGateway, gateway  # noqa: F401
from app.hitl.mfa import MfaVerificationError, verify_mfa  # noqa: F401

__all__ = ["HitlGateway", "gateway", "MfaVerificationError", "verify_mfa"]
