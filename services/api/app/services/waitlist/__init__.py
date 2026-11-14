"""Waitlist service module — T6.1 (managed-instance `tryaisoc.com`).

Exposes the helpers the signup endpoint needs without dragging the
endpoint into the implementation details of either the rate limiter or
the Slack webhook poster:

  * :class:`SignupRateLimiter` — per-IP token bucket. Public endpoints
    can't trust the tenant scope (there isn't one yet), so we limit on
    the request's source address. Defaults are tuned for a marketing
    landing page: ten signups per source per hour is plenty for a
    booth-with-laptop or a shared-NAT office; a runaway script gets
    capped at 20 burst then 10/hour sustained.
  * :func:`post_slack_notification` — fire-and-forget poster to the
    sales channel. Never raises into the caller; logs and moves on if
    the webhook is down or unset.

Both helpers live behind interfaces so the signup endpoint test can
stub them without monkey-patching ``urllib.request``.
"""

from __future__ import annotations

from app.services.waitlist.rate_limit import (
    SignupRateLimitDecision,
    SignupRateLimiter,
    get_signup_rate_limiter,
)
from app.services.waitlist.slack_notify import (
    SlackNotifier,
    build_signup_message,
    get_slack_notifier,
)

__all__ = [
    "SignupRateLimitDecision",
    "SignupRateLimiter",
    "SlackNotifier",
    "build_signup_message",
    "get_signup_rate_limiter",
    "get_slack_notifier",
]
