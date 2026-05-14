"""Runtime bounds for playbook step execution (H-7 / Batch 10).

Centralises the per-step ``timeout_seconds`` and ``retry_max`` limits so they
are enforced in *every* place a step parameter is consumed — including
``step.params.get("timeout_seconds")`` paths that bypass the Pydantic field
validator on :class:`PlaybookStep`.

Why a runtime clamp on top of Pydantic bounds?
----------------------------------------------
Some handlers (e.g. ``_handle_osquery_live_query``) intentionally read
``timeout_seconds`` out of ``step.params`` instead of the typed field on
``PlaybookStep``. Pydantic only validates the *field*, so a malicious or
malformed playbook can sneak ``params.timeout_seconds = 86400`` past the
model. This module provides a single source of truth that both the model
defaults and the handlers consult, so the bound holds regardless of where
the value originates.

Environment overrides
---------------------
Operators can raise the ceiling for slow-running on-prem agents via:

``AISOC_PLAYBOOK_MAX_TIMEOUT_SECONDS``
    Maximum per-step timeout enforced at runtime by :func:`clamp_timeout`.
    Default 300. Clamped to
    ``[MIN_TIMEOUT_SECONDS, ABSOLUTE_MAX_PARAM_TIMEOUT_SECONDS]``.

``AISOC_PLAYBOOK_MAX_RETRIES``
    Maximum ``retry_max`` value any step may declare. Default 10. Clamped
    to ``[0, ABSOLUTE_MAX_RETRIES]``.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Final

logger = logging.getLogger("aisoc.playbook.bounds")

# ── Hard limits ─────────────────────────────────────────────────────────────
# These are absolute ceilings — even with env overrides we will never accept
# a value above ABSOLUTE_MAX_*. They exist to bound the worst case (e.g. a
# malicious playbook trying to pin a connector thread for hours).
#
# Two distinct ceilings:
#
# - ``ABSOLUTE_MAX_TIMEOUT_SECONDS`` (1 hour) is the cap enforced by the
#   Pydantic field on :class:`PlaybookStep`. Some step types (notably
#   ``approval``) legitimately wait on a human and need long timeouts —
#   capping at 15 minutes would break existing approval-gated playbooks
#   (e.g. ``phishing-investigation`` declares a 920s step timeout for a
#   900s approval wait + 20s buffer).
#
# - ``ABSOLUTE_MAX_PARAM_TIMEOUT_SECONDS`` (15 minutes) is the cap applied
#   by :func:`clamp_timeout` when a handler reads ``step.params.timeout_seconds``
#   directly (e.g. ``_handle_osquery_live_query``). Those code paths do not
#   wait on humans, so a tight ceiling bounds DoS/amplification regardless
#   of what a malicious playbook declares.
MIN_TIMEOUT_SECONDS: Final[int] = 1
ABSOLUTE_MAX_TIMEOUT_SECONDS: Final[int] = 3600  # 1 hour — Pydantic field cap
ABSOLUTE_MAX_PARAM_TIMEOUT_SECONDS: Final[int] = 900  # 15 min — runtime params cap
ABSOLUTE_MAX_RETRIES: Final[int] = 25

# ── Default ceilings used by clamp_timeout / clamp_retries ──────────────────
# Defaults are deliberately tight: detections in this repo never read
# ``params.timeout_seconds`` above 60s and retry_max above 2, so 300s / 10
# leaves generous headroom while still being orders of magnitude below
# pathological values. Operators can raise these via env overrides up to
# the absolute ceilings above.
DEFAULT_MAX_TIMEOUT_SECONDS: Final[int] = 300  # 5 minutes
DEFAULT_MAX_RETRIES: Final[int] = 10


def _clamp_int(value: int, lo: int, hi: int) -> int:
    if value < lo:
        return lo
    if value > hi:
        return hi
    return value


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        parsed = int(raw)
    except (TypeError, ValueError):
        logger.warning(
            "Ignoring non-integer %s=%r, falling back to default %d",
            name,
            raw,
            default,
        )
        return default
    clamped = _clamp_int(parsed, lo, hi)
    if clamped != parsed:
        logger.warning(
            "%s=%d clamped to %d (range %d..%d)",
            name,
            parsed,
            clamped,
            lo,
            hi,
        )
    return clamped


def max_timeout_seconds() -> int:
    """Effective per-step runtime timeout ceiling, honouring env overrides.

    This is the ceiling used by :func:`clamp_timeout` for ``params``-derived
    values (e.g. ``_handle_osquery_live_query`` reading
    ``step.params.timeout_seconds``). It is intentionally tighter than the
    Pydantic field cap on :class:`PlaybookStep.timeout_seconds`, which has
    to accommodate long human-approval waits.
    """
    return _env_int(
        "AISOC_PLAYBOOK_MAX_TIMEOUT_SECONDS",
        DEFAULT_MAX_TIMEOUT_SECONDS,
        MIN_TIMEOUT_SECONDS,
        ABSOLUTE_MAX_PARAM_TIMEOUT_SECONDS,
    )


def max_retries() -> int:
    """Effective per-step retry ceiling, honouring env overrides."""
    return _env_int(
        "AISOC_PLAYBOOK_MAX_RETRIES",
        DEFAULT_MAX_RETRIES,
        0,
        ABSOLUTE_MAX_RETRIES,
    )


def clamp_timeout(value: Any, *, default: int | None = None) -> int:
    """Clamp an arbitrary ``timeout_seconds`` value into the allowed range.

    Non-integer or missing values fall back to ``default`` (or the
    PlaybookStep default of 30s if unspecified). Bools are rejected because
    Python treats ``True`` as ``1`` and we never want a step's timeout to be
    silently coerced from a misconfigured truthy flag.
    """
    fallback = 30 if default is None else default
    if value is None or isinstance(value, bool):
        candidate: int = fallback
    else:
        try:
            candidate = int(value)
        except (TypeError, ValueError):
            logger.warning("Invalid timeout_seconds=%r, using fallback %d", value, fallback)
            candidate = fallback
    return _clamp_int(candidate, MIN_TIMEOUT_SECONDS, max_timeout_seconds())


def clamp_retries(value: Any, *, default: int = 0) -> int:
    """Clamp an arbitrary ``retry_max`` value into the allowed range."""
    if value is None or isinstance(value, bool):
        candidate: int = default
    else:
        try:
            candidate = int(value)
        except (TypeError, ValueError):
            logger.warning("Invalid retry_max=%r, using fallback %d", value, default)
            candidate = default
    return _clamp_int(candidate, 0, max_retries())


__all__ = [
    "ABSOLUTE_MAX_PARAM_TIMEOUT_SECONDS",
    "ABSOLUTE_MAX_RETRIES",
    "ABSOLUTE_MAX_TIMEOUT_SECONDS",
    "DEFAULT_MAX_RETRIES",
    "DEFAULT_MAX_TIMEOUT_SECONDS",
    "MIN_TIMEOUT_SECONDS",
    "clamp_retries",
    "clamp_timeout",
    "max_retries",
    "max_timeout_seconds",
]
