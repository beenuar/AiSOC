"""
Adaptive Card data-payload signer / verifier.

Wraps the shared HMAC primitive from the Slack bot to keep one
implementation. We deliberately *don't* re-implement the verifier —
Adaptive Card data is signed with the same shape Teams's callback
posts back to us, so the same ``sign()`` / ``verify()`` from
:mod:`services.slack-bot.app.services.hmac_verify` apply verbatim.

Canonical signed payload
========================

::

    "<verb>|<action_id>|<case_id>|<issued_at>"

— picked so a copy-paste in a card audit log is enough to re-derive the
signature manually. ``verb`` is one of ``"approve"``, ``"reject"``,
``"need_info"``.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from typing import Any

# We import the shared verifier from the Slack bot package without making
# the Teams bot depend on the entire ``slack_bolt`` runtime.
# We resolve the module by absolute path so the Teams bot can be unit-
# tested in isolation (it doesn't share a pyproject with the Slack bot
# but the two repos co-evolve — see the README).
_SLACK_BOT_HMAC_PATH = Path(__file__).resolve().parents[3] / "slack-bot" / "app" / "services" / "hmac_verify.py"

_module_name = "_aisoc_hmac_verify"
_spec = importlib.util.spec_from_file_location(_module_name, _SLACK_BOT_HMAC_PATH)
if _spec is None or _spec.loader is None:  # pragma: no cover - import-time guard
    raise ImportError(f"Cannot locate shared HMAC primitive at {_SLACK_BOT_HMAC_PATH}")

# Allow ``AISOC_TEAMS_HMAC_MODULE_PATH`` to redirect the lookup in tests
# or in unusual deployment topologies (eg. the two services live in
# completely separate containers).
override = os.environ.get("AISOC_TEAMS_HMAC_MODULE_PATH")
if override:
    _spec = importlib.util.spec_from_file_location(_module_name, override)

_hmac_module = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
sys.modules[_module_name] = _hmac_module
_spec.loader.exec_module(_hmac_module)  # type: ignore[union-attr]

sign = _hmac_module.sign
verify = _hmac_module.verify
HmacVerificationError = _hmac_module.HmacVerificationError


def canonical_payload(*, verb: str, action_id: str, case_id: str, issued_at: int) -> str:
    """Return the canonical bytes signed by both sides."""
    return f"{verb}|{action_id}|{case_id}|{int(issued_at)}"


def sign_card_data(
    *,
    verb: str,
    action_id: str,
    case_id: str,
    issued_at: int,
    secret: str,
) -> dict[str, Any]:
    """
    Mint the ``data`` payload attached to an Adaptive Card
    ``Action.Submit`` button.
    """
    payload = canonical_payload(verb=verb, action_id=action_id, case_id=case_id, issued_at=issued_at)
    return {
        "verb": verb,
        "action_id": action_id,
        "case_id": case_id,
        "issued_at": int(issued_at),
        "signature": sign(payload, secret=secret),
    }


def verify_card_data(payload: dict[str, Any], *, secret: str, max_age_seconds: int) -> None:
    """
    Verify a callback ``data`` payload from a Teams Action.Submit.

    Raises :class:`HmacVerificationError` on any failure, the same
    exception type the Slack bot raises — uniform across surfaces.
    """
    verb = str(payload.get("verb") or "")
    action_id = str(payload.get("action_id") or "")
    case_id = str(payload.get("case_id") or "")
    issued_at = payload.get("issued_at")
    signature = str(payload.get("signature") or "")
    if not verb or not action_id or issued_at is None:
        raise HmacVerificationError("Missing required fields on signed payload")
    canonical = canonical_payload(verb=verb, action_id=action_id, case_id=case_id, issued_at=int(issued_at))
    verify(
        canonical,
        signature,
        secret=secret,
        max_age_seconds=max_age_seconds,
        timestamp=float(issued_at),
    )
