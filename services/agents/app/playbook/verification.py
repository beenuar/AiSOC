"""Ask the affected person, then their manager, and let the run branch on it.

Depth plan 5.4.

What was there
--------------
``chatops_verify`` mints three signed links, posts them to Slack or Teams and
returns ``AWAITING_COMPLETION``. The click lands on the actions service,
which writes a ``chatops.verify.responded`` timeline event and stops. That is
a message, not a workflow, and the three things it is missing are the three
things that make the question worth asking:

* **Nobody is asked second.** A person compromised at 02:00 is asleep. With
  no escalation the prompt expires unanswered and the incident waits for the
  morning, which is the window the whole exercise exists to close.
* **Nothing branches.** The answer is a timeline entry. A playbook cannot
  contain on "no, that wasn't me", so the analyst reads the answer and does
  by hand what the playbook was written to do.
* **Nothing times out with an outcome.** An unanswered prompt is
  indistinguishable from one that was never sent.

What this module is
-------------------
The state and the rules. The pause row (``app.playbook.pause``, ``kind =
'verification'``) is the state; this module owns the stage machine, the
manager lookup, the signature over an answer, and the two refusals that keep
the contract's caution.

The signature, and why a random token is not enough on its own
--------------------------------------------------------------
The link arrives in a chat message to a person who holds no AiSOC session, so
the URL is the whole credential — the same reasoning the ``wait`` callback
records. The 32-byte resume token covers "could somebody who was not asked
reach this run". It does not cover the other two:

* **The answer is in the URL.** Three links differing by one path segment
  means a holder of any of them can construct the other two. That is fine —
  they are entitled to all three answers — but it also means a *guessed*
  token yields three working links rather than one, so the signature is what
  makes the answer unforgeable rather than merely unguessable.
* **A stale link must not answer for the next stage.** The escalation reuses
  the row, so without binding the stage into the signature the user's
  original "yes" link would still resolve after the question moved to their
  manager, and the manager's answer would be whatever the user clicked an
  hour late.

So the signature covers ``(token, answer, stage)`` and is compared in
constant time.

Two refusals, and they are not the same refusal
-----------------------------------------------
Both live here rather than in the engine, because a rule enforced at the
call site is a rule the next call site forgets.

* **Never on a confirmed true positive.** Messaging the account an attacker
  is sitting on tells the attacker they are seen. The answer is worthless in
  both directions too: the person whose credentials were taken truthfully
  says "no, that wasn't me", and an attacker says whatever keeps the session
  alive. This refusal has no opt-out.
* **Auto-sent only for alert classes a tenant opted into.** Default-deny, in
  ``aisoc_verification_policies``. A playbook an analyst starts by hand is a
  human decision and is not governed by this table; the gate is on the
  automatic path.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
from dataclasses import dataclass
from typing import Any

# Stdlib logging, not structlog — `app.playbook.engine` imports this module
# and two gates import the engine with only httpx and pydantic installed.
# The same constraint `pause.py` and `action_bridge.py` record.
logger = logging.getLogger("aisoc.playbook.verification")

#: The three answers a person may give. ``unsure`` is deliberately not a
#: second ``denied``: "I don't recognise this" from someone who travels is a
#: different signal from "that was not me", and collapsing them would make
#: the cautious answer trigger containment.
ANSWERS: tuple[str, ...] = ("acknowledged", "denied", "unsure")

#: Outcomes a run can branch on. The first three are answers; the last two
#: are the absence of one, recorded rather than left as silence.
OUTCOMES: tuple[str, ...] = (*ANSWERS, "timed_out", "no_manager")

#: Button labels, in a fixed order so the prompt reads the same on every
#: transport and a screenshot in the docs stays true.
ANSWER_LABELS: tuple[tuple[str, str], ...] = (
    ("acknowledged", "Yes, that was me"),
    ("denied", "No, that wasn't me"),
    ("unsure", "I'm not sure"),
)

STAGE_USER = "user"
STAGE_MANAGER = "manager"
STAGES: tuple[str, ...] = (STAGE_USER, STAGE_MANAGER)


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    try:
        value = int(raw) if raw else default
    except ValueError:
        logger.warning("%s is not an integer (%r); using %d", name, raw, default)
        return default
    return value if value > 0 else default


def user_stage_seconds() -> int:
    """How long the affected person has before it escalates.

    Thirty minutes by default. Long enough that somebody in a meeting is not
    escalated past, short enough that an escalation still lands inside the
    same shift as the alert.
    """
    return _int_env("AISOC_VERIFY_USER_TIMEOUT_SECONDS", 1800)


def manager_stage_seconds() -> int:
    """How long the manager has before the run gives up and says so.

    Longer than the user's: a manager is being asked about somebody else's
    activity and will usually go and check.
    """
    return _int_env("AISOC_VERIFY_MANAGER_TIMEOUT_SECONDS", 3600)


def execute_enabled() -> bool:
    """Whether a verification prompt may actually reach a person.

    Off unless an operator turns it on, matching every outbound verb in this
    engine. A product that messages a customer's employees the first time a
    playbook runs is one they switch off, and the preview path reports
    exactly who *would* be asked.
    """
    return os.getenv("AISOC_PLAYBOOK_VERIFY_EXECUTE", "0").strip().lower() in {"1", "true", "yes", "on"}


def _secret() -> str:
    """The HMAC key for answer signatures.

    Shares ``AISOC_CHATOPS_RESPONSE_SECRET`` with the actions service's
    verification links on purpose: both sign a click from the same person in
    the same prompt, and a second secret is a second thing to rotate and a
    second way for one half to be configured and the other not.
    """
    return os.getenv("AISOC_CHATOPS_RESPONSE_SECRET", "").strip()


class VerificationConfigError(RuntimeError):
    """The prompt cannot be signed, so it must not be sent.

    Raised rather than returned so no caller can treat an unsigned link as a
    signed one. An unsigned callback URL would accept any answer from
    anybody who could reach the route.
    """


def mint_resume_token() -> str:
    """The unguessable half of the credential. 32 bytes, URL-safe."""
    return secrets.token_urlsafe(32)


def sign_answer(*, resume_token: str, answer: str, stage: str, secret: str | None = None) -> str:
    """Signature binding one answer, at one stage, to one pause."""
    key = (secret if secret is not None else _secret()).encode("utf-8")
    if not key:
        raise VerificationConfigError(
            "AISOC_CHATOPS_RESPONSE_SECRET is unset, so a verification link cannot be signed. "
            "An unsigned link would accept any answer from anyone who reached the route."
        )
    if answer not in ANSWERS:
        raise VerificationConfigError(f"unknown verification answer {answer!r}")
    if stage not in STAGES:
        raise VerificationConfigError(f"unknown verification stage {stage!r}")
    message = f"{resume_token}|{answer}|{stage}".encode()
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def signature_valid(*, resume_token: str, answer: str, stage: str, signature: str, secret: str | None = None) -> bool:
    """Constant-time check. False on anything that does not verify.

    Returns rather than raises: a bad signature is a request to refuse, and
    the route answers the same way for "no such token" and "wrong
    signature" so neither becomes an oracle.
    """
    try:
        expected = sign_answer(resume_token=resume_token, answer=answer, stage=stage, secret=secret)
    except VerificationConfigError:
        return False
    return hmac.compare_digest(expected, signature or "")


def answer_links(*, base_url: str, resume_token: str, stage: str, secret: str | None = None) -> list[dict[str, str]]:
    """One signed URL per answer, in the fixed label order."""
    root = base_url.rstrip("/")
    return [
        {
            "answer": answer,
            "label": label,
            "url": (
                f"{root}/api/v1/playbook-verifications/{resume_token}/{answer}"
                f"?sig={sign_answer(resume_token=resume_token, answer=answer, stage=stage, secret=secret)}"
            ),
        }
        for answer, label in ANSWER_LABELS
    ]


# ---------------------------------------------------------------------------
# Who gets asked
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ManagerLookup:
    """The manager, and where the answer came from.

    The source travels with the value because the three are not equally
    trustworthy and an escalation that messaged the wrong person needs to be
    explicable afterwards. ``None`` with a source of ``"none"`` is a real
    answer — some people have no manager in the directory — and the run
    records ``no_manager`` rather than silently skipping the escalation.
    """

    manager: str | None
    source: str


async def _pool() -> Any | None:
    from app.memory.institutional import _get_pool

    try:
        return await _get_pool()
    except Exception as exc:  # noqa: BLE001
        logger.warning("verification: pool unavailable: %s", exc)
        return None


def _first_string(source: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = source.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


_MANAGER_KEYS = ("manager", "manager_email", "manager_ref", "manager_upn")


async def resolve_manager(*, tenant_id: str, subject: str, step_params: dict[str, Any], context: dict[str, Any]) -> ManagerLookup:
    """Who to ask second, from the most specific source that has an answer.

    Three sources, in order:

    1. **The step.** An author who names a manager has made a decision, and
       a directory lookup must not override it.
    2. **The run context.** Identity enrichment puts a manager here when the
       alert carried one; this is the IdP's answer arriving through the
       alert rather than through a second call.
    3. **SCIM.** ``aisoc_scim_users.manager_ref`` — ``manager.value`` from
       the enterprise user extension, which every IdP that provisions users
       sends when the directory has one.

    A failed lookup is reported as ``source="error"`` and not as "no
    manager". Escalating to nobody because the database was briefly
    unreachable, and recording that as "this person has no manager", is the
    kind of silence this repository keeps finding.
    """
    named = _first_string(step_params, _MANAGER_KEYS)
    if named:
        return ManagerLookup(named, "step")

    from_context = _first_string(context, _MANAGER_KEYS)
    if from_context:
        return ManagerLookup(from_context, "context")

    if not tenant_id or not subject:
        return ManagerLookup(None, "none")

    pool = await _pool()
    if pool is None:
        return ManagerLookup(None, "error")

    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT s.manager_ref
                  FROM aisoc_scim_users s
                  JOIN users u ON u.id = s.user_id
                 WHERE s.tenant_id = $1::uuid
                   AND s.manager_ref IS NOT NULL
                   AND (LOWER(u.email) = LOWER($2) OR LOWER(COALESCE(s.external_id, '')) = LOWER($2))
                 LIMIT 1
                """,
                tenant_id,
                subject,
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("verification: manager lookup failed for this tenant: %s", exc)
        return ManagerLookup(None, "error")

    if row is None or not row["manager_ref"]:
        return ManagerLookup(None, "none")
    return ManagerLookup(str(row["manager_ref"]), "scim")


# ---------------------------------------------------------------------------
# Whether to ask at all
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SendDecision:
    """Whether the prompt may be sent automatically, and why not."""

    allowed: bool
    reason: str


#: Dispositions that mean somebody already decided this is real. Matched
#: case-insensitively against the run context.
_CONFIRMED_TRUE_POSITIVE = frozenset({"true_positive", "confirmed_true_positive", "confirmed", "malicious"})

_DISPOSITION_KEYS = ("disposition", "verdict", "triage_disposition", "alert_disposition")
_CLASS_KEYS = ("alert_class", "rule_id", "category", "alert_category", "detection_id")


def _alert_classes(step_params: dict[str, Any], context: dict[str, Any]) -> list[str]:
    """Every name this alert could be opted into under, lower-cased."""
    found: list[str] = []
    for source in (step_params, context):
        for key in _CLASS_KEYS:
            value = source.get(key)
            if isinstance(value, str) and value.strip():
                folded = value.strip().lower()
                if folded not in found:
                    found.append(folded)
    alert = context.get("alert")
    if isinstance(alert, dict):
        for key in _CLASS_KEYS:
            value = alert.get(key)
            if isinstance(value, str) and value.strip():
                folded = value.strip().lower()
                if folded not in found:
                    found.append(folded)
    return found


def is_confirmed_true_positive(context: dict[str, Any]) -> bool:
    """Whether something already decided this alert is real."""
    sources: list[dict[str, Any]] = [context]
    alert = context.get("alert")
    if isinstance(alert, dict):
        sources.append(alert)
    for source in sources:
        for key in _DISPOSITION_KEYS:
            value = source.get(key)
            if isinstance(value, str) and value.strip().lower().replace("-", "_") in _CONFIRMED_TRUE_POSITIVE:
                return True
    return False


async def may_auto_send(*, tenant_id: str, step_params: dict[str, Any], context: dict[str, Any]) -> SendDecision:
    """The two refusals, in the order that matters.

    The true-positive refusal is checked first and has no opt-out, so a
    tenant that opted the class in still does not message an account an
    attacker holds.
    """
    if is_confirmed_true_positive(context):
        return SendDecision(
            False,
            "the alert is already a confirmed true positive, so the prompt was not sent: it would tell an attacker "
            "holding this account that they have been seen, and neither answer would be worth having",
        )

    classes = _alert_classes(step_params, context)
    if not classes:
        return SendDecision(
            False,
            "the alert carries no class (no alert_class, rule_id or category), so there is nothing for a tenant to "
            "have opted into; a prompt was not sent",
        )

    pool = await _pool()
    if pool is None:
        return SendDecision(
            False,
            "the verification policy could not be read, so the prompt was not sent. Unreadable permission is not permission.",
        )

    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT alert_class
                  FROM aisoc_verification_policies
                 WHERE tenant_id = $1::uuid
                   AND LOWER(alert_class) = ANY($2::text[])
                 LIMIT 1
                """,
                tenant_id,
                classes,
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("verification: policy lookup failed: %s", exc)
        return SendDecision(False, f"the verification policy could not be read ({exc}), so the prompt was not sent")

    if row is None:
        return SendDecision(
            False,
            f"this tenant has not opted into automatic verification for {', '.join(classes)}; a prompt was not sent",
        )
    return SendDecision(True, f"tenant opted into automatic verification for {row['alert_class']}")
