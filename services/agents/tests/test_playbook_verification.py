"""A verification asks a person, then their manager, and the run branches.

Depth plan 5.4. The "Done when" is one sentence — *a verification playbook
asks a user and then a manager, waits, branches on a signed answer, and
contains on "no" after approval* — and it is five separate properties, each
with a way of looking satisfied while being broken:

**Asks.** A prompt that was composed and not delivered. ``_deliver`` here
reports what the action bridge was actually asked to send, so a test cannot
pass on a message nobody sent.

**Then a manager.** An escalation that fires on a timer the sweeper never
reads, or one that messages the subject again because the manager lookup
quietly returned nothing. ``no_manager`` is a distinct recorded outcome for
exactly that reason, and a *failed* lookup leaves the row waiting rather
than declaring that somebody has no manager.

**Waits.** The one this file found a real defect in. A durable pause has to
stop the run, and until this work only the ``approval`` branch knew that —
so a durable ``wait`` wrote its pause and carried straight on.
``test_a_durable_pause_stops_the_run`` is the regression.

**Branches on a signed answer.** Not on *an* answer: the signature binds the
answer to the stage, so a link minted for the user cannot answer for the
manager an hour later.

**Contains on "no".** Through the ordinary ``condition`` step and the
ordinary governed dispatch, not a special path only this verb understands.
"""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from app.playbook import engine as engine_module
from app.playbook import pause as playbook_pause
from app.playbook import verification
from app.playbook.engine import PlaybookEngine, RunStatus
from app.playbook.models import Playbook, PlaybookStep, StepType

_SECRET = "verification-test-secret"


# ---------------------------------------------------------------------------
# A pause store that honours the predicates the real SQL uses
# ---------------------------------------------------------------------------


class _PauseRows:
    """Stands in for ``aisoc_playbook_pauses``.

    Every conditional ``UPDATE`` in ``pause.py`` carries predicates that are
    the whole of its concurrency safety — ``status = 'waiting'``,
    ``verification_stage = 'user'``, ``verification_outcome IS NULL``. A
    double that ignored them would pass against an implementation that
    ignored them too, which is how a double-answered prompt ships. So each
    is honoured here, and the live-Postgres pass in
    ``tests/isolation/test_verification_pause_live.py`` runs the same calls
    against the real schema so the SQL itself is graded somewhere.
    """

    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    async def execute(self, sql: str, *args: Any) -> str:
        if "INSERT INTO aisoc_playbook_pauses" in sql:
            self.rows.append(
                {
                    "id": args[0],
                    "tenant_id": args[1],
                    "run_id": args[2],
                    "playbook_id": args[3],
                    "playbook_name": args[4],
                    "step_index": args[5],
                    "step_id": args[6],
                    "run_context": args[7],
                    "step_results": args[8],
                    "approval_id": args[9],
                    "expires_at": args[10],
                    "kind": args[11],
                    "resume_at": args[12],
                    "resume_token": args[13],
                    "verification_stage": args[14],
                    "verification_subject": args[15],
                    "verification_manager": args[16],
                    "verification_outcome": None,
                    "status": "waiting",
                }
            )
            return "INSERT 0 1"

        if "SET verification_stage = 'manager'" in sql:
            for row in self._waiting(args[0], args[1]):
                if row["kind"] != "verification" or row["verification_stage"] != "user":
                    continue
                row["verification_stage"] = "manager"
                row["verification_manager"] = args[2]
                row["resume_at"] = args[3]
                return "UPDATE 1"
            return "UPDATE 0"

        if "SET verification_outcome = $3" in sql:
            for row in self._waiting(args[0], args[1]):
                if row["kind"] != "verification" or row["verification_outcome"] is not None:
                    continue
                row["verification_outcome"] = args[2]
                return "UPDATE 1"
            return "UPDATE 0"

        if "UPDATE aisoc_playbook_pauses" in sql and "WHERE id =" in sql:
            for row in self._waiting(args[0], args[3]):
                row["status"] = args[1]
                row["resolution"] = args[2]
                return "UPDATE 1"
            return "UPDATE 0"
        return "OK"

    def _waiting(self, pause_id: Any, tenant_id: Any) -> list[dict[str, Any]]:
        return [r for r in self.rows if r["id"] == pause_id and str(r["tenant_id"]) == str(tenant_id) and r["status"] == "waiting"]

    async def fetchrow(self, sql: str, *args: Any) -> dict[str, Any] | None:
        if "aisoc_verification_policies" in sql:
            opted_in = {c.lower() for c in _POLICY_CLASSES}
            for candidate in args[1]:
                if candidate in opted_in:
                    return {"alert_class": candidate}
            return None
        if "aisoc_scim_users" in sql:
            manager = _SCIM_MANAGERS.get(str(args[1]).lower())
            return {"manager_ref": manager} if manager else None
        if "kind = 'verification'" in sql:
            for row in self.rows:
                if row.get("resume_token") == args[0] and row["kind"] == "verification" and row["status"] == "waiting":
                    return row
            return None
        return None

    async def fetch(self, sql: str, *args: Any) -> list[dict[str, Any]]:
        if "kind = 'verification'" in sql:
            due = args[0]
            return [
                r
                for r in self.rows
                if r["status"] == "waiting" and r["kind"] == "verification" and r["resume_at"] is not None and r["resume_at"] <= due
            ]
        return []


#: Mutated per test rather than passed in, because the policy and SCIM reads
#: happen three call frames below the code under test.
_POLICY_CLASSES: set[str] = set()
_SCIM_MANAGERS: dict[str, str] = {}


@pytest.fixture(autouse=True)
def _wire(monkeypatch: pytest.MonkeyPatch) -> _PauseRows:
    rows = _PauseRows()

    @asynccontextmanager
    async def _acquire():
        yield rows

    class _Pool:
        def acquire(self):  # noqa: ANN202
            return _acquire()

    async def _pool() -> Any:
        return _Pool()

    monkeypatch.setattr(playbook_pause, "_pool", _pool)
    monkeypatch.setattr(verification, "_pool", _pool)
    monkeypatch.setenv("AISOC_CHATOPS_RESPONSE_SECRET", _SECRET)
    monkeypatch.setenv("AISOC_PLAYBOOK_VERIFY_EXECUTE", "1")
    monkeypatch.setenv("AISOC_AGENTS_PUBLIC_URL", "https://agents.example.test")
    _POLICY_CLASSES.clear()
    _SCIM_MANAGERS.clear()
    return rows


@pytest.fixture
def sent() -> list[dict[str, Any]]:
    return []


@pytest.fixture(autouse=True)
def _capture_dispatch(monkeypatch: pytest.MonkeyPatch, sent: list[dict[str, Any]]) -> None:
    """Record what the action bridge was asked to send.

    Returns ``executed: True`` because the question under test is the
    workflow, not the Slack arm. The arm's own failure path is covered by
    ``test_a_prompt_that_did_not_deliver_fails_the_step``, which flips this.
    """

    async def _dispatch(**kwargs: Any) -> dict[str, Any]:
        sent.append(kwargs)
        return {"executed": True, "status": "executed"}

    monkeypatch.setattr(engine_module.action_bridge, "dispatch_step", _dispatch)


@pytest.fixture(autouse=True)
def _approval_opens(monkeypatch: pytest.MonkeyPatch) -> None:
    """The approval the containment branch pauses on is created.

    Same reasoning as ``_capture_dispatch``: the question in this file is the
    verification workflow, not whether the agents service can reach the API.
    It matters that this is stubbed rather than absent, though — an approval
    step whose approval cannot be created now **fails closed** instead of
    suspending with ``approval_id=None``, so without this the branch under
    test would stop for a reason that has nothing to do with verification.
    The creation path itself is covered by ``test_playbook_approval_creation.py``.
    """

    async def _create(*_args: Any, **_kwargs: Any) -> str:
        return "approval-for-the-verification-branch"

    monkeypatch.setattr(engine_module, "_create_approval", _create)


# ---------------------------------------------------------------------------
# The signature
# ---------------------------------------------------------------------------


def test_a_user_stage_link_does_not_answer_for_the_manager() -> None:
    """The stale-link case the stage binding exists for.

    Without the stage in the signature, the subject's own "yes, that was me"
    link would still verify after the question escalated — so the subject
    could answer on their manager's behalf, which is precisely the
    separation the escalation exists to create.
    """
    token = verification.mint_resume_token()
    user_sig = verification.sign_answer(resume_token=token, answer="acknowledged", stage="user", secret=_SECRET)

    assert verification.signature_valid(resume_token=token, answer="acknowledged", stage="user", signature=user_sig, secret=_SECRET)
    assert not verification.signature_valid(resume_token=token, answer="acknowledged", stage="manager", signature=user_sig, secret=_SECRET)


def test_an_answer_cannot_be_swapped_for_another() -> None:
    """A link for one answer must not verify as a different answer."""
    token = verification.mint_resume_token()
    yes = verification.sign_answer(resume_token=token, answer="acknowledged", stage="user", secret=_SECRET)
    assert not verification.signature_valid(resume_token=token, answer="denied", stage="user", signature=yes, secret=_SECRET)


def test_no_secret_refuses_to_mint_rather_than_minting_an_unsigned_link(monkeypatch: pytest.MonkeyPatch) -> None:
    """An unsigned link would take an answer from anybody who reached it."""
    monkeypatch.delenv("AISOC_CHATOPS_RESPONSE_SECRET", raising=False)
    with pytest.raises(verification.VerificationConfigError):
        verification.sign_answer(resume_token="t", answer="denied", stage="user")


# ---------------------------------------------------------------------------
# The two refusals
# ---------------------------------------------------------------------------


def _verify_step(**params: Any) -> PlaybookStep:
    return PlaybookStep(id="verify", name="Ask the user", type=StepType.VERIFY_USER, params={"user": "alice@corp.test", **params})


def _playbook(*steps: PlaybookStep) -> Playbook:
    return Playbook(id="pb-verify", name="verification", steps=list(steps))


def _context(**extra: Any) -> dict[str, Any]:
    return {"tenant_id": str(uuid.uuid4()), "alert_class": "impossible_travel", **extra}


@pytest.mark.asyncio
async def test_a_confirmed_true_positive_is_never_asked(sent: list[dict[str, Any]]) -> None:
    """No opt-out, and not even for a class the tenant opted into.

    Messaging the account an attacker holds tells them they are seen.
    """
    _POLICY_CLASSES.add("impossible_travel")
    run = await PlaybookEngine().run(_playbook(_verify_step()), _context(disposition="true_positive"))

    assert sent == []
    result = run.step_results[0]["result"]
    assert result["sent"] is False
    assert result["verification"]["outcome"] == "refused"
    assert "confirmed true positive" in result["reason"]


@pytest.mark.asyncio
async def test_a_class_the_tenant_did_not_opt_into_is_not_asked(sent: list[dict[str, Any]]) -> None:
    """Default-deny. An empty policy table asks nobody."""
    run = await PlaybookEngine().run(_playbook(_verify_step()), _context())

    assert sent == []
    assert run.step_results[0]["result"]["verification"]["outcome"] == "refused"
    assert "has not opted into" in run.step_results[0]["result"]["reason"]


@pytest.mark.asyncio
async def test_an_unreadable_policy_refuses_rather_than_proceeding(monkeypatch: pytest.MonkeyPatch, sent: list[dict[str, Any]]) -> None:
    """Unreadable permission is not permission."""

    async def _no_pool() -> Any:
        return None

    monkeypatch.setattr(verification, "_pool", _no_pool)
    run = await PlaybookEngine().run(_playbook(_verify_step()), _context())

    assert sent == []
    assert "could not be read" in run.step_results[0]["result"]["reason"]


@pytest.mark.asyncio
async def test_an_analyst_initiated_run_does_not_need_the_opt_in(sent: list[dict[str, Any]]) -> None:
    """The opt-in governs the *automatic* path.

    A playbook a human started is a human decision; requiring a policy row
    for it would make the control a blocker rather than a default.
    """
    run = await PlaybookEngine().run(_playbook(_verify_step()), _context(initiated_by_human=True))

    assert len(sent) == 1
    assert run.status is RunStatus.PAUSED


# ---------------------------------------------------------------------------
# The wait, and the defect it uncovered
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_durable_pause_stops_the_run(sent: list[dict[str, Any]]) -> None:
    """The regression for the defect this item found in 5.3's `wait`.

    Only the ``approval`` branch broke out of the run loop, so a step that
    suspended to Postgres and returned PENDING had its pause written and
    then ran everything after it — and ran it again when the callback
    resumed from ``step_index + 1``. Reverting the ``paused``/``pause_id``
    break in ``PlaybookEngine.run`` makes this fail with the second step
    recorded.
    """
    _POLICY_CLASSES.add("impossible_travel")
    after = PlaybookStep(id="after", name="should not run yet", type=StepType.CLOSE_CASE, params={})
    run = await PlaybookEngine().run(_playbook(_verify_step(), after), _context())

    assert run.status is RunStatus.PAUSED
    assert [r["step_id"] for r in run.step_results] == ["verify"]


@pytest.mark.asyncio
async def test_a_prompt_that_did_not_deliver_fails_the_step(monkeypatch: pytest.MonkeyPatch) -> None:
    """A question nobody received is not a question that was asked."""
    _POLICY_CLASSES.add("impossible_travel")

    async def _refuse(**_kwargs: Any) -> dict[str, Any]:
        return {"executed": False, "error": "no Slack destination configured"}

    monkeypatch.setattr(engine_module.action_bridge, "dispatch_step", _refuse)
    run = await PlaybookEngine().run(_playbook(_verify_step()), _context())

    assert run.status is RunStatus.FAILED
    assert run.step_results[0]["result"]["sent"] is False


@pytest.mark.asyncio
async def test_a_preview_names_who_would_be_asked(monkeypatch: pytest.MonkeyPatch, sent: list[dict[str, Any]]) -> None:
    """Off by default, and the preview is useful rather than reassuring."""
    monkeypatch.setenv("AISOC_PLAYBOOK_VERIFY_EXECUTE", "0")
    _POLICY_CLASSES.add("impossible_travel")
    run = await PlaybookEngine().run(_playbook(_verify_step()), _context())

    assert sent == []
    result = run.step_results[0]["result"]
    assert result["previewed"] is True
    assert result["subject"] == "alice@corp.test"
    assert result["answers"] == ["acknowledged", "denied", "unsure"]


# ---------------------------------------------------------------------------
# The whole workflow
# ---------------------------------------------------------------------------


def _containment_playbook() -> Playbook:
    """Ask, branch on the answer, and contain on "no" behind an approval."""
    return Playbook(
        id="pb-verify",
        name="verify then contain",
        steps=[
            _verify_step(),
            PlaybookStep(
                id="branch",
                name="Was it them?",
                type=StepType.CONDITION,
                condition={"expression": "verification_outcome == 'denied'"},
                next_true="approve",
                next_false="done",
            ),
            PlaybookStep(id="approve", name="Approve containment", type=StepType.APPROVAL, params={"prompt": "Disable the account?"}),
            PlaybookStep(id="disable", name="Disable the account", type=StepType.DISABLE_USER, params={"user": "alice@corp.test"}),
            PlaybookStep(id="done", name="Close", type=StepType.CLOSE_CASE, params={}),
        ],
    )


async def _store_returns(monkeypatch: pytest.MonkeyPatch, playbook: Playbook) -> None:
    from app.playbook import store as store_module

    class _Store:
        def get(self, _id: str, *, tenant_id: str | None = None) -> Playbook:
            return playbook

    monkeypatch.setattr(store_module.PlaybookStore, "default", classmethod(lambda _cls: _Store()))


@pytest.mark.asyncio
async def test_denied_resumes_into_the_approval_that_gates_containment(
    monkeypatch: pytest.MonkeyPatch,
    _wire: _PauseRows,
    sent: list[dict[str, Any]],
) -> None:
    """The plan's sentence, end to end.

    Asks, pauses, takes a signed "no", resumes, branches to the approval
    step and stops there — because containment is gated on a human and this
    test must not be able to pass by containing without one.
    """
    _POLICY_CLASSES.add("impossible_travel")
    playbook = _containment_playbook()
    await _store_returns(monkeypatch, playbook)

    first = await PlaybookEngine().run(playbook, _context())
    assert first.status is RunStatus.PAUSED
    token = _wire.rows[0]["resume_token"]

    signature = verification.sign_answer(resume_token=token, answer="denied", stage="user", secret=_SECRET)
    resumed = await engine_module.resume_verification(resume_token=token, answer="denied", signature=signature)

    assert resumed is not None
    assert resumed.run_id == first.run_id
    assert resumed.context["verification"]["outcome"] == "denied"
    # Branched to the approval, and stopped there: `disable` never ran.
    #
    # The resumed record starts at `branch` rather than at `verify`, which
    # is the engine's existing resume shape and not a quirk of this verb: a
    # pause stores the results captured *before* the suspending step, so
    # `approval` and `wait` lose their own record the same way. What the
    # verification contributes to the resumed run is the context the branch
    # reads, asserted above.
    assert [r["step_id"] for r in resumed.step_results] == ["branch", "approve"]
    assert resumed.status is RunStatus.PAUSED


@pytest.mark.asyncio
async def test_acknowledged_takes_the_other_branch(monkeypatch: pytest.MonkeyPatch, _wire: _PauseRows) -> None:
    """ "Yes, that was me" must not reach the containment branch."""
    _POLICY_CLASSES.add("impossible_travel")
    playbook = _containment_playbook()
    await _store_returns(monkeypatch, playbook)

    await PlaybookEngine().run(playbook, _context())
    token = _wire.rows[0]["resume_token"]
    signature = verification.sign_answer(resume_token=token, answer="acknowledged", stage="user", secret=_SECRET)
    resumed = await engine_module.resume_verification(resume_token=token, answer="acknowledged", signature=signature)

    assert resumed is not None
    assert "approve" not in [r["step_id"] for r in resumed.step_results]


@pytest.mark.asyncio
async def test_a_second_click_resumes_once(monkeypatch: pytest.MonkeyPatch, _wire: _PauseRows) -> None:
    """A double-tap, or a chat client prefetching the link."""
    _POLICY_CLASSES.add("impossible_travel")
    playbook = _containment_playbook()
    await _store_returns(monkeypatch, playbook)

    await PlaybookEngine().run(playbook, _context())
    token = _wire.rows[0]["resume_token"]
    signature = verification.sign_answer(resume_token=token, answer="denied", stage="user", secret=_SECRET)

    assert await engine_module.resume_verification(resume_token=token, answer="denied", signature=signature) is not None
    assert await engine_module.resume_verification(resume_token=token, answer="denied", signature=signature) is None


@pytest.mark.asyncio
async def test_an_unsigned_answer_is_refused(monkeypatch: pytest.MonkeyPatch, _wire: _PauseRows) -> None:
    """The token alone is not the credential."""
    _POLICY_CLASSES.add("impossible_travel")
    playbook = _containment_playbook()
    await _store_returns(monkeypatch, playbook)

    await PlaybookEngine().run(playbook, _context())
    token = _wire.rows[0]["resume_token"]

    assert await engine_module.resume_verification(resume_token=token, answer="denied", signature="") is None
    assert _wire.rows[0]["status"] == "waiting"


# ---------------------------------------------------------------------------
# The escalation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_an_unanswered_prompt_escalates_to_the_manager_from_scim(
    monkeypatch: pytest.MonkeyPatch,
    _wire: _PauseRows,
    sent: list[dict[str, Any]],
) -> None:
    """The second question, to a different person, on the same pause."""
    _POLICY_CLASSES.add("impossible_travel")
    _SCIM_MANAGERS["alice@corp.test"] = "bob@corp.test"
    playbook = _containment_playbook()
    await _store_returns(monkeypatch, playbook)

    await PlaybookEngine().run(playbook, _context())
    assert sent[-1]["target"] == "alice@corp.test"

    later = datetime.now(UTC) + timedelta(hours=1)
    resumed = await engine_module.resume_due_verifications(now=later)

    # Nothing resumed — a second question was asked.
    assert resumed == []
    assert _wire.rows[0]["verification_stage"] == "manager"
    assert _wire.rows[0]["verification_manager"] == "bob@corp.test"
    assert sent[-1]["target"] == "bob@corp.test"


@pytest.mark.asyncio
async def test_the_manager_answers_and_the_run_branches(
    monkeypatch: pytest.MonkeyPatch,
    _wire: _PauseRows,
    sent: list[dict[str, Any]],
) -> None:
    """A manager-stage link verifies where the user-stage one no longer does."""
    _POLICY_CLASSES.add("impossible_travel")
    _SCIM_MANAGERS["alice@corp.test"] = "bob@corp.test"
    playbook = _containment_playbook()
    await _store_returns(monkeypatch, playbook)

    await PlaybookEngine().run(playbook, _context())
    token = _wire.rows[0]["resume_token"]
    await engine_module.resume_due_verifications(now=datetime.now(UTC) + timedelta(hours=1))

    stale = verification.sign_answer(resume_token=token, answer="denied", stage="user", secret=_SECRET)
    assert await engine_module.resume_verification(resume_token=token, answer="denied", signature=stale) is None

    fresh = verification.sign_answer(resume_token=token, answer="denied", stage="manager", secret=_SECRET)
    resumed = await engine_module.resume_verification(resume_token=token, answer="denied", signature=fresh)

    assert resumed is not None
    assert resumed.context["verification"]["stage"] == "manager"
    assert resumed.context["verification"]["manager"] == "bob@corp.test"
    assert "approve" in [r["step_id"] for r in resumed.step_results]


@pytest.mark.asyncio
async def test_nobody_answers_and_the_run_resumes_with_timed_out(
    monkeypatch: pytest.MonkeyPatch,
    _wire: _PauseRows,
) -> None:
    """A timeout is an outcome, not an absence of one."""
    _POLICY_CLASSES.add("impossible_travel")
    _SCIM_MANAGERS["alice@corp.test"] = "bob@corp.test"
    playbook = _containment_playbook()
    await _store_returns(monkeypatch, playbook)

    await PlaybookEngine().run(playbook, _context())
    await engine_module.resume_due_verifications(now=datetime.now(UTC) + timedelta(hours=1))
    resumed_ids = await engine_module.resume_due_verifications(now=datetime.now(UTC) + timedelta(hours=10))

    assert len(resumed_ids) == 1
    assert _wire.rows[0]["verification_outcome"] == "timed_out"
    assert _wire.rows[0]["status"] == "resumed"


@pytest.mark.asyncio
async def test_a_subject_with_no_manager_resumes_with_no_manager(
    monkeypatch: pytest.MonkeyPatch,
    _wire: _PauseRows,
) -> None:
    """There is nobody to escalate to, and the run is told so.

    Distinct from ``timed_out``: a playbook may reasonably contain on "the
    person did not answer and there is nobody above them" while waiting out
    a second deadline for a manager who exists.
    """
    _POLICY_CLASSES.add("impossible_travel")
    playbook = _containment_playbook()
    await _store_returns(monkeypatch, playbook)

    await PlaybookEngine().run(playbook, _context())
    resumed_ids = await engine_module.resume_due_verifications(now=datetime.now(UTC) + timedelta(hours=1))

    assert len(resumed_ids) == 1
    assert _wire.rows[0]["verification_outcome"] == "no_manager"


@pytest.mark.asyncio
async def test_a_failed_manager_lookup_leaves_the_pause_waiting(
    monkeypatch: pytest.MonkeyPatch,
    _wire: _PauseRows,
) -> None:
    """A database blip must not become a statement about a reporting line."""
    _POLICY_CLASSES.add("impossible_travel")
    playbook = _containment_playbook()
    await _store_returns(monkeypatch, playbook)
    await PlaybookEngine().run(playbook, _context())

    async def _error(**_kwargs: Any) -> verification.ManagerLookup:
        return verification.ManagerLookup(None, "error")

    monkeypatch.setattr(verification, "resolve_manager", _error)
    assert await engine_module.resume_due_verifications(now=datetime.now(UTC) + timedelta(hours=1)) == []
    assert _wire.rows[0]["status"] == "waiting"
    assert _wire.rows[0]["verification_outcome"] is None


@pytest.mark.asyncio
async def test_a_manager_named_on_the_step_beats_the_directory(
    monkeypatch: pytest.MonkeyPatch,
    _wire: _PauseRows,
    sent: list[dict[str, Any]],
) -> None:
    """An author who named one has made a decision."""
    _POLICY_CLASSES.add("impossible_travel")
    _SCIM_MANAGERS["alice@corp.test"] = "bob@corp.test"
    playbook = _playbook(_verify_step(manager="carol@corp.test"))
    await _store_returns(monkeypatch, playbook)

    await PlaybookEngine().run(playbook, _context())
    await engine_module.resume_due_verifications(now=datetime.now(UTC) + timedelta(hours=1))

    assert _wire.rows[0]["verification_manager"] == "carol@corp.test"
    assert sent[-1]["target"] == "carol@corp.test"
