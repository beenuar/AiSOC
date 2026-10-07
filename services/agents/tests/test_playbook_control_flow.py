"""Depth 5.3 — `wait`, `parallel` and `loop`, and the keys that make them safe.

Reproduce, on the tree this started from: ``StepType`` had 22 members and
none of them was any of these three. ``Playbook.model_validate`` rejected
``{"type": "wait"}`` at ``steps.0.type``, the published union in
``packages/types`` had 22 members and the console palette could not offer
one. So "contain, then re-check in five minutes", "revoke every session this
user holds" and "ask three vendors at once" each had to be hand-unrolled
into a fixed chain, which is why none of the 62 shipped packs attempts any
of them.

What is asserted here is mostly the *refusals*, because a control-flow step
that quietly does less than it says is worse than one that is absent:

* an empty ``parallel`` or ``loop`` fails rather than reporting a success
  for work it did not do;
* a ``loop`` that hits its ceiling says so instead of silently truncating —
  stopping at 25 of 300 sessions leaves 275 live and a clean-looking record;
* a ``wait`` with neither a duration nor a callback fails rather than
  becoming a no-op that reads exactly like a wait that happened;
* a ``wait`` whose pause cannot be written fails, because continuing past it
  runs the steps the wait exists to delay.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

import pytest
from app.playbook import engine as engine_mod
from app.playbook import idempotency
from app.playbook.bounds import ABSOLUTE_MAX_LOOP_ITERATIONS, ABSOLUTE_MAX_WAIT_SECONDS, MAX_INLINE_WAIT_SECONDS
from app.playbook.engine import PlaybookEngine, RunStatus, StepStatus
from app.playbook.models import Playbook, PlaybookStep, StepCondition, StepType

pytestmark = pytest.mark.asyncio


def _playbook(*steps: PlaybookStep) -> Playbook:
    return Playbook(id="pb-cf", name="control flow", steps=list(steps))


def _child(step_id: str, **kwargs: Any) -> PlaybookStep:
    """A child step whose handler is replaced per test."""
    return PlaybookStep(id=step_id, name=step_id, type=StepType.ENRICH, **kwargs)


@pytest.fixture
def enrich(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Record every enrich call, with the context it saw."""
    calls: list[dict[str, Any]] = []

    async def _handler(step: PlaybookStep, context: dict[str, Any], http: Any) -> dict:
        calls.append({"step_id": step.id, "item": context.get("item"), "index": context.get("index")})
        return {"ok": True, "seen": step.id}

    monkeypatch.setitem(engine_mod._HANDLERS, StepType.ENRICH, _handler)
    return calls


# ---------------------------------------------------------------------------
# The vocabulary
# ---------------------------------------------------------------------------


def test_the_three_types_exist_and_are_runnable() -> None:
    for name in ("wait", "parallel", "loop"):
        assert name in {s.value for s in StepType}
    assert set(engine_mod._CONTROL_FLOW) == {StepType.WAIT, StepType.PARALLEL, StepType.LOOP}


def test_a_control_flow_step_is_not_in_the_handler_table() -> None:
    """They need the run, the client and the dry-run flag.

    Pinned because the obvious "fix" for the gate is to put them in
    `_HANDLERS` with a widened signature, which would hand a mutable run
    object to fifteen response verbs that have no business touching it.
    """
    for step_type in engine_mod._CONTROL_FLOW:
        assert step_type not in engine_mod._HANDLERS


# ---------------------------------------------------------------------------
# wait
# ---------------------------------------------------------------------------


class TestWait:
    async def test_a_short_timer_sleeps_in_place(self, monkeypatch: pytest.MonkeyPatch) -> None:
        slept: list[float] = []
        real_sleep = asyncio.sleep

        async def _recording(delay: float, *args: Any, **kwargs: Any) -> Any:
            slept.append(delay)
            return await real_sleep(0, *args, **kwargs)

        monkeypatch.setattr(engine_mod.asyncio, "sleep", _recording)
        run = await PlaybookEngine().run(
            _playbook(PlaybookStep(id="w", name="hold", type=StepType.WAIT, params={"seconds": 5})),
            {"tenant_id": "t"},
        )
        assert run.status is RunStatus.COMPLETED
        assert slept == [5]
        assert run.step_results[0]["result"]["durable"] is False

    async def test_a_long_timer_becomes_a_durable_pause(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Past the inline ceiling it suspends, because a wait held in a
        process is lost by the deploy most likely to interrupt it."""
        suspended: dict[str, Any] = {}

        async def _suspend(**kwargs: Any) -> Any:
            suspended.update(kwargs)

            class _Pause:
                id = "pause-1"
                resume_token = "tok"
                resume_at = None

            return _Pause()

        monkeypatch.setattr(engine_mod.playbook_pause, "suspend", _suspend)
        run = await PlaybookEngine().run(
            _playbook(PlaybookStep(id="w", name="hold", type=StepType.WAIT, params={"seconds": MAX_INLINE_WAIT_SECONDS + 1})),
            {"tenant_id": "t"},
        )
        assert suspended["kind"] == "wait"
        assert suspended["resume_at"] is not None
        assert suspended["resume_token"]
        assert run.step_results[0]["status"] is StepStatus.PENDING

    async def test_a_callback_wait_has_no_timer(self, monkeypatch: pytest.MonkeyPatch) -> None:
        suspended: dict[str, Any] = {}

        async def _suspend(**kwargs: Any) -> Any:
            suspended.update(kwargs)
            return type("P", (), {"id": "p", "resume_token": "tok", "resume_at": None})()

        monkeypatch.setattr(engine_mod.playbook_pause, "suspend", _suspend)
        await PlaybookEngine().run(
            _playbook(PlaybookStep(id="w", name="hold", type=StepType.WAIT, params={"until": "callback"})),
            {"tenant_id": "t"},
        )
        assert suspended["resume_at"] is None, "a callback wait must not also be on a clock"

    @pytest.mark.parametrize("params", [{}, {"seconds": 0}, {"seconds": "soon"}, {"seconds": True}])
    async def test_a_wait_with_nothing_to_wait_for_fails(self, params: dict[str, Any]) -> None:
        """A no-op that reports success reads exactly like a wait that happened.

        ``seconds: true`` is in here because ``int(True)`` is 1: coercing it
        would turn "this field is malformed" into a one-second wait that the
        run record calls a wait.
        """
        run = await PlaybookEngine().run(
            _playbook(PlaybookStep(id="w", name="hold", type=StepType.WAIT, params=params)),
            {"tenant_id": "t"},
        )
        assert run.status is RunStatus.FAILED
        assert "waited for nothing" in run.step_results[0]["result"]["error"]

    async def test_a_long_wait_is_not_clamped_to_the_step_timeout(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A six-hour wait must stay six hours.

        ``clamp_timeout`` bounds how long a worker may be held on one
        outbound call and tops out at five minutes. Reusing it here — which
        the first version of this did — silently turned every long wait into
        a five-minute one, which is the same silent truncation the loop
        ceiling is explicitly written to avoid.
        """
        suspended: dict[str, Any] = {}

        async def _suspend(**kwargs: Any) -> Any:
            suspended.update(kwargs)
            return type("P", (), {"id": "p", "resume_token": "tok", "resume_at": None})()

        monkeypatch.setattr(engine_mod.playbook_pause, "suspend", _suspend)
        await PlaybookEngine().run(
            _playbook(PlaybookStep(id="w", name="hold", type=StepType.WAIT, params={"seconds": 6 * 3600})),
            {"tenant_id": "t"},
        )
        waited = (suspended["resume_at"] - datetime.now(UTC)).total_seconds()
        assert 6 * 3600 - 60 < waited <= 6 * 3600

    async def test_a_wait_beyond_the_absolute_ceiling_is_bounded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def _suspend(**kwargs: Any) -> Any:
            return type("P", (), {"id": "p", "resume_token": "tok", "resume_at": None})()

        monkeypatch.setattr(engine_mod.playbook_pause, "suspend", _suspend)
        run = await PlaybookEngine().run(
            _playbook(PlaybookStep(id="w", name="hold", type=StepType.WAIT, params={"seconds": 10**9})),
            {"tenant_id": "t"},
            dry_run=True,
        )
        assert run.step_results[0]["result"]["would_wait_seconds"] == ABSOLUTE_MAX_WAIT_SECONDS

    async def test_a_pause_that_cannot_be_written_fails_closed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Continuing would run the steps the wait exists to delay."""

        async def _no_pause(**kwargs: Any) -> Any:
            return None

        monkeypatch.setattr(engine_mod.playbook_pause, "suspend", _no_pause)
        ran: list[str] = []

        async def _after(step: PlaybookStep, context: dict[str, Any], http: Any) -> dict:
            ran.append(step.id)
            return {"ok": True}

        monkeypatch.setitem(engine_mod._HANDLERS, StepType.ENRICH, _after)
        run = await PlaybookEngine().run(
            _playbook(
                PlaybookStep(id="w", name="hold", type=StepType.WAIT, params={"until": "callback"}),
                _child("after"),
            ),
            {"tenant_id": "t"},
        )
        assert run.status is RunStatus.FAILED
        assert ran == [], "the run continued past a wait nothing could resume"

    async def test_a_preview_neither_sleeps_nor_suspends(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A preview that took five minutes is a preview nobody runs."""

        async def _boom(**kwargs: Any) -> Any:
            raise AssertionError("a dry run suspended")

        monkeypatch.setattr(engine_mod.playbook_pause, "suspend", _boom)
        run = await PlaybookEngine().run(
            _playbook(PlaybookStep(id="w", name="hold", type=StepType.WAIT, params={"seconds": 3600})),
            {"tenant_id": "t"},
            dry_run=True,
        )
        assert run.status is RunStatus.COMPLETED
        assert run.step_results[0]["result"]["would_wait_seconds"] == 3600


# ---------------------------------------------------------------------------
# parallel
# ---------------------------------------------------------------------------


class TestParallel:
    async def test_branches_all_run_and_the_step_joins(self, enrich: list[dict[str, Any]]) -> None:
        run = await PlaybookEngine().run(
            _playbook(
                PlaybookStep(
                    id="p",
                    name="fan out",
                    type=StepType.PARALLEL,
                    steps=[_child("a"), _child("b"), _child("c")],
                )
            ),
            {"tenant_id": "t"},
        )
        assert run.status is RunStatus.COMPLETED
        assert {call["step_id"] for call in enrich} == {"a", "b", "c"}
        assert run.step_results[0]["result"]["branches_succeeded"] == 3

    async def test_branches_run_concurrently(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Sequential execution would satisfy every other assertion here."""
        running = 0
        peak = 0

        async def _handler(step: PlaybookStep, context: dict[str, Any], http: Any) -> dict:
            nonlocal running, peak
            running += 1
            peak = max(peak, running)
            await asyncio.sleep(0)
            running -= 1
            return {"ok": True}

        monkeypatch.setitem(engine_mod._HANDLERS, StepType.ENRICH, _handler)
        await PlaybookEngine().run(
            _playbook(PlaybookStep(id="p", name="fan out", type=StepType.PARALLEL, steps=[_child("a"), _child("b"), _child("c")])),
            {"tenant_id": "t"},
        )
        assert peak > 1, "the branches ran one after another"

    async def test_a_branch_cannot_overwrite_another_branchs_context(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Each branch gets its own copy, so the merged result does not
        depend on which finished first."""
        seen: list[Any] = []

        async def _handler(step: PlaybookStep, context: dict[str, Any], http: Any) -> dict:
            seen.append(context.get("verdict"))
            return {"verdict": step.id}

        monkeypatch.setitem(engine_mod._HANDLERS, StepType.ENRICH, _handler)
        await PlaybookEngine().run(
            _playbook(PlaybookStep(id="p", name="fan out", type=StepType.PARALLEL, steps=[_child("a"), _child("b")])),
            {"tenant_id": "t", "verdict": "initial"},
        )
        assert seen == ["initial", "initial"]

    async def test_join_all_fails_when_one_branch_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def _handler(step: PlaybookStep, context: dict[str, Any], http: Any) -> dict:
            if step.id == "b":
                raise RuntimeError("vendor said no")
            return {"ok": True}

        monkeypatch.setitem(engine_mod._HANDLERS, StepType.ENRICH, _handler)
        run = await PlaybookEngine().run(
            _playbook(PlaybookStep(id="p", name="fan out", type=StepType.PARALLEL, steps=[_child("a"), _child("b")])),
            {"tenant_id": "t"},
        )
        assert run.status is RunStatus.FAILED
        assert "1 of 2 parallel branches failed" in run.step_results[0]["result"]["error"]

    async def test_join_any_succeeds_when_one_branch_succeeds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def _handler(step: PlaybookStep, context: dict[str, Any], http: Any) -> dict:
            if step.id == "b":
                raise RuntimeError("vendor said no")
            return {"ok": True}

        monkeypatch.setitem(engine_mod._HANDLERS, StepType.ENRICH, _handler)
        run = await PlaybookEngine().run(
            _playbook(
                PlaybookStep(id="p", name="fan out", type=StepType.PARALLEL, params={"join": "any"}, steps=[_child("a"), _child("b")])
            ),
            {"tenant_id": "t"},
        )
        assert run.status is RunStatus.COMPLETED

    async def test_a_parallel_with_no_branches_fails(self) -> None:
        run = await PlaybookEngine().run(
            _playbook(PlaybookStep(id="p", name="fan out", type=StepType.PARALLEL)),
            {"tenant_id": "t"},
        )
        assert run.status is RunStatus.FAILED
        assert "runs nothing" in run.step_results[0]["result"]["error"]

    async def test_an_unknown_join_is_refused_rather_than_defaulted(self) -> None:
        run = await PlaybookEngine().run(
            _playbook(PlaybookStep(id="p", name="fan out", type=StepType.PARALLEL, params={"join": "most"}, steps=[_child("a")])),
            {"tenant_id": "t"},
        )
        assert run.status is RunStatus.FAILED
        assert "unknown join" in run.step_results[0]["result"]["error"]

    async def test_a_branch_condition_is_honoured(self, enrich: list[dict[str, Any]]) -> None:
        await PlaybookEngine().run(
            _playbook(
                PlaybookStep(
                    id="p",
                    name="fan out",
                    type=StepType.PARALLEL,
                    steps=[_child("a"), _child("b", condition=StepCondition(expression="severity == 'critical'"))],
                )
            ),
            {"tenant_id": "t", "severity": "low"},
        )
        assert {call["step_id"] for call in enrich} == {"a"}


# ---------------------------------------------------------------------------
# loop
# ---------------------------------------------------------------------------


class TestLoop:
    async def test_the_body_runs_once_per_item(self, enrich: list[dict[str, Any]]) -> None:
        run = await PlaybookEngine().run(
            _playbook(PlaybookStep(id="l", name="each", type=StepType.LOOP, params={"over": "sessions"}, steps=[_child("revoke")])),
            {"tenant_id": "t", "sessions": ["s1", "s2", "s3"]},
        )
        assert run.status is RunStatus.COMPLETED
        assert [call["item"] for call in enrich] == ["s1", "s2", "s3"]
        assert [call["index"] for call in enrich] == [0, 1, 2]

    async def test_a_path_that_resolves_to_nothing_is_not_zero_items(self) -> None:
        """A typo in the path and an empty list are different facts.

        Reporting "zero items" for a bad path sends the author to look at
        their data instead of their playbook.
        """
        run = await PlaybookEngine().run(
            _playbook(PlaybookStep(id="l", name="each", type=StepType.LOOP, params={"over": "sessionz"}, steps=[_child("revoke")])),
            {"tenant_id": "t", "sessions": ["s1"]},
        )
        assert run.status is RunStatus.FAILED
        assert "resolved to nothing" in run.step_results[0]["result"]["error"]

    async def test_a_non_list_is_refused(self) -> None:
        run = await PlaybookEngine().run(
            _playbook(PlaybookStep(id="l", name="each", type=StepType.LOOP, params={"over": "user"}, steps=[_child("revoke")])),
            {"tenant_id": "t", "user": "alice"},
        )
        assert run.status is RunStatus.FAILED
        assert "not a list" in run.step_results[0]["result"]["error"]

    async def test_the_ceiling_is_reported_not_silently_applied(self, enrich: list[dict[str, Any]]) -> None:
        """A loop that stopped at 25 of 300 sessions leaves 275 live."""
        run = await PlaybookEngine().run(
            _playbook(
                PlaybookStep(
                    id="l",
                    name="each",
                    type=StepType.LOOP,
                    params={"over": "sessions", "max_iterations": 2},
                    steps=[_child("revoke")],
                )
            ),
            {"tenant_id": "t", "sessions": ["s1", "s2", "s3", "s4"]},
        )
        assert run.status is RunStatus.FAILED
        result = run.step_results[0]["result"]
        assert result["truncated"] is True
        assert result["items_seen"] == 4
        assert result["iterations_run"] == 2
        assert "2 were not processed" in result["error"]

    async def test_the_absolute_ceiling_cannot_be_raised_by_a_playbook(self, enrich: list[dict[str, Any]]) -> None:
        """`over` routinely resolves to an enrichment response, which is to
        say to attacker-influenced data."""
        run = await PlaybookEngine().run(
            _playbook(
                PlaybookStep(
                    id="l",
                    name="each",
                    type=StepType.LOOP,
                    params={"over": "sessions", "max_iterations": 10_000},
                    steps=[_child("revoke")],
                )
            ),
            {"tenant_id": "t", "sessions": [f"s{i}" for i in range(ABSOLUTE_MAX_LOOP_ITERATIONS + 5)]},
        )
        assert run.status is RunStatus.FAILED
        assert run.step_results[0]["result"]["iterations_run"] == ABSOLUTE_MAX_LOOP_ITERATIONS

    async def test_a_loop_with_no_body_fails(self) -> None:
        run = await PlaybookEngine().run(
            _playbook(PlaybookStep(id="l", name="each", type=StepType.LOOP, params={"over": "sessions"})),
            {"tenant_id": "t", "sessions": ["s1"]},
        )
        assert run.status is RunStatus.FAILED
        assert "runs nothing" in run.step_results[0]["result"]["error"]

    async def test_a_failed_iteration_is_counted_and_reported(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def _handler(step: PlaybookStep, context: dict[str, Any], http: Any) -> dict:
            if context.get("index") == 1:
                raise RuntimeError("vendor said no")
            return {"ok": True}

        monkeypatch.setitem(engine_mod._HANDLERS, StepType.ENRICH, _handler)
        run = await PlaybookEngine().run(
            _playbook(PlaybookStep(id="l", name="each", type=StepType.LOOP, params={"over": "sessions"}, steps=[_child("revoke")])),
            {"tenant_id": "t", "sessions": ["s1", "s2", "s3"]},
        )
        assert run.status is RunStatus.FAILED
        result = run.step_results[0]["result"]
        assert result["failed_iterations"] == 1
        assert result["iterations_run"] == 3, "the default is to carry on through a failed item"


# ---------------------------------------------------------------------------
# idempotency keys
# ---------------------------------------------------------------------------


class TestIdempotencyKeys:
    def test_a_key_is_stable_for_the_same_step_in_the_same_run(self) -> None:
        """This is what makes a resume safe: the retry carries the key the
        first attempt did."""
        first = idempotency.step_key(run_id="r1", step_id="s1")
        assert first == idempotency.step_key(run_id="r1", step_id="s1")

    def test_keys_differ_by_run_step_and_position(self) -> None:
        keys = {
            idempotency.step_key(run_id="r1", step_id="s1"),
            idempotency.step_key(run_id="r2", step_id="s1"),
            idempotency.step_key(run_id="r1", step_id="s2"),
            idempotency.step_key(run_id="r1", step_id="s1", path=("i0",)),
            idempotency.step_key(run_id="r1", step_id="s1", path=("i1",)),
            idempotency.step_key(run_id="r1", step_id="s1", path=("b0", "i1")),
        }
        assert len(keys) == 6

    def test_the_separator_cannot_be_forged_by_an_id(self) -> None:
        """``("a", "b:c")`` and ``("a:b", "c")`` must not collide.

        Ids reach this from playbook content, so a separator an author can
        type would let two different steps share a key — and a shared key
        is a deduplicated action somebody expected to happen twice.
        """
        assert idempotency.step_key(run_id="a", step_id="b:c") != idempotency.step_key(run_id="a:b", step_id="c")
        assert idempotency.step_key(run_id="a", step_id="b-c") != idempotency.step_key(run_id="a-b", step_id="c")

    def test_a_key_does_not_leak_the_run_or_step_id(self) -> None:
        """Keys travel to vendors in request bodies."""
        key = idempotency.step_key(run_id="run-secret", step_id="step-secret")
        assert "run-secret" not in key
        assert "step-secret" not in key

    async def test_every_step_result_carries_its_key(self, enrich: list[dict[str, Any]]) -> None:
        run = await PlaybookEngine().run(_playbook(_child("a"), _child("b")), {"tenant_id": "t"})
        keys = [r["result"]["idempotency_key"] for r in run.step_results]
        assert all(keys)
        assert len(set(keys)) == 2

    async def test_loop_iterations_get_distinct_keys(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Without the iteration coordinate every revoke in a loop would
        carry one key, and a vendor deduplicating on it would act once."""
        run = await PlaybookEngine().run(
            _playbook(PlaybookStep(id="l", name="each", type=StepType.LOOP, params={"over": "sessions"}, steps=[_child("revoke")])),
            {"tenant_id": "t", "sessions": ["s1", "s2", "s3"]},
        )
        iterations = run.step_results[0]["result"]["iterations"]
        keys = [it["steps"][0]["result"]["idempotency_key"] for it in iterations]
        assert len(set(keys)) == 3

    async def test_parallel_branches_get_distinct_keys(self, enrich: list[dict[str, Any]]) -> None:
        run = await PlaybookEngine().run(
            _playbook(PlaybookStep(id="p", name="fan out", type=StepType.PARALLEL, steps=[_child("a"), _child("b")])),
            {"tenant_id": "t"},
        )
        branches = run.step_results[0]["result"]["branches"]
        keys = [b["result"]["idempotency_key"] for b in branches]
        assert len(set(keys)) == 2

    async def test_a_resumed_run_reproduces_its_keys(self, enrich: list[dict[str, Any]]) -> None:
        """A resume must not look like new work to a vendor dedupe window."""
        first = await PlaybookEngine().run(_playbook(_child("a")), {"tenant_id": "t"})
        again = await PlaybookEngine().run(
            _playbook(_child("a")),
            {"tenant_id": "t"},
            resume_run_id=first.run_id,
        )
        assert first.step_results[0]["result"]["idempotency_key"] == again.step_results[0]["result"]["idempotency_key"]


# ---------------------------------------------------------------------------
# The resumers — a durable pause with no caller is a run that never continues
# ---------------------------------------------------------------------------


class TestWaitsAreActuallyResumed:
    """The half that a passing unit test cannot see.

    `pause.expire_due` has existed since parity 5.2 and its only reference
    in the tree is a test, so an approval nobody decided stayed `waiting`
    forever and the `expired` outcome was never recorded by anything. A
    `wait` inherits that and makes it worse: there is no human who might
    come back, so the run simply stops.
    """

    async def test_the_sweeper_drives_both_resume_and_expiry(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.playbook import sweeper

        called: list[str] = []

        async def _resume(**kwargs: Any) -> list[str]:
            called.append("resume")
            return ["run-1"]

        async def _expire(**kwargs: Any) -> list[str]:
            called.append("expire")
            return []

        monkeypatch.setattr(engine_mod, "resume_due_waits", _resume)
        monkeypatch.setattr(engine_mod.playbook_pause, "expire_due", _expire)

        counts = await sweeper.sweep_once()
        # Resume before expire: a pause whose timer came due in the same
        # tick that its TTL lapsed should run, not be cancelled.
        assert called == ["resume", "expire"]
        assert counts == {"resumed": 1, "expired": 0}

    async def test_the_sweeper_survives_a_failing_pass(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A sweeper that dies on one bad pass stops resuming everything."""
        from app.playbook import sweeper

        attempts = 0

        async def _boom() -> dict[str, int]:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise RuntimeError("database away")
            raise asyncio.CancelledError

        monkeypatch.setattr(sweeper, "sweep_once", _boom)

        async def _no_delay(_delay: float) -> None:
            return None

        monkeypatch.setattr(sweeper.asyncio, "sleep", _no_delay)
        with pytest.raises(asyncio.CancelledError):
            await sweeper.run_forever(interval_seconds=0.01)
        assert attempts == 2, "the loop ended on the first failure"

    async def test_a_callback_resumes_once_however_often_it_is_delivered(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Every webhook sender retries when a 2xx is slow.

        The pause is claimed before the run continues, so the second
        delivery matches no waiting row and resumes nothing.
        """
        claims: list[str] = []

        class _Pause:
            id = "p1"
            tenant_id = "t"
            run_id = "r1"
            playbook_id = "pb-cf"
            resume_index = 1
            run_context: dict[str, Any] = {"tenant_id": "t"}
            step_results: list[dict[str, Any]] = []

        async def _find(**kwargs: Any) -> Any:
            return _Pause()

        async def _resolve(**kwargs: Any) -> bool:
            claims.append(kwargs["pause_id"])
            return len(claims) == 1

        monkeypatch.setattr(engine_mod.playbook_pause, "find_wait_by_token", _find)
        monkeypatch.setattr(engine_mod.playbook_pause, "resolve", _resolve)
        from app.playbook.store import PlaybookStore

        monkeypatch.setattr(PlaybookStore, "default", classmethod(lambda cls: _StoreStub()))

        first = await engine_mod.resume_wait(resume_token="tok")
        second = await engine_mod.resume_wait(resume_token="tok")
        assert first is not None
        assert second is None, "a replayed callback resumed the run twice"

    async def test_an_unknown_token_resumes_nothing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def _none(**kwargs: Any) -> Any:
            return None

        monkeypatch.setattr(engine_mod.playbook_pause, "find_wait_by_token", _none)
        assert await engine_mod.resume_wait(resume_token="nope") is None

    def test_the_callback_route_is_registered_and_is_deliberately_unauthenticated(self) -> None:
        """A callback comes from a vendor that holds no AiSOC credential.

        Asserted rather than assumed because the route lives on a second
        router, and the shape this repo has shipped before is an
        authorization that reads as present and never runs.
        """
        from app.api.playbooks import router, waits_router

        paths = {route.path for route in waits_router.routes}
        assert "/api/v1/playbook-waits/{resume_token}/resume" in paths
        assert waits_router.dependencies == []
        assert router.dependencies, "the main playbooks router must stay default-deny"


class _StoreStub:
    def get(self, playbook_id: str) -> Playbook:
        return _playbook(_child("a"), _child("b"))
