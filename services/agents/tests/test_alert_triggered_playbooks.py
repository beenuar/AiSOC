"""A playbook starts from an alert, in preview, behind three switches.

Parity plan 5.1: "`find_matching()` has no production caller today. Call
it from the fused-alert path behind a setting that ships off. A playbook
first runs in preview, with its plan and simulated steps shown on the
alert, and then goes live per tenant and per playbook."

Why the switches are tested harder than the matching
-----------------------------------------------------
A playbook that runs from an alert can isolate a host nobody asked it to.
The matching logic already existed and was already tested; what did not
exist was any caller, and what matters now is that turning the caller on
is deliberate at three independent levels and that the **default of every
one of them is off**.

The ordering is the part worth pinning: preview is the default state, not
a mode somebody has to remember to use first. A deployment that enables
the feature and forgets the per-playbook list gets previews, not actions.
"""

from __future__ import annotations

import pytest
from app.playbook import alert_trigger


class _State:
    def __init__(self, **kw) -> None:  # noqa: ANN003
        self.tenant_id = kw.pop("tenant_id", "t-1")
        self.incident_id = kw.pop("incident_id", "a-1")
        self.verdict = kw.pop("verdict", "true_positive")
        self.confidence = kw.pop("confidence", 0.9)
        self.raw_alert = kw.pop("raw_alert", {"severity": "high", "tags": ["identity"]})
        self.findings: list[str] = []

    def add_finding(self, text: str) -> None:
        self.findings.append(text)


class TestTheDefaultsAreOff:
    def test_the_deployment_switch_is_off_by_default(self, monkeypatch) -> None:  # noqa: ANN001
        """A fresh install must not take a containment action on its first
        alert."""
        monkeypatch.delenv(alert_trigger.ENABLED_ENV, raising=False)
        assert alert_trigger.deployment_enabled() is False

    def test_no_playbook_is_live_by_default(self, monkeypatch) -> None:  # noqa: ANN001
        monkeypatch.delenv(alert_trigger.LIVE_PLAYBOOKS_ENV, raising=False)
        assert alert_trigger.live_playbook_ids() == set()
        assert alert_trigger.is_live(tenant_id="t-1", playbook_id="pb-1") is False

    @pytest.mark.asyncio
    async def test_disabled_says_how_to_enable_it(self, monkeypatch) -> None:  # noqa: ANN001
        """Not a silent no-op: an operator looking for why nothing ran
        should find the answer on the alert."""
        monkeypatch.delenv(alert_trigger.ENABLED_ENV, raising=False)
        outcome = await alert_trigger.run_for_alert(_State())
        assert outcome.matched == []
        assert outcome.skipped_reason
        assert alert_trigger.ENABLED_ENV in outcome.skipped_reason


class TestTheLiveList:
    @pytest.mark.parametrize(
        ("value", "tenant", "playbook", "expected"),
        [
            ("t-1:pb-1", "t-1", "pb-1", True),
            ("t-1:pb-1", "t-2", "pb-1", False),
            ("pb-1", "t-9", "pb-1", True),
            ("pb-2", "t-1", "pb-1", False),
            ("", "t-1", "pb-1", False),
            ("t-1:pb-1, t-1:pb-2", "t-1", "pb-2", True),
        ],
    )
    def test_scoping(self, monkeypatch, value, tenant, playbook, expected) -> None:  # noqa: ANN001
        monkeypatch.setenv(alert_trigger.LIVE_PLAYBOOKS_ENV, value)
        assert alert_trigger.is_live(tenant_id=tenant, playbook_id=playbook) is expected

    def test_the_list_is_read_per_call(self, monkeypatch) -> None:  # noqa: ANN001
        """Turning one off should take effect on the next alert, not the
        next restart. A playbook that can contain a host should be
        switchable off faster than a deploy."""
        monkeypatch.setenv(alert_trigger.LIVE_PLAYBOOKS_ENV, "pb-1")
        assert alert_trigger.is_live(tenant_id="t", playbook_id="pb-1") is True
        monkeypatch.setenv(alert_trigger.LIVE_PLAYBOOKS_ENV, "")
        assert alert_trigger.is_live(tenant_id="t", playbook_id="pb-1") is False


class TestTheTriggerContext:
    def test_it_is_flat(self) -> None:
        """`find_matching` filters on `severity` and `tags` at the top
        level, so a nested alert would match nothing while looking like it
        should."""
        context = alert_trigger.alert_context(_State())
        assert context["severity"] == "high"
        assert context["tags"] == ["identity"]
        assert context["tenant_id"] == "t-1"

    def test_it_carries_the_verdict_and_confidence(self) -> None:
        """A playbook's conditions read them, which is why the trigger runs
        after triage rather than before."""
        context = alert_trigger.alert_context(_State(verdict="benign", confidence=0.4))
        assert context["verdict"] == "benign"
        assert context["confidence"] == 0.4

    def test_entity_fields_are_lifted_for_templating(self) -> None:
        context = alert_trigger.alert_context(_State(raw_alert={"severity": "high", "host": "WIN-01", "username": "j.doe"}))
        assert context["host"] == "WIN-01"
        assert context["username"] == "j.doe"

    def test_a_malformed_alert_does_not_raise(self) -> None:
        context = alert_trigger.alert_context(_State(raw_alert="not a dict"))
        assert context["tenant_id"] == "t-1"


@pytest.mark.asyncio
class TestRunning:
    async def test_an_enabled_deployment_with_no_live_list_previews(self, monkeypatch) -> None:  # noqa: ANN001
        """The property the plan asks for: preview is the default state,
        not a mode somebody has to remember to use."""
        monkeypatch.setenv(alert_trigger.ENABLED_ENV, "1")
        monkeypatch.delenv(alert_trigger.LIVE_PLAYBOOKS_ENV, raising=False)

        seen: list[bool] = []

        class _Engine:
            async def run(self, playbook, context, *, dry_run=False):  # noqa: ANN001, ANN202, ARG002
                seen.append(dry_run)

                class _Run:
                    run_id = "r1"
                    status = "completed"
                    step_results: list = []

                return _Run()

        class _Playbook:
            id = "pb-1"
            name = "Contain"

        class _Store:
            def find_matching(self, event, context):  # noqa: ANN001, ANN202, ARG002
                return [_Playbook()]

        import app.playbook.engine as engine_mod
        import app.playbook.store as store_mod

        monkeypatch.setattr(engine_mod, "PlaybookEngine", _Engine)
        monkeypatch.setattr(store_mod.PlaybookStore, "default", staticmethod(lambda: _Store()))

        outcome = await alert_trigger.run_for_alert(_State())
        assert seen == [True], "the playbook ran live without being on the live list"
        assert outcome.previewed and not outcome.executed
        assert alert_trigger.LIVE_PLAYBOOKS_ENV in outcome.previewed[0]["reason"]

    async def test_a_listed_playbook_runs_live(self, monkeypatch) -> None:  # noqa: ANN001
        monkeypatch.setenv(alert_trigger.ENABLED_ENV, "1")
        monkeypatch.setenv(alert_trigger.LIVE_PLAYBOOKS_ENV, "t-1:pb-1")

        seen: list[bool] = []

        class _Engine:
            async def run(self, playbook, context, *, dry_run=False):  # noqa: ANN001, ANN202, ARG002
                seen.append(dry_run)

                class _Run:
                    run_id = "r1"
                    status = "completed"
                    step_results: list = []

                return _Run()

        class _Playbook:
            id = "pb-1"
            name = "Contain"

        class _Store:
            def find_matching(self, event, context):  # noqa: ANN001, ANN202, ARG002
                return [_Playbook()]

        import app.playbook.engine as engine_mod
        import app.playbook.store as store_mod

        monkeypatch.setattr(engine_mod, "PlaybookEngine", _Engine)
        monkeypatch.setattr(store_mod.PlaybookStore, "default", staticmethod(lambda: _Store()))

        outcome = await alert_trigger.run_for_alert(_State())
        assert seen == [False]
        assert outcome.executed and not outcome.previewed

    async def test_a_playbook_failure_does_not_lose_the_triage_result(self, monkeypatch) -> None:  # noqa: ANN001
        monkeypatch.setenv(alert_trigger.ENABLED_ENV, "1")

        import app.playbook.store as store_mod

        def _boom():  # noqa: ANN202
            raise RuntimeError("store is gone")

        monkeypatch.setattr(store_mod.PlaybookStore, "default", staticmethod(_boom))
        outcome = await alert_trigger.run_for_alert(_State())
        assert outcome.skipped_reason and "store is gone" in outcome.skipped_reason

    async def test_an_alert_with_no_tenant_is_refused(self, monkeypatch) -> None:  # noqa: ANN001
        monkeypatch.setenv(alert_trigger.ENABLED_ENV, "1")
        outcome = await alert_trigger.run_for_alert(_State(tenant_id=""))
        assert "no tenant" in (outcome.skipped_reason or "")


class TestTheWiring:
    def test_the_fused_alert_worker_calls_it(self) -> None:
        """Before this, `find_matching` had no production caller at all."""
        import pathlib

        source = pathlib.Path(__file__).resolve().parents[1].joinpath("app/workers/fused_alert_consumer.py").read_text()
        assert "alert_trigger.run_for_alert(" in source, "no playbook can start from an alert, which is the defect 5.1 exists to fix"

    def test_it_runs_after_triage_not_before(self) -> None:
        """A playbook's conditions read the verdict and the confidence."""
        import pathlib

        source = pathlib.Path(__file__).resolve().parents[1].joinpath("app/workers/fused_alert_consumer.py").read_text()
        trigger_at = source.index("alert_trigger.run_for_alert(")
        verdict_at = source.index("verdict = state.verdict")
        assert trigger_at < verdict_at
        assert source.index("tokens = tracker.total_tokens") < trigger_at


class TestTheTriggerEventMatchesTheCorpus:
    """The defect live QA found, and the suite could not.

    `run_for_alert` asked for `alert.created`. Every alert-triggered
    playbook in the corpus declares `on: alert`, so **nothing ever
    matched**: the feature was wired, enabled, and dead.

    Every test above passed, because they drive a fake store that returns
    a playbook whatever event name it is handed. A fake that ignores the
    argument cannot fail on it — the same shape that let a query select a
    column `detection_rules` does not have.

    This reads the real store rather than a second hardcoded list, because
    a list maintained beside the constant drifts with it.
    """

    def test_the_constant_matches_what_shipped_playbooks_declare(self) -> None:
        from app.playbook.alert_trigger import TRIGGER_EVENT
        from app.playbook.store import PlaybookStore

        store = PlaybookStore.default()
        store.seed_defaults()
        declared = {str(pb.trigger.get("on")) for pb in store.list()}

        assert TRIGGER_EVENT in declared, (
            f"run_for_alert asks for {TRIGGER_EVENT!r} and no shipped playbook declares it "
            f"(they declare {sorted(declared)}), so no playbook can ever start from an alert"
        )

    def test_the_real_store_matches_a_real_playbook_on_a_real_alert(self) -> None:
        """End to end through the actual store, not a fake.

        The severity and tag come **from the corpus** rather than being
        written here. A hardcoded fixture tag passes while describing an
        alert no shipped playbook wants (this test first used
        `identity`, which none of the 64 packs declare) and would keep
        passing if the trigger vocabulary moved underneath it.
        """
        from app.playbook.alert_trigger import TRIGGER_EVENT, alert_context
        from app.playbook.store import PlaybookStore

        store = PlaybookStore.default()
        store.seed_defaults()

        wanted = next(pb for pb in store.list() if pb.enabled and pb.trigger.get("tags") and pb.trigger.get("severity"))
        context = alert_context(
            _State(
                raw_alert={
                    "severity": wanted.trigger["severity"][0],
                    "tags": [wanted.trigger["tags"][0]],
                }
            )
        )

        matches = store.find_matching(TRIGGER_EVENT, context)
        assert matches, (
            f"the real store matched no playbook on an alert built from {wanted.id}'s own "
            "trigger, so the alert-trigger path is wired to nothing"
        )
        assert wanted.id in {pb.id for pb in matches}
