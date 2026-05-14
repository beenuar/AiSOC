"""Unit tests for the rule-tuning workbench backend (W8 / PR-6).

Mirrors the ``test_alert_queue.py`` shape: pure helpers get hand-built
``DetectionRule`` stand-ins, async coordinators / mutators get an in-memory
``MagicMock(AsyncSession)``. No real Postgres, no FastAPI ``TestClient`` —
the endpoint module is a transport-only wrapper; the service layer here is
what carries the business rules.

What this suite locks down:

* **classify_suggestion** — every lane (disable / add_suppression /
  raise_threshold / tune_confidence / review_stale / healthy) plus the
  precedence between them (disable wins over add_suppression, etc.). If
  the classifier regresses, the whole workbench surfaces the wrong
  recommendations.

* **project_rule** — full ORM → ``TuningEntry`` projection: enabled
  mapping, fp_rate/confidence/hits coercion, suppression-config
  read-throughs (``auto_tune``, ``tuning_dismissed_at``,
  ``tuning_last_action``), and the version/updated_at marshalling.

* **build_tuning** — coordinator math: page slicing, suggestion filter
  is applied **after** summary so header counts stay stable as you
  filter, ``include_dismissed`` toggle, severity / enabled_only /
  search-arg pass-through into the SQL builder.

* **apply_tuning** — all four actions (``raise_threshold``,
  ``add_suppression``, ``disable``, ``acknowledge``) mutate the rule
  correctly, bump ``version``, stamp ``tuning_last_action`` /
  ``last_raised_at`` / ``last_tuned_at``, and emit a
  ``detection.tuning.apply`` audit event. ``apply`` also implicitly
  un-dismisses (clears ``tuning_dismissed_at``) because the analyst is
  engaging with the rule again.

* **dismiss_tuning** — stamps ``tuning_dismissed_at`` / ``_by`` /
  ``_reason`` and emits ``detection.tuning.dismiss``.

* **set_auto_tune** — flips ``suppression_config.auto_tune`` either way
  and emits ``detection.tuning.auto_tune``.

* **_load_rule_for_tenant** — the security tripod: 404 on missing,
  404 on cross-tenant, 403 on platform-wide (NULL tenant_id) rules.

AiSOC — open-source AI Security Operations Center (MIT License)
Author: Beenu Arora <beenu@cyble.com>
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.services.rule_tuning import (
    ACTIONABLE_SUGGESTIONS,
    TUNING_FP_RATE_BUMPABLE,
    TUNING_FP_RATE_DISABLE,
    TUNING_FP_RATE_NOISY,
    TUNING_LOW_CONFIDENCE,
    TUNING_MIN_HITS_FOR_THRESHOLD,
    TUNING_STALE_DAYS,
    ApplyTuningRequest,
    AutoTuneRequest,
    DismissTuningRequest,
    apply_tuning,
    build_tuning,
    build_tuning_summary,
    classify_suggestion,
    dismiss_tuning,
    project_rule,
    set_auto_tune,
)
from fastapi import HTTPException

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


class _StubRule:
    """Hand-built ``DetectionRule`` stand-in.

    We can't use ``SimpleNamespace`` here because ``apply_tuning`` mutates
    attributes (``rule.threshold_config = ...``) and needs to round-trip
    back through ``project_rule``. A plain class with __init__ defaults is
    the lightest thing that satisfies every read+write the service does.
    """

    def __init__(
        self,
        *,
        rule_id: uuid.UUID | None = None,
        tenant_id: uuid.UUID | None = None,
        name: str = "Suspicious PowerShell",
        description: str | None = "Catches encoded PowerShell command lines",
        category: str = "endpoint",
        severity: str = "high",
        status: str = "active",
        confidence: int = 75,
        fp_rate: float = 0.05,
        total_hits: int = 30,
        last_triggered: datetime | None = None,
        suppression_config: dict[str, Any] | None = None,
        threshold_config: dict[str, Any] | None = None,
        tags: list[str] | None = None,
        mitre_tactics: list[str] | None = None,
        mitre_techniques: list[str] | None = None,
        version: int = 1,
        created_at: datetime | None = None,
        updated_at: datetime | None = None,
    ) -> None:
        self.id = rule_id or uuid.uuid4()
        self.tenant_id = tenant_id or uuid.uuid4()
        self.name = name
        self.description = description
        self.category = category
        self.severity = severity
        self.status = status
        self.confidence = confidence
        self.fp_rate = fp_rate
        self.total_hits = total_hits
        self.last_triggered = last_triggered or (datetime.now(UTC) - timedelta(hours=4))
        self.suppression_config = suppression_config if suppression_config is not None else {}
        self.threshold_config = threshold_config if threshold_config is not None else {}
        self.tags = tags or []
        self.mitre_tactics = mitre_tactics or []
        self.mitre_techniques = mitre_techniques or []
        self.version = version
        self.created_at = created_at or (datetime.now(UTC) - timedelta(days=5))
        self.updated_at = updated_at or datetime.now(UTC)


def _scalars_all_result(values: list[Any]) -> MagicMock:
    """Mock ``await session.execute(...).scalars().all() == values``."""
    result = MagicMock()
    scalars = MagicMock()
    scalars.all = MagicMock(return_value=values)
    result.scalars = MagicMock(return_value=scalars)
    return result


def _scalar_one_or_none_result(value: Any) -> MagicMock:
    """Mock ``await session.execute(...).scalar_one_or_none() == value``."""
    result = MagicMock()
    result.scalar_one_or_none = MagicMock(return_value=value)
    return result


def _auth_user(tenant_id: uuid.UUID | None = None) -> MagicMock:
    """Stand-in for ``AuthUser`` (``CurrentUser``) — only the three
    attributes the service uses."""
    actor = MagicMock()
    actor.user_id = uuid.uuid4()
    actor.tenant_id = tenant_id or uuid.uuid4()
    actor.email = "analyst@example.com"
    return actor


# ---------------------------------------------------------------------------
# classify_suggestion — pure heuristics
# ---------------------------------------------------------------------------


class TestClassifySuggestion:
    """Each branch of the classifier, in precedence order.

    A regression here flips the recommendation the workbench shows — the
    most user-visible failure mode in the whole feature.
    """

    def test_high_fp_low_confidence_recommends_disable(self) -> None:
        # FP rate well above the disable threshold AND confidence under
        # the floor — the rule is just noise, not signal. Disable wins
        # even though add_suppression also matches at this FP rate.
        rule = _StubRule(fp_rate=TUNING_FP_RATE_DISABLE + 0.1, confidence=TUNING_LOW_CONFIDENCE - 1, total_hits=200)
        classification = classify_suggestion(rule)
        assert classification.suggestion == "disable"
        assert classification.reasons, "disable lane must surface at least one reason"

    def test_noisy_but_decent_confidence_recommends_add_suppression(self) -> None:
        # FP rate is high but confidence is reasonable — paper over the
        # noise with a suppression rather than killing the rule.
        rule = _StubRule(fp_rate=TUNING_FP_RATE_NOISY + 0.05, confidence=70, total_hits=100)
        classification = classify_suggestion(rule)
        assert classification.suggestion == "add_suppression"

    def test_moderate_fp_with_enough_hits_recommends_raise_threshold(self) -> None:
        # Below the "noisy" cutoff but still elevated, and the rule fires
        # often enough that bumping its threshold is a safe trim.
        rule = _StubRule(
            fp_rate=TUNING_FP_RATE_BUMPABLE + 0.02,
            confidence=70,
            total_hits=TUNING_MIN_HITS_FOR_THRESHOLD + 5,
        )
        classification = classify_suggestion(rule)
        assert classification.suggestion == "raise_threshold"

    def test_low_confidence_with_hits_recommends_tune_confidence(self) -> None:
        # FP rate is fine but the rule's body or scoring is weak — the
        # analyst should re-evaluate before trusting the alerts.
        rule = _StubRule(
            fp_rate=0.0,
            confidence=TUNING_LOW_CONFIDENCE - 5,
            total_hits=TUNING_MIN_HITS_FOR_THRESHOLD + 1,
        )
        classification = classify_suggestion(rule)
        assert classification.suggestion == "tune_confidence"

    def test_stale_active_rule_recommends_review_stale(self) -> None:
        # Active rule, healthy fp_rate, healthy confidence — but it
        # hasn't fired in ages. Surface it so the analyst can confirm
        # the rule is still relevant.
        now = datetime.now(UTC)
        rule = _StubRule(
            fp_rate=0.0,
            confidence=80,
            total_hits=5,
            last_triggered=now - timedelta(days=TUNING_STALE_DAYS + 10),
            created_at=now - timedelta(days=TUNING_STALE_DAYS + 60),
        )
        classification = classify_suggestion(rule, now=now)
        assert classification.suggestion == "review_stale"

    def test_never_fired_brand_new_rule_is_healthy(self) -> None:
        # Brand-new rule that has not fired must NOT be flagged as
        # stale — we'd cry wolf on every Sigma import otherwise.
        now = datetime.now(UTC)
        rule = _StubRule(
            fp_rate=0.0,
            confidence=80,
            total_hits=0,
            last_triggered=None,
            created_at=now - timedelta(days=2),
        )
        classification = classify_suggestion(rule, now=now)
        assert classification.suggestion == "healthy"

    def test_disabled_rule_is_never_classified_as_actionable(self) -> None:
        # Disabled rules can still appear in the projection but they
        # should not be screaming "disable!" at the analyst. The only
        # lane left for them is healthy or tune_confidence (which fires
        # on hits-but-low-confidence regardless of status).
        rule = _StubRule(
            status="disabled",
            fp_rate=TUNING_FP_RATE_DISABLE + 0.2,  # would normally trigger disable
            confidence=80,
            total_hits=50,
        )
        classification = classify_suggestion(rule)
        assert classification.suggestion == "healthy"

    def test_healthy_rule_returns_no_reasons(self) -> None:
        rule = _StubRule(fp_rate=0.02, confidence=85, total_hits=15)
        classification = classify_suggestion(rule)
        assert classification.suggestion == "healthy"
        assert classification.reasons == []


# ---------------------------------------------------------------------------
# project_rule — ORM → wire entry
# ---------------------------------------------------------------------------


class TestProjectRule:
    """The wire shape contract: every field the frontend reads must be
    populated correctly. If any of these regress the UI breaks silently."""

    def test_enabled_mirrors_status_active(self) -> None:
        rule = _StubRule(status="active")
        entry = project_rule(rule)
        assert entry.enabled is True

    def test_disabled_status_projects_enabled_false(self) -> None:
        rule = _StubRule(status="disabled")
        entry = project_rule(rule)
        assert entry.enabled is False

    def test_testing_status_projects_enabled_false(self) -> None:
        # ``testing`` is the canonical "drafting / not yet promoted"
        # status — must NOT count as enabled, otherwise the workbench
        # tries to suggest disabling rules that aren't even on.
        rule = _StubRule(status="testing")
        entry = project_rule(rule)
        assert entry.enabled is False

    def test_auto_tune_flag_reads_from_suppression_config(self) -> None:
        rule = _StubRule(suppression_config={"auto_tune": True})
        entry = project_rule(rule)
        assert entry.auto_tune is True

    def test_missing_suppression_config_defaults_auto_tune_to_false(self) -> None:
        rule = _StubRule(suppression_config=None)
        entry = project_rule(rule)
        assert entry.auto_tune is False

    def test_dismissed_at_reads_from_suppression_config(self) -> None:
        stamped = "2026-05-13T12:00:00+00:00"
        rule = _StubRule(suppression_config={"tuning_dismissed_at": stamped})
        entry = project_rule(rule)
        assert entry.dismissed_at == stamped

    def test_last_action_round_trip(self) -> None:
        # Re-projection after an apply must surface the action + stamp
        # so the UI can render "raised threshold 3m ago".
        rule = _StubRule(
            suppression_config={
                "tuning_last_action": "raise_threshold",
                "tuning_last_action_at": "2026-05-13T11:30:00+00:00",
            }
        )
        entry = project_rule(rule)
        assert entry.last_action == "raise_threshold"
        assert entry.last_action_at == "2026-05-13T11:30:00+00:00"

    def test_none_numerics_coerce_to_zero(self) -> None:
        # ORM defaults are NOT NULL but legacy rows or tests may still
        # ship Nones. The projection must not crash the workbench in
        # that case.
        rule = _StubRule(fp_rate=None, confidence=None, total_hits=None)
        entry = project_rule(rule)
        assert entry.fp_rate == 0.0
        assert entry.confidence == 0
        assert entry.total_hits == 0

    def test_score_orders_disable_above_healthy(self) -> None:
        # The "score" is the single sort key the workbench uses; if
        # disable doesn't outrank healthy the most-urgent rule sinks
        # below noise.
        noisy = _StubRule(
            fp_rate=TUNING_FP_RATE_DISABLE + 0.1,
            confidence=TUNING_LOW_CONFIDENCE - 1,
            total_hits=100,
        )
        clean = _StubRule(fp_rate=0.01, confidence=90, total_hits=10)
        assert project_rule(noisy).score > project_rule(clean).score


# ---------------------------------------------------------------------------
# build_tuning — coordinator math
# ---------------------------------------------------------------------------


def _setup_build_db(rules: list[_StubRule]) -> MagicMock:
    db = MagicMock()
    db.execute = AsyncMock(return_value=_scalars_all_result(rules))
    return db


class TestBuildTuning:
    """Filtering, pagination, and the summary-vs-filter ordering contract."""

    @pytest.mark.asyncio
    async def test_summary_counts_full_population_before_suggestion_filter(self) -> None:
        # CRITICAL: the header summary tiles must be computed across
        # every rule, NOT across the filtered page. Otherwise switching
        # the "disable" filter on hides the count we used to motivate
        # filtering in the first place.
        tenant_id = uuid.uuid4()
        noisy = _StubRule(
            fp_rate=TUNING_FP_RATE_DISABLE + 0.1,
            confidence=TUNING_LOW_CONFIDENCE - 1,
            total_hits=100,
        )
        clean = _StubRule(fp_rate=0.0, confidence=90, total_hits=5)
        db = _setup_build_db([noisy, clean])

        resp = await build_tuning(
            db,
            tenant_id=tenant_id,
            suggestion="disable",
        )

        # Only the noisy rule survives the filter:
        assert len(resp.entries) == 1
        assert resp.entries[0].suggestion == "disable"
        # ... but the summary still sees BOTH rules:
        assert resp.summary.total_rules == 2
        assert resp.summary.healthy == 1
        assert resp.summary.disable_count == 1

    @pytest.mark.asyncio
    async def test_pagination_slices_after_sort(self) -> None:
        # Three urgent + two healthy rules. With page_size=2 we expect
        # the two highest-scoring rules first.
        tenant_id = uuid.uuid4()
        rules = [_StubRule(name=f"rule_{i}", fp_rate=0.6, confidence=10, total_hits=100 + i) for i in range(3)] + [
            _StubRule(name=f"healthy_{i}", fp_rate=0.0, confidence=90) for i in range(2)
        ]
        db = _setup_build_db(rules)

        resp = await build_tuning(db, tenant_id=tenant_id, page=1, page_size=2)

        assert resp.total == 5
        assert len(resp.entries) == 2
        # Highest-scoring rules surface first:
        assert all(e.suggestion == "disable" for e in resp.entries)
        # Pagination echo:
        assert resp.filters.page == 1
        assert resp.filters.page_size == 2

    @pytest.mark.asyncio
    async def test_include_dismissed_toggle(self) -> None:
        # A rule with ``tuning_dismissed_at`` stamped must drop out of
        # the default view but reappear when include_dismissed=True.
        tenant_id = uuid.uuid4()
        dismissed = _StubRule(
            name="dismissed_rule",
            suppression_config={"tuning_dismissed_at": "2026-05-12T00:00:00+00:00"},
        )
        normal = _StubRule(name="normal_rule")
        db = _setup_build_db([dismissed, normal])

        # Default: dismissed rule is hidden
        resp_default = await build_tuning(db, tenant_id=tenant_id)
        assert len(resp_default.entries) == 1
        assert resp_default.entries[0].name == "normal_rule"

        # include_dismissed=True: it shows up again
        db.execute = AsyncMock(return_value=_scalars_all_result([dismissed, normal]))
        resp_all = await build_tuning(db, tenant_id=tenant_id, include_dismissed=True)
        assert len(resp_all.entries) == 2

    @pytest.mark.asyncio
    async def test_filters_echo_in_response(self) -> None:
        # The frontend mirrors the filter state from the response (so a
        # deep-linked URL hydrates the form). All input filters must be
        # echoed exactly.
        db = _setup_build_db([])
        resp = await build_tuning(
            db,
            tenant_id=uuid.uuid4(),
            severity="high",
            suggestion="disable",
            search="powershell",
            enabled_only=True,
            page=3,
            page_size=25,
        )
        assert resp.filters.severity == "high"
        assert resp.filters.suggestion == "disable"
        assert resp.filters.search == "powershell"
        assert resp.filters.enabled_only is True
        assert resp.filters.page == 3
        assert resp.filters.page_size == 25

    @pytest.mark.asyncio
    async def test_generated_at_is_iso_string(self) -> None:
        # generated_at is consumed by the UI for client-side clock-drift
        # correction. Must be a valid ISO-8601 string, not a datetime.
        db = _setup_build_db([])
        resp = await build_tuning(db, tenant_id=uuid.uuid4())
        # ``fromisoformat`` would raise if the string were malformed:
        datetime.fromisoformat(resp.generated_at)

    @pytest.mark.asyncio
    async def test_actionable_suggestions_constant_is_correct(self) -> None:
        # If someone adds a new suggestion lane, they must consciously
        # decide whether it counts toward the "needs work" tile.
        assert ACTIONABLE_SUGGESTIONS == frozenset({"disable", "add_suppression", "raise_threshold", "tune_confidence", "review_stale"})
        assert "healthy" not in ACTIONABLE_SUGGESTIONS


class TestBuildTuningSummary:
    """The summary-only endpoint is a sidebar/badge path — must stay cheap
    and must NOT hand back full rule details."""

    @pytest.mark.asyncio
    async def test_summary_skips_dismissed_rules(self) -> None:
        tenant_id = uuid.uuid4()
        dismissed = _StubRule(
            fp_rate=TUNING_FP_RATE_DISABLE + 0.1,
            confidence=10,
            total_hits=100,
            suppression_config={"tuning_dismissed_at": "2026-05-12T00:00:00+00:00"},
        )
        active_noisy = _StubRule(
            fp_rate=TUNING_FP_RATE_DISABLE + 0.1,
            confidence=10,
            total_hits=100,
        )
        db = _setup_build_db([dismissed, active_noisy])

        summary = await build_tuning_summary(db, tenant_id=tenant_id)

        # Only the un-dismissed rule counts:
        assert summary.total_rules == 1
        assert summary.disable_count == 1
        assert summary.actionable == 1


# ---------------------------------------------------------------------------
# Mutators — apply / dismiss / auto_tune
# ---------------------------------------------------------------------------


def _setup_mutator_db(rule: _StubRule) -> MagicMock:
    """Mock the two-step DB pattern every mutator uses: SELECT-by-id,
    then commit + refresh."""
    db = MagicMock()
    db.execute = AsyncMock(return_value=_scalar_one_or_none_result(rule))
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    return db


@pytest.fixture(autouse=True)
def _patch_audit(monkeypatch: pytest.MonkeyPatch) -> AsyncMock:
    """Stub out the audit-log writer so tests don't need a real session.

    The mutator service imports ``emit_audit`` at module load — we monkey-
    patch its bound name in ``app.services.rule_tuning`` so every test
    method can both (a) safely call the mutator and (b) assert that the
    audit event fired with the correct action label.
    """
    stub = AsyncMock(return_value=None)
    monkeypatch.setattr("app.services.rule_tuning.emit_audit", stub)
    return stub


class TestApplyTuning:
    """Each apply action must mutate the rule AND emit an audit event."""

    @pytest.mark.asyncio
    async def test_raise_threshold_bumps_threshold_and_version(self, _patch_audit: AsyncMock) -> None:
        actor = _auth_user()
        rule = _StubRule(
            tenant_id=actor.tenant_id,
            threshold_config={"event_threshold": 3},
            version=4,
        )
        db = _setup_mutator_db(rule)

        await apply_tuning(
            db,
            rule_id=rule.id,
            actor=actor,
            body=ApplyTuningRequest(action="raise_threshold"),
        )

        # Threshold incremented:
        assert rule.threshold_config["event_threshold"] == 4
        # Version bumped:
        assert rule.version == 5
        # Audit event fired with the right label:
        _patch_audit.assert_awaited_once()
        call = _patch_audit.await_args
        assert call.kwargs["action"] == "detection.tuning.apply"
        assert call.kwargs["resource"] == "detection_rule"
        db.commit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_raise_threshold_with_explicit_override(self) -> None:
        actor = _auth_user()
        rule = _StubRule(tenant_id=actor.tenant_id, threshold_config={"event_threshold": 5})
        db = _setup_mutator_db(rule)

        await apply_tuning(
            db,
            rule_id=rule.id,
            actor=actor,
            body=ApplyTuningRequest(action="raise_threshold", threshold=25),
        )

        # Analyst override wins over the auto-bump:
        assert rule.threshold_config["event_threshold"] == 25

    @pytest.mark.asyncio
    async def test_raise_threshold_with_no_existing_config_starts_at_two(self) -> None:
        # Fresh rule (no threshold_config yet) must not crash — we
        # default the existing threshold to 1 and bump to max(2, …).
        actor = _auth_user()
        rule = _StubRule(tenant_id=actor.tenant_id, threshold_config={})
        db = _setup_mutator_db(rule)

        await apply_tuning(
            db,
            rule_id=rule.id,
            actor=actor,
            body=ApplyTuningRequest(action="raise_threshold"),
        )

        assert rule.threshold_config["event_threshold"] == 2

    @pytest.mark.asyncio
    async def test_add_suppression_appends_placeholder(self) -> None:
        actor = _auth_user()
        rule = _StubRule(tenant_id=actor.tenant_id, suppression_config={"rules": []})
        db = _setup_mutator_db(rule)

        await apply_tuning(
            db,
            rule_id=rule.id,
            actor=actor,
            body=ApplyTuningRequest(
                action="add_suppression",
                suppression_reason="known scanner",
            ),
        )

        placeholder = rule.suppression_config["rules"][0]
        assert placeholder["kind"] == "tune_placeholder"
        assert placeholder["reason"] == "known scanner"
        assert placeholder["added_by"] == actor.email

    @pytest.mark.asyncio
    async def test_disable_flips_status(self) -> None:
        actor = _auth_user()
        rule = _StubRule(tenant_id=actor.tenant_id, status="active")
        db = _setup_mutator_db(rule)

        entry = await apply_tuning(
            db,
            rule_id=rule.id,
            actor=actor,
            body=ApplyTuningRequest(action="disable"),
        )

        assert rule.status == "disabled"
        # Re-projection sees the new status:
        assert entry.enabled is False
        assert entry.status == "disabled"

    @pytest.mark.asyncio
    async def test_acknowledge_records_action_without_mutation(self, _patch_audit: AsyncMock) -> None:
        # Acknowledge is a no-op for the rule's *semantics* — it just
        # stamps last_action so the workbench shows "ack'd 5m ago" and
        # the analyst can re-find the row.
        actor = _auth_user()
        original_status = "active"
        original_threshold = {"event_threshold": 3}
        rule = _StubRule(
            tenant_id=actor.tenant_id,
            status=original_status,
            threshold_config=dict(original_threshold),
            version=7,
        )
        db = _setup_mutator_db(rule)

        await apply_tuning(
            db,
            rule_id=rule.id,
            actor=actor,
            body=ApplyTuningRequest(action="acknowledge", note="false positive accepted"),
        )

        assert rule.status == original_status
        assert rule.threshold_config["event_threshold"] == 3
        assert rule.suppression_config["tuning_last_action"] == "acknowledge"
        assert rule.suppression_config["tuning_last_action_note"] == "false positive accepted"
        # Even an acknowledge bumps version + emits audit:
        assert rule.version == 8
        _patch_audit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_apply_clears_previous_dismissal(self) -> None:
        # If the analyst dismissed a rule yesterday, then re-engaged
        # with it today, the apply must implicitly un-dismiss it.
        # Otherwise the apply succeeds but the rule stays hidden from
        # the default view — a confusing dead-end UX.
        actor = _auth_user()
        rule = _StubRule(
            tenant_id=actor.tenant_id,
            suppression_config={
                "tuning_dismissed_at": "2026-05-12T00:00:00+00:00",
                "tuning_dismissed_reason": "not interesting yet",
            },
        )
        db = _setup_mutator_db(rule)

        await apply_tuning(
            db,
            rule_id=rule.id,
            actor=actor,
            body=ApplyTuningRequest(action="acknowledge"),
        )

        assert "tuning_dismissed_at" not in rule.suppression_config
        assert "tuning_dismissed_reason" not in rule.suppression_config

    @pytest.mark.asyncio
    async def test_apply_404s_on_missing_rule(self) -> None:
        actor = _auth_user()
        db = MagicMock()
        db.execute = AsyncMock(return_value=_scalar_one_or_none_result(None))

        with pytest.raises(HTTPException) as exc_info:
            await apply_tuning(
                db,
                rule_id=uuid.uuid4(),
                actor=actor,
                body=ApplyTuningRequest(action="acknowledge"),
            )
        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_apply_404s_on_cross_tenant_rule(self) -> None:
        # Wrong tenant = 404, NOT 403. We deliberately don't tell the
        # actor whether the rule exists in another tenant.
        actor = _auth_user()
        rule = _StubRule(tenant_id=uuid.uuid4())  # different tenant
        db = MagicMock()
        db.execute = AsyncMock(return_value=_scalar_one_or_none_result(rule))

        with pytest.raises(HTTPException) as exc_info:
            await apply_tuning(
                db,
                rule_id=rule.id,
                actor=actor,
                body=ApplyTuningRequest(action="acknowledge"),
            )
        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_apply_403s_on_platform_wide_rule(self) -> None:
        # Tenant-null rules are visible from every tenant but mutations
        # would leak across tenants. The service explicitly 403s.
        actor = _auth_user()
        rule = _StubRule(tenant_id=None)
        rule.tenant_id = None  # explicit override of fixture default
        db = MagicMock()
        db.execute = AsyncMock(return_value=_scalar_one_or_none_result(rule))

        with pytest.raises(HTTPException) as exc_info:
            await apply_tuning(
                db,
                rule_id=rule.id,
                actor=actor,
                body=ApplyTuningRequest(action="acknowledge"),
            )
        assert exc_info.value.status_code == 403


class TestDismissTuning:
    @pytest.mark.asyncio
    async def test_dismiss_stamps_suppression_config(self, _patch_audit: AsyncMock) -> None:
        actor = _auth_user()
        rule = _StubRule(tenant_id=actor.tenant_id, suppression_config={})
        db = _setup_mutator_db(rule)

        await dismiss_tuning(
            db,
            rule_id=rule.id,
            actor=actor,
            body=DismissTuningRequest(reason="acceptable noise"),
        )

        assert "tuning_dismissed_at" in rule.suppression_config
        assert rule.suppression_config["tuning_dismissed_by"] == actor.email
        assert rule.suppression_config["tuning_dismissed_reason"] == "acceptable noise"
        _patch_audit.assert_awaited_once()
        assert _patch_audit.await_args.kwargs["action"] == "detection.tuning.dismiss"

    @pytest.mark.asyncio
    async def test_dismiss_without_reason_drops_stale_reason(self) -> None:
        # Re-dismissing without a reason must not preserve the prior
        # reason — otherwise the UI shows a misleading stale message.
        actor = _auth_user()
        rule = _StubRule(
            tenant_id=actor.tenant_id,
            suppression_config={"tuning_dismissed_reason": "old reason"},
        )
        db = _setup_mutator_db(rule)

        await dismiss_tuning(
            db,
            rule_id=rule.id,
            actor=actor,
            body=DismissTuningRequest(reason=None),
        )

        assert "tuning_dismissed_reason" not in rule.suppression_config


class TestSetAutoTune:
    @pytest.mark.asyncio
    async def test_enable_auto_tune(self, _patch_audit: AsyncMock) -> None:
        actor = _auth_user()
        rule = _StubRule(tenant_id=actor.tenant_id, suppression_config={})
        db = _setup_mutator_db(rule)

        entry = await set_auto_tune(
            db,
            rule_id=rule.id,
            actor=actor,
            body=AutoTuneRequest(enabled=True),
        )

        assert rule.suppression_config["auto_tune"] is True
        assert "auto_tune_updated_at" in rule.suppression_config
        assert rule.suppression_config["auto_tune_updated_by"] == actor.email
        assert entry.auto_tune is True
        _patch_audit.assert_awaited_once()
        assert _patch_audit.await_args.kwargs["action"] == "detection.tuning.auto_tune"

    @pytest.mark.asyncio
    async def test_disable_auto_tune_round_trips(self) -> None:
        # Toggling auto_tune off must clear the flag (False), not delete
        # the key — auditors need to see that it WAS on previously.
        actor = _auth_user()
        rule = _StubRule(
            tenant_id=actor.tenant_id,
            suppression_config={"auto_tune": True},
        )
        db = _setup_mutator_db(rule)

        await set_auto_tune(
            db,
            rule_id=rule.id,
            actor=actor,
            body=AutoTuneRequest(enabled=False),
        )

        assert rule.suppression_config["auto_tune"] is False
        assert "auto_tune_updated_at" in rule.suppression_config
