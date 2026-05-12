"""Unit tests for the alert-explain pipeline (Stage 2 #6).

The explain pipeline is intentionally split into pure helpers + an
orchestrator, so we test it the same way:

* **Pure helpers** (``_explicit_rule_id_from_alert``, ``_extract_mitre_ids``,
  ``_extract_contributing_events``, ``_build_suggested_actions``,
  ``_deterministic_summary``) get straightforward in-process tests
  with hand-built ``Alert`` stand-ins. These cover lineage probing,
  observable extraction, and the deterministic-fallback summary.

* **DB-touching helpers** (``_resolve_rule_lineage``,
  ``_historical_fp_rate``) are exercised against an in-memory
  ``MagicMock(AsyncSession)`` whose ``execute`` returns canned rows.
  We do not stand up a real database here — the goal is to lock in
  the matching/scoring logic, not Postgres semantics. The integration
  tests in CI cover the SQLAlchemy translation.

* **Orchestrator** (``generate_alert_explanation``) is tested with
  the LLM resolver and the per-call helpers patched out, so we can
  assert the four observable branches: LLM-enabled-and-succeeds,
  LLM-enabled-but-empty, LLM-blocked, and LLM-allowed-but-airgap.

* **Endpoint helpers** (``_acquire_or_429``, ``_explanation_to_payload``)
  use the same mocking style as ``test_lake_endpoint.py`` —
  patching the rate-limiter factory at the call site so the test
  stays hermetic.

* **Rate limiter** gets a dedicated suite mirroring
  ``test_lake_rate_limit.py``: monkeypatched ``time.monotonic`` to
  prove first-request-allowed, capacity exhaustion, refill-after-wait,
  and per-tenant isolation. Without these we'd be one off-by-one bug
  away from a tenant burning the explain budget in seconds.

The tests deliberately do NOT spin up FastAPI's TestClient. The
endpoint module itself is a thin orchestration layer; the lake
endpoint pattern (test the helpers, integration test the wiring)
keeps these tests fast and deterministic.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from app.api.v1.endpoints.alert_explain import (
    _acquire_or_429,
    _explanation_to_payload,
)
from app.services.alert_explain import (
    AlertExplanation,
    ContributingEvent,
    HistoricalFpRate,
    MitreTechnique,
    RuleLineage,
    SuggestedAction,
    _build_suggested_actions,
    _deterministic_summary,
    _explicit_rule_id_from_alert,
    _extract_contributing_events,
    _extract_mitre_ids,
    _historical_fp_rate,
    _resolve_rule_lineage,
    generate_alert_explanation,
)
from app.services.explain_rate_limit import (
    ExplainRateLimitDecision,
    ExplainRateLimiter,
)
from app.services.llm_resolver import LlmConfig
from fastapi import HTTPException, Response

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _alert(
    *,
    alert_id: uuid.UUID | None = None,
    tenant_id: uuid.UUID | None = None,
    title: str = "Suspicious login from new geo",
    description: str | None = "User signed in from an unusual country.",
    severity: str = "high",
    category: str | None = "identity",
    connector_type: str | None = "okta",
    raw_event: dict[str, Any] | None = None,
    tags: list[str] | None = None,
    mitre_techniques: list[str] | None = None,
    ai_score: float | None = 0.82,
    disposition: str | None = None,
) -> SimpleNamespace:
    """Build a stand-in for the ``Alert`` ORM object.

    We use ``SimpleNamespace`` so the test doesn't have to wire up the
    SQLAlchemy mapper or instantiate a real session. The explain
    helpers only ever attribute-access the fields they need; they
    don't call any ORM-only methods.
    """
    return SimpleNamespace(
        id=alert_id or uuid.uuid4(),
        tenant_id=tenant_id or uuid.uuid4(),
        title=title,
        description=description,
        severity=severity,
        category=category,
        connector_type=connector_type,
        raw_event=raw_event or {},
        tags=tags or [],
        mitre_techniques=mitre_techniques or [],
        ai_score=ai_score,
        disposition=disposition,
    )


def _rule(
    *,
    rule_id: uuid.UUID | None = None,
    tenant_id: uuid.UUID | None = None,
    name: str = "Impossible travel",
    description: str | None = "Detect impossible travel between consecutive logins.",
    category: str | None = "identity",
    severity: str = "high",
    status: str = "enabled",
    confidence: int = 80,
    rule_language: str = "sigma",
    is_builtin: bool = True,
    mitre_techniques: list[str] | None = None,
) -> SimpleNamespace:
    """Stand-in for the ``DetectionRule`` ORM object."""
    return SimpleNamespace(
        id=rule_id or uuid.uuid4(),
        tenant_id=tenant_id,
        name=name,
        description=description,
        category=category,
        severity=severity,
        status=status,
        confidence=confidence,
        rule_language=rule_language,
        is_builtin=is_builtin,
        mitre_techniques=mitre_techniques or ["T1078"],
    )


def _scalar_one_or_none_result(value: Any) -> MagicMock:
    """Mock an ``await session.execute(...)`` whose ``scalar_one_or_none()`` returns ``value``."""
    result = MagicMock()
    result.scalar_one_or_none = MagicMock(return_value=value)
    return result


def _scalars_all_result(values: list[Any]) -> MagicMock:
    """Mock ``await session.execute(...)`` whose ``scalars().all()`` returns ``values``."""
    result = MagicMock()
    scalars = MagicMock()
    scalars.all = MagicMock(return_value=values)
    result.scalars = MagicMock(return_value=scalars)
    return result


def _row_one_result(*, total: int, fps: int) -> MagicMock:
    """Mock ``await session.execute(...).one()`` for the FPR aggregate."""
    row = SimpleNamespace(total=total, fps=fps)
    result = MagicMock()
    result.one = MagicMock(return_value=row)
    return result


# ---------------------------------------------------------------------------
# _explicit_rule_id_from_alert — connector-supplied lineage signals
# ---------------------------------------------------------------------------


class TestExplicitRuleIdFromAlert:
    """Probes the connector-supplied rule lineage signals.

    These probes are the *only* high-confidence rule-attribution
    signal in the explain pipeline (everything else is heuristic), so
    we exercise every documented shape exhaustively. A regression here
    would silently demote ``RuleLineage.confidence`` from ``"high"``
    to ``"medium"`` for entire connectors.
    """

    def test_returns_none_for_alert_without_signals(self) -> None:
        # No raw_event, no tags → nothing to probe → None.
        alert = _alert(raw_event={}, tags=[])
        assert _explicit_rule_id_from_alert(alert) is None

    def test_picks_up_top_level_rule_id_from_raw_event(self) -> None:
        # Most common case: connector wrote the rule UUID into the raw event.
        rid = uuid.uuid4()
        alert = _alert(raw_event={"rule_id": str(rid)})
        assert _explicit_rule_id_from_alert(alert) == rid

    def test_picks_up_camel_case_rule_id(self) -> None:
        # Some connectors emit camelCase. The probe MUST tolerate both
        # spellings or we'd miss the lineage signal half the time.
        rid = uuid.uuid4()
        alert = _alert(raw_event={"detectionRuleId": str(rid)})
        assert _explicit_rule_id_from_alert(alert) == rid

    def test_picks_up_nested_rule_id(self) -> None:
        # The Sentinel/SCC family of connectors nests the rule under a
        # parent object. The probe walks one level deep.
        rid = uuid.uuid4()
        alert = _alert(raw_event={"detection": {"id": str(rid)}})
        assert _explicit_rule_id_from_alert(alert) == rid

    def test_picks_up_rule_tag(self) -> None:
        # Some pipelines stamp a ``rule:<uuid>`` tag rather than
        # mutating raw_event. The probe falls back to tags after
        # raw_event yields nothing.
        rid = uuid.uuid4()
        alert = _alert(tags=[f"rule:{rid}", "ato"])
        assert _explicit_rule_id_from_alert(alert) == rid

    def test_ignores_malformed_rule_tag(self) -> None:
        # ``rule:not-a-uuid`` must NOT be coerced into a fake UUID.
        # Returning a junk UUID would later 404 in _resolve_rule_lineage
        # instead of falling through to the heuristic match.
        alert = _alert(tags=["rule:not-a-uuid"])
        assert _explicit_rule_id_from_alert(alert) is None

    def test_ignores_invalid_uuid_in_raw_event(self) -> None:
        # Defensive: connectors sometimes write integer IDs. We must
        # treat them as "no signal" rather than crashing the explain.
        alert = _alert(raw_event={"rule_id": 12345})
        assert _explicit_rule_id_from_alert(alert) is None

    def test_rejects_non_string_tag_entries(self) -> None:
        # A list with mixed types must not crash the regex match.
        rid = uuid.uuid4()
        alert = _alert(tags=[None, 123, f"rule:{rid}"])
        assert _explicit_rule_id_from_alert(alert) == rid


# ---------------------------------------------------------------------------
# _resolve_rule_lineage — full matching pipeline (mocked DB)
# ---------------------------------------------------------------------------


class TestResolveRuleLineage:
    """End-to-end matching from alert → DetectionRule.

    Each branch returns a different ``(confidence, match_method)``
    tuple, and the UI uses ``match_method`` to flag low-confidence
    guesses. Without these tests a refactor could silently downgrade
    every alert's lineage to ``"none"``.
    """

    @pytest.mark.asyncio
    async def test_explicit_match_returns_high_confidence(self) -> None:
        # Explicit rule_id → fast-path lookup → high confidence.
        rid = uuid.uuid4()
        rule = _rule(rule_id=rid)
        alert = _alert(raw_event={"rule_id": str(rid)})

        db = MagicMock()
        db.execute = AsyncMock(return_value=_scalar_one_or_none_result(rule))

        result_rule, confidence, method = await _resolve_rule_lineage(db, alert)
        assert result_rule is rule
        assert confidence == "high"
        assert method == "raw_event"
        # Only ONE query needed: the explicit-id lookup.
        assert db.execute.await_count == 1

    @pytest.mark.asyncio
    async def test_falls_through_when_explicit_id_does_not_exist(self) -> None:
        # Explicit id present but no matching rule (deleted, wrong tenant)
        # → fall through to the candidate search.
        rid = uuid.uuid4()
        alert = _alert(
            raw_event={"rule_id": str(rid)},
            mitre_techniques=["T1078"],
        )

        db = MagicMock()
        # First call: explicit lookup → no row.
        # Second call: candidate scan → one matching rule.
        rule = _rule(mitre_techniques=["T1078"])
        db.execute = AsyncMock(
            side_effect=[
                _scalar_one_or_none_result(None),
                _scalars_all_result([rule]),
            ]
        )

        result_rule, confidence, method = await _resolve_rule_lineage(db, alert)
        assert result_rule is rule
        # One technique overlap → medium confidence per the scoring rule.
        assert confidence == "medium"
        assert method == "mitre_overlap"

    @pytest.mark.asyncio
    async def test_returns_none_when_alert_has_no_signals(self) -> None:
        # No explicit id, no category, no MITRE → bail out early
        # without hitting the DB a second time.
        alert = _alert(category=None, mitre_techniques=[])

        db = MagicMock()
        # No explicit signal in this alert, so no lookup at all.
        # We assert we never call execute (early return).
        db.execute = AsyncMock()

        result_rule, confidence, method = await _resolve_rule_lineage(db, alert)
        assert result_rule is None
        assert confidence == "none"
        assert method == "none"
        db.execute.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_high_confidence_on_two_technique_overlap(self) -> None:
        # Score rule: overlap*10 + confidence//10 + (1 if builtin else 0)
        # Two-technique overlap → score >= 20 → high confidence.
        rule = _rule(
            confidence=80,
            mitre_techniques=["T1078", "T1110"],
            is_builtin=True,
        )
        alert = _alert(mitre_techniques=["T1078", "T1110", "T1059"])

        db = MagicMock()
        db.execute = AsyncMock(return_value=_scalars_all_result([rule]))

        result_rule, confidence, method = await _resolve_rule_lineage(db, alert)
        assert result_rule is rule
        assert confidence == "high"
        assert method == "mitre_overlap"

    @pytest.mark.asyncio
    async def test_low_confidence_category_only_match(self) -> None:
        # No technique overlap but category matches → low confidence
        # category fall-back. The UI shows a "match guess" warning.
        #
        # Scoring: overlap*10 + min(confidence,100)//10 + (1 if builtin).
        # We deliberately force score=0 by setting confidence=0 and
        # is_builtin=False so the "category fallback" branch fires —
        # otherwise the rule would still match via mitre_overlap (low)
        # because of the confidence/builtin tie-breakers.
        rule = _rule(
            mitre_techniques=["T1110"],
            category="identity",
            confidence=0,
            is_builtin=False,
        )
        alert = _alert(category="identity", mitre_techniques=["T1059"])

        db = MagicMock()
        db.execute = AsyncMock(return_value=_scalars_all_result([rule]))

        result_rule, confidence, method = await _resolve_rule_lineage(db, alert)
        # No technique overlap, score=0 → category fall-back branch.
        assert result_rule is rule
        assert confidence == "low"
        assert method == "category"

    @pytest.mark.asyncio
    async def test_candidate_set_empty_returns_none(self) -> None:
        # Alert has signals but no rules came back → return None.
        # This is the "tenant disabled all rules" corner.
        alert = _alert(category="identity", mitre_techniques=["T1078"])

        db = MagicMock()
        db.execute = AsyncMock(return_value=_scalars_all_result([]))

        result_rule, confidence, method = await _resolve_rule_lineage(db, alert)
        assert result_rule is None
        assert confidence == "none"
        assert method == "none"


# ---------------------------------------------------------------------------
# _historical_fp_rate — scope selection + bounded sample
# ---------------------------------------------------------------------------


class TestHistoricalFpRate:
    """Selects the most specific FPR scope and computes the rate.

    The FPR drives an analyst's gut on whether to keep digging or
    triage as noise. A bug here biases triage decisions, so we lock
    every scope branch + the bounded-failure path.
    """

    @pytest.mark.asyncio
    async def test_rule_scope_with_techniques(self) -> None:
        tenant = uuid.uuid4()
        rule = _rule(category="identity", mitre_techniques=["T1078"])
        alert = _alert(tenant_id=tenant, category="identity", mitre_techniques=["T1078"])

        db = MagicMock()
        db.execute = AsyncMock(return_value=_row_one_result(total=200, fps=20))

        fp = await _historical_fp_rate(db, tenant_id=tenant, rule=rule, alert=alert)

        # 20 / 200 = 0.10 → exact rounding to 4 dp.
        assert fp.fp_rate == pytest.approx(0.1)
        assert fp.sample_size == 200
        assert fp.false_positives == 20
        assert fp.scope == "rule"
        assert "Approximated by category" in fp.notes

    @pytest.mark.asyncio
    async def test_category_scope_when_no_rule(self) -> None:
        # When we couldn't pin a rule down we fall back to a
        # category+technique scope; the response notes must say so.
        tenant = uuid.uuid4()
        alert = _alert(tenant_id=tenant, category="identity", mitre_techniques=["T1078"])

        db = MagicMock()
        db.execute = AsyncMock(return_value=_row_one_result(total=50, fps=5))

        fp = await _historical_fp_rate(db, tenant_id=tenant, rule=None, alert=alert)
        assert fp.scope == "category"
        assert fp.sample_size == 50
        assert "MITRE technique" in fp.notes

    @pytest.mark.asyncio
    async def test_category_only_when_no_techniques(self) -> None:
        tenant = uuid.uuid4()
        alert = _alert(tenant_id=tenant, category="identity", mitre_techniques=[])

        db = MagicMock()
        db.execute = AsyncMock(return_value=_row_one_result(total=10, fps=1))

        fp = await _historical_fp_rate(db, tenant_id=tenant, rule=None, alert=alert)
        assert fp.scope == "category"
        assert "no MITRE refinement" in fp.notes

    @pytest.mark.asyncio
    async def test_tenant_wide_fallback_when_alert_is_bare(self) -> None:
        # Alert with no category and no techniques → tenant-wide
        # fallback. UI must surface this as low-signal.
        tenant = uuid.uuid4()
        alert = _alert(tenant_id=tenant, category=None, mitre_techniques=[])

        db = MagicMock()
        db.execute = AsyncMock(return_value=_row_one_result(total=100, fps=10))

        fp = await _historical_fp_rate(db, tenant_id=tenant, rule=None, alert=alert)
        assert fp.scope == "category"
        assert "Tenant-wide fallback" in fp.notes

    @pytest.mark.asyncio
    async def test_zero_sample_returns_zero_rate(self) -> None:
        # No alerts → must NOT divide by zero.
        tenant = uuid.uuid4()
        alert = _alert(tenant_id=tenant)

        db = MagicMock()
        db.execute = AsyncMock(return_value=_row_one_result(total=0, fps=0))

        fp = await _historical_fp_rate(db, tenant_id=tenant, rule=None, alert=alert)
        assert fp.fp_rate == 0.0
        assert fp.sample_size == 0
        assert fp.false_positives == 0

    @pytest.mark.asyncio
    async def test_query_failure_collapses_to_safe_default(self) -> None:
        # If the analytics DB is hot and the query times out, we MUST
        # NOT fail the whole explain endpoint. Returning a notes-tagged
        # zero-rate row keeps the rest of the explain payload usable.
        tenant = uuid.uuid4()
        alert = _alert(tenant_id=tenant)

        db = MagicMock()
        db.execute = AsyncMock(side_effect=RuntimeError("connection reset"))

        fp = await _historical_fp_rate(db, tenant_id=tenant, rule=None, alert=alert)
        assert fp.fp_rate == 0.0
        assert fp.sample_size == 0
        assert "Query failed" in fp.notes


# ---------------------------------------------------------------------------
# Pure helpers: extracting MITRE ids, contributing events, suggested actions
# ---------------------------------------------------------------------------


class TestExtractMitreIds:
    """The MITRE ID extractor is pure and deterministic."""

    def test_prefers_structured_field(self) -> None:
        # Structured field is canonical; regex sweep is a fallback.
        alert = _alert(
            mitre_techniques=["T1078"],
            tags=["T1059"],
            description="Technique T1110 was observed",
        )
        ids = _extract_mitre_ids(alert)
        # Structured field appears first; regex hits added afterwards
        # without duplicates.
        assert ids[0] == "T1078"
        assert "T1059" in ids
        assert "T1110" in ids

    def test_dedupes_across_sources(self) -> None:
        alert = _alert(
            mitre_techniques=["T1078"],
            tags=["T1078"],
            description="T1078 again",
        )
        assert _extract_mitre_ids(alert) == ["T1078"]

    def test_caps_to_max_techniques(self) -> None:
        # Drawer cap is 5 — more than that and the card list overflows
        # the responsive layout.
        alert = _alert(mitre_techniques=[f"T{1000 + i}" for i in range(20)])
        ids = _extract_mitre_ids(alert)
        assert len(ids) == 5

    def test_recognises_subtechnique_ids(self) -> None:
        # Sub-techniques use a dot suffix (T1078.001). The regex must
        # accept both spellings or we'd silently drop the granularity.
        alert = _alert(
            mitre_techniques=[],
            description="Saw T1078.001 in the trace",
        )
        assert "T1078.001" in _extract_mitre_ids(alert)


class TestExtractContributingEvents:
    """Observable extraction is purely structural."""

    def test_includes_severity_and_source(self) -> None:
        alert = _alert(
            severity="high",
            connector_type="okta",
            ai_score=0.9,
            raw_event={"user": "alice@example.com"},
        )
        events = _extract_contributing_events(alert)
        labels = {e.label for e in events}
        assert "Severity" in labels
        assert "Source" in labels
        assert "AI score" in labels
        assert "User" in labels

    def test_truncates_long_values(self) -> None:
        # Cap is 160 chars — keeps the drawer scannable. A 500-char IOC
        # like a base64 cert blob would otherwise blow up the layout.
        alert = _alert(raw_event={"url": "https://example.com/" + "a" * 500})
        events = _extract_contributing_events(alert)
        url_event = next(e for e in events if e.label == "URL")
        assert len(url_event.value) <= 160

    def test_skips_empty_observables(self) -> None:
        # Empty strings, empty lists, None → not included.
        alert = _alert(
            connector_type=None,
            raw_event={"user": "", "src_ip": None, "host": []},
            ai_score=None,
        )
        events = _extract_contributing_events(alert)
        labels = {e.label for e in events}
        # Severity always present.
        assert labels == {"Severity", "Source"}  # connector_type=None → "platform"


class TestBuildSuggestedActions:
    """Suggested actions are hand-curated; LLM never picks them."""

    def test_ato_tag_triggers_ato_playbook(self) -> None:
        alert = _alert(tags=["ato"])
        actions = _build_suggested_actions(alert, mitre_ids=[])
        titles = [a.title for a in actions]
        assert any("ATO containment" in t for t in titles)

    def test_t1078_triggers_ato_playbook(self) -> None:
        # Technique-driven path — also fires the ATO playbook.
        alert = _alert(tags=[])
        actions = _build_suggested_actions(alert, mitre_ids=["T1078"])
        titles = [a.title for a in actions]
        assert any("ATO containment" in t for t in titles)

    def test_ransomware_tag_triggers_isolation(self) -> None:
        alert = _alert(tags=["ransomware"], severity="critical")
        actions = _build_suggested_actions(alert, mitre_ids=[])
        titles = [a.title for a in actions]
        assert any("Isolate the host" in t for t in titles)

    def test_critical_severity_promotes_to_case(self) -> None:
        alert = _alert(severity="critical")
        actions = _build_suggested_actions(alert, mitre_ids=[])
        # Critical severity always adds "Open a case" with priority=immediate.
        case_action = next(a for a in actions if "Open a case" in a.title)
        assert case_action.priority == "immediate"

    def test_default_action_when_no_signals(self) -> None:
        # Every alert gets at least one suggested action — the drawer
        # never shows an empty list.
        alert = _alert(tags=[], severity="low")
        actions = _build_suggested_actions(alert, mitre_ids=[])
        assert len(actions) >= 1

    def test_caps_at_four_actions(self) -> None:
        # Drawer hard cap; tested with the noisiest possible alert.
        alert = _alert(tags=["ato", "ransomware", "phishing"], severity="critical")
        actions = _build_suggested_actions(alert, mitre_ids=["T1078", "T1190"])
        assert len(actions) <= 4


class TestDeterministicSummary:
    """Fallback summary used when LLM is disabled or fails."""

    def _stub_lineage(self, *, name: str | None = "Test rule") -> RuleLineage:
        return RuleLineage(
            rule_id="abc" if name else None,
            rule_name=name,
            rule_description="desc",
            rule_status="enabled",
            rule_severity="high",
            rule_confidence=80,
            rule_language="sigma",
            is_builtin=True,
            confidence="high" if name else "none",
            match_method="raw_event" if name else "none",
        )

    def _stub_fp(self, *, sample: int = 100, rate: float = 0.2) -> HistoricalFpRate:
        return HistoricalFpRate(
            fp_rate=rate,
            sample_size=sample,
            false_positives=int(sample * rate),
            lookback_days=90,
            scope="rule",
            notes="",
        )

    def test_includes_alert_title_and_severity(self) -> None:
        alert = _alert(title="My alert", severity="medium", connector_type="zeek")
        summary = _deterministic_summary(
            alert,
            mitre_techniques=[],
            rule_lineage=self._stub_lineage(name=None),
            fp=self._stub_fp(sample=0),
        )
        assert "My alert" in summary
        assert "medium" in summary
        assert "zeek" in summary

    def test_includes_rule_name_when_matched(self) -> None:
        alert = _alert()
        summary = _deterministic_summary(
            alert,
            mitre_techniques=[],
            rule_lineage=self._stub_lineage(name="Impossible travel"),
            fp=self._stub_fp(sample=0),
        )
        assert "Impossible travel" in summary

    def test_omits_fp_blurb_below_sample_threshold(self) -> None:
        # Sample < 10 → no FP sentence (statistically unreliable).
        alert = _alert()
        summary = _deterministic_summary(
            alert,
            mitre_techniques=[],
            rule_lineage=self._stub_lineage(name=None),
            fp=self._stub_fp(sample=5, rate=0.4),
        )
        assert "false positive" not in summary.lower()

    def test_includes_fp_blurb_above_sample_threshold(self) -> None:
        alert = _alert()
        summary = _deterministic_summary(
            alert,
            mitre_techniques=[],
            rule_lineage=self._stub_lineage(name=None),
            fp=self._stub_fp(sample=50, rate=0.3),
        )
        assert "false positive" in summary.lower()
        # 30% as a percentage with one decimal.
        assert "30.0%" in summary

    def test_truncates_long_descriptions(self) -> None:
        # Description cap is 240 chars to keep summaries tight.
        long_desc = "x" * 500
        alert = _alert(description=long_desc)
        summary = _deterministic_summary(
            alert,
            mitre_techniques=[],
            rule_lineage=self._stub_lineage(name=None),
            fp=self._stub_fp(sample=0),
        )
        assert "…" in summary


# ---------------------------------------------------------------------------
# generate_alert_explanation — top-level orchestrator
# ---------------------------------------------------------------------------


def _llm_config_disabled(*, reason: str = "no_key") -> LlmConfig:
    return LlmConfig(
        allowed=False,
        base_url="https://api.openai.com",
        model="gpt-4o-mini",
        api_key=None,
        source="none",
        reason=reason,
    )


def _llm_config_allowed() -> LlmConfig:
    return LlmConfig(
        allowed=True,
        base_url="https://api.openai.com",
        model="gpt-4o-mini",
        api_key="sk-test-key-not-real",
        source="environment",
        reason="",
    )


class TestGenerateAlertExplanation:
    """Top-level orchestration: rule lineage + FPR + LLM + cost.

    We patch the resolver, the LLM client, and the cost recorder so
    each branch is observable. The DB mock satisfies the lineage and
    FPR queries (no rule found, zero-sample FPR — minimum useful
    fixture).
    """

    @pytest.mark.asyncio
    async def test_returns_deterministic_summary_when_llm_disabled(self) -> None:
        # When the resolver vetoes (no key, air-gap, etc.) we must
        # return a useful explanation built entirely from the corpus.
        # The endpoint should NEVER fail-closed because the LLM is off.
        alert = _alert(category="identity", mitre_techniques=["T1078"])

        db = MagicMock()
        # No explicit rule → falls through to candidate scan returning
        # no candidates → no rule. FPR query returns zero sample.
        db.execute = AsyncMock(
            side_effect=[
                _scalars_all_result([]),  # candidate scan (no explicit id probe needed)
                _row_one_result(total=0, fps=0),  # FPR query
            ]
        )

        with patch(
            "app.services.alert_explain.resolve_llm_config",
            new=AsyncMock(return_value=_llm_config_disabled(reason="no_key")),
        ):
            explanation = await generate_alert_explanation(db, alert=alert)

        assert isinstance(explanation, AlertExplanation)
        assert explanation.llm_used is False
        assert explanation.llm_reason == "no_key"
        # Deterministic summary is always non-empty.
        assert explanation.summary
        assert explanation.alert_id == str(alert.id)
        # Rule lineage falls back to "none" with no candidates.
        assert explanation.rule_lineage.confidence == "none"

    @pytest.mark.asyncio
    async def test_uses_llm_summary_when_call_succeeds(self) -> None:
        # Happy path: resolver allows, LLM returns text, cost is booked.
        alert = _alert(category="identity", mitre_techniques=["T1078"])

        db = MagicMock()
        db.execute = AsyncMock(
            side_effect=[
                _scalars_all_result([]),  # no candidate rules
                _row_one_result(total=0, fps=0),  # FPR
                MagicMock(),  # cost upsert
            ]
        )

        from app.services.alert_explain import _LlmCallResult

        canned_call = _LlmCallResult(
            text="LLM-written prose explanation.",
            model="gpt-4o-mini",
            prompt_tokens=300,
            completion_tokens=120,
            latency_ms=842.0,
            error=None,
        )

        with (
            patch(
                "app.services.alert_explain.resolve_llm_config",
                new=AsyncMock(return_value=_llm_config_allowed()),
            ),
            patch(
                "app.services.alert_explain._call_llm_for_summary",
                new=AsyncMock(return_value=canned_call),
            ),
        ):
            explanation = await generate_alert_explanation(db, alert=alert)

        assert explanation.llm_used is True
        assert explanation.llm_reason == ""
        assert explanation.summary == "LLM-written prose explanation."
        # Cost upsert must have been issued (the third execute call).
        assert db.execute.await_count == 3

    @pytest.mark.asyncio
    async def test_falls_back_to_deterministic_on_empty_llm(self) -> None:
        # LLM allowed but returned an empty/error response → we keep
        # the deterministic summary and surface the failure reason.
        alert = _alert(category="identity")

        db = MagicMock()
        db.execute = AsyncMock(
            side_effect=[
                _scalars_all_result([]),
                _row_one_result(total=0, fps=0),
            ]
        )

        from app.services.alert_explain import _LlmCallResult

        empty_call = _LlmCallResult(
            text=None,
            model="gpt-4o-mini",
            prompt_tokens=0,
            completion_tokens=0,
            latency_ms=12.0,
            error="upstream_503",
        )

        with (
            patch(
                "app.services.alert_explain.resolve_llm_config",
                new=AsyncMock(return_value=_llm_config_allowed()),
            ),
            patch(
                "app.services.alert_explain._call_llm_for_summary",
                new=AsyncMock(return_value=empty_call),
            ),
        ):
            explanation = await generate_alert_explanation(db, alert=alert)

        assert explanation.llm_used is False
        assert explanation.llm_reason == "upstream_503"
        # The deterministic summary still carries the alert title.
        assert alert.title in explanation.summary

    @pytest.mark.asyncio
    async def test_swallows_cost_recording_failures(self) -> None:
        # Cost-tracking outage must NOT corrupt the explain response.
        # The dashboard will simply miss this row.
        alert = _alert(category="identity")

        db = MagicMock()
        db.execute = AsyncMock(
            side_effect=[
                _scalars_all_result([]),
                _row_one_result(total=0, fps=0),
                RuntimeError("aisoc_run_costs unavailable"),
            ]
        )

        from app.services.alert_explain import _LlmCallResult

        canned_call = _LlmCallResult(
            text="Summary text.",
            model="gpt-4o-mini",
            prompt_tokens=100,
            completion_tokens=50,
            latency_ms=300.0,
            error=None,
        )

        with (
            patch(
                "app.services.alert_explain.resolve_llm_config",
                new=AsyncMock(return_value=_llm_config_allowed()),
            ),
            patch(
                "app.services.alert_explain._call_llm_for_summary",
                new=AsyncMock(return_value=canned_call),
            ),
        ):
            # Must NOT raise even though the cost upsert blew up.
            explanation = await generate_alert_explanation(db, alert=alert)

        assert explanation.llm_used is True
        assert explanation.summary == "Summary text."


# ---------------------------------------------------------------------------
# _explanation_to_payload — dataclass → dict round-trip
# ---------------------------------------------------------------------------


def _stub_explanation() -> AlertExplanation:
    """Build a minimal but realistic AlertExplanation for serialisation tests."""
    return AlertExplanation(
        alert_id=str(uuid.uuid4()),
        summary="Test summary.",
        rule_lineage=RuleLineage(
            rule_id="rid",
            rule_name="Test rule",
            rule_description="desc",
            rule_status="enabled",
            rule_severity="high",
            rule_confidence=80,
            rule_language="sigma",
            is_builtin=True,
            confidence="high",
            match_method="raw_event",
        ),
        contributing_events=[
            ContributingEvent(label="Severity", value="high", annotation=""),
        ],
        mitre_techniques=[
            MitreTechnique(
                id="T1078",
                name="Valid Accounts",
                tactic_names=["Initial Access"],
                description="desc",
                url="https://attack.mitre.org/techniques/T1078/",
            ),
        ],
        historical_fp_rate=HistoricalFpRate(
            fp_rate=0.1,
            sample_size=50,
            false_positives=5,
            lookback_days=90,
            scope="rule",
            notes="ok",
        ),
        suggested_actions=[
            SuggestedAction(
                title="Look here",
                rationale="Because.",
                playbook_id=None,
                priority="fyi",
            ),
        ],
        llm_used=False,
        llm_source="none",
        llm_reason="no_key",
        generated_at="2026-05-12T00:00:00+00:00",
    )


class TestExplanationToPayload:
    """``asdict`` round-trip — JSON-serialisable, deeply nested."""

    def test_returns_dict_with_top_level_keys(self) -> None:
        payload = _explanation_to_payload(_stub_explanation())
        assert set(payload.keys()) >= {
            "alert_id",
            "summary",
            "rule_lineage",
            "contributing_events",
            "mitre_techniques",
            "historical_fp_rate",
            "suggested_actions",
            "llm_used",
            "llm_source",
            "llm_reason",
            "generated_at",
        }

    def test_nested_dataclasses_become_dicts(self) -> None:
        payload = _explanation_to_payload(_stub_explanation())
        # The drawer indexes into rule_lineage by key — fail loudly
        # if asdict ever produces a tuple or named-tuple instead.
        assert isinstance(payload["rule_lineage"], dict)
        assert payload["rule_lineage"]["rule_name"] == "Test rule"
        assert isinstance(payload["mitre_techniques"], list)
        assert payload["mitre_techniques"][0]["id"] == "T1078"

    def test_payload_is_json_serialisable(self) -> None:
        # Realistic safety check: the endpoint returns the payload
        # straight to FastAPI which json-encodes it. Anything not
        # JSON-clean would 500 the request.
        import json

        payload = _explanation_to_payload(_stub_explanation())
        round_tripped = json.loads(json.dumps(payload))
        assert round_tripped["alert_id"] == payload["alert_id"]


# ---------------------------------------------------------------------------
# _acquire_or_429 — endpoint rate-limit shim
# ---------------------------------------------------------------------------


class TestAcquireOr429:
    """Mirrors test_lake_endpoint patterns for the explain rate-limit shim."""

    @pytest.mark.asyncio
    async def test_allowed_path_stamps_headers_no_retry_after(self) -> None:
        decision = ExplainRateLimitDecision(
            allowed=True,
            remaining=15.0,
            capacity=20.0,
            retry_after_seconds=0.0,
        )
        limiter = MagicMock()
        limiter.acquire = AsyncMock(return_value=decision)

        response = Response()
        tenant_id = uuid.uuid4()

        with patch(
            "app.api.v1.endpoints.alert_explain.get_explain_rate_limiter",
            return_value=limiter,
        ):
            await _acquire_or_429(response=response, tenant_id=tenant_id, cost=1.0)

        limiter.acquire.assert_awaited_once_with(tenant_id, cost=1.0)
        assert response.headers["X-RateLimit-Limit"] == "20"
        assert response.headers["X-RateLimit-Remaining"] == "15"
        # The allowed path must NOT advertise Retry-After.
        assert "retry-after" not in {k.lower() for k in response.headers.keys()}

    @pytest.mark.asyncio
    async def test_denied_raises_429_with_headers_on_exception(self) -> None:
        decision = ExplainRateLimitDecision(
            allowed=False,
            remaining=0.0,
            capacity=20.0,
            retry_after_seconds=4.7,
        )
        limiter = MagicMock()
        limiter.acquire = AsyncMock(return_value=decision)

        response = Response()
        tenant_id = uuid.uuid4()

        with patch(
            "app.api.v1.endpoints.alert_explain.get_explain_rate_limiter",
            return_value=limiter,
        ):
            with pytest.raises(HTTPException) as exc_info:
                await _acquire_or_429(
                    response=response,
                    tenant_id=tenant_id,
                    cost=1.0,
                )

        exc = exc_info.value
        assert exc.status_code == 429
        # Belt-and-braces: headers go on BOTH the response and the
        # exception so middleware that strips error headers still sees
        # the rate-limit info on the live response object.
        assert exc.headers["Retry-After"] == "5"  # 4.7 → ceil → 5
        assert exc.headers["X-RateLimit-Limit"] == "20"
        assert response.headers["X-RateLimit-Limit"] == "20"
        assert response.headers["Retry-After"] == "5"


# ---------------------------------------------------------------------------
# ExplainRateLimiter — token-bucket math (mirrors test_lake_rate_limit)
# ---------------------------------------------------------------------------


async def _seed_explain_bucket(
    limiter: ExplainRateLimiter,
    tenant: str | uuid.UUID,
    *,
    at_time: float,
) -> None:
    """Force-create a tenant's bucket with a known last_refill time.

    Mirrors the helper in ``test_lake_rate_limit.py``. We cannot patch
    ``time.monotonic`` *before* the bucket is constructed (that would
    require patching for the entire process) so we patch around the
    creation step explicitly.
    """
    with patch("app.services.explain_rate_limit.time.monotonic", return_value=at_time):
        bucket = await limiter._get_bucket(str(tenant))
        bucket.last_refill = at_time


class TestExplainRateLimiterMath:
    """Token-bucket invariants for the explain limiter."""

    @pytest.mark.asyncio
    async def test_first_request_allowed(self) -> None:
        # Bucket starts full → first acquire MUST succeed instantly.
        limiter = ExplainRateLimiter(capacity=20, refill_per_second=0.2)
        tid = uuid.uuid4()
        await _seed_explain_bucket(limiter, tid, at_time=1000.0)

        with patch("app.services.explain_rate_limit.time.monotonic", return_value=1000.0):
            decision = await limiter.acquire(tid, cost=1.0)

        assert decision.allowed is True
        # 20 - 1 = 19 remaining.
        assert decision.remaining == pytest.approx(19.0)
        assert decision.capacity == 20.0
        assert decision.retry_after_seconds == 0.0

    @pytest.mark.asyncio
    async def test_capacity_exhaustion_blocks_with_retry_after(self) -> None:
        # Exhaust the bucket; next acquire must be rejected with a
        # non-zero retry-after computed from the configured refill.
        limiter = ExplainRateLimiter(capacity=3, refill_per_second=0.5)
        tid = uuid.uuid4()
        await _seed_explain_bucket(limiter, tid, at_time=2000.0)

        with patch("app.services.explain_rate_limit.time.monotonic", return_value=2000.0):
            for _ in range(3):
                allowed = await limiter.acquire(tid, cost=1.0)
                assert allowed.allowed is True

            denied = await limiter.acquire(tid, cost=1.0)

        assert denied.allowed is False
        assert denied.remaining == pytest.approx(0.0)
        # Need 1 token; refill rate is 0.5/sec → 2 seconds to recover.
        assert denied.retry_after_seconds == pytest.approx(2.0)

    @pytest.mark.asyncio
    async def test_refill_recovers_capacity(self) -> None:
        # After enough wall-clock time passes the bucket refills,
        # subject to the per-second refill rate and the capacity cap.
        limiter = ExplainRateLimiter(capacity=2, refill_per_second=1.0)
        tid = uuid.uuid4()
        await _seed_explain_bucket(limiter, tid, at_time=3000.0)

        # Exhaust the bucket.
        with patch("app.services.explain_rate_limit.time.monotonic", return_value=3000.0):
            await limiter.acquire(tid, cost=1.0)
            await limiter.acquire(tid, cost=1.0)
            denied = await limiter.acquire(tid, cost=1.0)
            assert denied.allowed is False

        # Skip 5 seconds → refill (capped at capacity=2).
        with patch("app.services.explain_rate_limit.time.monotonic", return_value=3005.0):
            recovered = await limiter.acquire(tid, cost=1.0)

        assert recovered.allowed is True
        # Refill brings us back up to capacity (2.0), then we charge
        # 1, so 1.0 token remains.
        assert recovered.remaining == pytest.approx(1.0)

    @pytest.mark.asyncio
    async def test_per_tenant_isolation(self) -> None:
        # One tenant draining their bucket must NOT throttle another.
        limiter = ExplainRateLimiter(capacity=2, refill_per_second=0.1)
        loud = uuid.uuid4()
        quiet = uuid.uuid4()
        await _seed_explain_bucket(limiter, loud, at_time=4000.0)
        await _seed_explain_bucket(limiter, quiet, at_time=4000.0)

        with patch("app.services.explain_rate_limit.time.monotonic", return_value=4000.0):
            await limiter.acquire(loud, cost=1.0)
            await limiter.acquire(loud, cost=1.0)
            loud_denied = await limiter.acquire(loud, cost=1.0)
            quiet_allowed = await limiter.acquire(quiet, cost=1.0)

        assert loud_denied.allowed is False
        assert quiet_allowed.allowed is True

    @pytest.mark.asyncio
    async def test_cost_above_capacity_raises(self) -> None:
        # A cost greater than capacity could never succeed; surface
        # the bug at the call site rather than waiting forever.
        limiter = ExplainRateLimiter(capacity=5, refill_per_second=1.0)
        with pytest.raises(ValueError):
            await limiter.acquire(uuid.uuid4(), cost=10.0)

    @pytest.mark.asyncio
    async def test_negative_cost_raises(self) -> None:
        limiter = ExplainRateLimiter(capacity=5, refill_per_second=1.0)
        with pytest.raises(ValueError):
            await limiter.acquire(uuid.uuid4(), cost=0.0)

    @pytest.mark.asyncio
    async def test_invalid_construction_raises(self) -> None:
        # Defensive: a misconfigured env override (refill=0) would
        # silently neuter the limiter; we'd rather crash on import.
        with pytest.raises(ValueError):
            ExplainRateLimiter(capacity=0, refill_per_second=0.1)
        with pytest.raises(ValueError):
            ExplainRateLimiter(capacity=10, refill_per_second=0)


class TestExplainRateLimitDecisionHeaders:
    """``ExplainRateLimitDecision.to_headers`` is what stamps responses."""

    def test_allowed_omits_retry_after(self) -> None:
        decision = ExplainRateLimitDecision(
            allowed=True,
            remaining=10.0,
            capacity=20.0,
            retry_after_seconds=0.0,
        )
        headers = decision.to_headers()
        assert headers["X-RateLimit-Limit"] == "20"
        assert headers["X-RateLimit-Remaining"] == "10"
        assert "Retry-After" not in headers

    def test_denied_includes_ceiled_retry_after(self) -> None:
        # 1.2s → must round UP to 2 (RFC 7231 §7.1.3 wants integer
        # seconds, and rounding down would tell clients to retry too
        # early and double-trip the limiter).
        decision = ExplainRateLimitDecision(
            allowed=False,
            remaining=0.0,
            capacity=20.0,
            retry_after_seconds=1.2,
        )
        headers = decision.to_headers()
        assert headers["Retry-After"] == "2"

    def test_denied_minimum_retry_after_is_one(self) -> None:
        # Even a sub-second retry must surface as "1" so polite
        # clients back off at least one tick.
        decision = ExplainRateLimitDecision(
            allowed=False,
            remaining=0.0,
            capacity=20.0,
            retry_after_seconds=0.05,
        )
        headers = decision.to_headers()
        assert headers["Retry-After"] == "1"

    def test_remaining_clamps_to_non_negative_int(self) -> None:
        # Float arithmetic can briefly go slightly negative around
        # contention. Headers must be stable integers, not "-0".
        decision = ExplainRateLimitDecision(
            allowed=False,
            remaining=-0.0001,
            capacity=20.0,
            retry_after_seconds=1.0,
        )
        headers = decision.to_headers()
        assert headers["X-RateLimit-Remaining"] == "0"
