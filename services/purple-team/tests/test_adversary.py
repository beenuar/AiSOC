"""Tests for the self-play purple team (v8 P2).

The safety-critical property — the scope guard hard-fails on any non-lab target
— has adversarial tests. The closed loop (plan → run → score → auto-file DAC) is
verified end-to-end via the canned campaign.
"""

from __future__ import annotations

import pytest
from app.adversary.campaign import CannedOracle, InMemoryEmitter, run_campaign
from app.adversary.canned import run as run_canned
from app.adversary.dac import InMemoryFiler, auto_file_gaps, build_gap_proposal
from app.adversary.planner import STAGES, InventoryTechnique, plan_campaign
from app.adversary.scope_guard import Asset, ScopeViolation, assert_in_scope, filter_lab_targets

INVENTORY = [
    InventoryTechnique("T1566.001", "Spearphishing", "initial-access", frozenset({"windows"}), 90),
    InventoryTechnique("T1059.001", "PowerShell", "execution", frozenset({"windows"}), 95),
    InventoryTechnique("T1547.001", "Run Keys", "persistence", frozenset({"windows"}), 80),
    InventoryTechnique("T1055", "Process Injection", "privilege-escalation", frozenset({"windows"}), 85),
    InventoryTechnique("T1048", "Exfil", "exfiltration", frozenset({"windows"}), 88),
]
LAB = [Asset.of("lab-win-01", "lab", "windows")]


# ── scope guard (safety-critical, adversarial) ────────────────────────────────


def test_scope_guard_hard_fails_on_production_asset():
    with pytest.raises(ScopeViolation):
        assert_in_scope([Asset.of("db-prod-01", "production", "windows")])


def test_scope_guard_hard_fails_on_untagged_asset():
    # An asset with no lab tag is refused — you must opt an asset INTO the range.
    with pytest.raises(ScopeViolation):
        assert_in_scope([Asset.of("mystery-host")])


def test_scope_guard_hard_fails_on_empty_targets():
    with pytest.raises(ScopeViolation):
        assert_in_scope([])


def test_scope_guard_hard_fails_when_forbidden_tag_coexists_with_lab_tag():
    # A "lab" tag can't launder a crown-jewel — forbidden tags always win.
    with pytest.raises(ScopeViolation):
        assert_in_scope([Asset.of("weird", "lab", "crown-jewel")])


def test_scope_guard_allows_lab_and_sandbox():
    assert_in_scope([Asset.of("lab-1", "lab"), Asset.of("sb-1", "sandbox")])  # no raise


def test_filter_lab_targets_drops_non_lab():
    mixed = [Asset.of("lab-1", "lab"), Asset.of("prod-1", "production"), Asset.of("x")]
    kept = filter_lab_targets(mixed)
    assert [a.asset_id for a in kept] == ["lab-1"]


# ── planner ───────────────────────────────────────────────────────────────────


def test_plan_composes_ordered_kill_chain():
    campaign = plan_campaign("c", INVENTORY, LAB)
    assert [s.stage for s in campaign.steps] == list(STAGES)
    assert campaign.steps[0].order == 1
    assert all(s.target == "lab-win-01" for s in campaign.steps)


def test_plan_only_attacks_present_platforms():
    # A linux-only lab shouldn't plan windows-only techniques.
    linux_lab = [Asset.of("lab-linux-01", "lab", "linux")]
    inv = [
        InventoryTechnique("T1059.004", "Unix Shell", "execution", frozenset({"linux"}), 90),
        InventoryTechnique("T1059.001", "PowerShell", "execution", frozenset({"windows"}), 95),
    ]
    campaign = plan_campaign("c", inv, linux_lab)
    assert campaign.techniques == ["T1059.004"]


def test_plan_raises_when_no_lab_target():
    with pytest.raises(ScopeViolation):
        plan_campaign("c", INVENTORY, [Asset.of("prod", "production")])


# ── closed loop ───────────────────────────────────────────────────────────────


def test_run_campaign_scores_detected_and_missed():
    campaign = plan_campaign("c", INVENTORY, LAB)
    report = run_campaign(campaign, InMemoryEmitter(), CannedOracle({"T1059.001", "T1055"}))
    assert len(report.results) == 5
    assert len(report.detected) == 2
    assert len(report.missed) == 3
    assert report.detection_rate == pytest.approx(0.4)
    assert report.mean_time_to_verdict_s == 12.0


def test_emitter_records_events_for_every_step():
    campaign = plan_campaign("c", INVENTORY, LAB)
    emitter = InMemoryEmitter()
    run_campaign(campaign, emitter, CannedOracle(set()))
    assert len(emitter.events) == 5
    assert all(e["source"] == "self-play" for e in emitter.events)


# ── DAC auto-file ─────────────────────────────────────────────────────────────


def test_auto_file_files_one_proposal_per_miss():
    campaign = plan_campaign("c", INVENTORY, LAB)
    report = run_campaign(campaign, InMemoryEmitter(), CannedOracle({"T1059.001"}))
    filer = InMemoryFiler()
    ids = auto_file_gaps(report, filer)
    assert len(ids) == 4  # 5 attempted, 1 detected → 4 gaps
    assert all(d.category == "purple-team-gap" for d in filer.filed)
    assert all(d.rule_language == "sigma" for d in filer.filed)


def test_gap_proposal_carries_the_technique_and_is_low_confidence():
    campaign = plan_campaign("c", INVENTORY, LAB)
    miss = run_campaign(campaign, InMemoryEmitter(), CannedOracle(set())).missed[0]
    draft = build_gap_proposal(miss)
    assert draft.mitre_techniques == [miss.technique_id]
    assert f"attack.{miss.technique_id.lower()}" in draft.rule_body
    assert draft.confidence <= 50  # scaffold, pending eval + human review
    assert "self-play" in draft.tags


# ── canned campaign (demo CI) ─────────────────────────────────────────────────


def test_canned_campaign_runs_end_to_end():
    result = run_canned(as_json=True)
    assert result["report"]["techniques_attempted"] == 5
    assert result["report"]["techniques_detected"] == 3
    assert len(result["dac_proposals_filed"]) == 2  # 2 misses
    assert result["scoreboard_row"]["synthetic"] is True
    assert result["scoreboard_row"]["new_detections_filed"] == 2
