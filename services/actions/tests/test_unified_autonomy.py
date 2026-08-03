"""Wave 5b — unified autonomy policy (confidence x blast radius x reversibility)."""

from __future__ import annotations

from app.models.action import BlastRadius
from app.services.autonomy_safety import AutonomyMode
from app.services.unified_autonomy import unified_decision


def test_reversible_low_blast_high_confidence_auto_executes():
    d = unified_decision(action_type="block_ip", blast_radius=BlastRadius.LOW, confidence=0.9, reversible=True)
    assert d.mode == AutonomyMode.AUTO


def test_reversible_low_blast_low_confidence_queues():
    d = unified_decision(action_type="block_ip", blast_radius=BlastRadius.LOW, confidence=0.6, reversible=True)
    assert d.mode == AutonomyMode.QUEUED_APPROVAL


def test_non_reversible_never_auto_even_at_max_confidence():
    d = unified_decision(action_type="isolate_host", blast_radius=BlastRadius.LOW, confidence=0.99, reversible=False)
    assert d.mode == AutonomyMode.QUEUED_APPROVAL


def test_critical_blast_never_auto():
    d = unified_decision(action_type="block_ip", blast_radius=BlastRadius.CRITICAL, confidence=0.99, reversible=True)
    assert d.mode == AutonomyMode.QUEUED_APPROVAL


def test_reversible_medium_blast_needs_higher_confidence():
    assert (
        unified_decision(action_type="block_ip", blast_radius=BlastRadius.MEDIUM, confidence=0.9, reversible=True).mode
        == AutonomyMode.QUEUED_APPROVAL
    )
    assert (
        unified_decision(action_type="block_ip", blast_radius=BlastRadius.MEDIUM, confidence=0.96, reversible=True).mode
        == AutonomyMode.AUTO
    )


def test_reversible_high_blast_queues():
    d = unified_decision(action_type="block_ip", blast_radius=BlastRadius.HIGH, confidence=0.99, reversible=True)
    assert d.mode == AutonomyMode.QUEUED_APPROVAL
