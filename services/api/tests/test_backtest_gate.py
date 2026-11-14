"""Wave 2 (W2.2) - the opt-in backtest hit-rate approval gate."""

from __future__ import annotations

from app.api.v1.endpoints.detection_proposals import _backtest_max_hit_rate


def test_gate_disabled_by_default(monkeypatch):
    monkeypatch.delenv("AISOC_BACKTEST_MAX_HIT_RATE", raising=False)
    assert _backtest_max_hit_rate() is None


def test_gate_reads_threshold(monkeypatch):
    monkeypatch.setenv("AISOC_BACKTEST_MAX_HIT_RATE", "0.5")
    assert _backtest_max_hit_rate() == 0.5


def test_gate_ignores_garbage(monkeypatch):
    monkeypatch.setenv("AISOC_BACKTEST_MAX_HIT_RATE", "not-a-number")
    assert _backtest_max_hit_rate() is None
