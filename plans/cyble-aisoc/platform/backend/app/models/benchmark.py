"""Persistent leaderboard rows for the open AI-SOC benchmark (t3g).

A :class:`BenchmarkRun` is one immutable submission to the leaderboard.
Every run captures:

- The benchmark version that produced it (so historical entries remain
  comparable when the rubric or scenarios change).
- The LLM provider + model that drove the agents (the leaderboard is
  meaningless without this — "AI-SOC" with the deterministic mock
  scores high because it follows a hand-coded path).
- Aggregate score (mean of per-scenario scores, 0..100), pass rate
  (fraction of scenarios that passed), and total wall-clock latency.
- The full per-scenario outcome blob, so the leaderboard UI can show
  *why* a row scored what it did without needing a re-run.

Persisting these as DB rows means the same query that powers the local
admin leaderboard is the one that will eventually populate the public
benchmark site — there's no separate file format to maintain.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlmodel import Column, Field, JSON, SQLModel


class BenchmarkRun(SQLModel, table=True):
    """One leaderboard row for the open AI-SOC eval benchmark."""

    id: Optional[int] = Field(default=None, primary_key=True)
    benchmark_version: str = Field(index=True)
    model_provider: str = Field(index=True)
    model_name: str = Field(index=True)
    aggregate_score: float = Field(index=True)
    pass_rate: float = 0.0
    total_latency_ms: int = 0
    scenarios_run: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    outcomes: list[dict[str, Any]] = Field(
        default_factory=list, sa_column=Column(JSON)
    )
    notes: str = ""
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), index=True
    )
