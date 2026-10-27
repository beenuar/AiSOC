"""Whether a configuration has *earned* the right to close alerts unattended.

The gap
-------
``state.confidence`` is the number the model put in its own ``confidence``
field, coerced and clamped by ``_coerce_confidence``. It is passed straight
into ``closure_policy.decide``, where ``allowed = confidence >= threshold``,
and it is the **sole numeric gate** on autonomous closure.

It is not evidence of correctness. A model that reports 0.97 on every reply
closes every alert, and nothing in the system has ever checked whether a 0.97
was earned — the repository has real calibration machinery in
:mod:`app.confidence.calibration`, and its only consumers are the eval suite
and the vendored benchmark. Measured accuracy has never reached the threshold
that governs production.

This module is the missing input. It answers a different question from the
closure policy's, and deliberately does not answer the policy's: *has this
model, on this prompt version, for this tenant context and alert class, been
separately measured closing alerts correctly, over enough samples, recently
enough for the measurement to still describe what is running?*

What makes a measurement apply
------------------------------
All of: model identity, prompt **version and content hash**, tenant context,
alert class. The prompt registry exists so that a prompt edit is declared and
re-graded; autonomy honouring the version but not the hash would let a text
change slip under a measurement that stayed, which is the exact drift the lock
was built to make visible. A narrower row wins over a broader one — a
tenant-wide 0.99 does not license a class measured at 0.70 — because a model
can be accurate overall and wrong precisely where it is most confident.

Three states, and the middle one is the design
----------------------------------------------
``ELIGIBLE``   a measurement exists and clears the bar.
``BLOCKED``    a measurement exists and does not. New safety, and it costs
               nothing today because no measurement exists yet.
``UNMEASURED`` nothing matches. Additive by default — today's behaviour is
               preserved — and denied under ``AISOC_AUTONOMY_REQUIRE_MEASURED=1``.

The default is additive on purpose and the reasoning is recorded here rather
than left to be rediscovered. The shipped record file carries **zero rows**,
because there is no funded evaluation provider in this repository and a
fabricated row would be worse than none. Enforcing deny-by-default today would
therefore switch off auto-closure on every deployment on the strength of a
measurement nobody has taken — a product change nobody asked for, justified by
no evidence. Shipping the mechanism unwired would be decoration. So it runs on
every closure decision and records its verdict on the confidence basis, the
strict posture is one documented flag, and the measurement is marked PENDING
in ``autonomy_performance.json`` and in
``docs/remediation/phase-7-8-evaluation-grounding.md``.

Relationship to the closure policy
----------------------------------
``app.closure.policy`` owns *whether this tenant has configured closure and at
what threshold*. This owns *whether the configuration in front of us has been
measured closing alerts correctly*. They compose by only ever narrowing: this
can withhold a closure the policy allowed, and can never grant one the policy
withheld — the same contract the groundedness, tool-provenance and injection
demotions already hold to. Nothing here reads or writes a closure policy row.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.confidence.signals import UNMEASURED, SignalKind

__all__ = [
    "Eligibility",
    "EligibilityDecision",
    "PerformanceRecord",
    "evaluate_eligibility",
    "load_records",
    "require_measured",
]

KIND = SignalKind.AUTO_CLOSURE_SAFETY

RECORD_PATH = Path(__file__).resolve().parent / "autonomy_performance.json"

#: Minimum closures a row must be computed over. A precision of 1.000 over
#: eleven alerts is a number, not a measurement: its 95% lower bound sits
#: around 0.72, which is below the floor the same row would have to clear.
MIN_SAMPLES = 100

#: Minimum share of unattended closures that were right to make. Not a
#: headline accuracy: a model can be accurate overall and wrong exactly on
#: the alerts it closes, which is the only population this number is about.
MIN_AUTO_CLOSE_PRECISION = 0.95

#: How long a measurement keeps describing the thing in front of it. Beyond
#: this it blocks rather than quietly counting — a stale row that still
#: authorises closure is worse than no row, because it reads as evidence.
MAX_AGE_DAYS = 180


class Eligibility(str, Enum):
    ELIGIBLE = "eligible"
    BLOCKED = "blocked"
    UNMEASURED = "unmeasured"


@dataclass(frozen=True)
class PerformanceRecord:
    """One measured auto-closure precision, and everything needed to trust it."""

    model: str
    prompt_name: str
    prompt_version: str
    prompt_sha256: str
    tenant_context: str
    #: ``None`` means "every class for this tenant context". A row naming a
    #: class outranks it.
    alert_class: str | None
    samples: int
    auto_close_precision: float
    corpus_digest: str
    code_revision: str
    measured_at: str
    measured_by: str
    is_synthetic: bool = True

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> PerformanceRecord:
        alert_class = raw.get("alert_class")
        return cls(
            model=str(raw["model"]),
            prompt_name=str(raw.get("prompt_name") or "triage.system"),
            prompt_version=str(raw["prompt_version"]),
            prompt_sha256=str(raw["prompt_sha256"]),
            tenant_context=str(raw.get("tenant_context") or "default"),
            alert_class=str(alert_class) if alert_class else None,
            samples=int(raw["samples"]),
            auto_close_precision=float(raw["auto_close_precision"]),
            corpus_digest=str(raw.get("corpus_digest") or ""),
            code_revision=str(raw.get("code_revision") or ""),
            measured_at=str(raw["measured_at"]),
            measured_by=str(raw.get("measured_by") or ""),
            is_synthetic=bool(raw.get("is_synthetic", True)),
        )

    def age_days(self, now: datetime) -> float:
        try:
            taken = datetime.fromisoformat(self.measured_at)
        except ValueError:
            # An unparseable timestamp is treated as infinitely old rather
            # than as fresh. A row whose date nobody can read must not be the
            # thing that authorises a closure.
            return float("inf")
        if taken.tzinfo is None:
            taken = taken.replace(tzinfo=UTC)
        return (now - taken).total_seconds() / 86400.0


@dataclass(frozen=True)
class EligibilityDecision:
    """Whether measured performance licenses an unattended closure here."""

    state: Eligibility
    reason: str
    record: PerformanceRecord | None = None
    #: Whether the *caller's* posture lets an unmeasured configuration close.
    require_measured: bool = False

    @property
    def measured(self) -> bool:
        return self.record is not None

    @property
    def precision(self) -> float | None:
        """``None`` when unmeasured. Never 0.0, which would read as a failed grade."""
        return self.record.auto_close_precision if self.record else None

    @property
    def allows_auto_close(self) -> bool:
        if self.state is Eligibility.BLOCKED:
            return False
        if self.state is Eligibility.UNMEASURED:
            return not self.require_measured
        return True

    def render_precision(self) -> str:
        """Human form, and never a bare number for something nobody measured."""
        return UNMEASURED if self.precision is None else f"{self.precision:.3f}"

    def as_dict(self) -> dict[str, Any]:
        record = self.record
        return {
            "kind": KIND.value,
            "state": self.state.value,
            "allows_auto_close": self.allows_auto_close,
            "reason": self.reason,
            "auto_close_precision": self.precision,
            "samples": record.samples if record else None,
            "model": record.model if record else None,
            "prompt_version": record.prompt_version if record else None,
            "prompt_sha256": record.prompt_sha256 if record else None,
            "alert_class": record.alert_class if record else None,
            "corpus_digest": record.corpus_digest if record else None,
            "code_revision": record.code_revision if record else None,
            "measured_at": record.measured_at if record else None,
            "measured_by": record.measured_by if record else None,
            "is_synthetic": record.is_synthetic if record else None,
        }


def _require_measured_from_env() -> bool:
    return (os.getenv("AISOC_AUTONOMY_REQUIRE_MEASURED", "") or "").strip().lower() in ("1", "true", "yes", "on")


def require_measured() -> bool:
    """Whether an unmeasured configuration is denied. Off by default; see the module docstring."""
    return _require_measured_from_env()


@lru_cache(maxsize=1)
def _cached_records() -> tuple[PerformanceRecord, ...]:
    if not RECORD_PATH.exists():
        return ()
    try:
        payload = json.loads(RECORD_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        # An unreadable record file yields no rows, which lands every
        # configuration in UNMEASURED. It must never yield a permissive
        # *measurement*, which is what a default row would be.
        return ()
    rows = payload.get("records") or []
    out: list[PerformanceRecord] = []
    for row in rows:
        try:
            out.append(PerformanceRecord.from_dict(row))
        except (KeyError, TypeError, ValueError):
            continue
    return tuple(out)


def load_records() -> tuple[PerformanceRecord, ...]:
    """The committed measurements. Empty while the measurement is PENDING."""
    return _cached_records()


def _matches(
    record: PerformanceRecord, *, model: str, prompt_version: str, prompt_sha256: str, tenant_context: str, alert_class: str | None
) -> bool:
    if record.model != model:
        return False
    if record.prompt_version != prompt_version or record.prompt_sha256 != prompt_sha256:
        return False
    if record.tenant_context != tenant_context:
        return False
    return record.alert_class in (None, alert_class)


def evaluate_eligibility(
    *,
    model: str | None,
    prompt_version: str,
    prompt_sha256: str,
    tenant_context: str,
    alert_class: str | None,
    records: tuple[PerformanceRecord, ...] | None = None,
    now_iso: str | None = None,
    require_measured: bool | None = None,
) -> EligibilityDecision:
    """Decide whether measured performance licenses closing this alert unattended."""
    strict = require_measured if require_measured is not None else _require_measured_from_env()
    rows = load_records() if records is None else records
    now = datetime.fromisoformat(now_iso) if now_iso else datetime.now(UTC)
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)

    if not model:
        return EligibilityDecision(
            state=Eligibility.UNMEASURED,
            reason="no model identity was resolved for this run, so no measurement can be matched to it",
            require_measured=strict,
        )

    candidates = [
        r
        for r in rows
        if _matches(
            r,
            model=model,
            prompt_version=prompt_version,
            prompt_sha256=prompt_sha256,
            tenant_context=tenant_context,
            alert_class=alert_class,
        )
    ]
    if not candidates:
        return EligibilityDecision(
            state=Eligibility.UNMEASURED,
            reason=(
                f"auto-closure safety is {UNMEASURED} for model {model!r} on prompt v{prompt_version} "
                f"({prompt_sha256[:12]}), tenant context {tenant_context!r}, class {alert_class or 'any'!r}"
            ),
            require_measured=strict,
        )

    # The narrowest row wins: a class-specific measurement describes this
    # alert, a tenant-wide one describes an average it may sit far from.
    candidates.sort(key=lambda r: (r.alert_class is None, r.measured_at), reverse=False)
    record = candidates[0]

    age = record.age_days(now)
    if age > MAX_AGE_DAYS:
        return EligibilityDecision(
            state=Eligibility.BLOCKED,
            reason=f"the only matching measurement is stale: taken {age:.0f} days ago, ceiling {MAX_AGE_DAYS}",
            record=record,
            require_measured=strict,
        )
    if record.samples < MIN_SAMPLES:
        return EligibilityDecision(
            state=Eligibility.BLOCKED,
            reason=f"the matching measurement covers {record.samples} sample(s), below the minimum of {MIN_SAMPLES}",
            record=record,
            require_measured=strict,
        )
    if record.auto_close_precision < MIN_AUTO_CLOSE_PRECISION:
        return EligibilityDecision(
            state=Eligibility.BLOCKED,
            reason=(
                f"measured auto-closure precision {record.auto_close_precision:.2f} over {record.samples} "
                f"closures is below the floor of {MIN_AUTO_CLOSE_PRECISION:.2f}"
            ),
            record=record,
            require_measured=strict,
        )

    return EligibilityDecision(
        state=Eligibility.ELIGIBLE,
        reason=(
            f"measured auto-closure precision {record.auto_close_precision:.3f} over {record.samples} closures "
            f"({record.measured_at}, {record.measured_by or 'unrecorded'})"
        ),
        record=record,
        require_measured=strict,
    )
