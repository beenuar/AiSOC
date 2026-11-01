"""Depth 2 wave 2 item 2.3 — several unalarming signals becoming one finding.

A new autonomous system for an account is not an alert. Neither is a new
client family, nor a sensitive action, nor an anonymizing egress. Each is
common enough on its own that alerting on it would bury the queue, and the
plan is explicit that one geography or ASN change alone must never be a
finding. Several of them on one session is the canonical compromise.

This module accumulates those signals per session, per principal and per
window, and past a strength threshold emits **one** finding that lists every
contributor and its weight. It does not alert; it returns a `WeakFinding` the
caller promotes, in the same shape as every other typed signal in this
package.

Where the ordered pairs went
----------------------------
Item 2.1 refused the plan's "recovery email changed, then the password,
within minutes" as a single-event rule: the windowed engine counts and does
not order, and 24 rules were already refused rather than shipped as weaker
count rules under a stronger name. This is where that case lands instead.
Each half is a weak signal; together on one principal inside the window they
clear the threshold, and the finding lists both with the order they arrived.

Severity and confidence are independent
---------------------------------------
Severity comes from the strongest contributing signal, on the five-tier
ladder (`info | low | medium | high | critical`). Confidence is an integer
0-100 derived from how far past the threshold the accumulated strength sits
and how many *distinct kinds* of signal contributed. They are deliberately
not the same number: four weak signals of one kind is a noisy integration,
four of different kinds on one session is a story.

Absent, not zero
----------------
An unreachable store contributes no finding, never an empty one. A session
with one signal returns `None` rather than a finding with a strength below
the threshold, because a caller that receives an object tends to render it.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()

#: How long signals accumulate against one subject. An hour: long enough for
#: a session-takeover sequence, short enough that two unrelated days of
#: ordinary work do not pool into a finding.
WINDOW_SECONDS = int(os.getenv("AISOC_WEAK_SIGNAL_WINDOW_SECONDS", "3600"))

#: Accumulated strength a subject must reach.
#:
#: **This is a rationale, not a measurement.**
#: `scripts/calibrate_weak_signals.py` runs against the balanced verdict
#: corpus and *refuses* to publish a sweep: the corpus carries vendor alert
#: evidence, while every signal here is produced by fusion's enrichment at
#: evaluate time, so all 72 items score zero. Publishing `recall 0.0000`
#: would have said "the aggregator detects nothing" having measured "this
#: corpus carries none of its inputs".
#:
#: The value is set at the point where the plan's canonical case clears it
#: — a credential change followed by the same principal acting from an
#: anonymizing egress inside the window, which is 2.32 — while every
#: individual weight below stays under it and `MIN_DISTINCT_KINDS` keeps one
#: repeated signal from reaching it. `docs/detections/weak-signal-calibration.json`
#: records the refusal and the condition that returns it to measured.
STRENGTH_THRESHOLD = float(os.getenv("AISOC_WEAK_SIGNAL_THRESHOLD", "2.2"))

#: Distinct signal *kinds* a finding needs. Without this a single noisy
#: integration emitting the same weak signal repeatedly would clear the
#: strength threshold alone, which is exactly the "one ASN change" case the
#: plan forbids.
MIN_DISTINCT_KINDS = int(os.getenv("AISOC_WEAK_SIGNAL_MIN_KINDS", "2"))

#: Signals the accumulator understands, and what each is worth. Weights are
#: ordered by how hard the signal is for an attacker to avoid: an anonymizing
#: egress is a choice they make, a vendor's own risk verdict is not.
#:
#: No single weight reaches `STRENGTH_THRESHOLD`. That is the invariant the
#: plan states — one geography or ASN change alone is never a finding — and
#: `test_no_single_signal_can_fire` holds it rather than leaving it to
#: whoever edits this table next.
SIGNAL_WEIGHTS: dict[str, float] = {
    "new_asn": 0.8,
    "new_country": 0.8,
    "new_client_family": 0.7,
    "new_isp": 0.6,
    "concurrent_locations": 1.4,
    "anonymizer_egress": 1.0,
    "sub_principal_deviation": 1.2,
    "sensitive_action": 1.0,
    "idp_risk_event": 1.5,
    "credential_change": 1.2,
    "mfa_weakened": 1.4,
}

#: Severity each kind contributes. The finding takes the highest.
SIGNAL_SEVERITY: dict[str, str] = {
    "new_asn": "low",
    "new_country": "low",
    "new_client_family": "low",
    "new_isp": "info",
    "concurrent_locations": "high",
    "anonymizer_egress": "medium",
    "sub_principal_deviation": "medium",
    "sensitive_action": "medium",
    "idp_risk_event": "high",
    "credential_change": "medium",
    "mfa_weakened": "high",
}

_SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


@dataclass(frozen=True)
class WeakSignal:
    """One observation that is not an alert on its own."""

    kind: str
    detail: str
    at: float

    @property
    def weight(self) -> float:
        return SIGNAL_WEIGHTS.get(self.kind, 0.0)


@dataclass(frozen=True)
class WeakFinding:
    """Several weak signals on one subject, inside one window."""

    subject: str
    subject_kind: str
    strength: float
    severity: str
    confidence: int
    signals: list[WeakSignal] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "subject_kind": self.subject_kind,
            "strength": round(self.strength, 3),
            "severity": self.severity,
            "confidence": self.confidence,
            "window_seconds": WINDOW_SECONDS,
            "contributing_signals": [
                {"kind": s.kind, "detail": s.detail, "weight": s.weight, "at": s.at} for s in self.signals
            ],
        }


def extract_signals(event: dict[str, Any], *, now: float | None = None) -> list[WeakSignal]:
    """The weak signals this event carries.

    Every one is read from a field something actually publishes: the
    first-seen store's novelty booleans, the ingest IP classification from
    item 1.6, the baseline store's deviation scores, and the vendor's own
    risk verdict. A signal with no publisher would be a weight that can
    never be added, which is worse than an absent signal because the
    threshold was calibrated as though it could.
    """
    at = now if now is not None else time.time()
    out: list[WeakSignal] = []

    def add(kind: str, detail: Any) -> None:
        out.append(WeakSignal(kind=kind, detail=str(detail), at=at))

    if event.get("first_seen_asn_for_principal"):
        add("new_asn", event.get("src_asn") or "unknown")
    if event.get("first_seen_country_for_principal"):
        add("new_country", event.get("src_country") or "unknown")
    if event.get("first_seen_client_for_principal"):
        add("new_client_family", event.get("client_browser") or event.get("client_app") or "unknown")
    if event.get("first_seen_isp_for_principal"):
        add("new_isp", event.get("src_isp") or "unknown")

    ip_class = event.get("ip_class")
    if isinstance(ip_class, str) and ip_class in {"vpn", "tor_exit", "public_proxy", "residential_proxy", "hosting_provider"}:
        add("anonymizer_egress", ip_class)

    for score_field in ("baseline_oauth_app_volume_z", "baseline_principal_volume_z"):
        score = event.get(score_field)
        if isinstance(score, int | float) and float(score) >= 3.0:
            add("sub_principal_deviation", f"{score_field}={score}")

    risk = event.get("risk_level_during_sign_in") or event.get("riskLevelDuringSignIn") or event.get("risk_state")
    if isinstance(risk, str) and risk.lower() in {"medium", "high", "atrisk", "confirmedcompromised"}:
        add("idp_risk_event", risk)

    event_type = str(event.get("event_type") or "")
    if event_type.endswith(("recovery_email_edit", "recovery_phone_edit", "password_edit", "change_password")):
        add("credential_change", event_type)
    if event_type.endswith(("2sv_disable", "unenroll_user_from_strong_auth", "pref.two_factor_auth_changed")):
        add("mfa_weakened", event_type)
    if event.get("sensitive_action") is True:
        add("sensitive_action", event_type or "sensitive")

    return out


def _severity_of(signals: list[WeakSignal]) -> str:
    worst = "info"
    for signal in signals:
        candidate = SIGNAL_SEVERITY.get(signal.kind, "info")
        if _SEVERITY_ORDER.index(candidate) > _SEVERITY_ORDER.index(worst):
            worst = candidate
    return worst


def _confidence_of(strength: float, distinct_kinds: int) -> int:
    """0-100, independent of severity.

    Two inputs rather than one: how far past the threshold the strength
    sits, and how many different kinds contributed. Four repeats of one
    signal is a noisy integration; four different kinds on one session is a
    story, and the number has to be able to tell them apart.
    """
    over = max(0.0, strength - STRENGTH_THRESHOLD) / max(STRENGTH_THRESHOLD, 1e-9)
    breadth = min(1.0, (distinct_kinds - 1) / 3.0)
    score = 50.0 + 30.0 * min(1.0, over) + 20.0 * breadth
    return int(max(0, min(100, round(score))))


class WeakSignalAggregator:
    """Accumulates weak signals per subject in the Redis fusion already runs."""

    def __init__(
        self,
        redis: Any,
        *,
        key_prefix: str = "aisoc:ws",
        window_seconds: int | None = None,
        threshold: float | None = None,
        min_distinct_kinds: int | None = None,
    ) -> None:
        self._redis = redis
        self._prefix = key_prefix
        self._window = window_seconds if window_seconds is not None else WINDOW_SECONDS
        self._threshold = threshold if threshold is not None else STRENGTH_THRESHOLD
        self._min_kinds = min_distinct_kinds if min_distinct_kinds is not None else MIN_DISTINCT_KINDS

    def _key(self, tenant: str, subject_kind: str, subject: str) -> str:
        return f"{self._prefix}:{tenant}:{subject_kind}:{subject}"

    async def accumulate(
        self,
        tenant: str,
        subject_kind: str,
        subject: str,
        signals: list[WeakSignal],
        *,
        now: float | None = None,
    ) -> WeakFinding | None:
        """Add these signals to the subject's window; return a finding if it clears.

        One finding per window per subject: the strength is reset once it
        fires, so a session producing signals steadily raises one finding
        rather than one per event. Re-accumulation after the reset is what
        makes a second, genuinely new burst visible.
        """
        if not tenant or not subject or not signals:
            return None
        at = now if now is not None else time.time()
        key = self._key(tenant, subject_kind, subject)
        try:
            for signal in signals:
                await self._redis.zadd(key, {json.dumps({"k": signal.kind, "d": signal.detail, "t": signal.at}): signal.at})
            await self._redis.zremrangebyscore(key, 0, at - self._window)
            await self._redis.expire(key, self._window)
            members = await self._redis.zrange(key, 0, -1)
        except Exception as exc:  # noqa: BLE001 — see the module docstring
            logger.debug("weak_signals.unavailable", subject_kind=subject_kind, error=str(exc))
            return None

        live: list[WeakSignal] = []
        for member in members or []:
            raw = member.decode() if isinstance(member, bytes) else str(member)
            try:
                parsed = json.loads(raw)
            except ValueError:
                continue
            live.append(WeakSignal(kind=str(parsed.get("k")), detail=str(parsed.get("d")), at=float(parsed.get("t", at))))

        # Strength counts each *kind* once at its weight, plus a small
        # increment for repeats. Without that a vendor emitting the same
        # risk event forty times would outscore a genuine four-kind
        # sequence, which inverts exactly the judgement this exists to make.
        by_kind: dict[str, int] = {}
        for signal in live:
            by_kind[signal.kind] = by_kind.get(signal.kind, 0) + 1
        strength = sum(SIGNAL_WEIGHTS.get(kind, 0.0) * (1.0 + 0.1 * min(count - 1, 3)) for kind, count in by_kind.items())

        if strength < self._threshold or len(by_kind) < self._min_kinds:
            return None

        try:
            await self._redis.delete(key)
        except Exception as exc:  # noqa: BLE001
            logger.debug("weak_signals.reset_failed", error=str(exc))

        ordered = sorted(live, key=lambda s: s.at)
        return WeakFinding(
            subject=subject,
            subject_kind=subject_kind,
            strength=strength,
            severity=_severity_of(ordered),
            confidence=_confidence_of(strength, len(by_kind)),
            signals=ordered,
        )

    async def observe(self, tenant: str, event: dict[str, Any], *, now: float | None = None) -> list[WeakFinding]:
        """Extract this event's weak signals and accumulate them per subject.

        Session first, then principal. A session is the tighter subject and
        the one the plan calls canonical; the principal catches the case
        where the vendor states no session, which is most audit logs.
        """
        signals = extract_signals(event, now=now)
        if not signals:
            return []
        out: list[WeakFinding] = []
        session = event.get("session_id") or event.get("correlation_id")
        if isinstance(session, str) and session:
            finding = await self.accumulate(tenant, "session", session, signals, now=now)
            if finding is not None:
                out.append(finding)
        principal = event.get("actor_email") or event.get("actor") or event.get("user_name")
        if isinstance(principal, str) and principal:
            finding = await self.accumulate(tenant, "principal", principal.lower(), signals, now=now)
            if finding is not None:
                out.append(finding)
        return out
