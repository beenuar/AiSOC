"""
Auto-Triage Agent: LLM-based autonomous alert classification.

Uses structured LLM reasoning to classify alerts as true_positive,
benign_true_positive, false_positive, or benign — replacing simple keyword
heuristics with contextual analysis. The taxonomy separates detection validity
from activity maliciousness so a rule that correctly detects authorized
activity (an approved pen-test, a scheduled scan) is a benign_true_positive,
not a false_positive (see ``app.agents.dispositions``). High-confidence
FP / benign / benign_true_positive verdicts are auto-closed; true_positive and
needs_review escalate into the full triage → enrichment → investigation
pipeline.

Metrics (module-level counters) are exposed via the /triage/stats API.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

import structlog
from langchain_core.messages import HumanMessage, SystemMessage

from app.agents.dispositions import (
    AUTO_CLOSEABLE_DISPOSITIONS,
    BENIGN,
    BENIGN_TRUE_POSITIVE,
    FALSE_POSITIVE,
    LLM_VERDICTS,
    TRUE_POSITIVE,
    normalize_disposition,
)
from app.investigator.prompt_sanitizer import sanitize_text, wrap_untrusted
from app.llm import safe_ainvoke
from app.llm.factory import make_chat_model
from app.models.state import AgentStatus, InvestigationState
from app.prompt_serialization import format_extra_fields_for_llm
from app.prompting.envelope import make_nonce, scan_evidence_fields, system_rule

logger = structlog.get_logger()

AUTO_CLOSE_THRESHOLD: float = float(os.getenv("AISOC_AUTO_CLOSE_THRESHOLD", "0.85"))


class AutoTriageError(RuntimeError):
    """Raised when the LLM auto-triage call or its response parsing fails.

    Issue #571: the old code swallowed LLM/parse exceptions and returned a
    RUNNING state with a null verdict, so the worker's deterministic fallback
    (`_llm_triage`'s except branch) was unreachable and a null verdict could be
    recorded as "completed". Raising a typed error lets the caller fall back to
    deterministic triage or mark the alert ``needs_review`` — never null.
    """

_metrics: dict[str, Any] = {
    "auto_resolved_count": 0,
    "escalated_count": 0,
    "total_processed": 0,
    "confidence_sum": 0.0,
    "fp_count": 0,
    "benign_count": 0,
    "btp_count": 0,
    "tp_count": 0,
    "injection_demoted": 0,
}

_SYSTEM_PROMPT = """\
You are the Auto-Triage Agent of an AI Security Operations Centre.

Judge two INDEPENDENT questions, then pick one verdict:
  1. Detection validity — did the rule correctly detect its intended condition?
  2. Activity maliciousness — was the detected activity an actual threat?

Classify the alert into exactly one of these verdicts:

  • true_positive — a VALID detection of MALICIOUS or unauthorized activity
    that requires investigation and potential response.
  • benign_true_positive — a VALID detection of AUTHORIZED, expected, or
    otherwise non-malicious activity. The rule fired correctly, but the
    behaviour was sanctioned (e.g. a scheduled vulnerability scan, an approved
    penetration test, sanctioned admin/red-team tooling). This is NOT a false
    positive: the detection was right, so recording it as false_positive would
    unfairly penalize the rule and corrupt its false-positive-rate metric.
  • false_positive — an INVALID or noisy detection: the rule's intended
    condition was not actually present (misfire, bad signature, mis-parsed
    field). Only use this when the detection itself was wrong.
  • benign — real but non-threatening activity that is not a detection-validity
    statement (informational log, expected configuration change).
  • needs_review — insufficient evidence to decide safely; route to a human.

You MUST respond with a JSON object and nothing else:
{
  "verdict": "true_positive" | "benign_true_positive" | "false_positive" | "benign" | "needs_review",
  "confidence": <float 0.0–1.0>,
  "rationale": "<2-4 sentence explanation of your reasoning>"
}

Reasoning guidelines:
- Consider the severity, IOC presence, MITRE technique IDs, and alert context.
- Vendor risk_score > 0.7 with critical keywords strongly suggests true_positive.
- Scheduled scans and authorized penetration tests, when the rule correctly
  detected the behaviour, are benign_true_positive — NOT false_positive.
- Reserve false_positive for cases where the rule misfired or its intended
  detection condition was not actually present.
- Informational alerts with no IOCs and low risk lean benign.
- Be conservative: when uncertain, prefer true_positive or needs_review over
  auto-closing, to avoid missing threats.
- confidence should reflect how certain you are, not the severity of the threat.
"""


def get_metrics() -> dict[str, Any]:
    """Return a copy of current auto-triage metrics."""
    m = _metrics.copy()
    total = m["total_processed"]
    m["auto_resolution_rate"] = m["auto_resolved_count"] / total if total > 0 else 0.0
    m["fp_rate"] = m["fp_count"] / total if total > 0 else 0.0
    # Benign-true-positive rate is reported independently of fp_rate so a valid
    # detection of authorized activity never looks like a false positive.
    m["btp_rate"] = m.get("btp_count", 0) / total if total > 0 else 0.0
    m["avg_confidence"] = m["confidence_sum"] / total if total > 0 else 0.0
    return m


def get_threshold() -> float:
    """Return the current auto-close confidence threshold."""
    return AUTO_CLOSE_THRESHOLD


def set_threshold(value: float) -> float:
    """Update the auto-close confidence threshold. Returns the new value."""
    global AUTO_CLOSE_THRESHOLD  # noqa: PLW0603
    value = max(0.0, min(1.0, value))
    AUTO_CLOSE_THRESHOLD = value
    return AUTO_CLOSE_THRESHOLD


def _build_alert_context(state: InvestigationState) -> str:
    """Serialise the alert into a compact string the LLM can reason over."""
    raw = state.raw_alert
    parts = [
        f"Alert Summary: {sanitize_text(state.alert_summary)}",
        f"Severity (vendor): {sanitize_text(str(raw.get('severity', 'unknown')))}",
        f"Risk Score (vendor): {sanitize_text(str(raw.get('risk_score', 'N/A')))}",
    ]

    ioc_fields = {
        "src_ip": "Source IP",
        "dst_ip": "Destination IP",
        "domain": "Domain",
        "file_hash": "File Hash",
        "url": "URL",
        "hostname": "Hostname",
    }
    present_iocs = {label: sanitize_text(str(raw[key])) for key, label in ioc_fields.items() if raw.get(key)}
    if present_iocs:
        parts.append("IOCs present: " + ", ".join(f"{k}={v}" for k, v in present_iocs.items()))
    else:
        parts.append("IOCs present: none")

    techniques = raw.get("mitre_techniques", [])
    if techniques:
        parts.append(f"MITRE Techniques: {', '.join(sanitize_text(str(t)) for t in techniques)}")

    extra_keys = {k for k in raw if k not in {"severity", "risk_score", "mitre_techniques", *ioc_fields}}
    if extra_keys:
        extras = {k: raw[k] for k in sorted(extra_keys)[:10]}
        parts.append("Additional fields (summary, not raw JSON):\n" + format_extra_fields_for_llm(extras))

    return wrap_untrusted("\n".join(parts), label="alert_telemetry")


def _parse_llm_response(text: str) -> dict[str, Any]:
    """Extract the JSON verdict from the LLM response, tolerating markdown fences."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        lines = [line for line in lines if not line.strip().startswith("```")]
        cleaned = "\n".join(lines).strip()

    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("{")
        end = cleaned.rfind("}") + 1
        if start >= 0 and end > start:
            data = json.loads(cleaned[start:end])
        else:
            raise

    # Normalize to the canonical taxonomy (shared with the deterministic
    # fallback). ``benign_true_positive`` is a first-class outcome; an
    # unrecognised verdict fails safe to ``true_positive`` (never auto-closed).
    verdict = normalize_disposition(data.get("verdict"), default=TRUE_POSITIVE)
    if verdict not in LLM_VERDICTS:
        verdict = TRUE_POSITIVE

    confidence = float(data.get("confidence", 0.5))
    confidence = max(0.0, min(1.0, confidence))

    rationale = data.get("rationale", "No rationale provided by LLM.")

    return {
        "verdict": verdict,
        "confidence": confidence,
        "rationale": str(rationale),
    }


async def run_auto_triage(state: InvestigationState) -> InvestigationState:
    """
    LLM-based auto-triage: classify the alert and decide whether to
    auto-close (FP/benign with high confidence) or escalate.
    """
    logger.info("Auto-triage agent starting", incident_id=str(state.incident_id))

    state.status = AgentStatus.RUNNING
    state.iteration_count += 1

    # Prompt-injection guard: scan the untrusted alert evidence BEFORE reasoning
    # over it. A high-severity hit demotes the case to L0 (manual review) so the
    # agent can never be steered into auto-closing an alert whose own evidence
    # is trying to manipulate the model. Per-run nonce fences the instructions.
    raw = state.raw_alert or {}
    injection = scan_evidence_fields((str(k), v) for k, v in raw.items() if isinstance(v, str | int | float | list | dict))
    nonce = make_nonce()

    alert_context = _build_alert_context(state)

    llm = make_chat_model("triage", temperature=0.0, max_tokens=512)

    t0 = time.monotonic()
    try:
        response = await safe_ainvoke(
            llm,
            [
                SystemMessage(content=_SYSTEM_PROMPT + "\n\n" + system_rule(nonce)),
                HumanMessage(content=alert_context),
            ],
        )
        raw_text = response.content
        result = _parse_llm_response(raw_text)
    except Exception as exc:
        # Issue #571: do NOT swallow + return a null-verdict RUNNING state.
        # Raise a typed error so the caller falls back to deterministic triage
        # (or marks the alert needs_review) instead of completing with no verdict.
        logger.error("Auto-triage LLM call failed", error=str(exc))
        state.add_finding(f"Auto-triage LLM error: {exc}")
        _metrics["total_processed"] += 1
        raise AutoTriageError(str(exc)) from exc

    elapsed_ms = round((time.monotonic() - t0) * 1000)

    verdict = result["verdict"]
    confidence = result["confidence"]
    rationale = result["rationale"]

    _metrics["total_processed"] += 1
    _metrics["confidence_sum"] += confidence
    if verdict == FALSE_POSITIVE:
        _metrics["fp_count"] += 1
    elif verdict == BENIGN_TRUE_POSITIVE:
        # Benign true positive is a VALID detection — tracked separately so it
        # never inflates the false-positive rate (#526).
        _metrics["btp_count"] += 1
    elif verdict == BENIGN:
        _metrics["benign_count"] += 1
    else:
        _metrics["tp_count"] += 1

    state.confidence = confidence
    state.verdict = verdict
    state.confidence_basis = [
        f"LLM auto-triage verdict: {verdict}",
        f"LLM confidence: {confidence:.2f}",
        f"Rationale: {rationale}",
    ]

    state.add_finding(f"Auto-triage: verdict={verdict}, confidence={confidence:.2f}, latency={elapsed_ms}ms")
    state.add_finding(f"Auto-triage rationale: {rationale}")

    # Auto-close FP / benign / benign_true_positive (no active threat, no
    # response needed); true_positive and needs_review always escalate.
    should_auto_close = verdict in AUTO_CLOSEABLE_DISPOSITIONS and confidence >= AUTO_CLOSE_THRESHOLD

    # Prompt-injection L0 demotion: a high-severity injection signal always
    # blocks auto-close and routes to a human, regardless of the LLM's verdict.
    if injection.should_demote_to_l0:
        _metrics["injection_demoted"] += 1
        should_auto_close = False
        ledger = injection.as_ledger_dict()
        state.confidence_basis.append(f"prompt_injection={ledger.get('max_severity')} (auto-close blocked, demoted to L0)")
        state.add_finding("Prompt-injection detected in alert evidence — demoted to manual review (L0); auto-close blocked.")
        logger.warning(
            "auto_triage.prompt_injection_demoted",
            incident_id=str(state.incident_id),
            signals=len(injection.signals),
            max_severity=ledger.get("max_severity"),
        )

    if should_auto_close:
        _metrics["auto_resolved_count"] += 1
        state.status = AgentStatus.COMPLETED
        state.add_finding(f"Auto-closed as {verdict} (confidence {confidence:.2f} >= threshold {AUTO_CLOSE_THRESHOLD:.2f})")
        logger.info(
            "Auto-triage: auto-closed",
            verdict=verdict,
            confidence=round(confidence, 2),
            threshold=AUTO_CLOSE_THRESHOLD,
            incident_id=str(state.incident_id),
            elapsed_ms=elapsed_ms,
        )
    else:
        _metrics["escalated_count"] += 1
        state.add_finding(
            f"Escalating to full pipeline — "
            f"{'TP verdict' if verdict == 'true_positive' else f'confidence {confidence:.2f} < threshold {AUTO_CLOSE_THRESHOLD:.2f}'}"
        )
        logger.info(
            "Auto-triage: escalating",
            verdict=verdict,
            confidence=round(confidence, 2),
            threshold=AUTO_CLOSE_THRESHOLD,
            incident_id=str(state.incident_id),
            elapsed_ms=elapsed_ms,
        )

    return state
