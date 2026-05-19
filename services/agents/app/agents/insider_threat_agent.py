"""
Insider Threat Analysis Agent: investigates insider-threat indicators.

Analyses behavioural anomalies such as data exfiltration, off-hours access,
bulk downloads, privilege abuse, USB device usage, and communication to
personal accounts.  Uses structured LLM reasoning to classify the alert and
assign a confidence-weighted verdict.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

import structlog
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI

from app.context import ContextBundle
from app.llm import safe_ainvoke
from app.models.state import AgentStatus, InvestigationState
from app.prompt_serialization import format_extra_fields_for_llm, summarize_structure_for_llm

logger = structlog.get_logger()

_SYSTEM_PROMPT = """\
You are the Insider Threat Analysis Agent of an AI Security Operations Centre.

Given a security alert that may indicate insider-threat activity, perform a
thorough investigation and produce a structured assessment.

Evaluate the following behavioural patterns:
1. Data exfiltration — large file transfers, bulk downloads from sensitive
   repositories, unusually high print volumes, or mass email forwarding to
   external addresses.
2. Off-hours access — login or system activity during atypical hours for the
   user's baseline schedule.
3. Privilege abuse — accessing systems or data outside the user's role,
   creating unauthorised accounts, elevating own privileges, or disabling
   security controls.
4. Removable media / USB — USB mass storage device connections, especially on
   hosts where removable media is policy-prohibited.
5. Communication to personal accounts — sending corporate data to personal
   email (gmail, outlook, yahoo), personal cloud storage (Dropbox, Google
   Drive), or messaging apps.
6. Resignation / termination indicators — user is on notice period, recently
   received negative performance review, or has submitted resignation.

You MUST respond with a JSON object and nothing else:
{
  "verdict": "true_positive" | "false_positive" | "benign",
  "confidence": <float 0.0–1.0>,
  "threat_indicators": ["<indicator1>", "<indicator2>", ...],
  "threat_category": "data_exfiltration" | "off_hours_access" |
                     "privilege_abuse" | "removable_media" |
                     "personal_comms" | "flight_risk" | "unknown",
  "user_risk_level": "low" | "medium" | "high" | "critical",
  "rationale": "<2-4 sentence explanation>"
}
"""


def _build_insider_context(state: InvestigationState) -> str:
    """Serialise alert data into an insider-threat focused analysis prompt."""
    raw = state.raw_alert
    parts = [
        f"Alert Summary: {state.alert_summary}",
        f"Severity: {raw.get('severity', 'unknown')}",
    ]

    user_fields = {
        "username": "Username",
        "user_email": "User Email",
        "user_id": "User ID",
        "department": "Department",
        "job_title": "Job Title",
        "manager": "Manager",
        "employment_status": "Employment Status",
        "hire_date": "Hire Date",
    }
    for key, label in user_fields.items():
        if raw.get(key):
            parts.append(f"{label}: {raw[key]}")

    activity_fields = {
        "action": "Action",
        "resource": "Resource",
        "source_ip": "Source IP",
        "destination": "Destination",
        "file_name": "File Name",
        "file_size": "File Size",
        "file_count": "File Count",
        "device_type": "Device Type",
        "device_id": "Device ID",
    }
    for key, label in activity_fields.items():
        if raw.get(key):
            parts.append(f"{label}: {raw[key]}")

    if raw.get("access_time") or raw.get("timestamp"):
        parts.append(f"Access time: {raw.get('access_time') or raw.get('timestamp')}")

    if raw.get("normal_hours"):
        parts.append(f"Normal hours: {raw['normal_hours']}")

    if raw.get("data_volume_mb") or raw.get("bytes_transferred"):
        vol = raw.get("data_volume_mb") or raw.get("bytes_transferred")
        parts.append(f"Data volume: {vol}")

    if raw.get("destination_type"):
        parts.append(f"Destination type: {raw['destination_type']}")
    if raw.get("destination_domain"):
        parts.append(f"Destination domain: {raw['destination_domain']}")

    if raw.get("usb_events"):
        parts.append("USB events:\n" + summarize_structure_for_llm(raw["usb_events"], label="usb_events", max_lines=24, max_depth=2))

    if raw.get("recent_activity"):
        parts.append(
            "Recent activity:\n" + summarize_structure_for_llm(raw["recent_activity"], label="recent_activity", max_lines=24, max_depth=2)
        )

    if raw.get("baseline_deviation"):
        parts.append(f"Baseline deviation: {raw['baseline_deviation']}")

    extra_keys = {
        k
        for k in raw
        if k
        not in {
            "severity",
            "risk_score",
            *user_fields,
            *activity_fields,
            "access_time",
            "timestamp",
            "normal_hours",
            "data_volume_mb",
            "bytes_transferred",
            "destination_type",
            "destination_domain",
            "usb_events",
            "recent_activity",
            "baseline_deviation",
        }
    }
    if extra_keys:
        extras = {k: raw[k] for k in sorted(extra_keys)[:8]}
        parts.append("Additional fields:\n" + format_extra_fields_for_llm(extras, max_keys=8))

    return "\n".join(parts)


def _parse_response(text: str) -> dict[str, Any]:
    """Extract JSON verdict from LLM output."""
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

    verdict = data.get("verdict", "true_positive")
    if verdict not in ("true_positive", "false_positive", "benign"):
        verdict = "true_positive"

    confidence = max(0.0, min(1.0, float(data.get("confidence", 0.5))))
    indicators = data.get("threat_indicators", [])
    threat_category = data.get("threat_category", "unknown")
    user_risk = data.get("user_risk_level", "medium")
    if user_risk not in ("low", "medium", "high", "critical"):
        user_risk = "medium"
    rationale = str(data.get("rationale", "No rationale provided."))

    return {
        "verdict": verdict,
        "confidence": confidence,
        "threat_indicators": indicators,
        "threat_category": threat_category,
        "user_risk_level": user_risk,
        "rationale": rationale,
    }


async def run_insider_threat(
    state: InvestigationState,
    bundle: ContextBundle | None = None,
) -> InvestigationState:
    """Analyse an alert for insider-threat indicators.

    Accepts an optional :class:`ContextBundle` (T2.1) carrying pre-fetched
    entity neighbourhood, historical similar-case verdicts, UEBA deviation,
    and threat-intel matches. When supplied the bundle's safe summary
    fields are appended to the LLM prompt; the agent's own enrichment
    paths become *augmentations*, not primary discovery.

    Backward-compatible: when ``bundle`` is ``None`` the agent falls back
    to the prior bare-alert reasoning path.
    """
    logger.info("Insider threat agent starting", incident_id=str(state.incident_id))

    state.status = AgentStatus.RUNNING
    state.iteration_count += 1

    base_context = _build_insider_context(state)
    bundle_lines = bundle.prompt_context_lines() if bundle is not None else []
    prompt_context = base_context + (("\n" + "\n".join(bundle_lines)) if bundle_lines else "")

    model_name = os.getenv("AISOC_LLM_MODEL", "gpt-4o-mini")
    llm = ChatOpenAI(model=model_name, temperature=0.0, max_tokens=768)

    t0 = time.monotonic()
    try:
        response = await safe_ainvoke(
            llm,
            [
                SystemMessage(content=_SYSTEM_PROMPT),
                HumanMessage(content=prompt_context),
            ],
        )
        result = _parse_response(response.content)
    except Exception as exc:
        logger.error("Insider threat agent LLM call failed", error=str(exc))
        state.add_finding(f"Insider threat analysis LLM error: {exc}")
        return state

    elapsed_ms = round((time.monotonic() - t0) * 1000)

    verdict = result["verdict"]
    confidence = result["confidence"]
    indicators = result["threat_indicators"]
    threat_category = result["threat_category"]
    user_risk = result["user_risk_level"]
    rationale = result["rationale"]

    state.confidence = confidence
    state.verdict = verdict
    state.confidence_basis = [
        f"Insider threat verdict: {verdict}",
        f"Threat category: {threat_category}",
        f"User risk level: {user_risk}",
        f"Confidence: {confidence:.2f}",
        f"Indicators: {', '.join(indicators) if indicators else 'none'}",
        f"Rationale: {rationale}",
    ]

    state.add_finding(
        f"Insider threat analysis: verdict={verdict}, category={threat_category}, "
        f"user_risk={user_risk}, confidence={confidence:.2f}, "
        f"indicators={len(indicators)}, latency={elapsed_ms}ms"
    )
    if indicators:
        state.add_finding(f"Threat indicators: {', '.join(indicators)}")
    state.add_finding(f"Insider threat rationale: {rationale}")

    logger.info(
        "Insider threat analysis complete",
        verdict=verdict,
        threat_category=threat_category,
        user_risk_level=user_risk,
        confidence=round(confidence, 2),
        indicator_count=len(indicators),
        elapsed_ms=elapsed_ms,
        incident_id=str(state.incident_id),
    )
    return state
