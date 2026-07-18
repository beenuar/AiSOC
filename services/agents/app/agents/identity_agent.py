"""
Identity & Authentication Analysis Agent: investigates auth-related alerts.

Analyses impossible travel, credential stuffing, brute force, privilege
escalation, and suspicious login patterns.  Uses structured LLM reasoning
to classify the alert and assign a confidence-weighted verdict.
"""

from __future__ import annotations

import json
import time
from typing import Any

import structlog
from langchain_core.messages import HumanMessage, SystemMessage

from app.context import ContextBundle
from app.investigator.prompt_sanitizer import sanitize_text, wrap_untrusted
from app.llm import safe_ainvoke
from app.llm.factory import make_chat_model
from app.models.state import AgentStatus, InvestigationState
from app.prompt_serialization import format_extra_fields_for_llm, summarize_structure_for_llm

logger = structlog.get_logger()

_SYSTEM_PROMPT = """\
You are the Identity & Authentication Analysis Agent of an AI Security
Operations Centre.

Given a security alert related to identity, authentication, or access
control, perform a deep investigation and produce a structured assessment.

Evaluate the following patterns:
1. Impossible travel — two logins from geographically distant locations
   within a physically impossible time window.  Consider VPNs as possible
   benign explanations but still flag them.
2. Credential stuffing / password spraying — many failed login attempts
   across different accounts from the same source, or one account from
   many sources.
3. Brute force — repeated failed attempts on a single account within a
   short time window.
4. Privilege escalation — a user gaining admin rights, adding themselves
   to privileged groups, or accessing resources far beyond their normal
   scope.
5. Anomalous session behaviour — concurrent sessions from different
   devices, token replay, MFA bypass attempts.

You MUST respond with a JSON object and nothing else:
{
  "verdict": "true_positive" | "false_positive" | "benign",
  "confidence": <float 0.0–1.0>,
  "identity_indicators": ["<indicator1>", "<indicator2>", ...],
  "attack_type": "impossible_travel" | "credential_stuffing" | "brute_force" |
                 "privilege_escalation" | "session_anomaly" | "unknown",
  "rationale": "<2-4 sentence explanation>"
}
"""


def _build_identity_context(state: InvestigationState) -> str:
    """Serialise alert data into an identity-focused analysis prompt."""
    raw = state.raw_alert
    parts = [
        f"Alert Summary: {sanitize_text(state.alert_summary)}",
        f"Severity: {sanitize_text(str(raw.get('severity', 'unknown')))}",
    ]

    identity_fields = {
        "user": "User",
        "username": "Username",
        "user_email": "User Email",
        "source_ip": "Source IP",
        "source_geo": "Source Geo",
        "dest_ip": "Destination IP",
        "dest_geo": "Destination Geo",
        "device": "Device",
        "user_agent": "User Agent",
        "auth_method": "Auth Method",
        "mfa_status": "MFA Status",
    }
    for key, label in identity_fields.items():
        if raw.get(key):
            parts.append(f"{label}: {sanitize_text(str(raw[key]))}")

    if raw.get("login_attempts"):
        parts.append(
            "Login attempts:\n" + summarize_structure_for_llm(raw["login_attempts"], label="login_attempts", max_lines=24, max_depth=2)
        )
    if raw.get("failed_count"):
        parts.append(f"Failed attempt count: {raw['failed_count']}")

    geo_fields = ["login_locations", "geo_locations"]
    for gf in geo_fields:
        if raw.get(gf):
            parts.append(f"Geo locations ({gf}):\n" + summarize_structure_for_llm(raw[gf], label=gf, max_lines=20, max_depth=2))

    priv_fields = ["role_change", "group_added", "permissions_changed", "privilege_level"]
    priv_parts = []
    for pf in priv_fields:
        if raw.get(pf):
            priv_parts.append(f"{pf}={raw[pf]}")
    if priv_parts:
        parts.append(f"Privilege changes: {', '.join(priv_parts)}")

    if raw.get("timestamp"):
        parts.append(f"Event time: {raw['timestamp']}")
    if raw.get("previous_login"):
        parts.append(
            "Previous login:\n" + summarize_structure_for_llm(raw["previous_login"], label="previous_login", max_lines=16, max_depth=2)
        )

    extra_keys = {
        k
        for k in raw
        if k
        not in {
            "severity",
            "risk_score",
            *identity_fields,
            "login_attempts",
            "failed_count",
            *geo_fields,
            *priv_fields,
            "timestamp",
            "previous_login",
        }
    }
    if extra_keys:
        extras = {k: raw[k] for k in sorted(extra_keys)[:8]}
        parts.append("Additional fields:\n" + format_extra_fields_for_llm(extras, max_keys=8))

    return wrap_untrusted("\n".join(parts), label="identity_telemetry")


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
    indicators = data.get("identity_indicators", [])
    attack_type = data.get("attack_type", "unknown")
    rationale = str(data.get("rationale", "No rationale provided."))

    return {
        "verdict": verdict,
        "confidence": confidence,
        "identity_indicators": indicators,
        "attack_type": attack_type,
        "rationale": rationale,
    }


async def run_identity(
    state: InvestigationState,
    bundle: ContextBundle | None = None,
) -> InvestigationState:
    """Analyse an identity/authentication alert for compromise indicators.

    Accepts an optional :class:`ContextBundle` (T2.1) carrying pre-fetched
    entity neighbourhood, historical similar-case verdicts, UEBA deviation
    (peer-baseline cosine distance), and threat-intel matches. When supplied
    the bundle's safe summary fields are appended to the LLM prompt; the
    agent's own enrichment paths become *augmentations*, not primary
    discovery.

    Backward-compatible: when ``bundle`` is ``None`` the agent falls back
    to the prior bare-alert reasoning path.
    """
    logger.info("Identity agent starting", incident_id=str(state.incident_id))

    state.status = AgentStatus.RUNNING
    state.iteration_count += 1

    base_context = _build_identity_context(state)
    bundle_lines = bundle.prompt_context_lines() if bundle is not None else []
    prompt_context = base_context + (("\n" + "\n".join(bundle_lines)) if bundle_lines else "")

    llm = make_chat_model("investigation", temperature=0.0, max_tokens=768)

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
        logger.error("Identity agent LLM call failed", error=str(exc))
        state.add_finding(f"Identity analysis LLM error: {exc}")
        return state

    elapsed_ms = round((time.monotonic() - t0) * 1000)

    verdict = result["verdict"]
    confidence = result["confidence"]
    indicators = result["identity_indicators"]
    attack_type = result["attack_type"]
    rationale = result["rationale"]

    state.confidence = confidence
    state.verdict = verdict
    state.confidence_basis = [
        f"Identity analysis verdict: {verdict}",
        f"Attack type: {attack_type}",
        f"Confidence: {confidence:.2f}",
        f"Indicators: {', '.join(indicators) if indicators else 'none'}",
        f"Rationale: {rationale}",
    ]

    state.add_finding(
        f"Identity analysis: verdict={verdict}, attack_type={attack_type}, "
        f"confidence={confidence:.2f}, indicators={len(indicators)}, "
        f"latency={elapsed_ms}ms"
    )
    if indicators:
        state.add_finding(f"Identity indicators: {', '.join(indicators)}")
    state.add_finding(f"Identity rationale: {rationale}")

    logger.info(
        "Identity analysis complete",
        verdict=verdict,
        attack_type=attack_type,
        confidence=round(confidence, 2),
        indicator_count=len(indicators),
        elapsed_ms=elapsed_ms,
        incident_id=str(state.incident_id),
    )
    return state
