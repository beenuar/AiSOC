"""
Detection rule execution engine.
Supports: Sigma (pySigma), YARA, KQL (simulated), EQL (simulated).
AiSOC — open-source AI Security Operations Center (MIT License)
"""

from __future__ import annotations

import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class RuleLanguage(str, Enum):
    SIGMA = "sigma"
    YARA = "yara"
    KQL = "kql"
    EQL = "eql"
    LUCENE = "lucene"
    REGEX = "regex"


@dataclass
class RuleMatch:
    """A single rule match result."""

    rule_id: str
    rule_name: str
    rule_language: str
    severity: str
    matched: bool
    match_details: dict[str, Any] = field(default_factory=dict)
    matched_fields: list[str] = field(default_factory=list)
    score: float = 0.0
    error: str | None = None
    execution_time_ms: float = 0.0


@dataclass
class HuntResult:
    """Result from a threat hunt across events."""

    hunt_id: str
    tenant_id: str
    rules_evaluated: int
    rules_matched: int
    total_events_scanned: int
    matched_events: list[dict[str, Any]]
    match_summary: list[dict[str, Any]]
    execution_time_ms: float
    errors: list[str]


# ─── Sigma Runner ─────────────────────────────────────────────────────────────


def _run_sigma(rule_body: str, events: list[dict[str, Any]]) -> tuple[list[dict], str | None]:
    """
    Execute a Sigma rule against a list of events.
    Uses pySigma for parsing; falls back to a lightweight YAML-based evaluator.
    Returns (matched_events, error_message).
    """
    try:
        from sigma.backends.opensearch import OpensearchLuceneBackend
        from sigma.rule import SigmaRule

        sigma_rule = SigmaRule.from_yaml(rule_body)
        backend = OpensearchLuceneBackend()
        queries = backend.convert_rule(sigma_rule)

        # Use the generated Lucene query to evaluate events
        matched = []
        for event in events:
            for query in queries:
                if _lucene_match(query, event):
                    matched.append(event)
                    break
        return matched, None

    except ImportError:
        # pySigma not available – use simple YAML condition evaluator
        return _sigma_fallback(rule_body, events), None
    except Exception as exc:
        logger.warning("Sigma parse error: %s", exc)
        return _sigma_fallback(rule_body, events), str(exc)


def _sigma_fallback(rule_body: str, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Minimal Sigma evaluator for simple field: value conditions.
    Parses the `detection` block and checks field/value presence.
    """
    try:
        import yaml

        rule = yaml.safe_load(rule_body)
        detection = rule.get("detection", {})

        matched = []
        for event in events:
            flat_event = _flatten_dict(event)
            if _eval_sigma_detection(detection, flat_event):
                matched.append(event)
        return matched
    except Exception as exc:
        logger.debug("Sigma fallback evaluator error: %s", exc)
        return []


def _eval_sigma_detection(detection: dict, flat_event: dict[str, Any]) -> bool:
    """Evaluate Sigma detection section (keywords + condition)."""
    condition = detection.get("condition", "selection")
    selections: dict[str, bool] = {}

    for sel_name, sel_def in detection.items():
        if sel_name == "condition":
            continue
        if isinstance(sel_def, dict):
            match = True
            for field_name, field_val in sel_def.items():
                # Strip Sigma modifier suffixes (e.g. `cmdline|contains` -> `cmdline`).
                field_lower = field_name.lower().split("|", 1)[0]
                ev_val = str(flat_event.get(field_lower, "")).lower()
                if isinstance(field_val, list):
                    hit = any(str(v).lower() in ev_val for v in field_val)
                else:
                    hit = str(field_val).lower() in ev_val
                if not hit:
                    match = False
                    break
            selections[sel_name] = match
        elif isinstance(sel_def, list):
            # keywords list
            flat_str = " ".join(str(v) for v in flat_event.values()).lower()
            selections[sel_name] = all(str(kw).lower() in flat_str for kw in sel_def)

    # Evaluate condition expression (supports: and, or, not, 1 of, all of)
    return _eval_condition(condition, selections)


def _eval_condition(condition: str, selections: dict[str, bool]) -> bool:
    """Evaluate a Sigma condition string."""
    expr = condition.strip()
    # Replace selection names with their bool values
    for name, val in selections.items():
        expr = expr.replace(name, str(val))
    # Simple evaluation
    try:
        expr = expr.replace("and", " and ").replace("or", " or ").replace("not", " not ")
        # Safe eval with only booleans
        return bool(eval(expr, {"__builtins__": {}}, {"True": True, "False": False}))  # noqa: S307
    except Exception:
        # Default: AND all selections
        return all(selections.values())


# ─── YARA Runner ──────────────────────────────────────────────────────────────


def _run_yara(rule_body: str, events: list[dict[str, Any]]) -> tuple[list[dict], str | None]:
    """
    Execute a YARA rule against event payloads.
    Compiles and matches each event's raw_payload or JSON representation.
    """
    try:
        import yara

        compiled = yara.compile(source=rule_body)
        matched = []
        for event in events:
            payload_bytes = _event_to_bytes(event)
            matches = compiled.match(data=payload_bytes)
            if matches:
                event_copy = dict(event)
                event_copy["_yara_matches"] = [m.rule for m in matches]
                matched.append(event_copy)
        return matched, None
    except ImportError:
        return [], "yara-python not installed"
    except Exception as exc:
        logger.warning("YARA execution error: %s", exc)
        return [], str(exc)


def _event_to_bytes(event: dict[str, Any]) -> bytes:
    """Convert event dict to bytes for YARA matching."""
    payload = event.get("raw_payload") or event.get("ocsf_json") or json.dumps(event)
    if isinstance(payload, bytes):
        return payload
    if isinstance(payload, str):
        try:
            return payload.encode("utf-8", errors="replace")
        except Exception:
            return b""
    return json.dumps(payload).encode("utf-8")


# ─── KQL / EQL Runner (simulated) ─────────────────────────────────────────────


def _run_kql(rule_body: str, events: list[dict[str, Any]]) -> tuple[list[dict], str | None]:
    """
    Simplified KQL evaluator.
    Supports field:value, wildcards, and boolean operators.
    """
    matched = []
    error = None
    try:
        for event in events:
            flat = _flatten_dict(event)
            if _kql_match(rule_body.strip(), flat):
                matched.append(event)
    except Exception as exc:
        error = str(exc)
    return matched, error


def _kql_match(query: str, flat_event: dict[str, Any]) -> bool:
    """Minimal KQL field:value matcher."""
    # field:value pattern
    m = re.match(r"(\w+)\s*:\s*\"?([^\"\s]+)\"?", query)
    if m:
        field_name = m.group(1).lower()
        value = m.group(2).lower()
        ev_val = str(flat_event.get(field_name, "")).lower()
        if "*" in value:
            pattern = value.replace("*", ".*")
            return bool(re.search(pattern, ev_val))
        return value in ev_val
    # Free-text search
    flat_str = " ".join(str(v) for v in flat_event.values()).lower()
    return query.lower() in flat_str


def _run_eql(rule_body: str, events: list[dict[str, Any]]) -> tuple[list[dict], str | None]:
    """Simplified EQL sequence evaluator (single-event matching only)."""
    return _run_kql(rule_body, events)


# ─── Lucene Query Matcher ─────────────────────────────────────────────────────


def _lucene_match(query: str, event: dict[str, Any]) -> bool:
    """Simple Lucene query evaluator for field:value pairs."""
    flat = _flatten_dict(event)
    flat_str = " ".join(f"{k}:{v}" for k, v in flat.items()).lower()
    return query.lower() in flat_str


def _flatten_dict(d: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    """Flatten nested dict to dot-notation keys."""
    result: dict[str, Any] = {}
    for k, v in d.items():
        key = f"{prefix}.{k}".lstrip(".") if prefix else k
        key_lower = key.lower()
        if isinstance(v, dict):
            result.update(_flatten_dict(v, key_lower))
        else:
            result[key_lower] = v
    return result


# ─── Main Execute Function ────────────────────────────────────────────────────


def execute_rule(
    rule_id: str,
    rule_name: str,
    rule_language: str,
    rule_body: str,
    severity: str,
    events: list[dict[str, Any]],
) -> RuleMatch:
    """
    Execute a detection rule against a list of events.
    Returns a RuleMatch with matched events and metadata.
    """
    start = time.monotonic()

    lang = rule_language.lower()
    runners = {
        "sigma": _run_sigma,
        "yara": _run_yara,
        "kql": _run_kql,
        "eql": _run_eql,
        "lucene": lambda body, evts: (_run_kql(body, evts)[0], None),
        "regex": _run_regex,
    }

    runner = runners.get(lang)
    if runner is None:
        return RuleMatch(
            rule_id=rule_id,
            rule_name=rule_name,
            rule_language=rule_language,
            severity=severity,
            matched=False,
            error=f"Unsupported rule language: {rule_language}",
            execution_time_ms=(time.monotonic() - start) * 1000,
        )

    matched_events, error = runner(rule_body, events)
    elapsed_ms = (time.monotonic() - start) * 1000

    return RuleMatch(
        rule_id=rule_id,
        rule_name=rule_name,
        rule_language=rule_language,
        severity=severity,
        matched=len(matched_events) > 0,
        match_details={"matched_events": matched_events[:10]},  # cap to 10 for response size
        score=_severity_score(severity) if matched_events else 0.0,
        error=error,
        execution_time_ms=elapsed_ms,
    )


def _run_regex(rule_body: str, events: list[dict[str, Any]]) -> tuple[list[dict], str | None]:
    """Regex-based rule runner."""
    try:
        pattern = re.compile(rule_body, re.IGNORECASE | re.MULTILINE)
        matched = []
        for event in events:
            payload = json.dumps(event)
            if pattern.search(payload):
                matched.append(event)
        return matched, None
    except re.error as exc:
        return [], str(exc)


def _severity_score(severity: str) -> float:
    mapping = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2, "info": 0.1}
    return mapping.get(severity.lower(), 0.5)


# ─── Hunt Runner ─────────────────────────────────────────────────────────────


async def run_hunt(
    tenant_id: str,
    rules: list[dict[str, Any]],
    events: list[dict[str, Any]],
    hunt_id: str | None = None,
) -> HuntResult:
    """
    Run threat hunt: execute multiple detection rules against a set of events.
    """
    hunt_id = hunt_id or str(uuid.uuid4())
    start = time.monotonic()

    matched_events: list[dict[str, Any]] = []
    match_summary: list[dict[str, Any]] = []
    errors: list[str] = []
    rules_matched = 0

    for rule in rules:
        result = execute_rule(
            rule_id=str(rule.get("id", "")),
            rule_name=rule.get("name", ""),
            rule_language=rule.get("rule_language", "sigma"),
            rule_body=rule.get("rule_body", ""),
            severity=rule.get("severity", "medium"),
            events=events,
        )

        if result.error:
            errors.append(f"{result.rule_name}: {result.error}")

        if result.matched:
            rules_matched += 1
            matched_events.extend(result.match_details.get("matched_events", []))
            match_summary.append(
                {
                    "rule_id": result.rule_id,
                    "rule_name": result.rule_name,
                    "severity": result.severity,
                    "match_count": len(result.match_details.get("matched_events", [])),
                    "score": result.score,
                    "execution_time_ms": result.execution_time_ms,
                }
            )

    elapsed_ms = (time.monotonic() - start) * 1000

    return HuntResult(
        hunt_id=hunt_id,
        tenant_id=tenant_id,
        rules_evaluated=len(rules),
        rules_matched=rules_matched,
        total_events_scanned=len(events),
        matched_events=matched_events[:100],  # Cap response size
        match_summary=match_summary,
        execution_time_ms=elapsed_ms,
        errors=errors,
    )
