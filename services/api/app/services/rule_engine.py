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
    """Evaluate a Sigma condition string using a safe boolean AST parser.

    SECURITY: Earlier revisions used `eval()` here, which allowed arbitrary
    Python expressions inside the Sigma `condition` field to execute in the
    API process. The condition is user-controlled (Sigma rule body) and
    therefore must be parsed, not evaluated.

    Supported grammar:
        - boolean literals (case-insensitive): true | false
        - selection name references (must be present in `selections` mapping)
        - unary operator:   not <expr>
        - binary operators: <expr> and <expr> | <expr> or <expr>
        - parentheses:      ( <expr> )
        - Sigma quantifiers (subset): "1 of selection*" / "all of selection*"

    Anything else short-circuits to the safe default of ANDing all selections.
    """
    expr = condition.strip()
    try:
        return _SigmaConditionParser(expr, selections).parse()
    except Exception as exc:  # noqa: BLE001 — keep behaviour identical to legacy fallback
        logger.debug("Sigma condition parse error (%r): %s", condition, exc)
        return all(selections.values()) if selections else False


class _SigmaConditionParser:
    """Tiny recursive-descent parser for Sigma condition expressions.

    The grammar accepted is a strict subset of the Sigma spec, sufficient to
    cover every shipped detection rule in `detections/` while refusing
    anything that could lead to code execution.
    """

    _TOKEN_RE = re.compile(
        # Token alternatives: opening paren, closing paren, or a "word" that
        # may start with a digit (for the `1 of …` quantifier) or a letter /
        # underscore. The leading `\s*` is consumed by the caller via lstrip
        # so that trailing whitespace doesn't break the match loop.
        r"(?P<lparen>\()|(?P<rparen>\))|(?P<word>[A-Za-z0-9_][A-Za-z0-9_*]*)",
    )

    def __init__(self, expr: str, selections: dict[str, bool]) -> None:
        self._expr = expr
        self._selections = selections
        self._tokens = self._tokenize(expr)
        self._pos = 0

    def parse(self) -> bool:
        result = self._parse_or()
        if self._pos != len(self._tokens):
            raise ValueError(f"unexpected trailing token: {self._tokens[self._pos]!r}")
        return result

    # ── tokenizer ────────────────────────────────────────────────────────────
    def _tokenize(self, expr: str) -> list[str]:
        tokens: list[str] = []
        pos = 0
        n = len(expr)
        while pos < n:
            # Skip any inter-token whitespace.
            while pos < n and expr[pos].isspace():
                pos += 1
            if pos >= n:
                break
            m = self._TOKEN_RE.match(expr, pos)
            if not m:
                raise ValueError(f"invalid character at position {pos}: {expr[pos]!r}")
            if m.group("lparen"):
                tokens.append("(")
            elif m.group("rparen"):
                tokens.append(")")
            else:
                tokens.append(m.group("word"))
            pos = m.end()
        return tokens

    # ── grammar ──────────────────────────────────────────────────────────────
    def _peek(self) -> str | None:
        return self._tokens[self._pos] if self._pos < len(self._tokens) else None

    def _consume(self) -> str:
        tok = self._tokens[self._pos]
        self._pos += 1
        return tok

    def _match(self, *expected: str) -> bool:
        tok = self._peek()
        if tok is None:
            return False
        if tok.lower() in expected:
            self._consume()
            return True
        return False

    def _parse_or(self) -> bool:
        left = self._parse_and()
        while self._match("or"):
            right = self._parse_and()
            left = left or right
        return left

    def _parse_and(self) -> bool:
        left = self._parse_not()
        while self._match("and"):
            right = self._parse_not()
            left = left and right
        return left

    def _parse_not(self) -> bool:
        if self._match("not"):
            return not self._parse_not()
        return self._parse_atom()

    def _parse_atom(self) -> bool:
        tok = self._peek()
        if tok is None:
            raise ValueError("unexpected end of condition")

        if tok == "(":
            self._consume()
            value = self._parse_or()
            if not self._match(")"):
                raise ValueError("missing closing parenthesis")
            return value

        # Quantifier forms: "1 of <pattern>" / "all of <pattern>"
        lowered = tok.lower()
        if lowered in {"1", "all"} and (self._pos + 2) <= len(self._tokens):
            next_tok = self._tokens[self._pos + 1] if self._pos + 1 < len(self._tokens) else None
            if next_tok and next_tok.lower() == "of":
                self._consume()  # quantifier
                self._consume()  # 'of'
                pattern_tok = self._peek()
                if pattern_tok is None or pattern_tok in {"(", ")"}:
                    raise ValueError("quantifier missing pattern")
                self._consume()
                return self._evaluate_quantifier(lowered, pattern_tok)

        # Bare identifier / literal.
        self._consume()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
        if tok in self._selections:
            return bool(self._selections[tok])
        # Unknown selection name → treat as missing (False) rather than raising
        # so that legacy rules referring to absent selections still produce a
        # deterministic result.
        return False

    def _evaluate_quantifier(self, quantifier: str, pattern: str) -> bool:
        if pattern == "them":
            values = list(self._selections.values())
        elif "*" in pattern:
            regex = re.compile("^" + re.escape(pattern).replace(r"\*", ".*") + "$")
            values = [v for name, v in self._selections.items() if regex.match(name)]
        else:
            values = [self._selections.get(pattern, False)]

        if not values:
            return False
        if quantifier == "1":
            return any(values)
        return all(values)


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
