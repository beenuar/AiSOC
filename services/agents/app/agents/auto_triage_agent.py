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

Metrics are module-level counters. **No route exposes them**: the
``/triage/stats`` endpoint this used to name has never existed in the tree.
They are read in-process and by tests.
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any

import structlog
from langchain_core.messages import HumanMessage, SystemMessage

from app import closure as closure_policy
from app.agents.dispositions import (
    AUTO_CLOSEABLE_DISPOSITIONS,
    BENIGN,
    BENIGN_TRUE_POSITIVE,
    FALSE_POSITIVE,
    LLM_VERDICTS,
    TRUE_POSITIVE,
    normalize_disposition,
)
from app.closure.qa_sampling import ClosureQaSampler
from app.context.dispositions import basis as disposition_basis
from app.context.dispositions import render_for_prompt as render_dispositions
from app.context.identity import basis as identity_basis
from app.context.identity import render_for_prompt as render_identity
from app.context.knowledge_base import citation_basis, unresolvable_citations
from app.context.knowledge_base import render_for_prompt as render_runbooks
from app.context.organisation_memory import render_for_prompt
from app.investigator.prompt_sanitizer import sanitize_text, wrap_untrusted
from app.llm import safe_ainvoke
from app.llm.factory import make_chat_model
from app.llm.prompt_registry import prompt_text
from app.llm.structured_output import extract_json_block
from app.models.state import AgentStatus, InvestigationState
from app.prompt_serialization import format_extra_fields_for_llm
from app.prompting.envelope import make_nonce, scan_evidence_fields, system_rule
from app.prompting.tool_results import unverified_tool_claims

logger = structlog.get_logger()

AUTO_CLOSE_THRESHOLD: float = float(os.getenv("AISOC_AUTO_CLOSE_THRESHOLD", "0.85"))

#: Ceiling on the tenant-skill block in the triage prompt. The API caps each
#: field at authoring time; this is the floor under a body written before
#: those caps existed, and under a skill whose individually-legal fields sum
#: to more prompt than the evidence gets.
_MAX_SKILL_PROMPT_CHARS = 4000

#: Ceiling on each first-party context block. Every renderer caps its own
#: fields; this is the ceiling on the assembled block, and it exists because
#: the default `sanitize_text` cap of 2000 would silently cut five analyst
#: decisions mid-sentence. A truncated list of decisions reads to the model
#: like a complete one.
_MAX_CONTEXT_BLOCK_CHARS = 3000


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
    # Phase 6.3. A rationale citing a runbook marker no retrieved chunk
    # carries. Counted rather than only logged: this is the one hallucination
    # the groundedness scorer cannot see, because a marker is not an indicator
    # and would never appear in the evidence text it checks against.
    "kb_citations_unresolvable": 0,
    # Depth plan 1.3. A rationale crediting one of this agent's tools with a
    # result, on a path that called no tool. Counted beside the unresolvable
    # citation it is the sibling of: both are a claim whose provenance resolves
    # to nothing, and both block auto-close.
    "ungrounded_tool_claims": 0,
}


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


def _alert_class_of(state: InvestigationState) -> str | None:
    """The class a closure policy row keys on.

    Prefers the explicit category the fused alert carries; falls back to the
    detection rule's category, which is what the shadow-mode grants are
    scoped by, so a grant and a policy row agree on what "this class" means.
    """
    for attribute in ("alert_class", "category", "alert_category"):
        value = getattr(state, attribute, None)
        if isinstance(value, str) and value.strip():
            return value.strip()
    raw = getattr(state, "raw_alert", None) or {}
    if isinstance(raw, dict):
        for key in ("alert_class", "category", "rule_category"):
            value = raw.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


def get_threshold() -> float:
    """Return the current auto-close confidence threshold."""
    return AUTO_CLOSE_THRESHOLD


def set_threshold(value: float) -> float:
    """Update the auto-close confidence threshold. Returns the new value."""
    global AUTO_CLOSE_THRESHOLD  # noqa: PLW0603
    value = max(0.0, min(1.0, value))
    AUTO_CLOSE_THRESHOLD = value
    return AUTO_CLOSE_THRESHOLD


def _build_alert_context(state: InvestigationState, *, nonce: str) -> str:
    """Serialise the alert into a compact string the LLM can reason over.

    ``state.organisation_memory`` is prepended, outside the untrusted-evidence
    fence, because it is not evidence: it is the tenant's own compiled record
    of what analysts have repeatedly said is normal here. It is still
    sanitised and length-capped — the statements interpolate alert-derived
    values like a process name, so they are tenant-authored but not
    operator-typed.

    ``state.tenant_skill`` sits beside it on the same reasoning and with the
    same treatment. It is typed into the console by a user holding
    ``settings:write``, which is the same trust class, and it is capped for
    the reason that applies regardless of trust: the prompt budget is shared
    with the evidence the verdict is supposed to rest on. The block the
    resolver rendered is used verbatim rather than re-rendered here, so the
    text that steered the verdict is the text the provenance record names.

    ``state.knowledge_base`` is the one that does **not** sit beside them, and
    that is the whole reason this function now takes a nonce. A runbook is
    long, frequently imported in bulk, edited by more people than a skill, and
    routinely quotes attacker output verbatim while doing its job. So it goes
    inside a nonce fence of its own, with the boundary sentence stated inline,
    exactly as an MCP reply does. See ``app.context.knowledge_base``.
    """
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

    telemetry = wrap_untrusted("\n".join(parts), label="alert_telemetry")

    preamble: list[str] = []
    skill = state.tenant_skill or {}
    skill_guidance = str(skill.get("triage_guidance") or "").strip()
    if skill_guidance:
        preamble.append(sanitize_text(skill_guidance)[:_MAX_SKILL_PROMPT_CHARS])
    memory = render_for_prompt(state.organisation_memory)
    if memory:
        preamble.append(sanitize_text(memory))

    # Both first-party, so both sit in the preamble beside organisation memory
    # rather than inside the fence. A disposition and a reason code come from
    # a closed server-owned vocabulary and the note is typed by an
    # authenticated analyst; a directory record comes from the tenant's own
    # import. Each renderer sanitises and caps its own fields, and
    # `sanitize_text` here is the second pass the memory block already gets.
    decisions = render_dispositions(state.recent_dispositions)
    if decisions:
        preamble.append(sanitize_text(decisions, max_len=_MAX_CONTEXT_BLOCK_CHARS))
    who = render_identity(state.identity_context)
    if who:
        preamble.append(sanitize_text(who, max_len=_MAX_CONTEXT_BLOCK_CHARS))

    # Not sanitised again on the way in: the retrieval already capped and
    # sanitised each chunk, and `render_runbooks` fences the result. Running
    # `sanitize_text` over the rendered block would rewrite the nonce markers
    # it just placed, which is the one thing holding the fence together.
    runbooks = render_runbooks(state.knowledge_base, nonce=nonce)

    if not preamble and not runbooks:
        return telemetry
    return "\n\n".join([*preamble, *([runbooks] if runbooks else []), telemetry])


def _close_truncated_json(fragment: str) -> str:
    """Close an object the model started and did not finish.

    Small local models stop mid-object more or less routinely — with
    ``finish_reason: "stop"``, not a token limit, so there is nothing to raise
    by giving them more room. Measured against the model CORE ships
    (``llama3.2:3b-instruct-q4_K_M``), a triage response arrived as::

        {
          "verdict": "true_positive",
          "confidence": 0.8,
          "rationale": "…uncertainty remains due to the lack of IOCs.

    with the closing quote and brace simply absent. Every field the caller
    reads was present and correct; the response was discarded and the alert
    fell through to deterministic triage.

    This closes any open string and any unclosed brackets, and does nothing
    else. It cannot invent a field: a fragment that never reached ``verdict``
    still parses to an object without one, and the caller's
    ``normalize_disposition(..., default=TRUE_POSITIVE)`` fails safe to the
    conservative verdict exactly as it does for a malformed response today.
    """
    in_string = False
    escaped = False
    stack: list[str] = []
    for ch in fragment:
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_string:
            escaped = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch in "{[":
            stack.append("}" if ch == "{" else "]")
        elif ch in "}]" and stack:
            stack.pop()

    repaired = fragment
    if in_string:
        # Drop a dangling escape before closing, or the quote is consumed by it.
        if escaped:
            repaired = repaired[:-1]
        repaired += '"'
    # A trailing comma or bare key left by the cut is not recoverable; strip it.
    repaired = re.sub(r",\s*$", "", repaired)
    return repaired + "".join(reversed(stack))


_NEUTRAL_CONFIDENCE = 0.5


def _coerce_confidence(value: Any) -> float:
    """Read a confidence, and never discard a verdict over this field alone.

    ``float(value)`` was unguarded here. A model answering ``"confidence":
    "high"`` raised ``ValueError``, which the caller turns into an
    ``AutoTriageError``, throwing away a verdict and rationale that may have
    been perfectly good because one field of three was the wrong type.

    Not observed in the 70 measured calls behind this change — the failures
    there were all malformed ``rationale`` — but it is reachable by any model
    on any alert, and the cost of it firing is a fallback nobody can explain.

    Degrading to a neutral value is safe *here* specifically because confidence
    is a gate, not a verdict: ``run_auto_triage`` auto-closes only when
    ``confidence >= AUTO_CLOSE_THRESHOLD``, which defaults to 0.85, so 0.5
    routes to a human. An operator who lowers that below the neutral value is
    choosing to auto-close on an unread field, which is why this returns the
    neutral constant rather than 0.0 — a deployment that trusts everything
    should not be handed a number that also fails every other comparison.
    It is the verdict itself that must never be guessed, and that still fails
    closed through ``normalize_disposition``.
    """
    if isinstance(value, bool):  # bool is an int; "confidence": true means nothing
        return _NEUTRAL_CONFIDENCE
    if isinstance(value, int | float):
        return max(0.0, min(1.0, float(value)))
    if isinstance(value, str):
        text = value.strip().rstrip("%")
        try:
            number = float(text)
        except ValueError:
            return _NEUTRAL_CONFIDENCE
        # "85%" and "85" both mean 0.85; a bare 0.85 already does.
        if number > 1.0:
            number /= 100.0
        return max(0.0, min(1.0, number))
    return _NEUTRAL_CONFIDENCE


def _parse_llm_response(text: str) -> dict[str, Any]:
    """Extract the JSON verdict from the LLM response, tolerating markdown fences.

    Extraction is shared with every other caller through
    ``app.llm.structured_output.extract_json_block``: fences, and prose on
    either side of the body. What stays here is the part that is specific to a
    triage verdict — the taxonomy, the confidence gate, and the one repair
    below. Extraction is a property of LLM replies; a verdict is not.
    """
    cleaned = extract_json_block(text)

    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("{")
        end = cleaned.rfind("}") + 1
        if start >= 0 and end > start:
            data = json.loads(cleaned[start:end])
        elif start >= 0:
            # An object was opened and never closed. Repair once, then give up
            # and let the caller fall back to deterministic triage.
            data = json.loads(_close_truncated_json(cleaned[start:]))
        else:
            raise

    # Normalize to the canonical taxonomy (shared with the deterministic
    # fallback). ``benign_true_positive`` is a first-class outcome; an
    # unrecognised verdict fails safe to ``true_positive`` (never auto-closed).
    verdict = normalize_disposition(data.get("verdict"), default=TRUE_POSITIVE)
    if verdict not in LLM_VERDICTS:
        verdict = TRUE_POSITIVE

    confidence = _coerce_confidence(data.get("confidence"))

    rationale = data.get("rationale", "No rationale provided by LLM.")

    return {
        "verdict": verdict,
        "confidence": confidence,
        "rationale": str(rationale),
    }


async def _sample_for_qa(state: InvestigationState, *, verdict: str, confidence: float) -> None:
    """Record this closure for review, if it falls in the sample."""
    tenant_id = str(getattr(state, "tenant_id", "") or "")
    alert_id = str(getattr(state, "incident_id", "") or "")
    if not tenant_id or not alert_id:
        return
    try:
        sampler = ClosureQaSampler(await closure_policy.shared_pool())
        decision = await sampler.record(
            tenant_id=tenant_id,
            alert_id=alert_id,
            alert_class=_alert_class_of(state),
            disposition=verdict,
            confidence=confidence,
        )
        if decision.sampled:
            state.add_finding(f"Selected for closure QA review: an analyst will score this auto-closure (sample rate {decision.rate:.0%}).")
    except Exception as exc:  # noqa: BLE001
        logger.warning("auto_triage.qa_sample_failed", error=str(exc), incident_id=alert_id)


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

    alert_context = _build_alert_context(state, nonce=nonce)

    t0 = time.monotonic()
    try:
        # Inside the try: "the model could not be built" and "the call failed"
        # are the same condition to every caller, and only one of them used to
        # become an AutoTriageError. An unroutable gateway alias raises here,
        # and auto_triage_node catches AutoTriageError specifically — so
        # constructing outside would have failed the whole graph run over a
        # configuration problem the deterministic path handles fine.
        llm = make_chat_model("triage", temperature=0.0, max_tokens=512, json_output=True)
        system_prompt = prompt_text("triage.system") + "\n\n" + system_rule(nonce)
        response = await safe_ainvoke(
            llm,
            [
                SystemMessage(content=system_prompt),
                HumanMessage(content=alert_context),
            ],
        )
        raw_text = response.content
        # Recorded before parsing, so a verdict that fails to parse still
        # leaves behind what the model was asked and what it said. The
        # ledger carries this onto the run (issue #1276): auto-triage is
        # the path that handles every fused alert, and it was the one
        # path whose decisions could not be replayed.
        state.record_llm_exchange(
            agent="auto_triage",
            purpose="triage.classify",
            model=getattr(llm, "model_name", None) or getattr(llm, "model", None),
            prompt=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": alert_context},
            ],
            response=str(raw_text),
            duration_ms=round((time.monotonic() - t0) * 1000),
        )
        result = _parse_llm_response(raw_text)
    except Exception as exc:
        # Issue #571: do NOT swallow + return a null-verdict RUNNING state.
        # Raise a typed error so the caller falls back to deterministic triage
        # (or marks the alert needs_review) instead of completing with no verdict.
        #
        # The response excerpt is logged with it. A parse failure whose message
        # is a character offset into text nobody kept is not diagnosable: the
        # only way to find out what a model actually emitted was to reproduce
        # the prompt by hand against the gateway. Bounded at 400 characters,
        # and it is the model's own words about an alert this service already
        # logs the summary of.
        excerpt = str(locals().get("raw_text") or "")[:400].replace("\n", "\\n")
        logger.error("Auto-triage LLM call failed", error=str(exc), response_excerpt=excerpt)
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
    # Which version of which skill was in the prompt that produced this
    # verdict. On the basis rather than only in a log line, because this is
    # the field a disputed auto-close is explained from, and a log line is
    # gone long before the dispute arrives.
    skill_ref = str((state.tenant_skill or {}).get("ref") or "")
    if skill_ref:
        owner = str((state.tenant_skill or {}).get("owner") or "unrecorded")
        state.confidence_basis.append(f"Tenant skill applied: {skill_ref} (owner: {owner})")

    # Which runbook chunks the prompt carried, by the markers the rationale
    # cites. Recorded on the basis for the same reason the skill reference is:
    # a citation whose target nobody can find is not a citation, and the
    # retrieval that produced it is cached and gone by the time anyone asks.
    state.confidence_basis.extend(citation_basis(state.knowledge_base))
    state.confidence_basis.extend(disposition_basis(state.recent_dispositions))
    state.confidence_basis.extend(identity_basis(state.identity_context))
    unresolvable = unresolvable_citations(rationale, state.knowledge_base)
    if unresolvable:
        # The model cited a runbook that was never retrieved. Named rather
        # than left in the rationale looking like the others, because a marker
        # that resolves to nothing is indistinguishable from one that resolves
        # until somebody goes looking for the document.
        state.confidence_basis.append(f"Knowledge base: the rationale cites {', '.join(unresolvable)}, which no retrieved chunk carries")
        _metrics["kb_citations_unresolvable"] += 1
        logger.warning(
            "auto_triage.unresolvable_kb_citation",
            incident_id=str(state.incident_id),
            cited=unresolvable,
        )

    # Depth plan 1.3, third leg. A rationale crediting a tool with a result it
    # never returned, which is the same defect as citing a runbook nobody
    # retrieved and as asserting an indicator the evidence does not contain —
    # a claim whose provenance resolves to nothing.
    #
    # `called_tools` is empty and that is the point rather than a shortcut:
    # this path is a single `safe_ainvoke` with no tool channel, so the
    # Investigation Ledger holds no `tool_call` row for this run and can hold
    # none. Every tool result in this rationale therefore came from the
    # evidence or from the model, and in both cases the verdict is resting on
    # something that did not happen.
    fabricated_tools = unverified_tool_claims(rationale, called_tools=())

    state.add_finding(f"Auto-triage: verdict={verdict}, confidence={confidence:.2f}, latency={elapsed_ms}ms")
    state.add_finding(f"Auto-triage rationale: {rationale}")

    # Auto-close FP / benign / benign_true_positive (no active threat, no
    # response needed); true_positive and needs_review always escalate.
    #
    # The threshold comes from the tenant's closure policy rather than the
    # process-wide env var. Additive: a tenant with no policy row gets
    # `AUTO_CLOSE_THRESHOLD` exactly as before. The policy also consults the
    # earned `auto_close` grant, which until now had no reader at all, and
    # the kill switch, which refuses closure outright.
    closure = await closure_policy.decide(
        tenant_id=str(state.tenant_id) if getattr(state, "tenant_id", None) else None,
        alert_class=_alert_class_of(state),
        confidence=confidence,
        default_threshold=AUTO_CLOSE_THRESHOLD,
    )
    should_auto_close = verdict in AUTO_CLOSEABLE_DISPOSITIONS and closure.allowed

    if verdict in AUTO_CLOSEABLE_DISPOSITIONS and not closure.allowed:
        # Say why. An operator asking "why was this not closed" gets an
        # answer rather than an alert that silently stayed open.
        state.add_finding(f"Auto-close withheld: {closure.reason}")
        state.confidence_basis.append(f"closure_policy={closure.source}")

    if fabricated_tools:
        _metrics["ungrounded_tool_claims"] += 1
        should_auto_close = False
        named = ", ".join(fabricated_tools[:5])
        state.confidence_basis.append(f"Tool provenance: the rationale credits {named} with a result, and this triage called no tool")
        state.add_finding(
            f"Auto-close blocked: the rationale rests on output attributed to {named}, "
            "which this triage never called — there is no tool_call row for it. Routed to manual review."
        )
        logger.warning(
            "auto_triage.unverified_tool_claim",
            incident_id=str(state.incident_id),
            claimed=fabricated_tools[:10],
        )

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
        # Parity 3.5. A fraction of closures goes to an analyst, so there
        # is a measured closure accuracy on the tenant's own data rather
        # than only a synthetic-corpus grade and a count of how many were
        # closed. Best-effort: a sampling failure must not stop a closure
        # the policy allowed.
        await _sample_for_qa(state, verdict=verdict, confidence=confidence)
        state.add_finding(f"Auto-closed as {verdict} (confidence {confidence:.2f} >= threshold {closure.threshold:.2f}, {closure.source})")
        logger.info(
            "Auto-triage: auto-closed",
            verdict=verdict,
            confidence=round(confidence, 2),
            threshold=closure.threshold,
            threshold_source=closure.source,
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
            threshold=closure.threshold,
            threshold_source=closure.source,
            incident_id=str(state.incident_id),
            elapsed_ms=elapsed_ms,
        )

    return state
