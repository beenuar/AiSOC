"""
Router LangGraph topology — T2.2 (v8.0).

Topology
========

::

    START ──► auto_triage ──► classify ──► fan_out ──► join ──► responder ──► END
                                            │  ▲
                                            │  │ asyncio.gather over the
                                            │  │ four TriageCapability
                                            │  │ runners that the classifier
                                            │  │ triggered for this alert
                                            ▼  │
                                  (phishing | identity | cloud | insider)

The router does **not** mutate the existing investigator pipeline at
``app.investigator.orchestrator``; it lives next to it and is wired in by
the v8.0 router surface (T2.2). The sequential reference path matches the
v8.0 plan exactly:

    auto_triage → phishing → identity → cloud → insider → responder

so test suites can compare wall-clock between the two modes with the
same inputs and the same mocked sub-agents.

Feature flag
============

``AISOC_AGENT_PARALLEL_TOPOLOGY`` (env). Defaults to **on** for dev / CI;
flip it off in production until the eval scoreboard confirms green:

    - ``1`` / ``true`` / ``on``  → parallel fan-out (new behaviour)
    - ``0`` / ``false`` / ``off`` → sequential reference path
    - unset                      → parallel (the v8.0 default)

The selection is read on every ``RouterOrchestrator.run()`` call so an
operator can toggle the topology without restarting the service.

Substrate determinism
=====================

The runtime is fully async + tool-driven; the only non-deterministic surface
is the underlying LLM. Tests mock the four ``run_*`` runners directly, so
the topology itself stays deterministic and the wall-clock observed in
``test_orchestrator_parallel.py`` / ``test_latency.py`` reflects the
fan-out shape, not LLM variance.
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import datetime
from typing import Any

import structlog

from app.models.state import AgentStatus, InvestigationState

logger = structlog.get_logger()

PARALLEL_TOPOLOGY_FLAG = "AISOC_AGENT_PARALLEL_TOPOLOGY"

# Lazy imports of the four sub-agent runners so this module can be imported
# at app startup even before the heavyweight LLM dependencies are wired.
_SubAgentRunner = Callable[[InvestigationState], Awaitable[InvestigationState]]


def is_parallel_topology_enabled() -> bool:
    """Return True if the router should fan out, False to run sequentially.

    Read on every router invocation so the topology can be flipped without
    restarting the agents service. Default ``on``; explicit ``0`` /
    ``false`` / ``no`` / ``off`` (case-insensitive) selects the sequential
    reference path.
    """
    raw = os.getenv(PARALLEL_TOPOLOGY_FLAG)
    if raw is None:
        return True
    return raw.strip().lower() not in {"0", "false", "no", "off", "disabled"}


# ---------------------------------------------------------------------------
# Signal classification — picks which sub-agents to fan out to
# ---------------------------------------------------------------------------

# Keyword bags per capability. Deliberately small + readable; the auto-triage
# agent's LLM already produced a verdict + rationale by the time we reach the
# classifier, so this is a cheap signal-routing step, not a primary classifier.
_PHISHING_KEYWORDS = {
    "phishing",
    "phish",
    "email",
    "macro",
    "attachment",
    "spear",
    "url",
    "sender",
    "smtp",
    "imap",
    "exchange",
    "outlook",
    "bec",
    "credential harvest",
}
_IDENTITY_KEYWORDS = {
    "login",
    "auth",
    "authentication",
    "credential",
    "credentials",
    "password",
    "mfa",
    "saml",
    "okta",
    "azure ad",
    "kerberos",
    "kerberoasting",
    "dcsync",
    "lateral",
    "lateral movement",
    "pass-the-hash",
    "pth",
    "impossible travel",
    "vpn",
    "session",
    "token",
    "oauth",
    "consent",
}
_CLOUD_KEYWORDS = {
    "aws",
    "azure",
    "gcp",
    "oracle",
    "oci",
    "s3",
    "ec2",
    "iam",
    "imds",
    "rds",
    "lambda",
    "bucket",
    "kms",
    "vpc",
    "security group",
    "cloudtrail",
    "guardduty",
    "blob",
    "gcs",
    "kubernetes",
    "k8s",
    "container",
    "docker",
    "image",
    "registry",
}
_INSIDER_KEYWORDS = {
    "exfil",
    "exfiltration",
    "insider",
    "off-hours",
    "personal",
    "personal email",
    "personal drive",
    "usb",
    "removable",
    "mailbox export",
    "auto-forward",
    "bulk download",
    "data exfiltration",
    "termination",
    "resignation",
    "flight risk",
}

_PHISHING_RAW_FIELDS = {"sender", "subject", "urls", "url", "attachment_hashes", "spf_result", "dkim_result", "dmarc_result"}
_IDENTITY_RAW_FIELDS = {"username", "user", "user_email", "source_ip", "auth_method", "mfa_status", "source_geo"}
_CLOUD_RAW_FIELDS = {"cloud_provider", "region", "account_id", "project_id", "subscription_id", "resource_arn", "principal_arn"}
_INSIDER_RAW_FIELDS = {"data_volume_mb", "file_count", "destination_domain", "is_off_hours", "device_type", "removable_media"}


def classify_signals(state: InvestigationState) -> list[str]:
    """Pick which sub-agent capabilities should run for this alert.

    Returns a deterministic, de-duplicated list of capability names in the
    canonical sequential order: ``["phishing", "identity", "cloud",
    "insider"]``. Empty list is impossible — when no keyword matches we
    still fan out to all four so a multi-domain alert never silently skips
    a relevant analyst.

    The signal classifier deliberately avoids calling an LLM: by the time
    we reach it, the auto-triage step has already paid for an LLM round
    trip and emitted a verdict + rationale; routing on cheap keyword /
    raw-payload presence keeps the critical-path budget at one LLM call
    per sub-agent plus the auto-triage and responder LLM calls (total
    six on the parallel path vs six sequentially — same token cost, half
    the wall clock).
    """
    summary = (state.alert_summary or "").lower()
    raw = state.raw_alert or {}
    rationale = " ".join(state.confidence_basis or []).lower()
    findings_blob = " ".join(state.findings or []).lower()
    haystack = " ".join([summary, rationale, findings_blob])
    raw_keys = set(raw.keys())

    matched: list[str] = []
    if any(kw in haystack for kw in _PHISHING_KEYWORDS) or (raw_keys & _PHISHING_RAW_FIELDS):
        matched.append("phishing")
    if any(kw in haystack for kw in _IDENTITY_KEYWORDS) or (raw_keys & _IDENTITY_RAW_FIELDS):
        matched.append("identity")
    if any(kw in haystack for kw in _CLOUD_KEYWORDS) or (raw_keys & _CLOUD_RAW_FIELDS):
        matched.append("cloud")
    if any(kw in haystack for kw in _INSIDER_KEYWORDS) or (raw_keys & _INSIDER_RAW_FIELDS):
        matched.append("insider")

    if not matched:
        # Defensive default: fan out to every capability. Sub-agents that
        # don't see relevant signal cheaply no-op in their own LLM prompts.
        return ["phishing", "identity", "cloud", "insider"]
    return matched


# ---------------------------------------------------------------------------
# Sub-agent runner resolution — imported lazily so tests can monkeypatch
# either ``app.agents`` or the underlying module-level functions.
# ---------------------------------------------------------------------------


def _resolve_runner(name: str) -> _SubAgentRunner:
    """Return the live ``run_*`` coroutine for a given capability.

    Tests monkeypatch the runners on ``app.agents`` (the public façade);
    re-importing here on every call so the patch is honoured.
    """
    import importlib

    agents_pkg = importlib.import_module("app.agents")
    if name == "auto_triage":
        return agents_pkg.run_auto_triage
    if name == "phishing":
        return agents_pkg.run_phishing
    if name == "identity":
        return agents_pkg.run_identity
    if name == "cloud":
        return agents_pkg.run_cloud
    if name == "insider":
        return agents_pkg.run_insider_threat
    raise KeyError(f"Unknown sub-agent capability: {name}")


# ---------------------------------------------------------------------------
# Join — merges sub-agent outputs back into a single InvestigationState
# ---------------------------------------------------------------------------


def _join_states(base: InvestigationState, branch_states: list[InvestigationState]) -> InvestigationState:
    """Fold N sub-agent state objects back into the shared state.

    Strategy:

    * **Findings** are concatenated in capability order so the audit log
      reads like the sequential path would.
    * **MITRE mappings** are de-duplicated while preserving first-seen order.
    * **Verdict** takes the worst of {benign < false_positive < true_positive}
      across branches; a single sub-agent flagging ``true_positive`` wins.
    * **Confidence** is the max of the per-branch confidences for the
      winning verdict (mirrors the policy decision in
      ``services/agents/app/confidence/scoring.py``).
    * **Proposed actions** are deduped on ``(action_type, target)``.

    The branches mutate copies of ``base``; we never trust them to leave
    the shared slots untouched, so we re-derive everything from the
    incoming branch list.
    """
    verdict_rank = {None: -1, "benign": 0, "false_positive": 1, "true_positive": 2}
    merged_findings: list[str] = list(base.findings)
    merged_mitre: list[str] = list(base.mitre_mappings)
    merged_actions: list[Any] = list(base.proposed_actions)
    best_verdict: str | None = base.verdict
    best_confidence: float = base.confidence
    confidence_basis: list[str] = list(base.confidence_basis)

    seen_finding = set(merged_findings)
    seen_mitre = set(merged_mitre)
    seen_actions = {(a.action_type, a.target) for a in merged_actions if hasattr(a, "action_type")}

    for branch in branch_states:
        for f in branch.findings:
            if f not in seen_finding:
                merged_findings.append(f)
                seen_finding.add(f)
        for t in branch.mitre_mappings:
            if t not in seen_mitre:
                merged_mitre.append(t)
                seen_mitre.add(t)
        for a in branch.proposed_actions:
            key = (a.action_type, a.target) if hasattr(a, "action_type") else None
            if key is None or key in seen_actions:
                continue
            merged_actions.append(a)
            seen_actions.add(key)

        if verdict_rank.get(branch.verdict, -1) > verdict_rank.get(best_verdict, -1):
            best_verdict = branch.verdict
            best_confidence = branch.confidence
            confidence_basis = list(branch.confidence_basis)
        elif branch.verdict == best_verdict and branch.confidence > best_confidence:
            best_confidence = branch.confidence
            # Keep the more confident branch's basis for traceability.
            confidence_basis = list(branch.confidence_basis)

    base.findings = merged_findings
    base.mitre_mappings = merged_mitre
    base.proposed_actions = merged_actions
    if best_verdict is not None:
        base.verdict = best_verdict
    base.confidence = best_confidence
    base.confidence_basis = confidence_basis
    base.iteration_count = max(base.iteration_count, *(b.iteration_count for b in branch_states), 1)
    return base


# ---------------------------------------------------------------------------
# Lightweight Responder node — dry-run summary on the joined state
# ---------------------------------------------------------------------------


def _summarise_response(state: InvestigationState) -> InvestigationState:
    """Append a dry-run response summary as a finding.

    The full ``ResponderAgent`` lives in
    ``app.investigator.responder_agent`` and operates on
    ``InvestigatorState`` (a different state type used by the v6 pipeline).
    The router topology runs on ``InvestigationState`` so we keep responder
    work-product additive: a short, deterministic summary that downstream
    SOAR / ChatOps surfaces can consume without re-running an LLM. Real
    incident-response plans still flow through ``RespondAgent.plan`` for
    callers that want the full container/eradicate/recover JSON.
    """
    tactics_blob = ", ".join(state.mitre_mappings[:8]) or "no MITRE techniques mapped"
    verdict = state.verdict or "uncertain"
    state.add_finding(
        f"Responder (dry-run): verdict={verdict} confidence={state.confidence:.2f} "
        f"actions_pending={len(state.proposed_actions)} techniques=[{tactics_blob}]"
    )
    return state


# ---------------------------------------------------------------------------
# Topology runners
# ---------------------------------------------------------------------------


async def _run_auto_triage_step(state: InvestigationState) -> InvestigationState:
    runner = _resolve_runner("auto_triage")
    return await runner(state)


async def _run_sequential(state: InvestigationState, signals: list[str]) -> InvestigationState:
    """Reference path — run sub-agents one at a time, then responder."""
    for name in signals:
        runner = _resolve_runner(name)
        state = await runner(state)
    return _summarise_response(state)


async def _run_parallel(state: InvestigationState, signals: list[str]) -> InvestigationState:
    """Parallel path — asyncio.gather over the triggered sub-agents, then join."""
    # Each sub-agent must reason against an independent copy of the state so
    # concurrent mutations don't tear shared lists / verdicts apart. The Join
    # node re-folds branch outputs back into the canonical state.
    branch_inputs = []
    for _ in signals:
        copy = state.model_copy(deep=True)
        copy.iteration_count = state.iteration_count
        branch_inputs.append(copy)

    coros = [_resolve_runner(name)(branch_inputs[idx]) for idx, name in enumerate(signals)]
    branch_results = await asyncio.gather(*coros, return_exceptions=True)

    successful: list[InvestigationState] = []
    for name, result in zip(signals, branch_results, strict=False):
        if isinstance(result, Exception):
            state.add_finding(f"{name} sub-agent failed: {type(result).__name__}: {result}")
            logger.warning("orchestrator.subagent.failed", capability=name, error=str(result))
            continue
        successful.append(result)

    joined = _join_states(state, successful)
    return _summarise_response(joined)


# ---------------------------------------------------------------------------
# Streaming helpers — used by ``RouterOrchestrator.stream()``
# ---------------------------------------------------------------------------


def _state_snapshot(state: InvestigationState) -> dict[str, Any]:
    """Capture the volatile slots of ``state`` for inter-step diffing.

    The router's stream surface emits a ``step`` event after every internal
    stage (auto-triage, each sub-agent, join, responder). To describe what
    that stage actually *did* we snapshot before/after and diff the four
    growable slots (findings, MITRE, actions) plus the verdict/confidence
    pair. The snapshot stays cheap — counts only — because the full state
    rides on the ``done`` event at the end of the run anyway.
    """
    return {
        "findings": len(state.findings),
        "mitre": len(state.mitre_mappings),
        "actions": len(state.proposed_actions),
        "verdict": state.verdict,
        "confidence": state.confidence,
    }


def _summarise_diff(
    stage: str,
    pre: dict[str, Any],
    post: dict[str, Any],
    *,
    verdict: str | None,
    confidence: float,
) -> str:
    """Render a one-line, human-readable summary of a stage transition.

    Used as the ``summary`` field on the ``step`` event so a SOC analyst
    watching the live stream sees which stage produced what (e.g.
    ``"identity | +2 findings | +1 MITRE | verdict=true_positive | confidence=0.82"``).
    """
    fragments: list[str] = [stage]
    df = post["findings"] - pre["findings"]
    dm = post["mitre"] - pre["mitre"]
    da = post["actions"] - pre["actions"]
    if df:
        fragments.append(f"+{df} findings" if df > 0 else f"{df} findings")
    if dm:
        fragments.append(f"+{dm} MITRE" if dm > 0 else f"{dm} MITRE")
    if da:
        fragments.append(f"+{da} actions" if da > 0 else f"{da} actions")
    fragments.append(f"verdict={verdict or 'uncertain'}")
    try:
        fragments.append(f"confidence={float(confidence):.2f}")
    except (TypeError, ValueError):
        fragments.append("confidence=0.00")
    return " | ".join(fragments)


def _serialise_action(action: Any) -> dict[str, Any]:
    """Convert a :class:`ProposedAction` into a JSON-safe dict for ``done``.

    Falls back to a minimal shape if ``model_dump`` is unavailable so a
    stray non-Pydantic object on ``state.proposed_actions`` doesn't break
    the terminal event.
    """
    if hasattr(action, "model_dump"):
        try:
            return action.model_dump(mode="json")
        except Exception:  # noqa: BLE001
            pass
    return {
        "action_type": getattr(action, "action_type", "unknown"),
        "target": getattr(action, "target", ""),
        "rationale": getattr(action, "rationale", ""),
    }


def _build_done_event(
    state: InvestigationState,
    *,
    report_md: str,
    report_html: str,
    case_id: str,
    run_id: uuid.UUID,
    topology: str,
    signals: list[str],
    auto_closed: bool,
    wall_clock_ms: float,
) -> dict[str, Any]:
    """Synthesise the terminal ``done`` event payload.

    The state shape on this event is the router's flat
    :class:`InvestigationState` (no per-agent ``recon`` / ``forensic`` /
    ``responder`` blocks — those belong to the investigator pipeline).
    The future ``/investigate`` swap will adapt this shape on the API
    boundary; this PR only ships the substrate.
    """
    state.completed_at = state.completed_at or datetime.utcnow()
    status = state.status.value if hasattr(state.status, "value") else str(state.status)
    return {
        "type": "done",
        "case_id": case_id,
        "run_id": str(run_id),
        "state": {
            "status": status,
            "verdict": state.verdict,
            "confidence": state.confidence,
            "confidence_basis": list(state.confidence_basis),
            "findings": list(state.findings),
            "mitre_mappings": list(state.mitre_mappings),
            "proposed_actions": [_serialise_action(a) for a in state.proposed_actions],
            "report_md": report_md,
            "report_html": report_html,
            "started_at": state.started_at.isoformat() if state.started_at else None,
            "completed_at": state.completed_at.isoformat() if state.completed_at else None,
            "error": state.error,
        },
        "info": {
            "topology": topology,
            "signals": list(signals),
            "auto_closed": auto_closed,
            "wall_clock_ms": wall_clock_ms,
        },
    }


async def _persist_report_artifact(
    ledger_module: Any,
    *,
    run_id: uuid.UUID,
    tenant_id: uuid.UUID | None,
    report_md: str,
) -> None:
    """Best-effort persistence of the Markdown report as a ledger artifact.

    Ledger writes are advisory: a failure here must not block the live
    stream. The ``report_html`` companion isn't persisted — consumers can
    re-render it deterministically from ``report_md`` via
    :func:`app.orchestrator.report.render_router_report_html`.
    """
    if tenant_id is None or not report_md:
        return
    try:
        await ledger_module.record_artifact(
            run_id=run_id,
            tenant_id=tenant_id,
            kind="report_md",
            content=report_md,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "router.stream.ledger_artifact_failed",
            run_id=str(run_id),
            error=str(exc),
        )


async def _complete_run_safe(
    ledger_module: Any,
    *,
    run_id: uuid.UUID,
    tenant_id: uuid.UUID | None,
    status: str,
    error: str | None,
    iterations: int,
) -> None:
    """Best-effort finalisation of the ledger row."""
    if tenant_id is None:
        return
    try:
        await ledger_module.complete_run(
            run_id=run_id,
            tenant_id=tenant_id,
            status=status,
            error=error,
            iterations=iterations,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "router.stream.ledger_complete_failed",
            run_id=str(run_id),
            error=str(exc),
        )


# ---------------------------------------------------------------------------
# Public orchestrator
# ---------------------------------------------------------------------------


class RouterOrchestrator:
    """High-level wrapper around the router topology.

    Mirrors the surface of
    :class:`app.investigator.orchestrator.InvestigatorOrchestrator` but
    operates on ``InvestigationState`` (the four-agent shared state) and
    selects between the parallel fan-out / sequential reference path on
    every call via the ``AISOC_AGENT_PARALLEL_TOPOLOGY`` flag.
    """

    def __init__(self) -> None:
        # Topology selection is read per-call so an operator can flip the
        # flag without restarting the service.
        pass

    async def run(
        self,
        state: InvestigationState,
        *,
        topology: str | None = None,
    ) -> tuple[InvestigationState, dict[str, Any]]:
        """Execute the topology against ``state``.

        Args:
            state: the seeded :class:`InvestigationState` (caller fills
                ``incident_id``, ``tenant_id``, ``alert_summary``,
                ``raw_alert``).
            topology: explicit override for testing — one of ``"parallel"``
                or ``"sequential"``. When ``None``, the env flag decides.

        Returns:
            ``(final_state, info)`` — ``info`` carries the substrate
            telemetry the eval harness logs (active topology, signals,
            wall-clock ms).
        """
        if topology is None:
            mode = "parallel" if is_parallel_topology_enabled() else "sequential"
        else:
            mode = topology
        if mode not in {"parallel", "sequential"}:
            raise ValueError(f"unknown topology: {mode!r}")

        run_id = uuid.uuid4()
        state.status = AgentStatus.RUNNING
        state.iteration_count = max(state.iteration_count, 0)

        t0 = time.perf_counter()
        # 1. Auto-triage — same for both modes.
        state = await _run_auto_triage_step(state)

        # 2. If auto-triage auto-closed the alert (high-conf FP/benign), stop.
        if state.status == AgentStatus.COMPLETED:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            info = {
                "topology": mode,
                "signals": [],
                "auto_closed": True,
                "wall_clock_ms": elapsed_ms,
                "run_id": str(run_id),
                "substrate": True,
            }
            logger.info(
                "router.auto_closed",
                run_id=str(run_id),
                topology=mode,
                wall_clock_ms=round(elapsed_ms, 2),
            )
            return state, info

        # 3. Classify which sub-agents to trigger.
        signals = classify_signals(state)
        state.add_finding(f"Router: classified signals={signals}, topology={mode}")

        # 4. Fan-out or sequential.
        if mode == "parallel":
            state = await _run_parallel(state, signals)
        else:
            state = await _run_sequential(state, signals)

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        state.status = AgentStatus.COMPLETED

        info = {
            "topology": mode,
            "signals": signals,
            "auto_closed": False,
            "wall_clock_ms": elapsed_ms,
            "run_id": str(run_id),
            # Always label as substrate: the router latency is end-to-end
            # wall-clock under the deterministic substrate harness. Real
            # LLM-backed numbers come from the wet-eval workflow.
            "substrate": True,
        }
        logger.info(
            "router.completed",
            run_id=str(run_id),
            topology=mode,
            signals=signals,
            wall_clock_ms=round(elapsed_ms, 2),
            substrate=True,
        )
        return state, info

    async def stream(
        self,
        state: InvestigationState,
        *,
        topology: str | None = None,
    ) -> AsyncIterator[dict[str, Any]]:
        """Execute the topology and yield ``step`` / ``done`` events.

        Mirrors
        :meth:`app.investigator.orchestrator.InvestigatorOrchestrator.stream`'s
        event surface so the same WebSocket layer can carry router runs once
        ``/investigate`` is swapped over. The terminal ``done`` event carries
        a deterministically-rendered Markdown + HTML report and the full
        :class:`InvestigationState` payload; no extra LLM call is issued
        beyond the four sub-agents the router already invokes.

        Ledger writes (``start_run`` / ``record_event`` / ``record_artifact``
        / ``complete_run``) are best-effort: a database outage degrades
        observability but never blocks the stream.
        """
        # Import locally so a missing asyncpg in unit tests doesn't break the
        # module import path. Matches InvestigatorOrchestrator.stream.
        from app.investigator import ledger as ledger_module
        from app.orchestrator.report import render_router_report

        if topology is None:
            mode = "parallel" if is_parallel_topology_enabled() else "sequential"
        else:
            mode = topology
        if mode not in {"parallel", "sequential"}:
            raise ValueError(f"unknown topology: {mode!r}")

        run_id = uuid.uuid4()
        state.status = AgentStatus.RUNNING
        state.iteration_count = max(state.iteration_count, 0)
        state.started_at = state.started_at or datetime.utcnow()

        t0 = time.perf_counter()
        seq = 0
        tenant_id: uuid.UUID | None = None

        # ------------------------------------------------------------------
        # Ledger: open the run row (best-effort).
        # ------------------------------------------------------------------
        try:
            tenant_id = await ledger_module.start_run(
                run_id=run_id,
                case_id=state.incident_id,
                tenant_ref=state.tenant_id or "default",
                alert_summary=state.alert_summary or "",
                raw_alert=state.raw_alert or {},
                model_used=f"router:{mode}",
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "router.stream.ledger_start_failed",
                run_id=str(run_id),
                error=str(exc),
            )
            tenant_id = None

        async def _yield_step(
            *,
            agent: str,
            summary: str,
            pre: dict[str, Any] | None,
            post: dict[str, Any],
            payload: dict[str, Any] | None = None,
            duration_ms: float = 0.0,
        ) -> dict[str, Any]:
            """Build, persist, and return a ``step`` event payload.

            The closure captures ``seq``-by-reference via the outer scope
            via a ``nonlocal``-style list trick to keep the call sites
            readable.
            """
            nonlocal seq
            seq += 1
            event = {
                "type": "step",
                "seq": seq,
                "agent": agent,
                "summary": summary,
                "delta": (
                    {
                        "findings": post["findings"] - (pre["findings"] if pre else 0),
                        "mitre": post["mitre"] - (pre["mitre"] if pre else 0),
                        "actions": post["actions"] - (pre["actions"] if pre else 0),
                    }
                    if pre is not None
                    else {
                        "findings": post["findings"],
                        "mitre": post["mitre"],
                        "actions": post["actions"],
                    }
                ),
                "verdict": post["verdict"],
                "confidence": post["confidence"],
                "duration_ms": round(duration_ms, 2),
            }
            if tenant_id is not None:
                try:
                    await ledger_module.record_event(
                        run_id=run_id,
                        tenant_id=tenant_id,
                        seq=seq,
                        kind="step",
                        agent=agent,
                        summary=summary,
                        payload=payload or {},
                        duration_ms=int(duration_ms),
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "router.stream.ledger_event_failed",
                        run_id=str(run_id),
                        seq=seq,
                        agent=agent,
                        error=str(exc),
                    )
            return event

        # ------------------------------------------------------------------
        # Stage 1: auto-triage.
        # ------------------------------------------------------------------
        try:
            pre = _state_snapshot(state)
            stage_t0 = time.perf_counter()
            state = await _run_auto_triage_step(state)
            stage_ms = (time.perf_counter() - stage_t0) * 1000.0
            post = _state_snapshot(state)
            yield await _yield_step(
                agent="auto_triage",
                summary=_summarise_diff(
                    "auto_triage",
                    pre,
                    post,
                    verdict=state.verdict,
                    confidence=state.confidence,
                ),
                pre=pre,
                post=post,
                payload={"verdict": state.verdict, "confidence": state.confidence},
                duration_ms=stage_ms,
            )
        except Exception as exc:  # noqa: BLE001
            state.status = AgentStatus.FAILED
            state.error = f"auto_triage failed: {exc}"
            logger.exception("router.stream.auto_triage_failed", run_id=str(run_id))

        # ------------------------------------------------------------------
        # Early exit: auto-triage closed the alert.
        # ------------------------------------------------------------------
        if state.status == AgentStatus.COMPLETED:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            report_md, report_html = render_router_report(state)
            await _persist_report_artifact(
                ledger_module,
                run_id=run_id,
                tenant_id=tenant_id,
                report_md=report_md,
            )
            await _complete_run_safe(
                ledger_module,
                run_id=run_id,
                tenant_id=tenant_id,
                status="completed",
                error=None,
                iterations=max(state.iteration_count, 1),
            )
            yield _build_done_event(
                state,
                report_md=report_md,
                report_html=report_html,
                case_id=state.incident_id,
                run_id=run_id,
                topology=mode,
                signals=[],
                auto_closed=True,
                wall_clock_ms=elapsed_ms,
            )
            logger.info(
                "router.stream.auto_closed",
                run_id=str(run_id),
                topology=mode,
                wall_clock_ms=round(elapsed_ms, 2),
            )
            return

        # ------------------------------------------------------------------
        # Stage 2: signal classification.
        # ------------------------------------------------------------------
        try:
            pre = _state_snapshot(state)
            stage_t0 = time.perf_counter()
            signals = classify_signals(state)
            state.add_finding(f"Router: classified signals={signals}, topology={mode}")
            stage_ms = (time.perf_counter() - stage_t0) * 1000.0
            post = _state_snapshot(state)
            yield await _yield_step(
                agent="router",
                summary=f"router | signals={signals} | topology={mode}",
                pre=pre,
                post=post,
                payload={"signals": list(signals), "topology": mode},
                duration_ms=stage_ms,
            )
        except Exception as exc:  # noqa: BLE001
            state.status = AgentStatus.FAILED
            state.error = f"router classification failed: {exc}"
            signals = []
            logger.exception("router.stream.classify_failed", run_id=str(run_id))

        # ------------------------------------------------------------------
        # Stage 3: sub-agent fan-out — emit one step per agent.
        # ------------------------------------------------------------------
        branch_states: list[InvestigationState] = []
        if signals:
            if mode == "parallel":
                # Launch all sub-agents concurrently but yield step events
                # in completion order via ``as_completed``. Each branch sees
                # a deep copy of the pre-router state — matching the join
                # contract in ``_run_parallel``.
                runners = [_resolve_runner(s) for s in signals]
                branch_inputs = [state.model_copy(deep=True) for _ in runners]
                pre_state = _state_snapshot(state)

                async def _wrap(idx: int, signal: str, runner: _SubAgentRunner, branch: InvestigationState):
                    bt0 = time.perf_counter()
                    try:
                        result = await runner(branch)
                    except Exception as exc:  # noqa: BLE001
                        logger.exception(
                            "router.stream.subagent_failed",
                            run_id=str(run_id),
                            agent=signal,
                        )
                        branch.add_finding(f"{signal} agent failed: {exc}")
                        result = branch
                    return idx, signal, result, (time.perf_counter() - bt0) * 1000.0

                tasks = [
                    asyncio.create_task(_wrap(i, s, r, b)) for i, (s, r, b) in enumerate(zip(signals, runners, branch_inputs, strict=False))
                ]
                results_by_idx: dict[int, InvestigationState] = {}
                for coro in asyncio.as_completed(tasks):
                    idx, signal, result, branch_ms = await coro
                    results_by_idx[idx] = result
                    branch_post = _state_snapshot(result)
                    yield await _yield_step(
                        agent=signal,
                        summary=_summarise_diff(
                            signal,
                            pre_state,
                            branch_post,
                            verdict=result.verdict,
                            confidence=result.confidence,
                        ),
                        pre=pre_state,
                        post=branch_post,
                        payload={
                            "signal": signal,
                            "verdict": result.verdict,
                            "confidence": result.confidence,
                        },
                        duration_ms=branch_ms,
                    )
                # Preserve declared signal order for the join.
                branch_states = [results_by_idx[i] for i in range(len(signals))]
            else:
                for signal in signals:
                    runner = _resolve_runner(signal)
                    branch_state = state.model_copy(deep=True)
                    pre_branch = _state_snapshot(branch_state)
                    bt0 = time.perf_counter()
                    try:
                        result = await runner(branch_state)
                    except Exception as exc:  # noqa: BLE001
                        logger.exception(
                            "router.stream.subagent_failed",
                            run_id=str(run_id),
                            agent=signal,
                        )
                        branch_state.add_finding(f"{signal} agent failed: {exc}")
                        result = branch_state
                    branch_ms = (time.perf_counter() - bt0) * 1000.0
                    branch_post = _state_snapshot(result)
                    yield await _yield_step(
                        agent=signal,
                        summary=_summarise_diff(
                            signal,
                            pre_branch,
                            branch_post,
                            verdict=result.verdict,
                            confidence=result.confidence,
                        ),
                        pre=pre_branch,
                        post=branch_post,
                        payload={
                            "signal": signal,
                            "verdict": result.verdict,
                            "confidence": result.confidence,
                        },
                        duration_ms=branch_ms,
                    )
                    branch_states.append(result)

            # Join the branches back into the base state.
            try:
                pre = _state_snapshot(state)
                stage_t0 = time.perf_counter()
                state = _join_states(state, branch_states)
                stage_ms = (time.perf_counter() - stage_t0) * 1000.0
                post = _state_snapshot(state)
                yield await _yield_step(
                    agent="join",
                    summary=_summarise_diff(
                        "join",
                        pre,
                        post,
                        verdict=state.verdict,
                        confidence=state.confidence,
                    ),
                    pre=pre,
                    post=post,
                    payload={"branches": len(branch_states)},
                    duration_ms=stage_ms,
                )
            except Exception as exc:  # noqa: BLE001
                state.status = AgentStatus.FAILED
                state.error = f"join failed: {exc}"
                logger.exception("router.stream.join_failed", run_id=str(run_id))

        # ------------------------------------------------------------------
        # Stage 4: responder summary (deterministic).
        # ------------------------------------------------------------------
        try:
            pre = _state_snapshot(state)
            stage_t0 = time.perf_counter()
            state = _summarise_response(state)
            stage_ms = (time.perf_counter() - stage_t0) * 1000.0
            post = _state_snapshot(state)
            yield await _yield_step(
                agent="responder",
                summary=_summarise_diff(
                    "responder",
                    pre,
                    post,
                    verdict=state.verdict,
                    confidence=state.confidence,
                ),
                pre=pre,
                post=post,
                payload={"verdict": state.verdict, "confidence": state.confidence},
                duration_ms=stage_ms,
            )
        except Exception as exc:  # noqa: BLE001
            state.status = AgentStatus.FAILED
            state.error = f"responder failed: {exc}"
            logger.exception("router.stream.responder_failed", run_id=str(run_id))

        # ------------------------------------------------------------------
        # Finalise: render report, persist, emit ``done``.
        # ------------------------------------------------------------------
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        if state.status != AgentStatus.FAILED:
            state.status = AgentStatus.COMPLETED
        state.completed_at = datetime.utcnow()

        report_md, report_html = render_router_report(state)
        await _persist_report_artifact(
            ledger_module,
            run_id=run_id,
            tenant_id=tenant_id,
            report_md=report_md,
        )
        await _complete_run_safe(
            ledger_module,
            run_id=run_id,
            tenant_id=tenant_id,
            status="completed" if state.status == AgentStatus.COMPLETED else "failed",
            error=state.error,
            iterations=max(state.iteration_count, 1),
        )
        yield _build_done_event(
            state,
            report_md=report_md,
            report_html=report_html,
            case_id=state.incident_id,
            run_id=run_id,
            topology=mode,
            signals=signals,
            auto_closed=False,
            wall_clock_ms=elapsed_ms,
        )
        logger.info(
            "router.stream.completed",
            run_id=str(run_id),
            topology=mode,
            signals=signals,
            wall_clock_ms=round(elapsed_ms, 2),
            substrate=True,
        )


async def run_router_investigation(
    state: InvestigationState,
    *,
    topology: str | None = None,
) -> tuple[InvestigationState, dict[str, Any]]:
    """One-shot helper — instantiates a fresh :class:`RouterOrchestrator`."""
    return await RouterOrchestrator().run(state, topology=topology)
