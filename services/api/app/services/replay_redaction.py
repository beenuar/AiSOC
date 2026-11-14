"""Build a redacted, immutable public snapshot from an investigation ledger.

Powers the v8 W3 public-replay publish flow. Given a run + its events, this
produces:

* a **redacted snapshot** (safe to serve at ``/r/<slug>``) — the animated
  playback the web page renders: verdict stamp, MITRE techniques, elapsed time,
  step count, an ordered step list, evidence cards, and a small attack graph;
* an **alias map** (``{token: original}``) so the publisher can review exactly
  what will be hidden in a pre-publish diff before confirming.

Only the redacted snapshot is ever persisted — the alias map stays in the
preview response and is never stored. Redaction reuses the vendored
:class:`Pseudonymizer` (internal IPs / emails / paths / secrets / internal
hostnames / usernames → opaque tokens); public IOCs (external domains/IPs) are
intentionally preserved because they are the shareable threat-intelligence
value of a replay, not customer PII.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app._vendor.redactor import Pseudonymizer, RedactionConfig


@dataclass
class ReplaySnapshot:
    """The redacted, display-safe snapshot + the review-only alias map."""

    snapshot: dict[str, Any]
    alias_map: dict[str, str] = field(default_factory=dict)
    title: str = ""


def _collect_techniques(raw_alert: dict | None, events: list[dict]) -> list[str]:
    seen: list[str] = []

    def add(values: Any) -> None:
        if isinstance(values, str):
            values = [values]
        if isinstance(values, list | tuple):
            for v in values:
                tid = str(v).upper().strip()
                if tid and tid.startswith("T") and tid not in seen:
                    seen.append(tid)

    if raw_alert:
        add(raw_alert.get("mitre_techniques") or raw_alert.get("techniques"))
    for ev in events:
        payload = ev.get("payload") or {}
        add(payload.get("techniques") or payload.get("mitre") or payload.get("technique"))
    return seen


def _build_attack_graph(techniques: list[str], case_title: str) -> dict[str, Any]:
    """A minimal, deterministic attack graph: an alert node feeding a
    technique chain. Enough for the replay page's "graph growing" animation
    without exposing any entity data (techniques are public taxonomy)."""
    nodes: list[dict[str, Any]] = [{"id": "alert", "label": "Alert", "kind": "alert"}]
    edges: list[dict[str, Any]] = []
    prev = "alert"
    for i, tid in enumerate(techniques[:10]):
        node_id = f"technique-{i}"
        nodes.append({"id": node_id, "label": tid, "kind": "technique"})
        edges.append({"source": prev, "target": node_id, "label": "leads_to"})
        prev = node_id
    return {"nodes": nodes, "edges": edges}


def build_redacted_snapshot(
    *,
    run: dict[str, Any],
    events: list[dict[str, Any]],
    config: RedactionConfig | None = None,
) -> ReplaySnapshot:
    """Assemble and redact a public replay snapshot.

    ``run`` keys used: ``case_id``, ``alert_summary``, ``raw_alert``,
    ``model_used``, ``status``, ``started_at``, ``completed_at``.
    ``events`` are ledger event dicts with ``seq``/``kind``/``agent``/
    ``summary``/``payload``/``ts``/``duration_ms``.
    """
    pseudo = Pseudonymizer(config=config or RedactionConfig())

    def r(text: Any) -> str:
        return pseudo.redact(str(text)) if text is not None else ""

    raw_alert = run.get("raw_alert") or {}
    techniques = _collect_techniques(raw_alert, events)

    # Counts + timing.
    tool_calls = sum(1 for e in events if e.get("kind") == "tool_call")
    evidence_events = [e for e in events if e.get("kind") == "evidence_cited"]
    llm_calls = sum(1 for e in events if e.get("kind") in ("llm_call", "llm_response"))

    started = run.get("started_at")
    completed = run.get("completed_at")
    elapsed_ms = 0
    if started and completed:
        try:
            elapsed_ms = int((completed - started).total_seconds() * 1000)
        except (TypeError, AttributeError):
            elapsed_ms = 0

    # Verdict: prefer a structured verdict in a report/decision event.
    verdict = ""
    for ev in reversed(events):
        payload = ev.get("payload") or {}
        v = payload.get("verdict")
        if v:
            verdict = str(v)
            break
    if not verdict:
        verdict = str(run.get("status") or "completed")

    redacted_title = r(run.get("alert_summary") or run.get("case_id") or "Investigation")

    steps = []
    for ev in events:
        payload = ev.get("payload") or {}
        decision = None
        reason = payload.get("reason") or payload.get("rationale")
        tool = payload.get("tool") or payload.get("tool_name")
        if reason or tool:
            decision = {
                "reason": r(reason) if reason else None,
                "tool": pseudo.redact(str(tool)) if tool else None,
                "confidence": payload.get("confidence"),
            }
        steps.append(
            {
                "seq": ev.get("seq"),
                "kind": ev.get("kind"),
                "agent": ev.get("agent"),
                "summary": r(ev.get("summary")),
                "durationMs": ev.get("duration_ms") or 0,
                "decision": decision,
            }
        )

    evidence_cards = [
        {
            "seq": ev.get("seq"),
            "summary": r(ev.get("summary")),
            "source": (ev.get("payload") or {}).get("source", "evidence"),
        }
        for ev in evidence_events
    ]

    snapshot = {
        "schemaVersion": 1,
        "caseId": r(run.get("case_id")),
        "title": redacted_title,
        "verdict": verdict,
        "model": run.get("model_used") or "deterministic",
        "elapsedMs": elapsed_ms,
        "stepCount": len(events),
        "toolCallCount": tool_calls,
        "llmCallCount": llm_calls,
        "evidenceSourceCount": len(evidence_events),
        "techniques": techniques,
        "steps": steps,
        "evidenceCards": evidence_cards,
        "attackGraph": _build_attack_graph(techniques, redacted_title),
    }

    return ReplaySnapshot(snapshot=snapshot, alias_map=pseudo.mapping, title=redacted_title)
