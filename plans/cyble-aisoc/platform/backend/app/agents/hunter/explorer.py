"""Iterative hypothesis-tree explorer for the Hunter agent.

The explorer turns a free-form hypothesis statement into a tree of
``HypothesisNode`` and walks it until the budget runs out or every node
has been explored. It is the heart of todo ``t2b-hunter``:

* **Iterative**, not recursive — a BFS queue makes budgeting trivial and
  keeps the call stack shallow even on deep IOC pivot chains.
* **Tree-shaped** — each tool call's output can spawn child hypotheses
  (an IP from CTI enrichment becomes its own node), but the parent's
  evidence is preserved so the analyst sees how we got there.
* **Retro-hunt aware** — for telemetry-style categories (process /
  network behavior), the explorer re-runs the same query with an
  extended window and stamps the resulting evidence ``retro=True``. That
  lets the verdict consider "we also looked back 30 days and saw the
  same pattern" without losing the live-vs-retro distinction.
* **Tool-caller agnostic** — the explorer talks to whatever
  :class:`HunterToolCaller` it is handed, so production uses
  :class:`BaseAgentToolCaller` (HITL, audit, tenancy) and tests use
  :class:`FakeToolCaller`. The explorer itself never imports the agent.

The explorer is intentionally *not* an LLM agent. An outer LLM can
generate the root statement and read the resulting :class:`HuntResult`,
but the inner loop is deterministic so it can be replayed and tested.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from app.agents.hunter.classifier import (
    Classification,
    classify_hypothesis,
    extract_hostnames,
    extract_iocs,
)
from app.agents.hunter.models import (
    Evidence,
    HuntResult,
    HypothesisCategory,
    HypothesisNode,
    HypothesisStatus,
    HypothesisVerdict,
)
from app.agents.hunter.tools import HunterToolCaller


# ── Configuration ───────────────────────────────────────────────────────


@dataclass(frozen=True)
class ExplorerBudget:
    """Hard caps on how much exploration one hunt may do.

    Budgets exist because the tree could in principle fan out forever
    (every IOC in an enrichment payload spawns a child hypothesis). The
    explorer stops cleanly when *any* budget trips and marks the
    not-yet-explored frontier ``BUDGET_EXHAUSTED`` so the analyst can see
    that the tree is incomplete rather than thinking it is decisive.
    """

    max_nodes: int = 12
    """Maximum nodes that may be created (including the root)."""

    max_tool_calls: int = 24
    """Maximum live tool calls. Retro calls are counted separately."""

    max_depth: int = 3
    """Hard cap on tree depth. Root is depth 0."""

    retro_enabled: bool = True
    """Whether to run extended-window retro queries on telemetry categories."""

    retro_window_days: int = 30
    """How far back the retro pass looks. Surfaced as ``window_days`` to tools."""

    max_pivots_per_node: int = 3
    """Maximum IOC / host pivots a single node may spawn. Prevents fan-out
    explosion when an enrichment payload returns dozens of related IOCs."""


_DEFAULT_BUDGET = ExplorerBudget()


# ── Result-scoring helpers ──────────────────────────────────────────────


# Tools that, when they return a non-trivial payload, count toward the
# hypothesis being SUPPORTED. (Conversely, an empty payload from these
# tools is a soft refutation.)
_POSITIVE_EVIDENCE_TOOLS = frozenset(
    {
        "cti.darkweb_search",
        "cti.brand_intel",
        "cti.asm_lookup",
        "cti.vuln_intel",
        "cti.enrich_ioc",
        "siem.search_events",
        "siem.get_related_alerts",
        "edr.get_process_tree",
    }
)


def _payload_signal(payload: dict[str, Any]) -> tuple[bool, int]:
    """Best-effort "did this tool return anything interesting?" check.

    Returns ``(has_signal, count)`` where ``count`` is whatever the
    explorer can use as a magnitude (number of hits, leaks, processes
    etc.). The check is intentionally heuristic — tools have wildly
    different shapes — but it errs on the side of *some signal* so the
    explorer keeps exploring rather than prematurely refuting.
    """
    if not isinstance(payload, dict) or not payload:
        return (False, 0)

    # Generic list-shaped fields we treat as evidence.
    for key in (
        "leaks",
        "results",
        "matches",
        "hits",
        "alerts",
        "processes",
        "events",
        "typosquats",
        "exposures",
        "iocs",
    ):
        val = payload.get(key)
        if isinstance(val, list) and val:
            return (True, len(val))
        if isinstance(val, int) and val > 0:
            return (True, val)

    # Vulnerability intel often returns a single CVSS / severity field.
    for key in ("cvss", "severity", "verdict"):
        val = payload.get(key)
        if isinstance(val, (int, float)) and val > 0:
            return (True, int(val))
        if isinstance(val, str) and val.lower() in {"high", "critical"}:
            return (True, 1)

    return (False, 0)


def _summarize_evidence(tool: str, payload: dict[str, Any]) -> str:
    """Short analyst-readable line for an evidence row."""
    has_signal, count = _payload_signal(payload)
    if not has_signal:
        return f"{tool}: no signal"
    return f"{tool}: {count} hit(s)"


def _weight_for(tool: str, has_signal: bool, retro: bool) -> float:
    """Map a tool result to a signed confidence weight.

    Retro evidence is dampened (0.6×) so a thirty-day-old echo cannot
    on its own flip a hypothesis to SUPPORTED, while live evidence is
    full strength. Empty results from "positive evidence" tools count
    as mild refutation — useful so a brand-intel hypothesis that
    returned no typosquats actually moves toward REFUTED.
    """
    base = 0.6 if tool in _POSITIVE_EVIDENCE_TOOLS else 0.3
    sign = 1.0 if has_signal else -0.5  # absent signal is a soft refute
    weight = base * sign
    if retro:
        weight *= 0.6
    return round(weight, 3)


def _node_verdict_from_evidence(node: HypothesisNode) -> tuple[HypothesisVerdict, float]:
    """Aggregate evidence on a single node into ``(verdict, confidence)``."""
    if not node.evidence:
        return (HypothesisVerdict.UNKNOWN, 0.0)
    total = sum(ev.weight for ev in node.evidence)
    # Normalize roughly by evidence count so a long chain of weak hits
    # does not auto-promote to SUPPORTED. We cap at ±1.0.
    n = len(node.evidence)
    score = max(-1.0, min(1.0, total / max(1, n)))
    if score >= 0.3:
        return (HypothesisVerdict.SUPPORTED, round(score, 3))
    if score <= -0.3:
        return (HypothesisVerdict.REFUTED, round(score, 3))
    return (HypothesisVerdict.INCONCLUSIVE, round(score, 3))


def _roll_up_verdict(root: HypothesisNode) -> HypothesisVerdict:
    """Aggregate a verdict across the whole tree.

    Rule of thumb: if *anything* in the tree is SUPPORTED, the hunt is
    SUPPORTED. Otherwise, if anything is REFUTED, the hunt is REFUTED.
    Otherwise, INCONCLUSIVE if we saw evidence at all, else UNKNOWN.
    This matches how SOC analysts read tree results — one strong
    positive on a descendant is enough to escalate.
    """
    saw_any_evidence = False
    saw_refuted = False
    for node in [root, *root.iter_descendants()]:
        if node.evidence:
            saw_any_evidence = True
        if node.verdict == HypothesisVerdict.SUPPORTED:
            return HypothesisVerdict.SUPPORTED
        if node.verdict == HypothesisVerdict.REFUTED:
            saw_refuted = True
    if saw_refuted:
        return HypothesisVerdict.REFUTED
    if saw_any_evidence:
        return HypothesisVerdict.INCONCLUSIVE
    return HypothesisVerdict.UNKNOWN


# ── Explorer ────────────────────────────────────────────────────────────


@dataclass
class _ExplorationState:
    """Mutable counters shared across the BFS walk."""

    nodes_created: int = 1  # root counts immediately
    tool_calls: int = 0
    retro_calls: int = 0
    iocs_pivoted: list[str] = field(default_factory=list)


class HypothesisTreeExplorer:
    """Walk a hypothesis tree iteratively against a :class:`HunterToolCaller`.

    The explorer owns no state across calls — every call to
    :meth:`explore` builds a fresh tree from scratch. The state object
    above is per-run and lives only inside ``explore``.
    """

    def __init__(
        self,
        tool_caller: HunterToolCaller,
        budget: ExplorerBudget = _DEFAULT_BUDGET,
    ) -> None:
        self._tool_caller = tool_caller
        self._budget = budget

    # ── Public entrypoint ──────────────────────────────────────────────

    async def explore(self, statement: str) -> HuntResult:
        """Build a tree rooted at ``statement`` and walk it under budget."""
        started_at = datetime.now(timezone.utc)
        root = self._make_root(statement)
        state = _ExplorationState()

        # BFS queue. We only walk nodes that are still ``PENDING`` so
        # callers can pre-seed the tree if they want (not used today, but
        # cheap to support).
        queue: list[HypothesisNode] = [root]
        while queue:
            node = queue.pop(0)
            if node.status != HypothesisStatus.PENDING:
                continue
            if self._budget_tripped(state, node):
                node.status = HypothesisStatus.BUDGET_EXHAUSTED
                node.notes.append("Skipped: explorer budget exhausted.")
                continue
            await self._explore_node(node, state, queue)

        # Any nodes still pending got skipped by budget; mark them so the
        # caller can see the frontier was not finished.
        for node in [root, *root.iter_descendants()]:
            if node.status == HypothesisStatus.PENDING:
                node.status = HypothesisStatus.BUDGET_EXHAUSTED
                if "Skipped: explorer budget exhausted." not in node.notes:
                    node.notes.append("Skipped: explorer budget exhausted.")

        finished_at = datetime.now(timezone.utc)
        verdict = _roll_up_verdict(root)
        nodes_explored = sum(
            1
            for n in [root, *root.iter_descendants()]
            if n.status in (HypothesisStatus.EXPLORED, HypothesisStatus.DEAD_END)
        )
        summary = self._summarize_result(root, verdict, nodes_explored, state)
        follow_ups = self._follow_ups(root, verdict, state)

        return HuntResult(
            root=root,
            nodes_explored=nodes_explored,
            tool_calls=state.tool_calls,
            retro_calls=state.retro_calls,
            verdict=verdict,
            summary=summary,
            follow_ups=tuple(follow_ups),
            iocs_pivoted=tuple(state.iocs_pivoted),
            started_at=started_at,
            finished_at=finished_at,
        )

    # ── Internals ──────────────────────────────────────────────────────

    def _make_root(self, statement: str) -> HypothesisNode:
        cls = classify_hypothesis(statement)
        node = HypothesisNode(
            statement=(statement or "").strip() or "(empty hypothesis)",
            category=cls.category,
            suggested_tools=cls.suggested_tools,
            seed_params=dict(cls.seed_params),
        )
        if cls.rationale:
            node.notes.append("Classifier: " + "; ".join(cls.rationale))
        return node

    def _budget_tripped(self, state: _ExplorationState, node: HypothesisNode) -> bool:
        if node.depth > self._budget.max_depth:
            return True
        if state.tool_calls >= self._budget.max_tool_calls:
            return True
        return False

    async def _explore_node(
        self,
        node: HypothesisNode,
        state: _ExplorationState,
        queue: list[HypothesisNode],
    ) -> None:
        node.status = HypothesisStatus.EXPLORING

        if not node.suggested_tools:
            # Nothing to do; the classifier had no tool for this lane.
            node.status = HypothesisStatus.DEAD_END
            node.notes.append("No tools suggested by classifier.")
            return

        for tool in node.suggested_tools:
            if state.tool_calls >= self._budget.max_tool_calls:
                node.notes.append(f"Skipped tool {tool}: tool-call budget exhausted.")
                break

            params = self._params_for_tool(tool, node)
            try:
                payload = await self._tool_caller.call(tool, params)
            except Exception as exc:  # noqa: BLE001 — surface as evidence
                state.tool_calls += 1
                node.add_evidence(
                    Evidence(
                        tool=tool,
                        summary=f"{tool} raised {type(exc).__name__}: {exc}",
                        weight=0.0,
                        payload={"error": str(exc), "type": type(exc).__name__},
                        tool_params=dict(params),
                    )
                )
                continue

            state.tool_calls += 1
            has_signal, _ = _payload_signal(payload)
            node.add_evidence(
                Evidence(
                    tool=tool,
                    summary=_summarize_evidence(tool, payload),
                    weight=_weight_for(tool, has_signal, retro=False),
                    payload=dict(payload),
                    tool_params=dict(params),
                    retro=False,
                )
            )

            # Retro pass for telemetry categories where it's meaningful.
            if (
                self._budget.retro_enabled
                and self._retro_eligible(node, tool)
                and state.retro_calls < self._budget.max_tool_calls
            ):
                retro_params = dict(params)
                retro_params["window_days"] = self._budget.retro_window_days
                retro_params["retro"] = True
                try:
                    retro_payload = await self._tool_caller.call(tool, retro_params)
                except Exception as exc:  # noqa: BLE001
                    state.retro_calls += 1
                    node.add_evidence(
                        Evidence(
                            tool=tool,
                            summary=f"retro {tool} failed: {exc}",
                            weight=0.0,
                            payload={"error": str(exc)},
                            tool_params=retro_params,
                            retro=True,
                        )
                    )
                else:
                    state.retro_calls += 1
                    retro_signal, _ = _payload_signal(retro_payload)
                    node.add_evidence(
                        Evidence(
                            tool=tool,
                            summary="retro " + _summarize_evidence(tool, retro_payload),
                            weight=_weight_for(tool, retro_signal, retro=True),
                            payload=dict(retro_payload),
                            tool_params=retro_params,
                            retro=True,
                        )
                    )

        # Score the node from accumulated evidence.
        verdict, confidence = _node_verdict_from_evidence(node)
        node.verdict = verdict
        node.confidence = confidence
        node.status = (
            HypothesisStatus.EXPLORED
            if node.evidence
            else HypothesisStatus.DEAD_END
        )

        # Spawn pivot children from the live evidence on this node.
        if node.depth < self._budget.max_depth:
            self._spawn_pivots(node, state, queue)

    def _params_for_tool(self, tool: str, node: HypothesisNode) -> dict[str, Any]:
        """Build the parameter dict for one tool invocation.

        We project the node's ``seed_params`` plus a couple of generic
        fallbacks. The explorer does not try to perfectly model every
        tool schema — the tool layer validates its own params. If a key
        is missing, the tool will reject the call and the resulting
        error becomes evidence with weight 0.0.
        """
        seed = dict(node.seed_params)
        if tool == "cti.darkweb_search":
            seed.setdefault("query", node.statement)
        elif tool == "cti.brand_intel":
            seed.setdefault("brand", seed.get("query") or node.statement)
        elif tool == "cti.asm_lookup":
            seed.setdefault("domain", seed.get("query") or node.statement)
        elif tool == "cti.vuln_intel":
            seed.setdefault("software", seed.get("query") or node.statement)
        elif tool == "cti.enrich_ioc":
            seed.setdefault("ioc", seed.get("ioc") or node.statement)
        elif tool == "siem.search_events":
            seed.setdefault("query", node.statement)
        elif tool == "siem.get_related_alerts":
            seed.setdefault("entity", seed.get("entity") or seed.get("host_id") or node.statement)
        elif tool == "edr.get_process_tree":
            seed.setdefault("host_id", seed.get("host_id") or node.statement)
        return seed

    def _retro_eligible(self, node: HypothesisNode, tool: str) -> bool:
        """Only telemetry-style tools meaningfully benefit from retro-hunt.

        Re-running ``cti.brand_intel`` over an extended window adds
        nothing — the CTI provider already does its own historicization.
        But ``siem.search_events`` and ``edr.get_process_tree`` over a
        30-day window can surface dormant beacons that the live window
        missed.
        """
        if not tool.startswith(("siem.", "edr.")):
            return False
        return node.category in {
            HypothesisCategory.PROCESS_BEHAVIOR,
            HypothesisCategory.NETWORK_BEHAVIOR,
            HypothesisCategory.HOST_PIVOT,
            HypothesisCategory.IOC_PIVOT,
        }

    def _spawn_pivots(
        self,
        node: HypothesisNode,
        state: _ExplorationState,
        queue: list[HypothesisNode],
    ) -> None:
        """Extract IOCs / hostnames from this node's evidence into children.

        Pivots are the reason the Hunter is a *tree* and not a list: each
        IOC we discover becomes its own hypothesis, classified into the
        ``IOC_PIVOT`` lane and routed to ``cti.enrich_ioc`` so the
        explorer can chase second-order signal.
        """
        spawned = 0
        for ev in node.evidence:
            if ev.retro:
                # Don't pivot off retro evidence to avoid double-counting
                # the same IOCs the live pass already produced.
                continue
            text = _payload_text(ev.payload)
            iocs = extract_iocs(text)
            for ioc in (*iocs["ips"], *iocs["domains"], *iocs["hashes"]):
                if spawned >= self._budget.max_pivots_per_node:
                    break
                if state.nodes_created >= self._budget.max_nodes:
                    break
                if ioc in state.iocs_pivoted:
                    continue
                state.iocs_pivoted.append(ioc)
                child = HypothesisNode(
                    statement=f"Investigate IOC {ioc} pivoted from {node.category.value}",
                    category=HypothesisCategory.IOC_PIVOT,
                    suggested_tools=("cti.enrich_ioc",),
                    seed_params={"ioc": ioc},
                )
                child.notes.append(f"Spawned by IOC pivot from node {node.node_id}.")
                node.add_child(child)
                queue.append(child)
                state.nodes_created += 1
                spawned += 1

            for host in extract_hostnames(text):
                if spawned >= self._budget.max_pivots_per_node:
                    break
                if state.nodes_created >= self._budget.max_nodes:
                    break
                child = HypothesisNode(
                    statement=f"Investigate host {host} pivoted from {node.category.value}",
                    category=HypothesisCategory.HOST_PIVOT,
                    suggested_tools=("edr.get_process_tree", "siem.get_related_alerts"),
                    seed_params={"host_id": host, "entity": host},
                )
                child.notes.append(f"Spawned by host pivot from node {node.node_id}.")
                node.add_child(child)
                queue.append(child)
                state.nodes_created += 1
                spawned += 1

    def _summarize_result(
        self,
        root: HypothesisNode,
        verdict: HypothesisVerdict,
        nodes_explored: int,
        state: _ExplorationState,
    ) -> str:
        descendants = list(root.iter_descendants())
        head = (
            f"Hunt verdict: {verdict.value}. "
            f"Explored {nodes_explored} node(s) "
            f"({len(descendants)} descendant pivot(s)) "
            f"using {state.tool_calls} live tool call(s)"
        )
        if state.retro_calls:
            head += f" and {state.retro_calls} retro call(s) over the past "
            head += f"{self._budget.retro_window_days} day(s)"
        head += "."

        if verdict == HypothesisVerdict.SUPPORTED:
            head += (
                " At least one branch produced positive signal — recommend "
                "escalating to an investigation case."
            )
        elif verdict == HypothesisVerdict.REFUTED:
            head += " No supporting signal in live or retro telemetry."
        elif verdict == HypothesisVerdict.INCONCLUSIVE:
            head += " Evidence too weak to either support or refute."
        return head

    def _follow_ups(
        self,
        root: HypothesisNode,
        verdict: HypothesisVerdict,
        state: _ExplorationState,
    ) -> list[str]:
        follow_ups: list[str] = []
        if verdict == HypothesisVerdict.SUPPORTED:
            follow_ups.append(
                "Promote the SUPPORTED branch into a case and assign the "
                "Investigator agent."
            )
        if state.iocs_pivoted:
            follow_ups.append(
                "Push pivoted IOCs into the watchlist and rerun the retro "
                "window in 24h."
            )
        # Any node that hit the budget gets surfaced so the analyst knows
        # the tree is incomplete.
        unfinished = [
            n
            for n in [root, *root.iter_descendants()]
            if n.status == HypothesisStatus.BUDGET_EXHAUSTED
        ]
        if unfinished:
            follow_ups.append(
                f"Re-run with a wider budget — {len(unfinished)} hypothesis "
                "node(s) were skipped."
            )
        return follow_ups


# ── Local helpers ───────────────────────────────────────────────────────


def _payload_text(payload: Any) -> str:
    """Flatten a tool payload into searchable text for IOC extraction.

    Recursively walks dicts / lists. Non-string scalars are stringified.
    Kept here (not on the model) so we can swap to a faster impl later
    without touching the public surface.
    """
    buf: list[str] = []

    def walk(obj: Any) -> None:
        if obj is None:
            return
        if isinstance(obj, str):
            buf.append(obj)
        elif isinstance(obj, (int, float, bool)):
            buf.append(str(obj))
        elif isinstance(obj, dict):
            for v in obj.values():
                walk(v)
        elif isinstance(obj, (list, tuple, set)):
            for item in obj:
                walk(item)

    walk(payload)
    return " ".join(buf)


__all__ = [
    "ExplorerBudget",
    "HypothesisTreeExplorer",
]
