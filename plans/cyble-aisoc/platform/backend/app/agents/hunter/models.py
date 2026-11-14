"""Data contracts for the iterative hypothesis-tree Hunter.

The Hunter rebuilds the proactive threat-hunting flow as a tree of
*hypotheses*. Each node carries:

- A natural-language statement (what we suspect).
- A deterministic classification (what kind of hypothesis it is so the
  explorer knows which tools answer it).
- Status / verdict bookkeeping so the tree converges on a SOC decision.
- The evidence the explorer pulled from CTI / SIEM / EDR while testing it.

The tree is intentionally a plain dataclass graph — not an ORM model — so it
can be built, mutated, snapshotted, serialized to a trace row, and replayed
in tests without DB plumbing.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


# ── Classification ──────────────────────────────────────────────────────


class HypothesisCategory(str, Enum):
    """Coarse category produced by the deterministic classifier.

    The category tells the explorer which tools to default-pivot through.
    Free-form LLM text is fine for the *statement* of a hypothesis; the
    *category* is a closed set so the tree expansion logic stays testable.
    """

    CREDENTIAL_LEAK = "credential_leak"
    """Credentials / cookies / tokens potentially exposed (darkweb, leak sites)."""

    EXTERNAL_EXPOSURE = "external_exposure"
    """Externally-reachable assets (open ports, exposed admin panels, ASM)."""

    VULNERABILITY = "vulnerability"
    """CVE / patch posture / vulnerable software."""

    BRAND_IMPERSONATION = "brand_impersonation"
    """Typosquats, phishing infrastructure, brand abuse."""

    PROCESS_BEHAVIOR = "process_behavior"
    """Endpoint behavior — process trees, command lines, parent/child anomalies."""

    NETWORK_BEHAVIOR = "network_behavior"
    """Network telemetry — beacons, DNS, egress patterns."""

    IOC_PIVOT = "ioc_pivot"
    """Spawned by extracting an IOC (IP/domain/hash) from prior evidence."""

    HOST_PIVOT = "host_pivot"
    """Spawned by extracting a host/asset identifier from prior evidence."""

    OTHER = "other"
    """Free-form hypothesis the classifier could not bucket."""


class HypothesisStatus(str, Enum):
    """Lifecycle of a single node in the hypothesis tree."""

    PENDING = "pending"
    """Created but not yet explored."""

    EXPLORING = "exploring"
    """Tools are currently being called against it."""

    EXPLORED = "explored"
    """Tools ran; evidence captured; verdict computed."""

    DEAD_END = "dead_end"
    """Explored but produced no useful signal — pruned."""

    BUDGET_EXHAUSTED = "budget_exhausted"
    """Could not explore — explorer hit its global tool / depth budget."""


class HypothesisVerdict(str, Enum):
    """The explorer's verdict for an individual hypothesis."""

    UNKNOWN = "unknown"
    """Default before any evidence is gathered, or when evidence is ambiguous."""

    SUPPORTED = "supported"
    """Evidence points toward the hypothesis being true."""

    REFUTED = "refuted"
    """Evidence points toward the hypothesis being false."""

    INCONCLUSIVE = "inconclusive"
    """Evidence exists but is too weak to either support or refute."""


# ── Evidence ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Evidence:
    """One piece of evidence pulled from a tool while testing a hypothesis.

    Frozen so the explorer can stash an immutable record of *what we saw at
    the time*. Even if the upstream system later changes the answer, the
    case file keeps the original observation.
    """

    tool: str
    """Fully-qualified tool name, e.g. `cti.darkweb_search`."""

    summary: str
    """One-line analyst-readable description (what this evidence shows)."""

    weight: float
    """Signed confidence in `[-1.0, 1.0]`. Positive = supports, negative = refutes."""

    payload: dict[str, Any] = field(default_factory=dict)
    """The (sanitized, provenance-stripped) tool response."""

    tool_params: dict[str, Any] = field(default_factory=dict)
    """Exact parameters passed to the tool — for reproducibility."""

    retro: bool = False
    """True if pulled via the extended retro-hunt window rather than live."""

    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ── Hypothesis nodes ────────────────────────────────────────────────────


@dataclass
class HypothesisNode:
    """A single node in the hypothesis tree.

    Not frozen: the explorer flips status / verdict and appends evidence /
    children as exploration proceeds. The `node_id` is stable so the same
    node referenced from a parent's `children` list stays addressable.
    """

    statement: str
    """Natural-language hypothesis (analyst-readable)."""

    category: HypothesisCategory
    """Deterministic bucket, set by the classifier."""

    status: HypothesisStatus = HypothesisStatus.PENDING
    verdict: HypothesisVerdict = HypothesisVerdict.UNKNOWN

    confidence: float = 0.0
    """Aggregated confidence in `[-1.0, 1.0]`; sign matches the verdict."""

    suggested_tools: tuple[str, ...] = ()
    """Tools the classifier wants the explorer to try first."""

    seed_params: dict[str, Any] = field(default_factory=dict)
    """Default parameters (entity, IOC, query) the classifier extracted."""

    evidence: list[Evidence] = field(default_factory=list)
    children: list["HypothesisNode"] = field(default_factory=list)

    depth: int = 0
    """Depth in the tree; root nodes are 0."""

    parent_id: Optional[str] = None
    """`node_id` of the parent, or None for the root."""

    node_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    notes: list[str] = field(default_factory=list)
    """Free-form analyst-readable notes appended by the explorer."""

    def add_child(self, child: "HypothesisNode") -> "HypothesisNode":
        """Attach `child` to this node, stamping parent + depth."""
        child.parent_id = self.node_id
        child.depth = self.depth + 1
        self.children.append(child)
        return child

    def add_evidence(self, ev: Evidence) -> None:
        self.evidence.append(ev)

    def iter_descendants(self):
        """DFS over every descendant (excluding self)."""
        for child in self.children:
            yield child
            yield from child.iter_descendants()


# ── Aggregate result ────────────────────────────────────────────────────


@dataclass(frozen=True)
class HuntResult:
    """The full result of one hunt: the tree, totals, and a verdict.

    Frozen so the orchestrator / API layer can serialize it once and trust
    it for the rest of the request.
    """

    root: HypothesisNode

    nodes_explored: int
    tool_calls: int
    retro_calls: int

    verdict: HypothesisVerdict
    """Aggregated verdict across the whole tree."""

    summary: str
    """Analyst-ready one-paragraph readout."""

    follow_ups: tuple[str, ...] = ()
    """Concrete next-step actions the explorer recommends."""

    iocs_pivoted: tuple[str, ...] = ()
    """Distinct IOCs (IPs / domains / hashes) that produced child hypotheses."""

    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def all_nodes(self) -> list[HypothesisNode]:
        """Flat list of every node in the tree, root first."""
        out = [self.root]
        out.extend(self.root.iter_descendants())
        return out
