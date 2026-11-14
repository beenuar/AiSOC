"""MCP-aligned marketplace + open eval benchmark (t3g-mcp-marketplace).

Two surfaces:

1.  **Marketplace catalog** — a curated list of tools and connectors
    with vendor metadata, verification badges, install instructions,
    and links to source repositories. Built on top of the existing
    :class:`ToolRegistry` and connector factory registry so the
    marketplace listing is always derived from what the platform can
    actually call (no drift between docs and reality).

2.  **Benchmark suite** — a versioned set of analyst-grade scenarios
    (e.g. "FIN7 phishing chain", "CL0P MOVEit exposure", "Okta
    impersonation") with deterministic graders. The scaffolding lets
    operators run a benchmark on the local platform, compare scores
    against historical runs, and submit results to the public
    leaderboard.

Design rules:

- Read-only and dependency-light: no DB writes from the marketplace
  catalog endpoints (the catalog is computed from the in-memory
  registries on each call); benchmark runs do persist to the DB so
  history is queryable.
- MCP-aligned: every entry exposes the same fields an MCP server
  manifest carries (``name``, ``description``, ``params_schema``,
  ``result_schema``, ``vendor``, ``risk``) so the marketplace JSON
  is a superset of an MCP listing.
- Trust-first: every entry carries a ``verified`` flag. Cyble-native
  tools start verified; community submissions go through the curated
  review path before flipping the flag.
"""
from app.marketplace.benchmark import (
    BenchmarkOutcome,
    BenchmarkRunner,
    BenchmarkScenario,
    benchmark_runner,
    builtin_scenarios,
)
from app.marketplace.catalog import (
    ConnectorEntry,
    MarketplaceCatalog,
    ToolEntry,
    catalog,
)
from app.marketplace.redteam import (
    AdversarialAttack,
    AttackOutcome,
    REDTEAM_VERSION,
    RedTeamOutcome,
    RedTeamRunner,
    builtin_attacks,
    redteam_runner,
)

__all__ = [
    "AdversarialAttack",
    "AttackOutcome",
    "BenchmarkOutcome",
    "BenchmarkRunner",
    "BenchmarkScenario",
    "ConnectorEntry",
    "MarketplaceCatalog",
    "REDTEAM_VERSION",
    "RedTeamOutcome",
    "RedTeamRunner",
    "ToolEntry",
    "benchmark_runner",
    "builtin_attacks",
    "builtin_scenarios",
    "catalog",
    "redteam_runner",
]
