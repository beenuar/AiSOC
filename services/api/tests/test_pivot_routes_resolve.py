"""Every pivot the Investigation Rail emits must resolve to a real console route.

``test_alert_rail.py`` already pins the pivot strings, with a docstring saying
the pin "prevents an accidental rename". It cannot: it compares the producer
against a copy of itself. For months it asserted ``/attack-graph?entity=…``
while ``apps/web`` defined no ``attack-graph`` route at all, so every entity
chip in the rail 404'd — and the pin reported OK the whole time, because
nothing ever compared the emitted path against the routes that exist.

This gate closes that direction. It derives the route table from the Next.js
app directory on disk and checks it against what ``build_related_entities``
*actually returns* for a fully-populated alert, rather than against a regex
over the producer's source. A pivot that stops resolving fails here whether
the producer moved or the route did.

AiSOC — open-source AI Security Operations Center (MIT License)
"""

from __future__ import annotations

import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import unquote, urlsplit

import pytest
from app.services.alert_rail import build_related_entities

# services/api/tests/test_pivot_routes_resolve.py → repo root is four up.
REPO_ROOT = Path(__file__).resolve().parents[3]
APP_DIR = REPO_ROOT / "apps" / "web" / "src" / "app"

_PAGE_SUFFIXES = {".tsx", ".ts", ".jsx", ".js"}


def _route_patterns(app_dir: Path) -> set[tuple[str, ...]]:
    """The addressable routes ``apps/web`` defines, as segment tuples.

    Next.js App Router conventions: ``(group)`` segments are organisational and
    contribute nothing to the URL, ``[param]`` matches one segment, ``[...rest]``
    one or more, ``[[...rest]]`` zero or more. Directories under a ``@slot``
    parallel route are not addressable on their own and are skipped.
    """
    patterns: set[tuple[str, ...]] = set()
    for page in app_dir.rglob("page.*"):
        if page.suffix not in _PAGE_SUFFIXES:
            continue
        segments: list[str] = []
        for part in page.parent.relative_to(app_dir).parts:
            if part.startswith("@"):
                break
            if part.startswith("(") and part.endswith(")"):
                continue
            segments.append(part)
        else:
            patterns.add(tuple(segments))
    return patterns


def _pattern_matches(pattern: tuple[str, ...], segments: tuple[str, ...]) -> bool:
    index = 0
    for part in pattern:
        if part.startswith("[[...") and part.endswith("]]"):
            return True
        if part.startswith("[...") and part.endswith("]"):
            return index < len(segments)
        if index >= len(segments):
            return False
        if not (part.startswith("[") and part.endswith("]")) and part != segments[index]:
            return False
        index += 1
    return index == len(segments)


def _resolves(path: str, patterns: set[tuple[str, ...]]) -> bool:
    segments = tuple(s for s in unquote(urlsplit(path).path).split("/") if s)
    return any(_pattern_matches(p, segments) for p in patterns)


def _fully_populated_alert() -> SimpleNamespace:
    """One alert carrying every field the rail knows how to pivot on.

    Populated rather than minimal on purpose: a pivot that is only built for
    (say) a destination IP is exactly the one a sparse fixture never exercises.
    """
    base: dict[str, Any] = {
        "id": uuid.uuid4(),
        "tenant_id": uuid.uuid4(),
        "severity": "high",
        "title": "Suspicious authentication",
        "connector_type": "okta",
        "case_id": uuid.uuid4(),
        "ai_recommendations": [],
        "affected_ips": ["10.0.0.7"],
        "affected_hosts": ["WIN-DC01"],
        "affected_users": ["alice@example.com"],
        "affected_assets": ["Finance File Server"],
        "mitre_tactics": [{"id": "TA0006", "name": "Credential Access"}],
        "mitre_techniques": [{"id": "T1110", "name": "Brute Force"}],
        "raw_event": {
            "dst_ip": "198.51.100.9",
            "domain": "updates.example.test",
            "url": "https://updates.example.test/payload",
            "rule_name": "Impossible travel",
        },
        "enrichment_data": {"rba_top_promotion": {"entity": "host:WIN-DC01"}},
    }
    return SimpleNamespace(**base)


@pytest.fixture(scope="module")
def route_patterns() -> set[tuple[str, ...]]:
    assert APP_DIR.is_dir(), (
        f"Next.js app directory not found at {APP_DIR}. This gate compares the "
        "rail's pivots against the routes the console defines; without the web "
        "tree it would pass by doing nothing."
    )
    patterns = _route_patterns(APP_DIR)
    assert patterns, f"no page.tsx found under {APP_DIR}"
    return patterns


def test_the_route_table_is_parsed_the_way_next_resolves_it(route_patterns):
    """Guard the parser itself, so a silent mis-parse cannot make the gate vacuous.

    If ``_route_patterns`` returned nothing useful every assertion below would
    pass trivially, which is the failure mode this whole file exists to remove.
    """
    assert _resolves("/graph", route_patterns)
    assert _resolves("/alerts", route_patterns)
    # A route group contributes nothing to the URL: /graph lives at (app)/graph.
    assert not _resolves("/(app)/graph", route_patterns)
    # Dynamic segments match one segment, and only one.
    assert _resolves("/cases/INC-1", route_patterns)
    assert not _resolves("/cases/INC-1/extra", route_patterns)
    # A route nobody defines must not resolve, or the gate proves nothing.
    assert not _resolves("/attack-graph", route_patterns)
    assert not _resolves("/no-such-route", route_patterns)


def test_every_rail_pivot_resolves_to_a_defined_route(route_patterns):
    entities = build_related_entities(_fully_populated_alert())
    pivots = [(e.kind, e.pivot) for e in entities if e.pivot]
    assert pivots, "fixture produced no pivots — the gate would pass vacuously"

    broken = [(kind, pivot) for kind, pivot in pivots if not _resolves(pivot, route_patterns)]
    assert not broken, "these pivots 404 — no route in apps/web/src/app matches them: " f"{broken}"


def test_the_entity_pivots_target_the_graph_route_that_reads_the_parameter(
    route_patterns,
):
    """The chip has to land on the page that honours ``?entity=``.

    Resolving to *some* route is not enough. ``AttackGraphView`` is the only
    view that reads the parameter and selects the node; any other resolving
    path would silently drop the entity and land the analyst on a generic page,
    which is the softer version of the same bug.
    """
    entities = build_related_entities(_fully_populated_alert())
    graph_kinds = {"host", "user", "asset", "ip", "domain"}
    targeted = [e for e in entities if e.kind in graph_kinds and e.pivot]
    assert targeted, "fixture produced no entity pivots"

    for entity in targeted:
        split = urlsplit(entity.pivot)
        assert split.path == "/graph", f"{entity.kind} pivot targets {split.path!r}; only /graph parses ?entity="
        assert split.query.startswith("entity="), entity.pivot
        assert _resolves(entity.pivot, route_patterns)


def test_a_value_with_url_metacharacters_survives_the_round_trip():
    """An unencoded value truncates the parameter at the first ``&`` or ``#``.

    ``AttackGraphView`` splits on the first colon and uses the remainder, so the
    producer has to encode the value the same way the federated-search helper
    (``apps/web/src/components/federated/pivot.ts``) does — otherwise an asset
    named ``Finance & Legal`` pivots to ``Finance`` and looks like it worked.
    """
    alert = _fully_populated_alert()
    alert.affected_assets = ["Finance & Legal #2"]
    alert.affected_hosts = []
    alert.affected_users = []
    alert.affected_ips = []
    alert.raw_event = {}
    alert.enrichment_data = {}

    asset = next(e for e in build_related_entities(alert) if e.kind == "asset")
    query = urlsplit(asset.pivot).query
    assert query.count("=") == 1, f"value leaked out of the parameter: {asset.pivot}"

    # Decoding the parameter has to give the value back unchanged.
    raw = unquote(query.removeprefix("entity="))
    assert raw == "asset:Finance & Legal #2"
