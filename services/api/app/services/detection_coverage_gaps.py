"""Depth 2 wave 2 item 2.5 — rank what this tenant is not covered for.

The governed proposal flow already exists end to end: `detection_proposals.py`
takes a DRAFT, evaluates it against the harness, backtests it over real
tenant events, and promotes it only on a decision by someone other than the
author. What it never had was a reason to start. A proposal was something a
person thought of, so coverage grew wherever attention happened to fall.

This module supplies the ranking. It compares two things the tree already
knows and nothing had ever joined:

* which connectors **this tenant** has enabled, and
* which executable rules exist for each connector's product, and which of
  the named scenario families (item 2.1) are represented among them.

A gap is a connected source with no executable rule, a connected source with
rules but none from a family its peers have, or a family with no rule for
any connected source. Each carries the evidence that produced it, so a
reader can check the ranking rather than trust it.

Two things it deliberately does not do
--------------------------------------
It does not write a proposal. Ranking gaps and drafting rules are different
authorities, and the drafting path already has an approver requirement that
would be meaningless if the ranker could bypass it.

It does not rank a product the tenant has not connected. A tenant with no
Snowflake does not have a Snowflake coverage gap, and listing one would
bury the gaps they can act on under a catalogue of everything AiSOC could
in principle detect.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

#: Connector id -> the `product` its rules declare. The two namespaces are
#: genuinely different — `google_workspace` the connector emits rules tagged
#: `google-workspace` — and joining them by string similarity would silently
#: mis-attribute every underscore-versus-hyphen pair.
CONNECTOR_PRODUCT: dict[str, str] = {
    "aws_cloudtrail": "aws",
    "aws_cloudtrail_s3": "aws",
    "aws_guardduty": "aws",
    "aws_security_hub": "aws",
    "aws_vpc_flow": "aws",
    "azure_activity": "azure",
    "azure_defender": "azure",
    "azure_entra": "azure",
    "azure_event_hubs": "azure",
    "box": "box",
    "confluence_audit": "confluence",
    "dropbox": "dropbox",
    "gcp_cloud_audit": "gcp",
    "gcp_pubsub": "gcp",
    "gcp_scc": "gcp",
    "gcp_service_account": "gcp",
    "github": "github",
    "gitlab": "gitlab",
    "google_workspace": "google-workspace",
    "jira_connector": "atlassian",
    "kubernetes_audit": "kubernetes",
    "m365_audit": "m365",
    "okta": "okta",
    "onepassword": "onepassword",
    "salesforce": "salesforce",
    "servicenow": "servicenow",
    "slack_audit": "slack",
    "snowflake": "snowflake",
}


@dataclass(frozen=True)
class CoverageGap:
    """One ranked gap, with the evidence that produced it."""

    kind: str
    connector_id: str
    product: str
    family: str | None
    executable_rules: int
    rank: int
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "connector_id": self.connector_id,
            "product": self.product,
            "family": self.family,
            "executable_rules": self.executable_rules,
            "rank": self.rank,
            "reason": self.reason,
        }


def _ruleset_paths() -> list[Path]:
    """The compiled rulesets, wherever this service is running from.

    The API image ships a byte-identical copy under `app/data/detections`
    because its build context cannot see `services/fusion`. Both locations
    are searched so the ranking is the same in a container and in a checkout.
    """
    here = Path(__file__).resolve()
    roots: list[Path] = []
    for parent in here.parents:
        candidate = parent / "data" / "detections"
        if candidate.is_dir():
            roots.append(candidate)
        candidate = parent / "services" / "fusion" / "app" / "data"
        if candidate.is_dir():
            roots.append(candidate)
    paths: list[Path] = []
    for root in roots:
        for name in ("detection_ruleset.json", "detection_ruleset_imported.json"):
            path = root / name
            if path.is_file():
                paths.append(path)
        if paths:
            break
    return paths


@lru_cache(maxsize=1)
def corpus_shape() -> tuple[dict[str, int], dict[str, frozenset[str]], frozenset[str]]:
    """(rules per product, families per product, every declared family).

    Cached because it is a read of two committed artefacts that cannot
    change inside a process. `reset_cache()` exists for the tests.
    """
    per_product: dict[str, int] = {}
    families_by_product: dict[str, set[str]] = {}
    all_families: set[str] = set()
    for path in _ruleset_paths():
        try:
            rules = (json.loads(path.read_text(encoding="utf-8")) or {}).get("rules") or []
        except ValueError:
            continue
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            product = str(rule.get("product") or "")
            if not product:
                continue
            per_product[product] = per_product.get(product, 0) + 1
            family = rule.get("family")
            if family:
                families_by_product.setdefault(product, set()).add(str(family))
                all_families.add(str(family))
    return (
        per_product,
        {k: frozenset(v) for k, v in families_by_product.items()},
        frozenset(all_families),
    )


def reset_cache() -> None:
    corpus_shape.cache_clear()


#: Below this a connected source is thinly covered rather than uncovered.
#: Chosen as depth plan 3.6's own floor for a SaaS source, so the gap list
#: and the published minimum say the same thing.
THIN_COVERAGE = 20


def rank_gaps(connected: list[str]) -> list[CoverageGap]:
    """Gaps for this tenant's connected connectors, worst first.

    `connected` is connector ids, as the tenant's own `connectors` rows
    carry them. A connector with no product mapping is skipped and not
    reported as a gap — "AiSOC has no rules for this" and "this ranker does
    not know what product this connector emits" are different statements,
    and the second is a defect in this file rather than in the corpus.
    """
    per_product, families_by_product, all_families = corpus_shape()
    gaps: list[CoverageGap] = []
    seen_products: set[str] = set()

    for connector_id in sorted(set(connected)):
        product = CONNECTOR_PRODUCT.get(connector_id)
        if product is None:
            continue
        count = per_product.get(product, 0)
        if product in seen_products:
            continue
        seen_products.add(product)

        if count == 0:
            gaps.append(
                CoverageGap(
                    kind="uncovered_source",
                    connector_id=connector_id,
                    product=product,
                    family=None,
                    executable_rules=0,
                    rank=0,
                    reason=f"{connector_id} is connected and no executable rule declares product {product!r}.",
                )
            )
            continue
        if count < THIN_COVERAGE:
            gaps.append(
                CoverageGap(
                    kind="thin_source",
                    connector_id=connector_id,
                    product=product,
                    family=None,
                    executable_rules=count,
                    rank=THIN_COVERAGE - count,
                    reason=(
                        f"{connector_id} is connected and has {count} executable rules, below the "
                        f"{THIN_COVERAGE} depth plan 3.6 sets as a per-source minimum."
                    ),
                )
            )

        have = families_by_product.get(product, frozenset())
        for family in sorted(all_families - have):
            gaps.append(
                CoverageGap(
                    kind="uncovered_family",
                    connector_id=connector_id,
                    product=product,
                    family=family,
                    executable_rules=count,
                    rank=THIN_COVERAGE + 1,
                    reason=f"No rule in the {family!r} family declares product {product!r}, which {connector_id} emits.",
                )
            )

    # Worst first: an uncovered source outranks a thin one, which outranks a
    # missing family. Ties break on the connector id so the list is stable
    # across calls — a ranking that reorders on every request is one nobody
    # can act on across two sessions.
    return sorted(gaps, key=lambda g: (-g.rank, g.kind, g.connector_id, g.family or ""))
