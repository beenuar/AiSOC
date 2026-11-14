"""Item 2.5: gaps are ranked against what the tenant actually connected."""

from __future__ import annotations

import pytest
from app.services.detection_coverage_gaps import (
    CONNECTOR_PRODUCT,
    THIN_COVERAGE,
    corpus_shape,
    rank_gaps,
    reset_cache,
)


@pytest.fixture(autouse=True)
def _clear() -> None:
    reset_cache()


def test_the_corpus_is_actually_readable_from_the_api_service() -> None:
    """The API image ships its own copy; a zero here is a wiring failure.

    The API's Docker build context cannot see `services/fusion`, which is
    why the artefacts are sync-committed into the API tree. A ranker that
    silently read an empty corpus would report every connected source as
    uncovered, which is the most alarming possible way to be broken.
    """
    per_product, families, all_families = corpus_shape()
    assert per_product, "no compiled ruleset was found from the API service"
    assert per_product.get("aws", 0) > 0
    assert all_families, "no rule declares a scenario family"


def test_unconnected_products_are_not_reported() -> None:
    """A tenant with no Snowflake does not have a Snowflake gap."""
    gaps = rank_gaps(["aws_cloudtrail"])
    assert {g.product for g in gaps} <= {"aws"}


def test_a_connected_source_below_the_minimum_is_thin_not_uncovered() -> None:
    per_product, _families, _all = corpus_shape()
    thin = [c for c, p in CONNECTOR_PRODUCT.items() if 0 < per_product.get(p, 0) < THIN_COVERAGE]
    if not thin:
        pytest.skip("every mapped product now meets the per-source minimum")
    gaps = rank_gaps([thin[0]])
    kinds = {g.kind for g in gaps}
    assert "thin_source" in kinds
    assert "uncovered_source" not in kinds


def test_unknown_connector_is_skipped_rather_than_reported_as_a_gap() -> None:
    """Not knowing a connector's product is a defect here, not in the corpus."""
    assert rank_gaps(["a_connector_that_does_not_exist"]) == []


def test_missing_families_are_reported_per_connected_product() -> None:
    gaps = rank_gaps(["slack_audit"])
    families = {g.family for g in gaps if g.kind == "uncovered_family"}
    # Slack has third-party-access rules, so that family must not appear as
    # a gap, while a family it has no rule in must.
    assert "third-party-access" not in families
    assert families, "slack is in no other family and the ranker found nothing"


def test_ranking_is_stable_and_worst_first() -> None:
    first = rank_gaps(["slack_audit", "aws_cloudtrail", "box"])
    second = rank_gaps(["box", "aws_cloudtrail", "slack_audit"])
    assert [g.as_dict() for g in first] == [g.as_dict() for g in second]
    ranks = [g.rank for g in first]
    assert ranks == sorted(ranks, reverse=True)


def test_every_mapped_connector_id_exists() -> None:
    """A mapping entry for a connector that is not registered is dead.

    Checked against the connector registry's own module list rather than a
    second copy of it, so a renamed connector fails here instead of quietly
    dropping its product from every tenant's ranking.
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[3]
    directory = root / "services" / "connectors" / "app" / "connectors"
    on_disk = {p.stem for p in directory.glob("*.py")}
    missing = sorted(c for c in CONNECTOR_PRODUCT if c not in on_disk)
    assert not missing, f"CONNECTOR_PRODUCT names connectors that do not exist: {missing}"
