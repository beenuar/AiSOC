"""The incident traversal must stay inside its tenant and fail legibly.

Two classes of bug matter here and neither shows up in a happy-path test.

Cross-tenant leakage: a traversal scoped only at its start node walks out
through a shared entity — a public IP two tenants have both seen — and
enumerates the other tenant's estate. This is the highest-value
reconnaissance query in the product, so every node of every path is scoped
and these tests read the generated Cypher to prove it.

Silent emptiness: an unreachable graph and an alert with genuinely no context
both produce an empty bundle. An agent cannot tell them apart, so it treats
"we could not look" as "there is nothing to find". Partial results must name
what failed.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

import pytest
from app.services import incident_context as module
from app.services.incident_context import (
    _DIMENSIONS,
    GLOBAL_LABELS,
    LIMIT_ASSETS,
    IncidentContext,
    get_incident_context,
)


def _bound_variables(cypher: str) -> dict[str, str]:
    """Variables bound by MATCH / OPTIONAL MATCH, mapped to their label."""
    bound: dict[str, str] = {}
    for line in cypher.splitlines():
        stripped = line.strip()
        if not stripped.startswith(("MATCH", "OPTIONAL MATCH")):
            continue
        for var, label in re.findall(r"\(\s*(\w+)\s*:\s*(\w+)", stripped):
            bound[var] = label
    return bound


TENANT = "11111111-1111-1111-1111-111111111111"
ALERT = "alert-abc"


class FakeResult:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows

    async def data(self) -> list[dict[str, Any]]:
        return self._rows


class FakeSession:
    """Answers each dimension by matching on a distinctive token in its Cypher."""

    def __init__(self, answers: dict[str, list[dict[str, Any]]] | None = None) -> None:
        self.answers = answers or {}
        self.queries: list[tuple[str, dict[str, Any]]] = []

    async def run(self, cypher: str, **params: Any) -> FakeResult:
        self.queries.append((cypher, params))
        for token, key in (
            ("Employee)-[:AUTHENTICATES_AS]", "identities"),
            ("AFFECTED_BY", "assets"),
            ("IN_ACCOUNT", "cloud"),
            (":RUNS]->(app:Application)", "business"),
            ("OBSERVED_IOC", "threat"),
        ):
            if token in cypher:
                return FakeResult(self.answers.get(key, []))
        return FakeResult([])


class TestTenantScoping:
    def test_every_matched_variable_is_scoped_or_globally_exempt(self) -> None:
        """Not just the start node.

        A path scoped only at its origin can leave the tenant through any
        shared node it traverses. The only acceptable exception is a label
        that holds no tenant data at all (MITRE vocabulary, public threat
        intel, CVE reference), and those are enumerated in GLOBAL_LABELS.
        """
        for name, cypher, _ in _DIMENSIONS:
            bound = _bound_variables(cypher)
            assert bound, f"{name}: parsed no bound variables; the test is vacuous"

            for var, label in bound.items():
                if label in GLOBAL_LABELS:
                    continue
                assert f"{var}.tenant_id = $tenant_id" in cypher, (
                    f"{name}: variable {var!r} (:{label}) is matched but never "
                    f"tenant-scoped, and {label} is not global reference data. "
                    f"A traversal through it can leave the tenant."
                )

    def test_global_labels_are_never_traversed_through(self) -> None:
        """A global node inside a variable-length hop is a cross-tenant bridge.

        Reaching a shared CVE or malware node from tenant A is fine. Walking
        *onward* from it is how the traversal arrives in tenant B's estate,
        so global labels may only ever appear as a terminal hop.
        """
        for name, cypher, _ in _DIMENSIONS:
            for line in cypher.splitlines():
                if "*" not in line:
                    continue
                # A variable-length pattern. Whatever it binds must be
                # tenant-scoped, never a global label.
                for var, label in _bound_variables(line).items():
                    assert label not in GLOBAL_LABELS, (
                        f"{name}: variable-length pattern binds global label " f"{label} as {var!r}; that node can bridge tenants"
                    )

    def test_null_tenant_is_not_treated_as_readable(self) -> None:
        """An untagged node would otherwise bridge two tenants."""
        for name, cypher, _ in _DIMENSIONS:
            assert "tenant_id IS NULL" not in cypher, name

    def test_global_reference_labels_are_the_only_exemption(self) -> None:
        for name, cypher, _ in _DIMENSIONS:
            if "$global_labels" in cypher:
                assert "labels(" in cypher, name
        # MITRE vocabulary and public intel are shared; tenant data is not.
        assert "Technique" in GLOBAL_LABELS and "ThreatActor" in GLOBAL_LABELS
        assert not any(
            label in GLOBAL_LABELS for label in ("Employee", "Application", "CloudAccount", "Secret", "IOC")
        ), "a tenant-scoped label was exempted from scoping"

    async def test_tenant_id_is_bound_as_a_parameter(self) -> None:
        """Interpolating it would make the predicate injectable."""
        session = FakeSession()
        await get_incident_context(ALERT, TENANT, session=session)
        assert session.queries
        for cypher, params in session.queries:
            assert params["tenant_id"] == TENANT
            assert TENANT not in cypher, "tenant id was interpolated into the query text"


class TestBoundedFanOut:
    def test_every_dimension_has_a_limit(self) -> None:
        """A traversal from a jump host is not slow, it is unbounded."""
        for name, cypher, extra in _DIMENSIONS:
            assert "LIMIT $limit" in cypher, f"{name} has no row cap"
            assert extra.get("limit", 0) > 0, name

    async def test_limits_are_passed_through(self) -> None:
        session = FakeSession()
        await get_incident_context(ALERT, TENANT, session=session)
        asset_query = next(q for q in session.queries if "AFFECTED_BY" in q[0])
        assert asset_query[1]["limit"] == LIMIT_ASSETS
        assert asset_query[1]["vuln_limit"] > 0


class TestPartialResults:
    async def test_one_failing_dimension_does_not_lose_the_others(self) -> None:
        class PartlyBroken(FakeSession):
            async def run(self, cypher: str, **params: Any) -> FakeResult:
                if "OBSERVED_IOC" in cypher:
                    raise RuntimeError("threat store unavailable")
                return await super().run(cypher, **params)

        session = PartlyBroken({"identities": [{"account": "svc_backup", "employee": "Dana Reed"}]})
        ctx = await get_incident_context(ALERT, TENANT, session=session)

        assert ctx.identities, "a failure in one dimension discarded another"
        assert ctx.is_partial
        assert any("threat" in e for e in ctx.errors)

    async def test_unreachable_graph_is_distinguishable_from_no_context(self) -> None:
        """Both produce an empty bundle; only one is a finding."""

        class Dead(FakeSession):
            async def run(self, cypher: str, **params: Any) -> FakeResult:
                raise ConnectionError("neo4j down")

        unreachable = await get_incident_context(ALERT, TENANT, session=Dead())
        genuinely_empty = await get_incident_context(ALERT, TENANT, session=FakeSession())

        assert unreachable.errors and not genuinely_empty.errors
        assert unreachable.is_partial and not genuinely_empty.is_partial
        assert unreachable.dimensions_resolved == genuinely_empty.dimensions_resolved == 0

    async def test_a_slow_dimension_does_not_hang_the_bundle(self) -> None:
        """This sits on the hot path of every escalated alert."""

        class Slow(FakeSession):
            async def run(self, cypher: str, **params: Any) -> FakeResult:
                if "IN_ACCOUNT" in cypher:
                    await asyncio.sleep(5)
                return await super().run(cypher, **params)

        original = module.QUERY_TIMEOUT_SECONDS
        module.QUERY_TIMEOUT_SECONDS = 0.05
        try:
            ctx = await asyncio.wait_for(
                get_incident_context(ALERT, TENANT, session=Slow({"assets": [{"id": "h1"}]})),
                timeout=3,
            )
        finally:
            module.QUERY_TIMEOUT_SECONDS = original

        assert ctx.assets, "a slow dimension blocked a fast one"
        assert any("cloud" in e for e in ctx.errors)


class TestNarrative:
    def test_departed_employee_with_a_live_account_is_called_out(self) -> None:
        """The single highest-signal fact this traversal can produce."""
        ctx = IncidentContext(alert_id=ALERT, tenant_id=TENANT)
        ctx.identities = [{"account": "j.doe", "employee": "Jordan Doe", "is_active": False}]
        text = "\n".join(ctx.narrative_lines())
        assert "no longer active" in text

    def test_attribution_is_never_rendered_as_fact(self) -> None:
        """Attribution is contested and frequently revised."""
        ctx = IncidentContext(alert_id=ALERT, tenant_id=TENANT)
        ctx.threat = [{"ioc": "1.2.3.4", "actor": "APT-Example"}]
        text = "\n".join(ctx.narrative_lines())
        assert "unconfirmed" in text

        ctx.threat = [{"ioc": "1.2.3.4", "actor": "APT-Example", "attribution_confidence": 80}]
        assert "confidence 80" in "\n".join(ctx.narrative_lines())

    def test_known_exploited_vulnerabilities_are_counted_separately(self) -> None:
        ctx = IncidentContext(alert_id=ALERT, tenant_id=TENANT)
        ctx.assets = [
            {
                "name": "web-01",
                "vulnerabilities": [
                    {"cve_id": "CVE-2026-1", "known_exploited": True},
                    {"cve_id": "CVE-2026-2", "known_exploited": False},
                ],
            }
        ]
        text = "\n".join(ctx.narrative_lines())
        assert "2 known vulnerabilities" in text and "1 known-exploited" in text

    def test_partial_context_says_so_in_the_prompt(self) -> None:
        """Otherwise the model reasons over a gap it cannot see."""
        ctx = IncidentContext(alert_id=ALERT, tenant_id=TENANT)
        ctx.identities = [{"account": "a"}]
        ctx.errors = ["threat (ConnectionError)"]
        assert "context is partial" in "\n".join(ctx.narrative_lines())

    def test_no_context_renders_nothing_rather_than_empty_headings(self) -> None:
        ctx = IncidentContext(alert_id=ALERT, tenant_id=TENANT)
        assert ctx.narrative_lines() == []


async def test_null_columns_are_dropped_from_rows() -> None:
    """Neo4j returns every RETURN key even when an OPTIONAL MATCH missed."""
    session = FakeSession({"identities": [{"account": "svc", "employee": None, "manager": None, "title": ""}]})
    ctx = await get_incident_context(ALERT, TENANT, session=session)
    assert ctx.identities == [{"account": "svc"}]


async def test_all_five_dimensions_are_queried() -> None:
    session = FakeSession()
    await get_incident_context(ALERT, TENANT, session=session)
    assert len(session.queries) == 5, "a dimension was dropped from the traversal"


@pytest.mark.parametrize("dimension", ["identities", "assets", "cloud", "business", "threat"])
async def test_each_dimension_populates_its_own_slot(dimension: str) -> None:
    session = FakeSession({dimension: [{"id": "x", "account_id": "1", "name": "n", "ioc": "i"}]})
    ctx = await get_incident_context(ALERT, TENANT, session=session)
    assert getattr(ctx, dimension), f"{dimension} query ran but its slot stayed empty"
    assert ctx.dimensions_resolved == 1
