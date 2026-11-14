"""CORE gets real indicator evidence, with expiry and decay.

Parity plan 3.1.

What was wrong
--------------
`AlertEnricher` asks the **enrichment service**, which runs in the `full`
profile. On a CORE install that call fails, the exception is caught, logged
at `debug` and `{}` is returned, so the investigation agent receives "could
not check" for every indicator on every alert. That is the first thing the
capability review found: the default install gives the agent almost nothing
to reason with.

The tenant's own `threat_intel_iocs` table is in the Postgres every CORE
service already connects to, and CORE ships a real CISA KEV feed, so there
is genuinely something to match on a first run.

Why decay is tested as hard as matching
---------------------------------------
A matcher with no decay treats a two-year-old commodity IP with the weight
of a fresh one, which is how a stale feed produces confident nonsense. The
half-lives are judgement rather than measurement and are labelled as such,
but the *shape* is testable: an IP must fade faster than a file hash,
because an address reassigns and bytes do not.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

import pytest
from app.services.ioc_match import (
    DEFAULT_HALF_LIFE_DAYS,
    HALF_LIFE_DAYS,
    WEAK_CONFIDENCE_FLOOR,
    TenantIocMatcher,
    decay_factor,
    effective_confidence,
)

NOW = datetime(2026, 10, 1, tzinfo=UTC)


class _Conn:
    def __init__(self, rows) -> None:  # noqa: ANN001
        self.rows = rows
        self.queries: list[str] = []

    async def fetch(self, sql: str, *args):  # noqa: ANN001, ARG002
        self.queries.append(sql)
        return self.rows


class _Pool:
    def __init__(self, conn: _Conn) -> None:
        self._conn = conn

    @asynccontextmanager
    async def acquire(self):
        yield self._conn


def _row(**kw):  # noqa: ANN001, ANN201
    base = {
        "ioc_type": "ip",
        "value": "203.0.113.9",
        "confidence": 90,
        "severity": "high",
        "source": "cisa-kev",
        "last_seen": NOW,
        "threat_actor": None,
        "malware_family": None,
    }
    base.update(kw)
    return base


class TestDecay:
    def test_a_fresh_indicator_is_not_decayed(self) -> None:
        effective, age, _ = effective_confidence(confidence=90, last_seen=NOW, ioc_type="ip", now=NOW)
        assert effective == 90.0
        assert age == 0.0

    def test_one_half_life_halves_it(self) -> None:
        half_life = HALF_LIFE_DAYS["ip"]
        effective, _, _ = effective_confidence(
            confidence=90,
            last_seen=NOW - timedelta(days=half_life),
            ioc_type="ip",
            now=NOW,
        )
        assert effective == pytest.approx(45.0, abs=0.1)

    def test_an_ip_fades_faster_than_a_file_hash(self) -> None:
        """The shape that matters. An address reassigns; bytes do not."""
        age = timedelta(days=60)
        ip, _, _ = effective_confidence(confidence=90, last_seen=NOW - age, ioc_type="ip", now=NOW)
        sha, _, _ = effective_confidence(confidence=90, last_seen=NOW - age, ioc_type="sha256", now=NOW)
        assert ip < sha / 3, (
            f"an IP at 60 days scored {ip:.1f} and a hash {sha:.1f}; they are being treated "
            "as equally durable, which is how a stale feed produces confident nonsense"
        )

    def test_an_unknown_type_gets_the_default_half_life(self) -> None:
        _, _, half_life = effective_confidence(confidence=50, last_seen=NOW, ioc_type="something-new", now=NOW)
        assert half_life == DEFAULT_HALF_LIFE_DAYS

    def test_a_missing_last_seen_is_not_decayed_to_zero(self) -> None:
        """No timestamp is not evidence of age."""
        effective, _, _ = effective_confidence(confidence=70, last_seen=None, ioc_type="ip", now=NOW)
        assert effective == 70.0

    @pytest.mark.parametrize(("age", "half_life", "expected"), [(0, 30, 1.0), (30, 30, 0.5), (60, 30, 0.25)])
    def test_the_curve(self, age: float, half_life: float, expected: float) -> None:
        assert decay_factor(age, half_life) == pytest.approx(expected, abs=0.001)


@pytest.mark.asyncio
class TestMatching:
    async def test_a_known_indicator_matches(self) -> None:
        matcher = TenantIocMatcher(_Pool(_Conn([_row()])))
        matches = await matcher.match(tenant_id="t1", indicators=[{"ioc_type": "ip", "value": "203.0.113.9"}], now=NOW)
        assert len(matches) == 1
        assert matches[0].value == "203.0.113.9"
        assert matches[0].effective_confidence == 90.0

    async def test_the_query_excludes_expired_inactive_and_false_positive_rows(self) -> None:
        """Expiry is a hard gate in SQL, not a filter afterwards.

        Filtering in Python would read every indicator the tenant has ever
        had on every alert.
        """
        conn = _Conn([])
        matcher = TenantIocMatcher(_Pool(conn))
        await matcher.match(tenant_id="t1", indicators=[{"ioc_type": "ip", "value": "x"}], now=NOW)
        sql = conn.queries[0]
        assert "is_active = TRUE" in sql
        assert "false_positive = FALSE" in sql
        assert "expires_at IS NULL OR expires_at > NOW()" in sql

    async def test_a_row_the_alert_did_not_ask_about_is_dropped(self) -> None:
        """The two array predicates match a cross-product, so a tenant with
        `(ip, A)` and `(domain, B)` would match an alert carrying
        `(ip, B)`."""
        conn = _Conn([_row(ioc_type="domain", value="evil.example")])
        matcher = TenantIocMatcher(_Pool(conn))
        matches = await matcher.match(
            tenant_id="t1",
            indicators=[{"ioc_type": "domain", "value": "other.example"}],
            now=NOW,
        )
        assert matches == []

    async def test_a_query_failure_is_logged_loudly_and_returns_nothing(self) -> None:
        """A matcher that silently stops matching looks exactly like a
        tenant with no indicators, and the agent would report "no known
        indicators" as a finding."""

        class _Broken:
            @asynccontextmanager
            async def acquire(self):
                raise RuntimeError("down")
                yield  # pragma: no cover

        matcher = TenantIocMatcher(_Broken())
        assert await matcher.match(tenant_id="t1", indicators=[{"ioc_type": "ip", "value": "x"}]) == []

    async def test_no_pool_means_no_match_rather_than_an_error(self) -> None:
        matcher = TenantIocMatcher(None)
        assert matcher.available is False
        assert await matcher.match(tenant_id="t1", indicators=[{"ioc_type": "ip", "value": "x"}]) == []


class TestTheEnrichmentShape:
    def test_a_weak_hit_is_reported_rather_than_dropped(self) -> None:
        """ "We have seen this, weakly" is different information from "we
        have never seen this"."""
        matcher = TenantIocMatcher(None)
        old = NOW - timedelta(days=365)
        effective, age, half_life = effective_confidence(confidence=40, last_seen=old, ioc_type="ip", now=NOW)
        assert effective < WEAK_CONFIDENCE_FLOOR

        from app.services.ioc_match import IocMatch

        match = IocMatch(
            ioc_type="ip",
            value="203.0.113.9",
            confidence=40,
            effective_confidence=effective,
            severity="low",
            source="feed",
            age_days=age,
            half_life_days=half_life,
        )
        out = matcher.to_enrichments([match])
        assert out["ti_hits"], "the weak hit was dropped"
        assert out["ti_weak_hits"] == 1
        assert out["ti_strong_hits"] == 0

    def test_every_hit_explains_its_own_decay(self) -> None:
        """So a reader does not have to re-derive it to trust the number."""
        from app.services.ioc_match import IocMatch

        match = IocMatch(
            ioc_type="ip",
            value="v",
            confidence=90,
            effective_confidence=45.0,
            severity="high",
            source="s",
            age_days=30.0,
            half_life_days=30.0,
        )
        note = match.as_dict()["decay_note"]
        assert "90" in note and "45" in note and "30" in note

    def test_the_scope_is_stated(self) -> None:
        """So the agent does not read a local-only match as a full-spectrum
        intelligence verdict."""
        from app.services.ioc_match import IocMatch

        matcher = TenantIocMatcher(None)
        out = matcher.to_enrichments(
            [
                IocMatch(
                    ioc_type="ip",
                    value="v",
                    confidence=90,
                    effective_confidence=90.0,
                    severity="high",
                    source="s",
                    age_days=0.0,
                    half_life_days=30.0,
                )
            ]
        )
        assert "tenant" in out["ti_scope"].lower()
        assert "full" in out["ti_scope"]

    def test_no_matches_produces_no_keys(self) -> None:
        """An empty enrichment dict, not a dict of empty lists: the latter
        reads downstream as "checked, found nothing" from a source that may
        not have run."""
        assert TenantIocMatcher(None).to_enrichments([]) == {}


@pytest.mark.asyncio
class TestTheEnricherUsesIt:
    async def test_a_local_match_survives_the_enrichment_service_being_absent(self) -> None:
        """The whole point. On CORE the external call fails, and before
        this the method returned `{}`."""
        from app.services.alert_enricher import AlertEnricher

        class _Matcher:
            available = True

            async def match(self, *, tenant_id, indicators, now=None):  # noqa: ANN001, ARG002
                from app.services.ioc_match import IocMatch

                return [
                    IocMatch(
                        ioc_type="ip",
                        value="203.0.113.9",
                        confidence=90,
                        effective_confidence=90.0,
                        severity="high",
                        source="cisa-kev",
                        age_days=0.0,
                        half_life_days=30.0,
                    )
                ]

            def to_enrichments(self, matches):  # noqa: ANN001
                return {"ti_hits": [m.as_dict() for m in matches], "ti_source": "tenant_ioc_store"}

        enricher = AlertEnricher(
            # Unroutable on purpose: this is the CORE case, where the
            # enrichment service is not running.
            base_url="http://127.0.0.1:1",
            timeout_seconds=0.05,
            # Duck-typed stand-ins. The enricher only calls `available`,
            # `match` and `to_enrichments`, and a real `TenantIocMatcher`
            # would need a live pool to construct.
            ioc_matcher=_Matcher(),  # type: ignore[arg-type]
        )

        class _Alert:
            tenant_id = "00000000-0000-0000-0000-000000000001"
            src_ip = "203.0.113.9"

        result = await enricher.enrich(_Alert())  # type: ignore[arg-type]
        assert result.get("ti_hits"), (
            "the enrichment service was unreachable and the local match was discarded, which is the CORE behaviour this item exists to fix"
        )
        assert result["ti_source"] == "tenant_ioc_store"
