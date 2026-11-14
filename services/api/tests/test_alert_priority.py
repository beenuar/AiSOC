"""Asset and identity context changes the queue order.

Gap-closure wave 11. `assets.criticality` reached a prompt string and
a sort order and nothing else, so two alerts of equal severity — one
on a domain controller, one on a meeting-room display — arrived in the
order they were raised.
"""

from __future__ import annotations

from app.services.alert_priority import (
    MAX_SCORE,
    AssetContext,
    IdentityContext,
    score_alert_priority,
)


class TestContextReordersWithinASeverityTier:
    def test_a_critical_asset_outranks_a_low_one_at_equal_severity(self) -> None:
        """The whole point. Both are `high`; only the host differs."""
        dc = score_alert_priority(severity="high", asset=AssetContext(criticality="critical"))
        display = score_alert_priority(severity="high", asset=AssetContext(criticality="low"))
        assert dc.score > display.score

    def test_a_domain_admin_outranks_a_standard_user(self) -> None:
        admin = score_alert_priority(severity="medium", identity=IdentityContext(privilege_tier="domain_admin"))
        user = score_alert_priority(severity="medium", identity=IdentityContext(privilege_tier="standard"))
        assert admin.score > user.score

    def test_a_kev_vulnerability_outranks_an_ordinary_one(self) -> None:
        """A technique known to work is a different fact from a high
        CVSS score, and only the tenant's own inventory knows it."""
        kev = score_alert_priority(severity="medium", asset=AssetContext(has_kev_vulnerability=True))
        ordinary = score_alert_priority(severity="medium", asset=AssetContext(exploitable_vuln_count=4))
        assert kev.score > ordinary.score

    def test_break_glass_activity_is_notable_at_any_severity(self) -> None:
        """These accounts are expected to be dormant."""
        glass = score_alert_priority(severity="low", identity=IdentityContext(is_break_glass=True))
        plain = score_alert_priority(severity="low", identity=IdentityContext())
        assert glass.score > plain.score


class TestContextCannotInvertASeverityGap:
    def test_no_amount_of_context_lifts_info_above_critical(self) -> None:
        """Addition would allow it, and a scheme that ranks an
        informational alert above a critical one gets switched off the
        first time it surprises somebody."""
        loaded_info = score_alert_priority(
            severity="info",
            asset=AssetContext(criticality="critical", has_kev_vulnerability=True, internet_facing=True),
            identity=IdentityContext(privilege_tier="domain_admin", is_break_glass=True),
        )
        bare_critical = score_alert_priority(severity="critical")
        assert loaded_info.score < bare_critical.score

    def test_the_score_is_clamped(self) -> None:
        """Without a ceiling the most loaded alert reaches a number
        that makes every other alert look identical by comparison."""
        maxed = score_alert_priority(
            severity="critical",
            asset=AssetContext(criticality="critical", has_kev_vulnerability=True, internet_facing=True),
            identity=IdentityContext(privilege_tier="domain_admin", is_break_glass=True),
        )
        assert maxed.score == MAX_SCORE


class TestTheOrderingIsInterrogable:
    def test_every_factor_that_moved_it_is_recorded(self) -> None:
        result = score_alert_priority(
            severity="high",
            asset=AssetContext(criticality="critical", has_kev_vulnerability=True),
            identity=IdentityContext(privilege_tier="admin"),
        )
        reasons = " ".join(r["reason"] for r in result.rationale)
        assert "criticality" in reasons
        assert "Known Exploited" in reasons
        assert "privilege" in reasons

    def test_nothing_is_recorded_when_nothing_moved(self) -> None:
        """A rationale full of ×1.00 entries is noise that teaches
        people to stop reading it."""
        result = score_alert_priority(severity="high", asset=AssetContext(criticality="medium"))
        assert result.rationale == []

    def test_the_base_is_reported_separately(self) -> None:
        result = score_alert_priority(severity="high", asset=AssetContext(criticality="critical"))
        assert result.base == 600
        assert result.score != result.base


class TestUnknownInputsAreRankedNotDropped:
    def test_an_unknown_severity_ranks_as_medium_and_says_so(self) -> None:
        """A connector emitting a tier this deployment does not know is
        a mapping bug; dropping the alert out of the queue over it
        would be worse than ranking it in the middle."""
        result = score_alert_priority(severity="catastrophic")
        assert result.base == 350
        assert any("outside the five-tier ladder" in r["reason"] for r in result.rationale)

    def test_an_unknown_criticality_does_not_change_the_score(self) -> None:
        unknown = score_alert_priority(severity="high", asset=AssetContext(criticality="vital"))
        plain = score_alert_priority(severity="high")
        assert unknown.score == plain.score
        assert any("unrecognised" in r["reason"] for r in unknown.rationale)

    def test_no_context_at_all_is_just_severity(self) -> None:
        """Most deployments have no CMDB on day one, and the queue must
        still work."""
        assert score_alert_priority(severity="critical").score == 900
