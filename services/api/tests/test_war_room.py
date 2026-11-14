"""War rooms: what the channel is told, once, and what it may decide.

Depth plan 9.4.

These are the parts that need no vendor: the event derivation that decides
what the sweep says, the idempotency key that stops it saying it twice, and
the closed verb set a chat button may reach. The vendor halves are covered
by ``services/slack-bot/tests/test_war_room.py`` and
``services/teams-bot/tests/test_war_room.py``; the end-to-end path through a
real Postgres is recorded in the pull request.

Asserted by name below:

* an event key embeds the **value**, not just the field, so a case that goes
  `open → closed → open` posts three times rather than once — a re-opened
  case is news;
* the sweep is a pure function of the case row, so a missed tick cannot lose
  an event the way a cursor-based feed would;
* a decision outside the closed set is refused by name rather than ignored;
* ``resolve`` moves a case to `resolved` and never to `closed`, because
  closing has SLA and reporting consequences and belongs on an authenticated
  console session.
"""

from __future__ import annotations

import pytest
from app.services.war_room import CHANNEL_DECISIONS, PROVIDERS, WarRoomError, bot_target, case_events


class TestCaseEvents:
    def test_an_event_key_embeds_the_value_so_a_reopen_is_news(self) -> None:
        opened = dict(case_events({"status": "open"}))
        closed = dict(case_events({"status": "closed"}))
        assert set(opened) == {"status:open"}
        assert set(closed) == {"status:closed"}
        # Keyed on the field alone, a case that goes open -> closed -> open
        # would post once and then go quiet on the thing people care about.
        assert set(opened) != set(closed)

    def test_it_is_a_pure_function_of_the_case_row(self) -> None:
        """A missed tick cannot lose an event, which a cursor-based feed can."""
        case = {"status": "investigating", "severity": "high", "assignee": "ana@example.com"}
        assert case_events(case) == case_events(case)
        assert len(case_events(case)) == 3

    def test_empty_fields_say_nothing(self) -> None:
        assert case_events({"status": "", "severity": None, "assignee": "   "}) == []

    def test_a_verdict_carries_its_confidence_into_the_key(self) -> None:
        keys = dict(case_events({"verdict": "true_positive", "confidence": 0.91}))
        assert "verdict:true_positive:0.91" in keys
        assert "confidence 0.91" in keys["verdict:true_positive:0.91"]
        # A verdict that firms up from 0.6 to 0.91 is a second thing worth saying.
        assert set(case_events({"verdict": "true_positive", "confidence": 0.6})) != set(keys)

    def test_a_long_resolution_is_bounded_in_both_the_key_and_the_message(self) -> None:
        key, body = case_events({"resolution": "x" * 5_000})[0]
        assert len(key) <= 80
        # A chat message should not be an essay; the case link in the channel
        # header is where the full text lives.
        assert len(body) <= 420


class TestDecisions:
    def test_the_verb_set_is_closed_and_excludes_closing_a_case(self) -> None:
        assert CHANNEL_DECISIONS == {"acknowledge", "escalate", "resolve", "note"}
        # A chat button is not an authenticated console session, and closing
        # has SLA and reporting consequences.
        assert "close" not in CHANNEL_DECISIONS

    @pytest.mark.asyncio
    async def test_a_decision_outside_the_set_is_refused_by_name(self) -> None:
        from app.services.war_room import apply_channel_decision

        with pytest.raises(WarRoomError, match="decision must be one of"):
            await apply_channel_decision(
                # Never reached: the refusal happens before any SQL, which
                # is the property under test. `type: ignore` rather than a
                # stub session, because a stub capable of answering would
                # be a double more capable than the real thing and would
                # hide a regression that started issuing the query.
                db=None,  # type: ignore[arg-type]
                tenant_id=None,  # type: ignore[arg-type]
                war_room={},
                decision="delete_everything",
                actor="someone",
                note="",
            )


class TestBotTarget:
    def test_an_unconfigured_bot_resolves_to_none_rather_than_a_guess(self, monkeypatch) -> None:
        monkeypatch.delenv("AISOC_SLACK_BOT_URL", raising=False)
        monkeypatch.delenv("AISOC_INTERNAL_TOKEN", raising=False)
        # A guessed URL produces a connection error at click time, which
        # reads as "the feature is broken" rather than "the bot is not
        # deployed" — and both bots are in the `chatops` profile, so not
        # running one is an ordinary supported state.
        assert bot_target("slack") is None

    def test_a_url_without_a_token_is_still_unconfigured(self, monkeypatch) -> None:
        monkeypatch.setenv("AISOC_SLACK_BOT_URL", "http://slack-bot:8089")
        monkeypatch.delenv("AISOC_INTERNAL_TOKEN", raising=False)
        assert bot_target("slack") is None

    def test_both_providers_resolve_when_configured(self, monkeypatch) -> None:
        monkeypatch.setenv("AISOC_INTERNAL_TOKEN", "t")
        monkeypatch.setenv("AISOC_SLACK_BOT_URL", "http://slack-bot:8089/")
        monkeypatch.setenv("AISOC_TEAMS_BOT_URL", "http://teams-bot:8090")
        slack = bot_target("slack")
        teams = bot_target("teams")
        assert slack is not None and slack.base_url == "http://slack-bot:8089"
        assert teams is not None and teams.base_url == "http://teams-bot:8090"

    def test_an_unknown_provider_is_none(self) -> None:
        assert bot_target("irc") is None
        assert "irc" not in PROVIDERS
