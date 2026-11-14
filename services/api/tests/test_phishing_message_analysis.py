"""Headers, URLs and attachments: what was found, and what was not checked.

The reproduction this file pins is the absence: before depth 7.2 nothing in
the tree read an ``Authentication-Results`` header. ``grep -rl
"authentication-results" services/`` returned no match, so a reported message
whose SPF and DMARC both failed at the receiving boundary produced a triage
verdict that had never looked.

Everything else here guards the one rule the module turns on — **an
unanalysed artefact must never read as a clean one** — in the three places it
can be broken:

* a result token that is not a pass being treated as one (``neutral``,
  ``none``, ``permerror``, ``temperror``, and the absent header itself);
* an artefact nothing examined being omitted rather than reported;
* the analysed and unanalysed counts being summed, which is how five
  artefacts nobody checked render as "5 artefacts, 0 findings".
"""

from __future__ import annotations

import time

import pytest
from app.services.phishing.analysis import ArtefactResult, MessageAnalysis, _citations
from app.services.phishing.headers import AuthResult, analyse_headers
from app.services.phishing.intake import ReportedMessage, from_graph_message

PHISH = "billing@phish.example.net"
VICTIM = "alice@example.com"

FULL_FAIL = {
    "from": f'"Billing Dept" <{PHISH}>',
    "to": VICTIM,
    "return-path": "<bounce@mailer.example.org>",
    "reply-to": "accounts.payable@attacker.example.org",
    "authentication-results": (
        "mx.example.com; spf=fail smtp.mailfrom=phish.example.net; dkim=none; dmarc=fail header.from=phish.example.net"
    ),
    "received": "from mx1.example.com by mail.example.com\nfrom relay.phish.example.net by mx1.example.com",
    "subject": "Action required",
}

CLEAN_PASS = {
    "from": "Finance <finance@example.com>",
    "to": VICTIM,
    "return-path": "<finance@example.com>",
    "authentication-results": "mx.example.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass",
    "received": "from mx1.example.com by mail.example.com",
    "subject": "Q3 numbers",
}


class TestTheThirdValueIsThePoint:
    def test_an_absent_authentication_results_header_is_not_a_pass(self) -> None:
        """The reproduction. Nothing in the tree read this header before 7.2."""
        analysis = analyse_headers({"from": f"<{PHISH}>", "to": VICTIM})
        assert analysis.authentication == {
            "spf": AuthResult.NOT_EVALUATED.value,
            "dkim": AuthResult.NOT_EVALUATED.value,
            "dmarc": AuthResult.NOT_EVALUATED.value,
        }
        assert analysis.failed_methods == ()
        assert set(analysis.unevaluated_methods) == {"spf", "dkim", "dmarc"}
        assert "Authentication-Results" in analysis.missing_headers

    @pytest.mark.parametrize("token", ["none", "neutral", "policy", "permerror", "temperror"])
    def test_a_non_verdict_token_is_not_evaluated_rather_than_a_pass(self, token: str) -> None:
        """Treating these as passes is how a broken SPF record reads as authenticated."""
        analysis = analyse_headers({"authentication-results": f"mx; spf={token}", "from": f"<{PHISH}>"})
        assert analysis.authentication["spf"] == AuthResult.NOT_EVALUATED.value

    @pytest.mark.parametrize("token", ["fail", "softfail", "hardfail"])
    def test_every_failure_spelling_is_a_failure(self, token: str) -> None:
        analysis = analyse_headers({"authentication-results": f"mx; spf={token}", "from": f"<{PHISH}>"})
        assert analysis.authentication["spf"] == AuthResult.FAIL.value

    def test_every_method_gets_an_entry_even_when_no_clause_mentions_it(self) -> None:
        """Otherwise a console renders 'SPF fail' and silently omits DMARC."""
        analysis = analyse_headers({"authentication-results": "mx; spf=fail", "from": f"<{PHISH}>"})
        assert set(analysis.authentication) == {"spf", "dkim", "dmarc"}
        assert analysis.authentication["dmarc"] == AuthResult.NOT_EVALUATED.value

    def test_an_unevaluated_method_produces_its_own_indicator_saying_so(self) -> None:
        notes = [i["note"] for i in analyse_headers({"from": f"<{PHISH}>"}).as_indicators()]
        assert sum("not a pass" in n for n in notes) == 3

    def test_the_arc_sealed_header_is_read_when_the_plain_one_is_absent(self) -> None:
        """A forwarded report is exactly the case where only ARC carries the verdict."""
        analysis = analyse_headers({"arc-authentication-results": "i=1; mx; spf=fail; dmarc=fail", "from": f"<{PHISH}>"})
        assert analysis.authentication["spf"] == AuthResult.FAIL.value
        assert analysis.authentication["dmarc"] == AuthResult.FAIL.value

    def test_received_spf_is_a_fallback_and_the_considered_answer_wins(self) -> None:
        both = analyse_headers(
            {"authentication-results": "mx; spf=fail", "received-spf": "pass (example.com: domain of x designates y)", "from": f"<{PHISH}>"}
        )
        assert both.authentication["spf"] == AuthResult.FAIL.value
        fallback = analyse_headers({"received-spf": "pass (example.com: ...)", "from": f"<{PHISH}>"})
        assert fallback.authentication["spf"] == AuthResult.PASS.value


class TestWhatTheHeadersGiveAway:
    def test_a_reply_to_on_another_domain_is_a_finding(self) -> None:
        kinds = {f.kind for f in analyse_headers(FULL_FAIL).findings}
        assert "reply_to_redirect" in kinds

    def test_a_return_path_mismatch_is_informational_not_a_finding(self) -> None:
        """Routine on mailing lists. Flagging it as a finding trains people to ignore findings."""
        by_kind = {f.kind: f for f in analyse_headers(FULL_FAIL).findings}
        assert by_kind["return_path_mismatch"].severity_hint == "informational"

    def test_an_address_in_the_display_name_that_is_not_the_sender_is_impersonation(self) -> None:
        analysis = analyse_headers({"from": f'"finance@example.com" <{PHISH}>'})
        by_kind = {f.kind: f for f in analysis.findings}
        assert "display_name_impersonation" in by_kind
        assert by_kind["display_name_impersonation"].evidence["actual"] == PHISH

    def test_a_display_name_that_is_merely_a_name_is_not_impersonation(self) -> None:
        """The negative control. A matcher that fires on any display name fires on everything."""
        assert "display_name_impersonation" not in {f.kind for f in analyse_headers({"from": f'"Billing Dept" <{PHISH}>'}).findings}

    def test_the_hop_count_comes_from_repeated_received_headers(self) -> None:
        assert analyse_headers(FULL_FAIL).hop_count == 2

    def test_a_clean_message_produces_no_findings_beyond_the_passes(self) -> None:
        """The other negative control: an analyser that flags everything flags nothing."""
        analysis = analyse_headers(CLEAN_PASS)
        assert analysis.failed_methods == ()
        assert analysis.unevaluated_methods == ()
        assert [f.kind for f in analysis.findings] == []

    def test_the_analysis_reaches_no_network(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Header analysis must work on a deployment with no provider and no egress."""
        import socket

        def _boom(*_args, **_kwargs):
            raise AssertionError("header analysis opened a socket")

        monkeypatch.setattr(socket.socket, "connect", _boom)
        monkeypatch.setattr(socket, "getaddrinfo", _boom)
        assert analyse_headers(FULL_FAIL).failed_methods == ("dmarc", "spf")


class TestTheCountsAreNeverSummed:
    def _analysis(self, *, analysed: int, unanalysed: int) -> MessageAnalysis:
        urls = [
            ArtefactResult(kind="url", value=f"https://a{i}.example.net", outcome="known", detail="", verdict="benign")
            for i in range(analysed)
        ]
        urls += [
            ArtefactResult(kind="url", value=f"https://b{i}.example.net", outcome="no_provider", detail="not analysed")
            for i in range(unanalysed)
        ]
        return MessageAnalysis(headers=analyse_headers(CLEAN_PASS), urls=urls)

    def test_an_artefact_nothing_examined_is_counted_as_unanalysed(self) -> None:
        analysis = self._analysis(analysed=0, unanalysed=5)
        assert analysis.analysed_count == 0
        assert analysis.unanalysed_count == 5

    def test_a_pending_submission_is_not_analysed(self) -> None:
        """A submission accepted is not a result, the same distinction awaiting_completion draws."""
        pending = ArtefactResult(kind="url", value="https://x.example.net", outcome="pending", detail="submitted")
        assert pending.analysed is False

    def test_the_summary_says_how_many_could_not_be_analysed(self) -> None:
        summary = self._analysis(analysed=1, unanalysed=4).summary()
        assert "1 of 5" in summary
        assert "4 could not be" in summary

    def test_a_fully_unanalysed_message_does_not_read_as_zero_findings(self) -> None:
        """The exact rendering this split exists to prevent."""
        summary = self._analysis(analysed=0, unanalysed=5).summary()
        assert "0 of 5" in summary and "5 could not be" in summary


class TestTheRealAnalysisPathOnADeploymentWithNoProvider:
    """Drives ``analyse_message``, not a hand-built ``MessageAnalysis``.

    Written because the hand-built version missed the defect it was supposed
    to guard. Deleting the "no provider configured" branch from
    ``_analyse_urls`` — so unanalysable URLs are silently skipped — left every
    other test in this file green, because they construct their own
    ``ArtefactResult`` list and never run the code that builds one. A test
    that asserts on a fixture it wrote cannot notice a producer that stopped
    producing.
    """

    @pytest.mark.asyncio
    async def test_a_url_with_no_provider_is_reported_not_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.services.phishing import analysis as analysis_module

        class _Empty:
            def usable_names(self):
                return []

            def get(self, _name):  # pragma: no cover - never reached with no names
                return None

        monkeypatch.setattr(analysis_module, "build_registry", lambda: _Empty())
        message = ReportedMessage(
            intake_source="manual",
            sender=PHISH,
            headers=CLEAN_PASS,
            urls=("https://pay.phish.example.net/a", "https://pay.phish.example.net/b"),
        )
        result = await analysis_module.analyse_message(message)

        assert len(result.urls) == 2, "an unanalysable URL must appear in the output, not vanish from it"
        assert result.analysed_count == 0
        assert result.unanalysed_count == 2
        assert all("not a clean verdict" in u.detail for u in result.urls)

    @pytest.mark.asyncio
    async def test_an_unreachable_registry_is_could_not_check_not_an_empty_result(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.services.phishing import analysis as analysis_module

        def _boom():
            raise RuntimeError("provider registry unavailable")

        monkeypatch.setattr(analysis_module, "build_registry", _boom)
        message = ReportedMessage(intake_source="manual", sender=PHISH, headers=CLEAN_PASS, urls=("https://x.example.net",))
        result = await analysis_module.analyse_message(message)
        assert result.unanalysed_count == 1
        assert result.urls[0].outcome == "no_provider"

    @pytest.mark.asyncio
    async def test_only_the_first_five_urls_are_submitted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A footer with twenty links must not spend a provider's quota."""
        from app.services.phishing import analysis as analysis_module

        class _Empty:
            def usable_names(self):
                return []

            def get(self, _name):  # pragma: no cover
                return None

        monkeypatch.setattr(analysis_module, "build_registry", lambda: _Empty())
        message = ReportedMessage(
            intake_source="manual",
            sender=PHISH,
            headers=CLEAN_PASS,
            urls=tuple(f"https://x{i}.example.net" for i in range(20)),
        )
        result = await analysis_module.analyse_message(message)
        assert len(result.urls) == analysis_module.MAX_URLS_ANALYSED

    @pytest.mark.asyncio
    async def test_an_attachment_with_no_provider_is_reported_not_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The wording the submit path already shipped, now on the 7.2 path too."""
        from app.services.phishing import analysis as analysis_module

        async def _nothing(_digest):
            return {}

        monkeypatch.setattr(analysis_module, "enrich_file_hash", _nothing)
        message = ReportedMessage(intake_source="manual", sender=PHISH, headers=CLEAN_PASS, attachment_hashes=("a" * 64,))
        result = await analysis_module.analyse_message(message)
        assert result.unanalysed_count == 1
        assert "This is not a clean verdict" in result.attachments[0].detail

    @pytest.mark.asyncio
    async def test_a_sandbox_outage_is_could_not_check_rather_than_a_crash(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.services.phishing import analysis as analysis_module

        async def _boom(_digest):
            raise RuntimeError("sandbox down")

        monkeypatch.setattr(analysis_module, "enrich_file_hash", _boom)
        message = ReportedMessage(intake_source="manual", sender=PHISH, headers=CLEAN_PASS, attachment_hashes=("b" * 64,))
        result = await analysis_module.analyse_message(message)
        assert result.attachments[0].outcome == "could_not_check"
        assert result.unanalysed_count == 1


class TestTheCitationsAreWrittenEvenWhenNothingWasFound:
    def _message(self) -> ReportedMessage:
        return ReportedMessage(intake_source="manual", sender=PHISH, headers=FULL_FAIL)

    def test_a_message_with_no_artefacts_still_writes_a_row_per_component(self) -> None:
        """A ledger with no row for the URL check cannot be told from one where it passed."""
        rows = _citations(self._message(), MessageAnalysis(headers=analyse_headers(FULL_FAIL)))
        components = [payload["component"] for _k, _s, payload in rows]
        assert components == ["headers", "urls", "attachments"]
        assert all(kind == "evidence_cited" for kind, _s, _p in rows)

    def test_the_header_citation_carries_the_unevaluated_list(self) -> None:
        analysis = MessageAnalysis(headers=analyse_headers({"from": f"<{PHISH}>"}))
        _kind, _summary, payload = _citations(self._message(), analysis)[0]
        assert sorted(payload["not_evaluated"]) == ["dkim", "dmarc", "spf"]

    def test_an_unanalysed_artefact_citation_says_it_is_not_a_clean_verdict(self) -> None:
        analysis = MessageAnalysis(
            headers=analyse_headers(CLEAN_PASS),
            urls=[ArtefactResult(kind="url", value="https://x.example.net", outcome="no_provider", detail="not analysed")],
        )
        _kind, summary, payload = _citations(self._message(), analysis)[1]
        assert payload["analysed"] == 0 and payload["unanalysed"] == 1
        assert "not a clean verdict" in summary


class TestTheVerdictIsOnlyEverRaised:
    """``_merge_analysis_verdict`` follows the same rule the attachment merge did."""

    def _merge(self, verdict: str, analysis: MessageAnalysis):
        from app.api.v1.endpoints.phishing import TriageResult, _merge_analysis_verdict

        base = TriageResult(verdict=verdict, confidence=0.1, indicators=[], mitre_technique=None, summary="Heuristic triage.")
        return _merge_analysis_verdict(base, analysis)

    def test_spf_and_dmarc_both_failing_raises_a_benign_verdict_to_phishing(self) -> None:
        merged = self._merge("benign", MessageAnalysis(headers=analyse_headers(FULL_FAIL)))
        assert merged.verdict == "phishing"
        assert merged.confidence >= 0.75

    def test_spf_alone_failing_does_not(self) -> None:
        """A forwarded message routinely breaks SPF; flagging it alerts on every mailing list."""
        spf_only = analyse_headers({**FULL_FAIL, "authentication-results": "mx; spf=fail; dkim=pass; dmarc=pass"})
        assert self._merge("benign", MessageAnalysis(headers=spf_only)).verdict == "benign"

    def test_unevaluated_authentication_raises_nothing(self) -> None:
        assert self._merge("benign", MessageAnalysis(headers=analyse_headers({"from": f"<{PHISH}>"}))).verdict == "benign"

    def test_a_malicious_artefact_raises_to_malware(self) -> None:
        analysis = MessageAnalysis(
            headers=analyse_headers(CLEAN_PASS),
            urls=[ArtefactResult(kind="url", value="https://x.example.net", outcome="known", detail="bad", verdict="malicious")],
        )
        merged = self._merge("benign", analysis)
        assert merged.verdict == "malware"
        assert merged.confidence >= 0.9

    def test_an_existing_phishing_verdict_is_never_lowered_by_a_clean_analysis(self) -> None:
        merged = self._merge("phishing", MessageAnalysis(headers=analyse_headers(CLEAN_PASS)))
        assert merged.verdict == "phishing"

    def test_every_indicator_survives_the_merge(self) -> None:
        analysis = MessageAnalysis(headers=analyse_headers(FULL_FAIL))
        merged = self._merge("benign", analysis)
        assert len(merged.indicators) == len(analysis.as_indicators())


class TestTheIntakeAdapterFeedsTheAnalysis:
    def test_a_graph_payloads_headers_reach_the_analyser(self) -> None:
        """The path, not the function: the adapter and the analyser have to agree on casing."""
        payload = {
            "id": "AAMk=",
            "internetMessageId": "<x@example.net>",
            "subject": "Invoice",
            "from": {"emailAddress": {"address": VICTIM}},
            "toRecipients": [{"emailAddress": {"address": "phishing@example.com"}}],
            "internetMessageHeaders": [
                {"name": "Message-ID", "value": "<orig@phish.example.net>"},
                {"name": "From", "value": PHISH},
                {"name": "To", "value": VICTIM},
                {"name": "Authentication-Results", "value": "mx; spf=fail; dkim=none; dmarc=fail"},
            ],
        }
        message = from_graph_message(payload)
        analysis = analyse_headers(message.headers, reported_sender=message.sender)
        assert analysis.failed_methods == ("dmarc", "spf")


class TestAdversarialDisplayName:
    """GHSA-9m2j-23jf-gg3p: an attacker-sized ``From`` display name must not
    stall the process.

    The reported shape: ``_ADDRESS_IN_NAME`` was an unanchored scan, so a long
    display name containing no ``@`` was re-consumed from every interior
    position — quadratic, measured here at 8.4 s for 64 KB and reported at
    71 s for 128 KB through ``POST /phishing/reports``, which runs this
    synchronously on the event loop and therefore stalls every other request
    on the process while it spins. The display name is attacker-sized because
    nothing bounds a reported message's headers.

    The 1-second budget cannot flap in either direction: the pre-fix cost at
    128 KB is ~30 s on a fast machine (slower on a runner, so further *over*
    budget), and the post-fix cost is linear ``parseaddr`` plus a capped scan,
    ~20 ms on a slow runner — 30× or more of margin both ways.
    """

    def test_analysis_is_bounded_on_a_long_non_address_display_name(self) -> None:
        name = "a" * (128 * 1024)
        started = time.perf_counter()
        analysis = analyse_headers({"from": f'"{name}" <{PHISH}>'})
        elapsed = time.perf_counter() - started
        assert elapsed < 1.0, f"header analysis took {elapsed:.1f}s on a 128 KB display name"
        # The pathological name embeds no address, so no impersonation finding.
        assert "display_name_impersonation" not in {f.kind for f in analysis.findings}

    def test_impersonation_still_fires_and_evidence_stays_bounded(self) -> None:
        """Detection is not traded away, and a crafted name cannot push
        megabytes into the finding's stored ``evidence``."""
        embedded = "ceo@victim.example.com"
        name = f"{embedded} " + "b" * (128 * 1024)
        analysis = analyse_headers({"from": f'"{name}" <{PHISH}>'})
        finding = next(f for f in analysis.findings if f.kind == "display_name_impersonation")
        assert finding.evidence["claimed"] == embedded
        assert len(finding.evidence["display_name"]) <= 1024
