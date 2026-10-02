"""A first-run tenant gets a wizard, and sample data that proves something.

The gap
-------
A brand-new operator signed in and landed on `/dashboard`: every tile
zero, every panel an honest empty state, and nothing saying what to do
next. The empty states were correct — that work was already done — but
correct and *useful* are different things, and "0 connected sources" is
not a button.

Two properties this file exists to protect
-------------------------------------------
**Sample data must not mark setup complete.** Somebody who has only
looked at samples still has nothing connected, and a checklist that
congratulates them is the flattering fiction this product spends most of
its effort avoiding.

**Sample data must go through the real pipeline.** Inserting rows would
be easier and would prove nothing: a console full of seeded alerts looks
identical whether ingest, fusion and triage work or are completely
broken. Running the real path means a first-run operator who sees alerts
has also seen the product work.
"""

from __future__ import annotations

import pathlib

import pytest
from app.services import sample_data

ENDPOINT = pathlib.Path(__file__).resolve().parents[1] / "app/api/v1/endpoints/onboarding.py"


class TestTheScenarioSet:
    def test_it_is_not_all_critical(self) -> None:
        """A first run where everything is critical teaches an operator
        nothing about how the product separates signal from routine."""
        severities = {s.severity for s in sample_data.SCENARIOS}
        assert len(severities) >= 3, f"only {severities} represented"
        assert "low" in severities or "info" in severities, (
            "nothing in the sample set is routine, so the console cannot show what a benign verdict looks like"
        )

    def test_every_scenario_says_why_it_is_in_the_set(self) -> None:
        for scenario in sample_data.SCENARIOS:
            assert scenario.rationale, f"{scenario.key} has no rationale"
            assert len(scenario.rationale) > 30

    def test_addresses_are_documentation_ranges(self) -> None:
        """RFC 5737 and RFC 2606. Sample data that uses a real IP or a
        registrable domain is a sample that can point at somebody."""
        import ipaddress

        blob = repr([s.fields for s in sample_data.SCENARIOS])
        for octets in ("192.0.2.", "198.51.100.", "203.0.113."):
            blob = blob.replace(octets, "DOC.")
        found = [
            token
            for token in blob.replace("'", " ").replace(",", " ").split()
            if token.count(".") == 3 and token.replace(".", "").isdigit()
        ]
        for addr in found:
            parsed = ipaddress.ip_address(addr)
            assert not parsed.is_global, (
                f"{addr} is a globally routable address in sample data, so a sample alert points at a real host somebody owns"
            )

    def test_domains_are_reserved(self) -> None:
        blob = repr([s.fields for s in sample_data.SCENARIOS])
        assert "@example.com" in blob
        for risky in ("@gmail", "@outlook", "@acme.io", "@corp.net"):
            assert risky not in blob


class TestTheBatch:
    def test_events_are_spread_over_time(self) -> None:
        """Five events at one instant look like a bug, and leave the
        volume chart and the correlation window with nothing to show."""
        events = sample_data.build_events()
        stamps = {e["created_at"] for e in events}
        assert len(stamps) == len(events)

    def test_every_event_carries_a_distinct_vendor_id(self) -> None:
        """The CloudTrail lesson: without a distinct `external_id` and
        title, a v5 alert id derived from content makes every event
        deduplicate onto one row."""
        events = sample_data.build_events()
        assert len({e["external_id"] for e in events}) == len(events)
        assert len({e["title"] for e in events}) == len(events)

    def test_the_raw_event_is_marked_too(self) -> None:
        """So a reader inspecting the lake — not just the alert — can
        still tell these from real telemetry."""
        for event in sample_data.build_events():
            assert event["raw_event"]["aisoc_sample_data"] is True
            assert event["raw_event"]["aisoc_sample_scenario"]

    def test_the_connector_id_is_dedicated_not_borrowed(self) -> None:
        """Borrowing a vendor id would make sample data indistinguishable
        from that vendor's real data, and impossible to delete safely."""
        assert sample_data.SAMPLE_CONNECTOR == "aisoc_sample"
        for event in sample_data.build_events():
            assert event["source"] == "aisoc_sample"


class TestItUsesTheRealPipeline:
    def test_it_posts_to_ingest_rather_than_writing_rows(self) -> None:
        source = pathlib.Path(sample_data.__file__).read_text() if hasattr(sample_data, "__file__") else ""
        assert "/v1/ingest/batch" in source, (
            "sample data no longer goes through ingest, so it proves nothing about whether the pipeline works"
        )
        for row_write in ("INSERT INTO", "session.add", "db.add"):
            assert row_write not in source, (
                f"sample data writes rows directly ({row_write}), which looks identical whether the pipeline works or is completely broken"
            )

    @pytest.mark.asyncio
    async def test_no_service_token_is_an_actionable_error(self, monkeypatch) -> None:  # noqa: ANN001
        monkeypatch.delenv("AISOC_SERVICE_TOKEN", raising=False)
        monkeypatch.delenv("AISOC_INGEST_TOKEN", raising=False)
        with pytest.raises(sample_data.SampleDataError) as excinfo:
            await sample_data.load(tenant_id="00000000-0000-0000-0000-000000000001")
        message = str(excinfo.value)
        assert "AISOC_SERVICE_TOKEN" in message
        assert "make up" in message, "the error does not say how to fix it"


class TestTheEndpointContract:
    def test_sample_data_does_not_clear_first_run(self) -> None:
        """The property that matters most.

        Somebody who has only looked at samples still has nothing
        connected. A checklist that tells them they are set up is a lie
        the rest of this product works hard not to tell.
        """
        source = ENDPOINT.read_text()
        block = source[source.index("return OnboardingStatus(") :]
        assert "first_run=connectors == 0 and real_alerts == 0" in block, (
            "first_run is no longer computed from real sources only, so loading sample data would mark setup complete"
        )

    def test_real_alerts_exclude_the_sample_connector(self) -> None:
        source = ENDPOINT.read_text()
        assert "real_alerts = alerts - sample_alerts" in source

    def test_it_refuses_to_seed_a_working_estate(self) -> None:
        """A sample alert in a live queue is indistinguishable from a real
        one at a glance, and an analyst dismissing a genuine alert because
        they assumed it was sample data is the worse outcome."""
        source = ENDPOINT.read_text()
        assert "HTTP_409_CONFLICT" in source
        assert "already has" in source

    def test_status_is_derived_not_stored(self) -> None:
        """A `tenant.onboarded` flag drifts the moment somebody connects a
        source through the API or deletes their last one."""
        source = ENDPOINT.read_text()
        assert "SELECT COUNT(*) FROM connectors" in source
        assert "SELECT COUNT(*) FROM alerts" in source

    def test_a_missing_table_does_not_500_the_wizard(self) -> None:
        """A half-migrated deployment is exactly when somebody reaches for
        the thing that is supposed to help them fix it."""
        source = ENDPOINT.read_text()
        counter = source[source.index("async def _count") : source.index("@router.get")]
        assert "except Exception" in counter
        assert "return 0" in counter

    def test_an_unreachable_ingest_is_502_not_500(self) -> None:
        """The API is fine and something it depends on is not, and the
        status code should say which."""
        source = ENDPOINT.read_text()
        assert "HTTP_502_BAD_GATEWAY" in source

    def test_every_step_explains_why_it_matters(self) -> None:
        """A checklist that does not say why is a chore list."""
        source = ENDPOINT.read_text()
        assert source.count("why=(") + source.count('why="') >= 4


class TestTheIngestProfileExists:
    def test_aisoc_sample_is_mapped(self) -> None:
        """Without a profile the batch hits the lenient fallback, every
        event gets the same generic title and no vendor id, and all five
        deduplicate onto one alert — the exact CloudTrail defect."""
        normalizer = pathlib.Path(__file__).resolve().parents[3] / "services/ingest/internal/normalizer/normalizer.go"
        source = normalizer.read_text()
        assert '"aisoc_sample": {' in source, "aisoc_sample has no ingest profile, so all five sample events collapse into one alert"
        block = source[source.index('"aisoc_sample": {') :][:900]
        assert '"title":       "message"' in block or '"title":"message"' in block
        assert "external_id" in block
        assert "Sample data" in block, (
            "the profile does not name the sample vendor, so a reader cannot tell sample alerts from real ones in the source column"
        )
