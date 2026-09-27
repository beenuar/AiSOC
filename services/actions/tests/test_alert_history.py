"""Closed-finding history readers, against recorded vendor-shaped payloads.

Gap-closure Phase 1.1 gate.

Every payload here is **synthetic**, hand-built to the shape each vendor's API
documents. None came from a customer. They are recorded fixtures in the sense
the plan means: the reader's real HTTP path is driven against them with a mock
transport, so a wrong endpoint, a wrong filter or a parser that KeyErrors on
the documented response shape fails here rather than on a customer's history.

The assertions that matter are the ones about *not* labelling. An evaluation
that guesses a disposition manufactures agreement, so each vendor's explicit
"I do not know" value is asserted to land on ``unlabeled``, and ``unlabeled``
is asserted not to be a canonical disposition so nothing downstream can score
it as a verdict.
"""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest
import respx
from app.clients.defender_client import DefenderClient
from app.clients.elastic_client import ElasticClient
from app.clients.qradar_client import QRadarClient
from app.clients.sentinel_client import SentinelClient
from app.clients.splunk_client import SplunkClient
from app.services.alert_history import (
    UNLABELED,
    ClosedFinding,
    map_defender_disposition,
    map_elastic_disposition,
    map_qradar_disposition,
    map_sentinel_disposition,
    map_splunk_disposition,
    parse_defender_alert,
    parse_elastic_signal,
    parse_qradar_offense,
    parse_sentinel_incident,
    parse_splunk_notable,
)
from app.services.disposition_writeback import (
    BENIGN,
    BENIGN_TRUE_POSITIVE,
    CANONICAL_DISPOSITIONS,
    FALSE_POSITIVE,
    TRUE_POSITIVE,
)

SINCE = datetime(2026, 9, 1, tzinfo=UTC)
UNTIL = datetime(2026, 9, 26, tzinfo=UTC)


# ---------------------------------------------------------------------------
# The rule the whole phase rests on
# ---------------------------------------------------------------------------


def test_unlabeled_is_not_a_canonical_disposition():
    """If it were, a "do not know" would be scorable as a verdict.

    Everything downstream decides whether a row counts by asking whether its
    disposition is canonical. Putting ``unlabeled`` in that set would silently
    re-admit every row this phase exists to exclude.
    """
    assert UNLABELED not in CANONICAL_DISPOSITIONS


def test_a_mapper_returning_an_undefined_value_is_refused_at_construction():
    with pytest.raises(ValueError, match="neither canonical nor"):
        ClosedFinding(
            vendor="splunk",
            finding_id="1",
            title="t",
            disposition="probably_bad",
            vendor_disposition="?",
            closed_at=SINCE,
        )


@pytest.mark.parametrize(
    ("mapper", "undetermined_label"),
    [
        (map_splunk_disposition, "disposition:6"),  # ES "Undetermined"
        (map_splunk_disposition, "disposition:5"),  # ES "Other"
        (map_sentinel_disposition, "Undetermined"),
        (map_defender_disposition, "Unknown"),
        (map_qradar_disposition, "Acceptable Business Risk"),  # site-custom
        (map_elastic_disposition, []),
    ],
)
def test_every_vendors_i_do_not_know_lands_on_unlabeled(mapper, undetermined_label):
    assert mapper(undetermined_label) == UNLABELED


@pytest.mark.parametrize(
    "mapper",
    [
        map_splunk_disposition,
        map_sentinel_disposition,
        map_defender_disposition,
        map_qradar_disposition,
        map_elastic_disposition,
    ],
)
def test_an_unknown_label_is_never_guessed(mapper):
    for junk in ("", None, "totally-made-up", "   "):
        assert mapper(junk) == UNLABELED


def test_two_conflicting_elastic_tags_yield_unlabeled_rather_than_a_coin_flip():
    assert map_elastic_disposition(["true_positive", "false_positive"]) == UNLABELED
    assert map_elastic_disposition(["true_positive"]) == TRUE_POSITIVE


# ---------------------------------------------------------------------------
# Splunk Enterprise Security
# ---------------------------------------------------------------------------

_SPLUNK_NOTABLES = {
    "results": [
        {
            "event_id": "ABC123@@notable@@aaa",
            "rule_id": "ESCU-Suspicious-Powershell",
            "rule_name": "Suspicious PowerShell Encoded Command",
            "urgency": "high",
            "disposition": "disposition:1",
            "review_time": "1790294400",
            "reviewer": "a.analyst",
            "comment": "Confirmed beacon, host isolated.",
            "_time": "1790290800",
        },
        {
            "event_id": "ABC123@@notable@@bbb",
            "rule_id": "ESCU-Vuln-Scan",
            "rule_name": "Internal Vulnerability Scan Detected",
            "urgency": "medium",
            "disposition": "disposition:2",
            "review_time": "1790298000",
            "reviewer": "b.analyst",
            "comment": "Scheduled Qualys scan window.",
            "_time": "1790294400",
        },
        {
            "event_id": "ABC123@@notable@@ccc",
            "rule_id": "ESCU-Broken-Logic",
            "rule_name": "Anomalous Login Volume",
            "urgency": "low",
            "disposition": "disposition:6",  # Undetermined
            "review_time": "1790301600",
            "reviewer": "c.analyst",
            "comment": "Could not tell either way.",
            "_time": "1790298000",
        },
    ]
}


@pytest.mark.asyncio
@respx.mock
async def test_splunk_reader_drives_its_real_search_path():
    respx.post(url__regex=r"https://splunk:8089/services/search/jobs$").mock(return_value=httpx.Response(201, json={"sid": "sid-1"}))
    results = respx.get(url__regex=r".*/services/search/jobs/sid-1/results.*").mock(return_value=httpx.Response(200, json=_SPLUNK_NOTABLES))

    client = SplunkClient(host="https://splunk:8089", token="t")
    rows = await client.list_closed_notables(SINCE, UNTIL)

    assert results.called
    assert len(rows) == 3
    findings = [parse_splunk_notable(r) for r in rows]
    assert [f.disposition for f in findings] == [
        TRUE_POSITIVE,
        BENIGN_TRUE_POSITIVE,
        UNLABELED,
    ]
    assert findings[0].closed_by == "a.analyst"
    assert findings[0].reason == "Confirmed beacon, host isolated."
    assert findings[0].closed_at == datetime(2026, 9, 25, 0, 0, tzinfo=UTC)
    # The undetermined row is present but excluded from accuracy.
    assert [f.is_labelled for f in findings] == [True, True, False]


@pytest.mark.asyncio
@respx.mock
async def test_splunk_search_is_bounded_to_the_requested_window_and_to_closed_notables():
    created = respx.post(url__regex=r"https://splunk:8089/services/search/jobs$").mock(
        return_value=httpx.Response(201, json={"sid": "sid-1"})
    )
    respx.get(url__regex=r".*/results.*").mock(return_value=httpx.Response(200, json={"results": []}))
    client = SplunkClient(host="https://splunk:8089", token="t")
    await client.list_closed_notables(SINCE, UNTIL)

    body = created.calls[0].request.content.decode()
    assert "status+IN+%285%2C+6%29" in body or "status IN (5, 6)" in body.replace("+", " ")
    assert str(int(SINCE.timestamp())) in body
    assert str(int(UNTIL.timestamp())) in body


@pytest.mark.asyncio
@respx.mock
async def test_splunk_search_override_is_honoured_for_a_customised_es():
    created = respx.post(url__regex=r".*/services/search/jobs$").mock(return_value=httpx.Response(201, json={"sid": "s"}))
    respx.get(url__regex=r".*/results.*").mock(return_value=httpx.Response(200, json={"results": []}))
    client = SplunkClient(host="https://splunk:8089", token="t")
    await client.list_closed_notables(SINCE, UNTIL, search_override="`my_review_lookup`")

    assert "my_review_lookup" in created.calls[0].request.content.decode()


# ---------------------------------------------------------------------------
# Microsoft Sentinel
# ---------------------------------------------------------------------------

_SENTINEL_PAGE_1 = {
    "value": [
        {
            "name": "1111-2222",
            "properties": {
                "title": "Mass download by a single user",
                "status": "Closed",
                "severity": "Medium",
                "classification": "BenignPositive",
                "classificationReason": "SuspiciousButExpected",
                "classificationComment": "Quarterly data export by the finance team.",
                "lastModifiedTimeUtc": "2026-09-20T10:00:00Z",
                "closedBy": {"userPrincipalName": "analyst@example.com"},
                "relatedAnalyticRuleIds": ["/rules/mass-download"],
            },
        }
    ],
    "nextLink": "https://management.azure.com/next-page",
}

_SENTINEL_PAGE_2 = {
    "value": [
        {
            "name": "3333-4444",
            "properties": {
                "title": "Impossible travel",
                "status": "Closed",
                "severity": "High",
                "classification": "Undetermined",
                "lastModifiedTimeUtc": "2026-09-21T11:00:00Z",
            },
        }
    ]
}


@pytest.mark.asyncio
@respx.mock
async def test_sentinel_reader_follows_nextlink_rather_than_truncating_the_window():
    respx.post(url__regex=r".*/oauth2/v2.0/token").mock(return_value=httpx.Response(200, json={"access_token": "tok"}))
    respx.get(url__regex=r".*/providers/Microsoft\.SecurityInsights/incidents\?.*").mock(
        return_value=httpx.Response(200, json=_SENTINEL_PAGE_1)
    )
    page2 = respx.get(url__regex=r"https://management.azure.com/next-page").mock(return_value=httpx.Response(200, json=_SENTINEL_PAGE_2))

    client = SentinelClient("t", "c", "s", "sub", "rg", "ws")
    rows = await client.list_closed_incidents(SINCE, UNTIL)

    assert page2.called, "a first-page-only read reports a truncated sample as the whole window"
    assert len(rows) == 2
    findings = [parse_sentinel_incident(r) for r in rows]
    assert findings[0].disposition == BENIGN_TRUE_POSITIVE
    assert findings[0].closed_by == "analyst@example.com"
    assert "SuspiciousButExpected" in (findings[0].reason or "")
    assert findings[1].disposition == UNLABELED


@pytest.mark.asyncio
@respx.mock
async def test_sentinel_filter_names_closed_and_bounds_the_window():
    respx.post(url__regex=r".*/oauth2/v2.0/token").mock(return_value=httpx.Response(200, json={"access_token": "tok"}))
    route = respx.get(url__regex=r".*/incidents\?.*").mock(return_value=httpx.Response(200, json={"value": []}))
    client = SentinelClient("t", "c", "s", "sub", "rg", "ws")
    await client.list_closed_incidents(SINCE, UNTIL)

    query = str(route.calls[0].request.url)
    assert "status+eq+%27Closed%27" in query or "status eq 'Closed'" in query
    assert "2026-09-01" in query and "2026-09-26" in query


# ---------------------------------------------------------------------------
# Elastic Security
# ---------------------------------------------------------------------------

_ELASTIC_HITS = {
    "hits": {
        "hits": [
            {
                "_id": "sig-1",
                "_source": {
                    "kibana.alert.rule.name": "Potential Credential Dumping",
                    "kibana.alert.rule.uuid": "rule-abc",
                    "kibana.alert.severity": "high",
                    "kibana.alert.workflow_status": "closed",
                    "kibana.alert.workflow_tags": ["false_positive"],
                    "kibana.alert.workflow_user": "d.analyst",
                    "@timestamp": "2026-09-15T08:00:00Z",
                },
            },
            {
                "_id": "sig-2",
                "_source": {
                    "kibana.alert.rule.name": "Unusual Parent-Child Process",
                    "kibana.alert.workflow_status": "closed",
                    "@timestamp": "2026-09-16T08:00:00Z",
                },
            },
        ]
    }
}


@pytest.mark.asyncio
@respx.mock
async def test_elastic_reader_keeps_the_hit_id_and_labels_only_what_was_tagged():
    route = respx.post(url__regex=r"https://es:9200/.*/_search").mock(return_value=httpx.Response(200, json=_ELASTIC_HITS))
    client = ElasticClient(es_url="https://es:9200", api_key="k")
    hits = await client.list_closed_signals(SINCE, UNTIL)

    assert route.called
    findings = [parse_elastic_signal(h) for h in hits]
    # `_id` is the signal's identity; run_dsl_search drops it, which is why
    # this reader does not reuse it.
    assert [f.finding_id for f in findings] == ["sig-1", "sig-2"]
    assert findings[0].disposition == FALSE_POSITIVE
    # Untagged: Elastic records no reason when a signal is closed, so the
    # honest answer is unlabeled rather than "closed, therefore benign".
    assert findings[1].disposition == UNLABELED


@pytest.mark.asyncio
@respx.mock
async def test_elastic_query_asks_only_for_closed_signals_in_the_window():
    route = respx.post(url__regex=r".*/_search").mock(return_value=httpx.Response(200, json={"hits": {"hits": []}}))
    client = ElasticClient(es_url="https://es:9200", api_key="k")
    await client.list_closed_signals(SINCE, UNTIL)

    body = route.calls[0].request.content.decode()
    assert '"kibana.alert.workflow_status":"closed"' in body
    assert "2026-09-01" in body and "2026-09-26" in body


# ---------------------------------------------------------------------------
# IBM QRadar
# ---------------------------------------------------------------------------

_QRADAR_REASONS = [
    {"id": 1, "text": "False-Positive, Tuned"},
    {"id": 2, "text": "Non-Issue"},
    {"id": 3, "text": "Policy Violation"},
]

_QRADAR_OFFENSES = [
    {
        "id": 501,
        "description": "Multiple Login Failures\n",
        "status": "CLOSED",
        "severity": 8,
        "offense_type": 3,
        "close_time": 1790294400000,
        "closing_reason_id": 1,
        "closing_user": "e.analyst",
    },
    {
        "id": 502,
        "description": "Outbound Data Transfer\n",
        "status": "CLOSED",
        "severity": 9,
        "offense_type": 7,
        "close_time": 1790298000000,
        "closing_reason_id": 3,
        "closing_user": "f.analyst",
    },
    {
        "id": 503,
        "description": "Site-specific rule\n",
        "status": "CLOSED",
        "severity": 2,
        "close_time": 1790301600000,
        "closing_reason_id": 99,  # a reason the appliance does not resolve
    },
]


@pytest.mark.asyncio
@respx.mock
async def test_qradar_resolves_closing_reason_ids_to_names_before_mapping():
    respx.get(url__regex=r".*/api/siem/offense_closing_reasons.*").mock(return_value=httpx.Response(200, json=_QRADAR_REASONS))
    respx.get(url__regex=r".*/api/siem/offenses\?.*").mock(return_value=httpx.Response(200, json=_QRADAR_OFFENSES))

    client = QRadarClient(base_url="https://qradar", api_token="t")
    offenses = await client.list_closed_offenses(SINCE, UNTIL)
    findings = [parse_qradar_offense(o) for o in offenses]

    assert [f.disposition for f in findings] == [FALSE_POSITIVE, TRUE_POSITIVE, UNLABELED]
    # A numeric id is not a label anyone can map; the unresolved one stays
    # unlabeled rather than being invented.
    assert findings[2].vendor_disposition == ""
    assert findings[0].severity == "high"
    assert findings[1].severity == "critical"
    assert findings[0].closed_at == datetime(2026, 9, 25, 0, 0, tzinfo=UTC)


@pytest.mark.asyncio
@respx.mock
async def test_qradar_history_still_reads_when_the_reason_lookup_is_refused():
    """A partial answer beats no answer, and the rows land unlabeled."""
    respx.get(url__regex=r".*/offense_closing_reasons.*").mock(return_value=httpx.Response(403, json={"message": "forbidden"}))
    respx.get(url__regex=r".*/api/siem/offenses\?.*").mock(return_value=httpx.Response(200, json=_QRADAR_OFFENSES))
    client = QRadarClient(base_url="https://qradar", api_token="t")
    offenses = await client.list_closed_offenses(SINCE, UNTIL)

    assert len(offenses) == 3
    assert all(parse_qradar_offense(o).disposition == UNLABELED for o in offenses)


@pytest.mark.asyncio
@respx.mock
async def test_qradar_filter_names_closed_and_bounds_the_window_in_milliseconds():
    respx.get(url__regex=r".*/offense_closing_reasons.*").mock(return_value=httpx.Response(200, json=_QRADAR_REASONS))
    route = respx.get(url__regex=r".*/api/siem/offenses\?.*").mock(return_value=httpx.Response(200, json=[]))
    client = QRadarClient(base_url="https://qradar", api_token="t")
    await client.list_closed_offenses(SINCE, UNTIL)

    query = str(route.calls[0].request.url)
    assert "status+%3D+CLOSED" in query or "status = CLOSED" in query
    assert str(int(SINCE.timestamp() * 1000)) in query


# ---------------------------------------------------------------------------
# Microsoft Defender XDR
# ---------------------------------------------------------------------------

_DEFENDER_PAGE_1 = {
    "value": [
        {
            "id": "da-1",
            "title": "Suspicious process injection",
            "severity": "High",
            "status": "Resolved",
            "classification": "TruePositive",
            "determination": "Malware",
            "detectionSource": "WindowsDefenderAtp",
            "assignedTo": "g.analyst",
            "resolvedTime": "2026-09-18T12:00:00Z",
        }
    ],
    "@odata.nextLink": "https://api.securitycenter.microsoft.com/api/alerts?$skiptoken=2",
}

_DEFENDER_PAGE_2 = {
    "value": [
        {
            "id": "da-2",
            "title": "Security testing tool detected",
            "severity": "Medium",
            "status": "Resolved",
            "classification": "InformationalExpectedActivity",
            "determination": "SecurityTesting",
            "resolvedTime": "2026-09-19T12:00:00Z",
        },
        {
            "id": "da-3",
            "title": "Anomalous sign-in",
            "severity": "Low",
            "status": "Resolved",
            "classification": "Unknown",
            "resolvedTime": "2026-09-19T13:00:00Z",
        },
    ]
}


@pytest.mark.asyncio
@respx.mock
async def test_defender_reader_follows_odata_nextlink_and_separates_verdict_from_reason():
    respx.post(url__regex=r".*/oauth2/v2.0/token").mock(return_value=httpx.Response(200, json={"access_token": "tok"}))
    respx.get(url__regex=r"https://api\.securitycenter\.microsoft\.com/api/alerts\?%24filter.*").mock(
        return_value=httpx.Response(200, json=_DEFENDER_PAGE_1)
    )
    page2 = respx.get(url__regex=r".*skiptoken.*").mock(return_value=httpx.Response(200, json=_DEFENDER_PAGE_2))

    client = DefenderClient("t", "c", "s")
    rows = await client.list_resolved_alerts(SINCE, UNTIL)

    assert page2.called
    findings = [parse_defender_alert(r) for r in rows]
    assert [f.disposition for f in findings] == [
        TRUE_POSITIVE,
        BENIGN_TRUE_POSITIVE,
        UNLABELED,
    ]
    # `determination` is the reason, never the verdict. Scoring "Malware" as a
    # disposition would put a reason code into the confusion matrix.
    assert findings[0].reason == "Malware"
    assert findings[0].vendor_disposition == "TruePositive"
    assert findings[1].reason == "SecurityTesting"


@pytest.mark.asyncio
@respx.mock
async def test_defender_filter_names_resolved_and_bounds_the_window():
    respx.post(url__regex=r".*/oauth2/v2.0/token").mock(return_value=httpx.Response(200, json={"access_token": "tok"}))
    route = respx.get(url__regex=r".*/api/alerts\?%24filter.*").mock(return_value=httpx.Response(200, json={"value": []}))
    client = DefenderClient("t", "c", "s")
    await client.list_resolved_alerts(SINCE, UNTIL)

    query = str(route.calls[0].request.url)
    assert "status+eq+%27Resolved%27" in query or "status eq 'Resolved'" in query
    assert "2026-09-01T00%3A00%3A00Z" in query


# ---------------------------------------------------------------------------
# Timestamps decide which side of the train/test split a row lands on
# ---------------------------------------------------------------------------


def test_vendor_epoch_dialects_all_land_on_the_same_instant():
    """Splunk sends epoch seconds as a string, QRadar milliseconds as an int."""
    splunk = parse_splunk_notable({"event_id": "a", "disposition": "disposition:1", "review_time": "1790294400"})
    qradar = parse_qradar_offense({"id": 1, "closing_reason_name": "Policy Violation", "close_time": 1790294400000})
    assert splunk.closed_at == qradar.closed_at == datetime(2026, 9, 25, 0, 0, tzinfo=UTC)


def test_an_unparseable_close_time_raises_rather_than_defaulting_to_now():
    """A silently-wrong close time puts a row on the wrong side of the split.

    That is the leak this phase exists to prevent, so it fails loudly.
    """
    with pytest.raises(ValueError, match="unparseable close time"):
        parse_splunk_notable({"event_id": "a", "disposition": "disposition:1", "review_time": ""})


def test_the_vendor_label_is_kept_verbatim_even_when_it_maps():
    """A reader who disagrees with a mapping needs to see what was recorded."""
    finding = parse_sentinel_incident(
        {"name": "x", "properties": {"classification": "BenignPositive", "lastModifiedTimeUtc": "2026-09-20T10:00:00Z"}}
    )
    assert finding.disposition == BENIGN_TRUE_POSITIVE
    assert finding.vendor_disposition == "BenignPositive"


def test_qradar_non_issue_is_benign_not_benign_true_positive():
    """ "Non-Issue" makes no claim about whether the rule was right.

    ``benign`` exists to carry exactly that distinction, and folding it into
    ``benign_true_positive`` would credit the detection with being correct on
    the strength of an analyst saying only that nothing happened.
    """
    assert map_qradar_disposition("Non-Issue") == BENIGN
    assert map_qradar_disposition("Non-Issue") != BENIGN_TRUE_POSITIVE
