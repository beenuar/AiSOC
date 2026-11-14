"""Reader output, the production ``normalize()``, and the triage input it feeds.

Fix-pass item 3.3.

The defect this gates
---------------------
A closed-finding reader and its connector read **different vendor endpoints**,
so two of the five returned a row the connector's ``normalize()`` could not
read at all: Elastic's reader returns ``_search`` hits while the connector
expects the flat document, and Defender's reader returns a Defender for
Endpoint alert while the connector expects a Microsoft Graph ``alerts_v2``
one. The symptom is not an exception — every lookup simply misses, so the
finding reaches triage with a fabricated default severity and no host or user,
and the agent is then graded on an alert that describes nobody.

Three vendor endpoints are involved per source and they are all real:

* Splunk ES notables, ``POST /services/search/jobs`` then the results endpoint
  — https://help.splunk.com/en/splunk-enterprise-security/administer
* Microsoft Sentinel incidents and their entities
  — https://learn.microsoft.com/en-us/rest/api/securityinsights/incidents/list-entities
* Elastic Security detection alerts, ``POST <index>/_search``
  — https://www.elastic.co/docs/reference/security/fields-and-object-schemas/alert-schema
* IBM QRadar offenses and offense types
  — https://ibmsecuritydocs.github.io/qradar_api_20.0/20.0--siem-offenses-GET.html
* Microsoft Defender for Endpoint alerts
  — https://learn.microsoft.com/en-us/defender-endpoint/api/alerts

Every payload below is **synthetic**, built to the shape those pages document.
None came from a customer.

Why this test spawns two subprocesses
-------------------------------------
The three links live in three deployables that all package their code as a
top-level ``app``, so one interpreter cannot import two of them: the second
``import app`` returns the first. ``services/actions`` runs in-process here
because it owns the readers; ``normalize()`` and the envelope builder run in
children with the peer service's directory on ``sys.path``.

The agents child pre-registers ``app`` and ``app.replay`` as namespace
packages before importing. That skips only ``__init__.py``, whose sole job is
re-exporting, and avoids dragging the whole agent graph — and its model
dependencies — into a test about dictionary shapes. The two modules that do
the work are loaded from their real files, unmodified; nothing here is a
stand-in for them.

What "present" means in the assertions
--------------------------------------
``alert["hostname"]``, ``alert["username"]`` and ``alert["severity"]`` on the
``aisoc.alerts.fused`` envelope, because those are the three keys
``build_state`` reads. A severity that is present but is the connector's
``medium`` default rather than the vendor's own value is a failure here: a
fabricated severity is worse than an absent one, since it reads as measured.

QRadar is asserted differently, and the reason is a property of the vendor
rather than of this code. An offense indexes exactly one entity —
``offense_source``, typed by ``offense_type`` — so an offense is host-indexed
or user-indexed and never both. Both mappings are proven, and the slot the
offense does not carry is asserted **empty**, because filling it would be a
fabricated entity on a forensic record.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from app.clients.defender_client import DefenderClient
from app.clients.elastic_client import ElasticClient
from app.clients.qradar_client import QRadarClient
from app.clients.sentinel_client import SentinelClient
from app.clients.splunk_client import SplunkClient
from app.services.alert_history import (
    parse_defender_alert,
    parse_elastic_signal,
    parse_qradar_offense,
    parse_sentinel_incident,
    parse_splunk_notable,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
CONNECTORS = REPO_ROOT / "services" / "connectors"
AGENTS = REPO_ROOT / "services" / "agents"

SINCE = datetime(2026, 9, 1, tzinfo=UTC)
UNTIL = datetime(2026, 9, 26, tzinfo=UTC)

#: One host and one account across all five payloads, so a value that reaches
#: the envelope from the wrong vendor's row cannot look like a pass.
HOST = "fin-wks-0423.corp.example.com"
USER = "m.okafor"

#: ``(module, class, constructor kwargs)`` for the connector each reader
#: feeds. Resolved in the child, where ``app`` is the connectors package.
_CONNECTORS: dict[str, tuple[str, str, dict[str, Any]]] = {
    "splunk": ("app.connectors.splunk", "SplunkConnector", {"base_url": "https://splunk:8089", "token": "t"}),
    "sentinel": (
        "app.connectors.microsoft_sentinel",
        "MicrosoftSentinelConnector",
        {"tenant_id": "t", "client_id": "c", "client_secret": "s", "subscription_id": "sub", "resource_group": "rg", "workspace": "ws"},
    ),
    "elastic": ("app.connectors.elastic", "ElasticConnector", {"base_url": "https://es:9200", "api_key": "k"}),
    "qradar": ("app.connectors.qradar", "QRadarConnector", {"console_url": "https://qradar", "sec_token": "t"}),
    "defender": ("app.connectors.azure_defender", "AzureDefenderConnector", {"tenant_id": "t", "client_id": "c", "client_secret": "s"}),
}


# ---------------------------------------------------------------------------
# Recorded vendor payloads
# ---------------------------------------------------------------------------

_SPLUNK_RESULTS = {
    "results": [
        {
            "event_id": "A1B2@@notable@@1",
            "rule_id": "ESCU-Suspicious-Powershell",
            "rule_name": "Suspicious PowerShell Encoded Command",
            "urgency": "high",
            "disposition": "disposition:1",
            "review_time": "1790294400",
            "reviewer": "a.analyst",
            "comment": "Confirmed beacon, host isolated.",
            "_time": "1790290800",
            # The notable's asset and identity fields. Enterprise Security
            # correlates assets on src/dest/dvc and identities on user/src_user.
            "src": "10.21.4.88",
            "dest": HOST,
            "dvc": HOST,
            "user": USER,
            "src_user": USER,
        }
    ]
}

_SENTINEL_INCIDENTS = {
    "value": [
        {
            "id": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.SecurityInsights/incidents/1111-2222",
            "name": "1111-2222",
            "properties": {
                "incidentNumber": 42,
                "title": "Mass download by a single user",
                "description": "A single account downloaded 4.2 GB in ten minutes.",
                "status": "Closed",
                "severity": "High",
                "classification": "BenignPositive",
                "classificationReason": "SuspiciousButExpected",
                "classificationComment": "Quarterly data export by the finance team.",
                "createdTimeUtc": "2026-09-20T08:00:00Z",
                "lastModifiedTimeUtc": "2026-09-20T10:00:00Z",
                "closedBy": {"userPrincipalName": "analyst@example.com"},
                "relatedAnalyticRuleIds": ["/rules/mass-download"],
            },
        }
    ]
}

_SENTINEL_ENTITIES = {
    "entities": [
        {
            "id": "/entities/acc-1",
            "name": "acc-1",
            "kind": "Account",
            "properties": {"accountName": USER, "friendlyName": USER, "upnSuffix": "example.com"},
        },
        {
            "id": "/entities/host-1",
            "name": "host-1",
            "kind": "Host",
            "properties": {"hostName": HOST, "friendlyName": HOST, "netBiosName": "FIN-WKS-0423"},
        },
    ],
    "metaData": [{"entityKind": "Account", "count": 1}, {"entityKind": "Host", "count": 1}],
}

#: A detection alert as `.alerts-security.alerts-*` stores it: the
#: `kibana.alert.*` fields as literal dotted keys, the ECS fields copied from
#: the source document as nested objects. `critical` is deliberate — it is the
#: value the connector's `medium` default silently replaces.
_ELASTIC_HITS = {
    "hits": {
        "hits": [
            {
                "_index": ".internal.alerts-security.alerts-default-000001",
                "_id": "sig-1",
                "_source": {
                    "@timestamp": "2026-09-15T08:00:00.000Z",
                    "kibana.alert.uuid": "sig-1",
                    "kibana.alert.rule.name": "Potential Credential Dumping via LSASS",
                    "kibana.alert.rule.uuid": "rule-abc",
                    "kibana.alert.severity": "critical",
                    "kibana.alert.risk_score": 73,
                    "kibana.alert.reason": "process lsass.exe accessed by rundll32.exe",
                    "kibana.alert.workflow_status": "closed",
                    "kibana.alert.workflow_tags": ["false_positive"],
                    "kibana.alert.workflow_status_updated_at": "2026-09-15T09:30:00.000Z",
                    "kibana.alert.workflow_user": "d.analyst",
                    "event": {"kind": "signal"},
                    "host": {"name": HOST, "os": {"family": "windows"}},
                    "user": {"name": USER, "domain": "CORP"},
                },
            }
        ]
    }
}

_QRADAR_REASONS = [
    {"id": 1, "text": "False-Positive, Tuned"},
    {"id": 3, "text": "Policy Violation"},
]

#: Offense types are site-configurable, which is why the reader resolves them
#: from the appliance instead of hardcoding the stock ids.
_QRADAR_OFFENSE_TYPES = [
    {"id": 0, "name": "Source IP", "property_name": "sourceIP", "custom": False, "database_type": "COMMON"},
    {"id": 3, "name": "Username", "property_name": "username", "custom": False, "database_type": "COMMON"},
    {"id": 7, "name": "Hostname", "property_name": "hostName", "custom": False, "database_type": "EVENTS"},
]

_QRADAR_OFFENSES = [
    {
        "id": 501,
        "description": "Multiple Login Failures for Single Username\n",
        "status": "CLOSED",
        "severity": 8,
        "magnitude": 7,
        "offense_type": 3,
        "offense_source": USER,
        "event_count": 42,
        "start_time": 1790287200000,
        "close_time": 1790294400000,
        "last_updated_time": 1790294400000,
        "closing_reason_id": 1,
        "closing_user": "e.analyst",
    },
    {
        "id": 502,
        "description": "Outbound Data Transfer\n",
        "status": "CLOSED",
        "severity": 9,
        "magnitude": 9,
        "offense_type": 7,
        "offense_source": HOST,
        "event_count": 11,
        "start_time": 1790290800000,
        "close_time": 1790298000000,
        "last_updated_time": 1790298000000,
        "closing_reason_id": 3,
        "closing_user": "f.analyst",
    },
]

_DEFENDER_ALERTS = {
    "value": [
        {
            "id": "da637472900382838869_1364969609",
            "incidentId": 1126093,
            "assignedTo": "g.analyst",
            "severity": "High",
            "status": "Resolved",
            "classification": "TruePositive",
            "determination": "Malware",
            "investigationState": "Benign",
            "detectionSource": "WindowsDefenderAtp",
            "category": "Execution",
            "title": "Low-reputation arbitrary code executed by signed executable",
            "description": "Binaries signed by Microsoft can be used to run low-reputation arbitrary code.",
            "alertCreationTime": "2026-09-18T10:00:00Z",
            "firstEventTime": "2026-09-18T09:58:00Z",
            "lastEventTime": "2026-09-18T09:59:00Z",
            "lastUpdateTime": "2026-09-18T12:00:00Z",
            "resolvedTime": "2026-09-18T12:00:00Z",
            "machineId": "111e6dd8c833c8a052ea231ec1b19adaf497b625",
            "computerDnsName": HOST,
            "threatFamilyName": None,
            "mitreTechniques": ["T1055"],
            "relatedUser": {"userName": USER, "domainName": "CORP"},
            "evidence": [
                {
                    "entityType": "User",
                    "evidenceCreationTime": "2026-09-18T10:00:01Z",
                    "accountName": USER,
                    "domainName": "CORP",
                    "userSid": "S-1-5-21-11111607-1111760036-109187956-75141",
                    "userPrincipalName": f"{USER}@example.com",
                    "detectionStatus": None,
                },
                {
                    "entityType": "Process",
                    "evidenceCreationTime": "2026-09-18T10:00:01Z",
                    "sha256": "a4752c71d81afd3d5865d24ddb11a6b0c615062fcc448d24050c2172d2cbccd6",
                    "fileName": "rundll32.exe",
                    "filePath": "C:\\Windows\\SysWOW64",
                    "processCommandLine": "rundll32.exe c:\\temp\\suspicious.dll,RepeatAfterMe",
                    "detectionStatus": "Detected",
                },
            ],
        }
    ]
}


# ---------------------------------------------------------------------------
# The three links
# ---------------------------------------------------------------------------


async def _read_all() -> dict[str, list[Any]]:
    """Drive each reader's real HTTP path against its recorded payload.

    Returns the parsed :class:`ClosedFinding` rows, and also asserts the two
    requests whose *contents* decide whether a real vendor would have returned
    the host and user at all. A mock hands back whatever it is given, so a
    reader that never asked Splunk for ``user`` or QRadar for ``magnitude``
    would otherwise pass here and return nothing in production.
    """
    out: dict[str, list[Any]] = {}

    with respx.mock:
        respx.post(url__regex=r".*/oauth2/v2\.0/token").mock(return_value=httpx.Response(200, json={"access_token": "tok"}))

        splunk_job = respx.post(url__regex=r"https://splunk:8089/services/search/jobs$").mock(
            return_value=httpx.Response(201, json={"sid": "sid-1"})
        )
        respx.get(url__regex=r".*/services/search/jobs/sid-1/results.*").mock(return_value=httpx.Response(200, json=_SPLUNK_RESULTS))
        rows = await SplunkClient(host="https://splunk:8089", token="t").list_closed_notables(SINCE, UNTIL)
        spl = splunk_job.calls[0].request.content.decode().replace("+", " ")
        for field in ("dest", "user"):
            assert f" {field}" in spl, f"the SPL does not project {field!r}, so a real Splunk returns no such column: {spl}"
        out["splunk"] = [parse_splunk_notable(r) for r in rows]

        respx.get(url__regex=r".*/providers/Microsoft\.SecurityInsights/incidents\?.*").mock(
            return_value=httpx.Response(200, json=_SENTINEL_INCIDENTS)
        )
        entities = respx.post(url__regex=r".*/incidents/1111-2222/entities.*").mock(
            return_value=httpx.Response(200, json=_SENTINEL_ENTITIES)
        )
        rows = await SentinelClient("t", "c", "s", "sub", "rg", "ws").list_closed_incidents(SINCE, UNTIL)
        assert entities.called, "an incident carries no host or account of its own; they come from the entities endpoint"
        out["sentinel"] = [parse_sentinel_incident(r) for r in rows]

        respx.post(url__regex=r"https://es:9200/.*/_search").mock(return_value=httpx.Response(200, json=_ELASTIC_HITS))
        rows = await ElasticClient(es_url="https://es:9200", api_key="k").list_closed_signals(SINCE, UNTIL)
        out["elastic"] = [parse_elastic_signal(r) for r in rows]

        respx.get(url__regex=r".*/api/siem/offense_closing_reasons.*").mock(return_value=httpx.Response(200, json=_QRADAR_REASONS))
        respx.get(url__regex=r".*/api/siem/offense_types.*").mock(return_value=httpx.Response(200, json=_QRADAR_OFFENSE_TYPES))
        offenses = respx.get(url__regex=r".*/api/siem/offenses\?.*").mock(return_value=httpx.Response(200, json=_QRADAR_OFFENSES))
        rows = await QRadarClient(base_url="https://qradar", api_token="t").list_closed_offenses(SINCE, UNTIL)
        query = str(offenses.calls[0].request.url)
        for field in ("magnitude", "offense_source"):
            assert field in query, f"the offenses read does not request {field!r}, so QRadar omits it from the response: {query}"
        out["qradar"] = [parse_qradar_offense(r) for r in rows]

        respx.get(url__regex=r"https://api\.securitycenter\.microsoft\.com/api/alerts.*").mock(
            return_value=httpx.Response(200, json=_DEFENDER_ALERTS)
        )
        rows = await DefenderClient("t", "c", "s").list_resolved_alerts(SINCE, UNTIL)
        out["defender"] = [parse_defender_alert(r) for r in rows]

    return out


_CONNECTOR_CHILD = """
import importlib, json, sys
payload = json.load(sys.stdin)
out = {}
for vendor, spec in payload.items():
    cls = getattr(importlib.import_module(spec["module"]), spec["cls"])(**spec["kwargs"])
    out[vendor] = [cls.normalize(dict(row)) for row in spec["rows"]]
json.dump(out, sys.stdout)
"""

_AGENTS_CHILD = """
import json, pathlib, sys, types
root = pathlib.Path(sys.argv[1])
for name, rel in (("app", "app"), ("app.replay", "app/replay")):
    mod = types.ModuleType(name)
    mod.__path__ = [str(root / rel)]
    sys.modules[name] = mod
from app.replay.findings import HistoricalFinding
from app.replay.normalize import to_fused_envelope

payload = json.load(sys.stdin)
out = {}
for vendor, rows in payload.items():
    out[vendor] = [
        to_fused_envelope(
            HistoricalFinding.from_mapping(row["finding"]),
            row["normalized"],
            tenant_id="00000000-0000-0000-0000-000000000001",
            connector_id=vendor,
        )
        for row in rows
    ]
json.dump(out, sys.stdout)
"""


def _child(source: str, cwd: Path, payload: Any, *args: str) -> Any:
    """Run one link in a child interpreter rooted at the peer service.

    ``PYTHONPATH`` is cleared rather than inherited. ``python -c`` puts the
    working directory first, which is how the child resolves ``app`` to the
    peer service — but an inherited ``PYTHONPATH`` naming this service would
    put *its* ``app`` on the path too, and the test would then grade one
    service's code while reporting the other's.

    A non-zero exit is a failure, never a skip: this test exists to prove the
    three links agree, and a child that could not start proves nothing while
    reporting green.
    """
    assert cwd.is_dir(), f"{cwd} is missing; this test needs the monorepo checkout, not one service"
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", source, *args],
        cwd=cwd,
        env={k: v for k, v in os.environ.items() if k != "PYTHONPATH"},
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert proc.returncode == 0, f"child in {cwd.name} failed:\n{proc.stderr}"
    return json.loads(proc.stdout)


@pytest.fixture(scope="module")
def chain() -> dict[str, list[dict[str, Any]]]:
    """Reader rows, the connector envelope, and the fused alert, per vendor."""
    findings = asyncio.run(_read_all())

    normalized = _child(
        _CONNECTOR_CHILD,
        CONNECTORS,
        {
            vendor: {
                "module": _CONNECTORS[vendor][0],
                "cls": _CONNECTORS[vendor][1],
                "kwargs": _CONNECTORS[vendor][2],
                "rows": [dict(f.raw) for f in rows],
            }
            for vendor, rows in findings.items()
        },
    )

    envelopes = _child(
        _AGENTS_CHILD,
        AGENTS,
        {
            vendor: [{"finding": f.as_dict(), "normalized": n} for f, n in zip(rows, normalized[vendor], strict=True)]
            for vendor, rows in findings.items()
        },
        str(AGENTS),
    )

    return {
        vendor: [
            {"finding": f.as_dict(), "normalized": n, "alert": e["alert"]}
            for f, n, e in zip(rows, normalized[vendor], envelopes[vendor], strict=True)
        ]
        for vendor, rows in findings.items()
    }


@pytest.mark.parametrize("vendor", ["splunk", "sentinel", "elastic", "defender"])
def test_triage_input_carries_host_user_and_severity(chain, vendor):
    """The three fields an analyst needs survive reader to normalize to triage."""
    alert = chain[vendor][0]["alert"]
    assert alert["hostname"] == HOST, f"{vendor}: host lost between the reader and the triage input"
    assert alert["username"] == USER, f"{vendor}: user lost between the reader and the triage input"
    assert alert["severity"] in {"info", "low", "medium", "high", "critical"}, f"{vendor}: {alert['severity']!r}"


@pytest.mark.parametrize(
    ("vendor", "expected"),
    [("splunk", "high"), ("sentinel", "high"), ("elastic", "critical"), ("defender", "high")],
)
def test_severity_is_the_vendors_own_not_a_default(chain, vendor, expected):
    """A connector default that replaces the vendor's severity reads as measured.

    Elastic is the case that motivates this: against a ``_search`` hit every
    lookup in ``normalize()`` missed and the alert reached triage at ``medium``
    while the signal said ``critical``.
    """
    assert chain[vendor][0]["alert"]["severity"] == expected


def test_qradar_offense_source_lands_in_the_slot_its_type_names(chain):
    """An offense indexes one entity, so the other slot must stay empty.

    ``offense_source`` is a bare string and ``offense_type`` is what says
    whether it is a username, a hostname or an address. Writing it into both
    slots would put a username in the hostname column of a forensic record.
    """
    by_id = {str(row["finding"]["finding_id"]): row["alert"] for row in chain["qradar"]}

    user_offense = by_id["501"]
    assert user_offense["username"] == USER
    assert not user_offense["hostname"], "a Username offense carries no host; QRadar did not report one"

    host_offense = by_id["502"]
    assert host_offense["hostname"] == HOST
    assert not host_offense["username"], "a Hostname offense carries no account; QRadar did not report one"

    assert user_offense["severity"] == "high"
    assert host_offense["severity"] == "critical"
