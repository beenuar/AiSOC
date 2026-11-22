"""`sync_detection_rule` reaches the vendor it names, verifies, and rolls back.

What was wrong (WS1.1 of the gap-closure program)
-------------------------------------------------
`SplunkSyncDetectionRule` in `live_actions/builtins.py` described creating a
Splunk saved search, but delegated to `SyncDetectionRuleExecutor`, which only
ever built an **Elastic** client from `elastic_url` — with Splunk credentials
the call could only simulate, while `SplunkClient.create_or_update_
correlation_search` sat in the tree with no caller. The rollback logged
"would disable rule" and returned ``True`` without acting, and the contract
declared no verification probe because no client could read a stored
definition back.

What this asserts
-----------------
* The Splunk arm drives the real Splunk client against a mock vendor server:
  the saved search is upserted with the intended SPL, through the real
  live-actions builtin (adapter) path.
* The write is **verified by read-back**: the stored definition is compared
  with the normalized intended content, and a vendor that stored different
  content fails the action naming the mismatch — existence alone is the
  wrong check (the contract's own words).
* The prior definition (or its absence) is captured before every write;
  rollback restores the captured prior version, deletes a rule the action
  created, and **returns False when the vendor refuses** — a rollback that
  logs and returns True without acting is the defect this file pins.
* The Elastic arm gets the same treatment through its own builtin.
* `dry_run` stays simulation: the mock vendor sees no request.
* The capability contract now declares the probe.
"""

from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

import httpx
import pytest
from app.clients.elastic_client import ElasticClient
from app.clients.splunk_client import SplunkClient
from app.executors import siem as siem_module
from app.live_actions.builtins import ElasticSyncDetectionRule, SplunkSyncDetectionRule
from app.live_actions.capability_contracts import CAPABILITY_CONTRACTS
from app.live_actions.models import LiveActionRequest, LiveActionStatus

SPL = "index=main sourcetype=auth action=failure | stats count by user | where count > 5"


class _FakeSplunk:
    """A Splunk management API: saved-search read, upsert, delete."""

    def __init__(self, *, tamper_on_store: bool = False, refuse_delete: bool = False) -> None:
        self.searches: dict[str, dict[str, str]] = {}
        self.requests: list[tuple[str, str]] = []
        self.tamper_on_store = tamper_on_store
        self.refuse_delete = refuse_delete

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append((request.method, request.url.path))
        path = request.url.path
        if "/saved/searches" not in path:
            return httpx.Response(404, json={"messages": [{"text": f"no route {path}"}]})
        name = path.rsplit("/", 1)[-1] if not path.endswith("/searches") else ""

        if request.method == "GET":
            if name in self.searches:
                content = self.searches[name]
                return httpx.Response(200, json={"entry": [{"name": name, "content": content}]})
            return httpx.Response(404, json={"messages": [{"text": "not found"}]})

        if request.method == "DELETE":
            if self.refuse_delete:
                return httpx.Response(503, json={"messages": [{"text": "kvstore busy"}]})
            self.searches.pop(name, None)
            return httpx.Response(200, json={})

        # POST: update at /saved/searches/{name}, create at /saved/searches
        form = dict(httpx.QueryParams(request.content.decode()))
        if path.endswith("/saved/searches"):
            name = form.pop("name", "")
            if name in self.searches:
                return httpx.Response(409, json={"messages": [{"text": "exists"}]})
        elif name not in self.searches:
            return httpx.Response(404, json={"messages": [{"text": "not found"}]})
        stored_search = form.get("search", "")
        if self.tamper_on_store:
            stored_search = stored_search + " | head 1"
        self.searches[name] = {
            "search": stored_search,
            "cron_schedule": form.get("cron_schedule", ""),
            "alert.severity": form.get("alert.severity", ""),
        }
        return httpx.Response(201, json={"entry": [{"name": name}]})


class _FakeKibana:
    """Kibana detection-engine rules: find by rule_id, upsert, delete."""

    def __init__(self, *, tamper_on_store: bool = False, refuse_delete: bool = False) -> None:
        self.rules: dict[str, dict[str, Any]] = {}
        self.requests: list[tuple[str, str]] = []
        self.tamper_on_store = tamper_on_store
        self.refuse_delete = refuse_delete

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append((request.method, request.url.path))
        if "/api/detection_engine/rules" not in request.url.path:
            return httpx.Response(404, json={"message": "no route"})
        rule_id = request.url.params.get("rule_id")

        if request.method == "GET":
            rule = self.rules.get(rule_id or "")
            if rule is None:
                return httpx.Response(404, json={"message": "rule not found"})
            return httpx.Response(200, json=rule)

        if request.method == "DELETE":
            if self.refuse_delete:
                return httpx.Response(503, json={"message": "busy"})
            self.rules.pop(rule_id or "", None)
            return httpx.Response(200, json={})

        body = json.loads(request.content)
        rid = body.get("rule_id") or f"generated-{len(self.rules) + 1}"
        stored = dict(body)
        if self.tamper_on_store:
            stored["query"] = stored.get("query", "") + " and tampered:true"
        stored["rule_id"] = rid
        stored["id"] = f"internal-{rid}"
        self.rules[rid] = stored
        return httpx.Response(200, json=stored)


@pytest.fixture()
def splunk(monkeypatch: pytest.MonkeyPatch) -> _FakeSplunk:
    fake = _FakeSplunk()
    _wire_splunk(monkeypatch, fake)
    return fake


def _wire_splunk(monkeypatch: pytest.MonkeyPatch, fake: _FakeSplunk) -> None:
    def factory(params: dict) -> SplunkClient | None:
        if not (params.get("splunk_url") or params.get("splunk_host")):
            return None
        return SplunkClient(
            host=params.get("splunk_url") or params["splunk_host"],
            token=params.get("splunk_token"),
            transport=httpx.MockTransport(fake.handle),
        )

    monkeypatch.setattr(siem_module, "_splunk_client", factory)


def _wire_kibana(monkeypatch: pytest.MonkeyPatch, fake: _FakeKibana) -> None:
    def factory(params: dict) -> ElasticClient | None:
        if not params.get("elastic_url"):
            return None
        return ElasticClient(
            es_url=params["elastic_url"],
            api_key=params.get("elastic_api_key"),
            kibana_url=params.get("kibana_url"),
            transport=httpx.MockTransport(fake.handle),
        )

    monkeypatch.setattr(siem_module, "_elastic_client", factory)


def _splunk_request(**overrides: Any) -> LiveActionRequest:
    params = {
        "splunk_url": "https://splunk.example:8089",
        "splunk_token": "tok-1",
        "query": SPL,
        "schedule": "*/10 * * * *",
        "severity": "high",
    }
    params.update(overrides.pop("params", {}))
    return LiveActionRequest(
        capability="sync_detection_rule",
        vendor_id="splunk",
        tenant_id=uuid4(),
        target="AiSOC - brute force by user",
        params=params,
        requested_by="test@aisoc.internal",
        **overrides,
    )


def _elastic_request(**overrides: Any) -> LiveActionRequest:
    params = {
        "elastic_url": "https://es.example:9200",
        "elastic_api_key": "key-1",
        "kibana_url": "https://kibana.example:5601",
        "rule_config": {
            "rule_id": "aisoc-rule-1",
            "name": "AiSOC - brute force by user",
            "type": "query",
            "query": 'event.action:"logon-failed" and user.name:*',
            "language": "kuery",
            "index": ["logs-*"],
            "enabled": True,
            "severity": "high",
            "risk_score": 73,
        },
    }
    params.update(overrides.pop("params", {}))
    return LiveActionRequest(
        capability="sync_detection_rule",
        vendor_id="elastic",
        tenant_id=uuid4(),
        target="AiSOC - brute force by user",
        params=params,
        requested_by="test@aisoc.internal",
        **overrides,
    )


@pytest.mark.asyncio
class TestSplunkArm:
    async def test_the_splunk_arm_reaches_splunk_and_reads_back(self, splunk: _FakeSplunk):
        result = await SplunkSyncDetectionRule().execute(_splunk_request())

        assert result.status == LiveActionStatus.SUCCEEDED
        assert "AiSOC - brute force by user" in splunk.searches
        assert splunk.searches["AiSOC - brute force by user"]["search"].strip() == SPL
        # The probe read the definition back after the write.
        reads = [(m, p) for m, p in splunk.requests if m == "GET"]
        assert reads, "no read-back probe was issued"

    async def test_a_vendor_that_stored_different_content_fails_the_action(self, monkeypatch: pytest.MonkeyPatch):
        fake = _FakeSplunk(tamper_on_store=True)
        _wire_splunk(monkeypatch, fake)

        result = await SplunkSyncDetectionRule().execute(_splunk_request())

        assert result.status == LiveActionStatus.FAILED
        assert "mismatch" in (result.error or "").lower() or "mismatch" in str(result.output).lower()

    async def test_prior_definition_is_captured_and_rollback_restores_it(self, splunk: _FakeSplunk):
        prior_spl = "index=main | stats count"
        splunk.searches["AiSOC - brute force by user"] = {
            "search": prior_spl,
            "cron_schedule": "*/30 * * * *",
            "alert.severity": "medium",
        }

        executor = SplunkSyncDetectionRule()
        result = await executor.execute(_splunk_request())
        assert result.status == LiveActionStatus.SUCCEEDED
        assert splunk.searches["AiSOC - brute force by user"]["search"].strip() == SPL

        rolled_back = await executor.rollback(result, params={"splunk_url": "https://splunk.example:8089", "splunk_token": "tok-1"})
        assert rolled_back is True
        assert splunk.searches["AiSOC - brute force by user"]["search"].strip() == prior_spl
        assert splunk.searches["AiSOC - brute force by user"]["cron_schedule"] == "*/30 * * * *"

    async def test_rollback_deletes_a_rule_the_action_created(self, splunk: _FakeSplunk):
        executor = SplunkSyncDetectionRule()
        result = await executor.execute(_splunk_request())
        assert "AiSOC - brute force by user" in splunk.searches

        rolled_back = await executor.rollback(result, params={"splunk_url": "https://splunk.example:8089", "splunk_token": "tok-1"})
        assert rolled_back is True
        assert "AiSOC - brute force by user" not in splunk.searches

    async def test_rollback_reports_failure_instead_of_lying(self, monkeypatch: pytest.MonkeyPatch):
        fake = _FakeSplunk(refuse_delete=True)
        _wire_splunk(monkeypatch, fake)

        executor = SplunkSyncDetectionRule()
        result = await executor.execute(_splunk_request())
        rolled_back = await executor.rollback(result, params={"splunk_url": "https://splunk.example:8089", "splunk_token": "tok-1"})

        assert rolled_back is False, (
            "the vendor refused the delete; reporting True is the log-and-return-True defect this file exists to pin"
        )

    async def test_dry_run_touches_no_vendor(self, splunk: _FakeSplunk):
        result = await SplunkSyncDetectionRule().execute(_splunk_request(dry_run=True))

        assert result.status == LiveActionStatus.SIMULATED
        assert splunk.requests == []


@pytest.mark.asyncio
class TestElasticArm:
    async def test_the_elastic_arm_upserts_and_reads_back(self, monkeypatch: pytest.MonkeyPatch):
        fake = _FakeKibana()
        _wire_kibana(monkeypatch, fake)

        result = await ElasticSyncDetectionRule().execute(_elastic_request())

        assert result.status == LiveActionStatus.SUCCEEDED
        assert "aisoc-rule-1" in fake.rules
        reads = [(m, p) for m, p in fake.requests if m == "GET"]
        assert reads, "no read-back probe was issued"

    async def test_elastic_content_mismatch_fails(self, monkeypatch: pytest.MonkeyPatch):
        fake = _FakeKibana(tamper_on_store=True)
        _wire_kibana(monkeypatch, fake)

        result = await ElasticSyncDetectionRule().execute(_elastic_request())

        assert result.status == LiveActionStatus.FAILED

    async def test_elastic_rollback_restores_prior_rule(self, monkeypatch: pytest.MonkeyPatch):
        fake = _FakeKibana()
        _wire_kibana(monkeypatch, fake)
        prior = {
            "rule_id": "aisoc-rule-1",
            "id": "internal-aisoc-rule-1",
            "name": "AiSOC - brute force by user",
            "type": "query",
            "query": 'event.action:"logon-failed"',
            "language": "kuery",
            "index": ["logs-*"],
            "enabled": False,
            "severity": "medium",
            "risk_score": 40,
        }
        fake.rules["aisoc-rule-1"] = dict(prior)

        executor = ElasticSyncDetectionRule()
        result = await executor.execute(_elastic_request())
        assert fake.rules["aisoc-rule-1"]["risk_score"] == 73

        rolled_back = await executor.rollback(
            result,
            params={"elastic_url": "https://es.example:9200", "elastic_api_key": "key-1", "kibana_url": "https://kibana.example:5601"},
        )
        assert rolled_back is True
        assert fake.rules["aisoc-rule-1"]["risk_score"] == 40
        assert fake.rules["aisoc-rule-1"]["severity"] == "medium"

    async def test_elastic_rollback_deletes_created_rule(self, monkeypatch: pytest.MonkeyPatch):
        fake = _FakeKibana()
        _wire_kibana(monkeypatch, fake)

        executor = ElasticSyncDetectionRule()
        result = await executor.execute(_elastic_request())
        assert "aisoc-rule-1" in fake.rules

        rolled_back = await executor.rollback(
            result,
            params={"elastic_url": "https://es.example:9200", "elastic_api_key": "key-1", "kibana_url": "https://kibana.example:5601"},
        )
        assert rolled_back is True
        assert "aisoc-rule-1" not in fake.rules


class TestContract:
    def test_the_contract_declares_the_readback_probe(self):
        contract = CAPABILITY_CONTRACTS["sync_detection_rule"]
        assert contract.has_verification_probe is True
        assert not getattr(contract, "verification_gap", None)
