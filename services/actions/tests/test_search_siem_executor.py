"""Issue #570 — SearchSIEMExecutor must call SplunkClient with the right kwarg.

`SplunkClient.run_search` takes `max_count`; the executor previously passed
`max_results=`, raising TypeError on every live Splunk search (silently
returning a FAILED action). These tests pin the contract so it can't regress.
"""

from __future__ import annotations

import inspect
from uuid import uuid4

import pytest
from app.clients.splunk_client import SplunkClient
from app.executors import siem
from app.executors.siem import SearchSIEMExecutor
from app.models.action import ActionRequest, ActionStatus, ActionType


def test_run_search_signature_uses_max_count_not_max_results():
    params = inspect.signature(SplunkClient.run_search).parameters
    assert "max_count" in params
    assert "max_results" not in params


class _FakeSplunk:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def run_search(self, **kwargs):  # noqa: ANN003 — mirror the real signature loosely
        self.calls.append(kwargs)
        return [{"_raw": "evt-1"}, {"_raw": "evt-2"}]


def _request() -> ActionRequest:
    return ActionRequest(
        incident_id=uuid4(),
        tenant_id=uuid4(),
        action_type=ActionType.SEARCH_SIEM,
        target="splunk",
        parameters={"query": "index=main sourcetype=WinEventLog", "max_results": 25},
    )


@pytest.mark.asyncio
async def test_executor_calls_run_search_with_max_count(monkeypatch):
    fake = _FakeSplunk()
    monkeypatch.setattr(siem, "_splunk_client", lambda params: fake)

    result = await SearchSIEMExecutor().execute(_request())

    assert result.status is ActionStatus.COMPLETED
    assert len(fake.calls) == 1
    kwargs = fake.calls[0]
    assert kwargs.get("max_count") == 25  # correct kwarg + value threaded through
    assert "max_results" not in kwargs  # the broken kwarg is gone
    assert result.output["result_count"] == 2
