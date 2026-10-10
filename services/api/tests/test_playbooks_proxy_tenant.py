"""The playbook proxy must tell the agents service which tenant it acts for."""

import uuid
from types import SimpleNamespace

import pytest
from app.api.v1.endpoints import playbooks as pb

TENANT = uuid.UUID("00000000-0000-0000-0000-0000000000aa")


class _Resp:
    status_code = 200

    def json(self):
        return []


class _Client:
    seen: list = []

    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def request(self, method, url, headers=None, **kwargs):
        _Client.seen.append({"method": method, "url": url, "headers": dict(headers or {})})
        return _Resp()


@pytest.fixture(autouse=True)
def _fake_httpx(monkeypatch):
    _Client.seen = []
    monkeypatch.setattr(pb.httpx, "AsyncClient", _Client)


def _user():
    return SimpleNamespace(tenant_id=TENANT)


async def test_list_playbooks_declares_the_tenant():
    await pb.list_playbooks(user=_user())
    assert _Client.seen[-1]["headers"][pb.SERVICE_TENANT_HEADER] == str(TENANT)


async def test_list_runs_declares_the_tenant():
    await pb.list_runs(user=_user(), limit=5)
    assert _Client.seen[-1]["headers"][pb.SERVICE_TENANT_HEADER] == str(TENANT)


async def test_get_playbook_declares_the_tenant():
    await pb.get_playbook("tpl-credential-access", user=_user())
    assert _Client.seen[-1]["headers"][pb.SERVICE_TENANT_HEADER] == str(TENANT)


async def test_proxy_refuses_to_forward_without_a_tenant():
    with pytest.raises(TypeError):
        await pb._proxy("GET", "")
