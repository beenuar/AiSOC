"""Depth 5.1 — the three step types that name an outbound effect and had none.

Each test here is a *reproduce* first and a regression second: before the
change in this commit, the first three fail against the shipped packs with
the exact counts recorded in their assertions.

Measured on the tree at the start of this work, over the 62 playbooks under
``playbooks/``:

* ``http``   — 69 of 69 steps raised ``SSRFError: scheme '' is not allowed``.
  Every pack URL begins with a ``${NAME}`` placeholder naming an integration
  (``${IDP_BASE_URL}/users/{{alert.user}}/sessions``), nothing resolved it,
  and ``urlsplit`` reads a string starting ``${`` as having no scheme.
* ``notify`` — 63 of 63 steps answered ``{"delivered": false, "reason": "no
  url"}``. The handler had one sender, ``channel == "webhook"``, and the
  packs use ``slack`` (49), ``pagerduty`` (63 across both copies) and
  ``email``, addressed by ``webhook_env`` / ``service_key_env`` rather than
  a literal URL.
* ``osquery_live_query`` — raised ``PermanentStepFailure`` in this image,
  because its three clients live in ``services/actions`` and
  ``app.clients`` does not exist here.

The counts are asserted as "none remain", not as a number, so the test keeps
working when a pack is added. The pre-change numbers live in this docstring
because a test that asserts the broken count has to be deleted to fix the
defect, and then nothing records what was wrong.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any

import pytest
from app.playbook import engine as engine_mod
from app.playbook import ssrf_guard
from app.playbook.models import PlaybookStep, StepType

_PACKS = Path(__file__).resolve().parents[3] / "playbooks"


@pytest.fixture(autouse=True)
def _resolvable_test_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    """Answer DNS for the documentation hostnames these tests use.

    The guard is left entirely in the path — it still classifies whatever
    address comes back. Only the lookup is stubbed, because a unit test that
    depends on ``example.com`` resolving is a unit test that fails on a
    runner with no egress, and the thing under test is the classification.

    The address has to be one Python's ``ipaddress`` calls public, which
    rules out every documentation range: ``203.0.113.0/24``, ``192.0.2.0/24``
    and ``100.64.0.0/10`` all answer ``is_private`` True, and ``240.0.0.0/4``
    answers ``is_reserved``. Nothing is sent to it — every test here either
    previews or expects the guard to raise first.
    """
    real = socket.getaddrinfo

    def _fake(host: str, *args: Any, **kwargs: Any) -> Any:
        if isinstance(host, str) and host.endswith(".example.com"):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
        return real(host, *args, **kwargs)

    monkeypatch.setattr(ssrf_guard.socket, "getaddrinfo", _fake)


def _pack_steps(step_type: str) -> list[tuple[str, PlaybookStep]]:
    """Every step of one type across the shipped packs, with its file."""
    found: list[tuple[str, PlaybookStep]] = []
    for path in sorted(_PACKS.rglob("*.playbook.json")):
        for raw in json.loads(path.read_text()).get("steps", []):
            if raw.get("type") == step_type:
                found.append((path.name, PlaybookStep.model_validate(raw)))
    return found


def test_the_packs_are_present() -> None:
    """A gate that scanned nothing would pass every assertion below."""
    assert len(list(_PACKS.rglob("*.playbook.json"))) >= 60


# ---------------------------------------------------------------------------
# http
# ---------------------------------------------------------------------------


def test_every_pack_http_url_names_an_integration_reference() -> None:
    """The shape the resolver has to handle, pinned so it cannot drift.

    Fails loudly if a pack ever hardcodes a vendor hostname, which is the
    thing ``${NAME}`` exists to stop: a playbook that ships with somebody
    else's Okta tenant in it.
    """
    steps = _pack_steps("http")
    assert steps, "no http steps in the packs; the rest of this file proves nothing"
    for name, step in steps:
        url = str(step.params.get("url", ""))
        assert url.startswith("${"), f"{name}: http url {url!r} does not start with an integration reference"


@pytest.mark.asyncio
async def test_pack_http_steps_resolve_and_are_guarded(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reproduce: 69 of 69 were rejected before a reference could resolve."""
    references = {
        name: {"value": "https://vendor.example.com", "secret": False}
        for name in (
            "AWS_URL",
            "AZURE_URL",
            "BACKUP_URL",
            "CI_URL",
            "CLOUD_MGMT_URL",
            "CLOUD_URL",
            "DDOS_URL",
            "DLP_URL",
            "DNS_URL",
            "EDGE_URL",
            "EDR_URL",
            "EMAIL_GATEWAY_URL",
            "ERP_URL",
            "FW_URL",
            "GCP_URL",
            "IAC_URL",
            "IDP_BASE_URL",
            "K8S_API_URL",
            "MAIL_URL",
            "PLATFORM_URL",
            "PROXY_URL",
            "REGISTRY_URL",
            "SAAS_URL",
            "SCA_URL",
            "SIEM_URL",
            "WAF_URL",
        )
    }
    references["IDP_BEARER_HEADERS"] = {"headers": {"Authorization": "SSWS test"}, "secret": True}

    async def _fake_references(*, tenant_id: str, names: list[str]) -> dict[str, Any]:  # noqa: ARG001
        return {name: references[name] for name in names if name in references}

    monkeypatch.setattr(engine_mod.references, "resolve", _fake_references)
    # Preview, so nothing leaves the process. The reference still has to
    # resolve and the URL still has to clear the guard — a preview that
    # skipped both would prove the opposite of what this test is for.
    monkeypatch.delenv("AISOC_PLAYBOOK_HTTP_EXECUTE", raising=False)

    context = {"tenant_id": "11111111-1111-1111-1111-111111111111", "alert": {"user": "alice@example.com", "source_ip": "203.0.113.9"}}
    unresolved: list[str] = []
    for name, step in _pack_steps("http"):
        result = await engine_mod._handle_http(step, dict(context), None)
        if result.get("error"):
            unresolved.append(f"{name}/{step.id}: {result['error']}")
    assert not unresolved, "http steps still cannot resolve:\n" + "\n".join(unresolved)


@pytest.mark.asyncio
async def test_http_step_previews_by_default_and_names_the_switch(monkeypatch: pytest.MonkeyPatch) -> None:
    """Off by default: an http step reaches nothing until an operator says so."""

    async def _fake_references(*, tenant_id: str, names: list[str]) -> dict[str, Any]:  # noqa: ARG001
        return {"IDP_BASE_URL": {"value": "https://idp.example.com", "secret": False}}

    monkeypatch.setattr(engine_mod.references, "resolve", _fake_references)
    monkeypatch.delenv("AISOC_PLAYBOOK_HTTP_EXECUTE", raising=False)

    step = PlaybookStep(name="revoke", type=StepType.HTTP, params={"url": "${IDP_BASE_URL}/sessions", "method": "DELETE"})
    result = await engine_mod._handle_http(step, {"tenant_id": "t"}, None)

    assert result["executed"] is False
    assert result["previewed"] is True
    assert "AISOC_PLAYBOOK_HTTP_EXECUTE" in result["reason"]
    assert result["url"] == "https://idp.example.com/sessions"


@pytest.mark.asyncio
async def test_http_step_refuses_an_unresolved_reference(monkeypatch: pytest.MonkeyPatch) -> None:
    """Negative control: an unknown reference must not fall through as a URL.

    Substituting the empty string would hand ``/sessions`` to httpx, which
    reads a scheme-relative path against whatever base it has. The step has
    to say which name it could not resolve.
    """

    async def _no_references(*, tenant_id: str, names: list[str]) -> dict[str, Any]:  # noqa: ARG001
        return {}

    monkeypatch.setattr(engine_mod.references, "resolve", _no_references)

    step = PlaybookStep(name="revoke", type=StepType.HTTP, params={"url": "${NOT_CONFIGURED}/sessions"})
    result = await engine_mod._handle_http(step, {"tenant_id": "t"}, None)
    assert result["executed"] is False
    assert "NOT_CONFIGURED" in result["error"]


@pytest.mark.asyncio
async def test_http_step_still_refuses_a_metadata_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    """Negative control: resolution must not become an SSRF bypass.

    A reference whose stored value points at the cloud metadata service is
    the attack this check exists for — the value comes from a tenant record,
    not from the playbook, so the guard has to run *after* substitution.
    """

    async def _metadata_reference(*, tenant_id: str, names: list[str]) -> dict[str, Any]:  # noqa: ARG001
        return {"EVIL": {"value": "http://169.254.169.254", "secret": False}}

    monkeypatch.setattr(engine_mod.references, "resolve", _metadata_reference)
    monkeypatch.setenv("AISOC_PLAYBOOK_HTTP_EXECUTE", "1")

    step = PlaybookStep(name="steal", type=StepType.HTTP, params={"url": "${EVIL}/latest/meta-data/"})
    with pytest.raises(engine_mod.SSRFError):
        await engine_mod._handle_http(step, {"tenant_id": "t"}, None)


@pytest.mark.asyncio
async def test_http_step_never_records_a_secret_header_value(monkeypatch: pytest.MonkeyPatch) -> None:
    """The run record is read by anyone with case access, so it holds names."""

    async def _secret_reference(*, tenant_id: str, names: list[str]) -> dict[str, Any]:  # noqa: ARG001
        return {
            "IDP_BASE_URL": {"value": "https://idp.example.com", "secret": False},
            "IDP_BEARER_HEADERS": {"headers": {"Authorization": "SSWS super-secret-token"}, "secret": True},
        }

    monkeypatch.setattr(engine_mod.references, "resolve", _secret_reference)
    monkeypatch.delenv("AISOC_PLAYBOOK_HTTP_EXECUTE", raising=False)

    step = PlaybookStep(
        name="revoke",
        type=StepType.HTTP,
        params={"url": "${IDP_BASE_URL}/sessions", "headers_env": "IDP_BEARER_HEADERS"},
    )
    result = await engine_mod._handle_http(step, {"tenant_id": "t"}, None)
    assert "super-secret-token" not in json.dumps(result)
    assert result["header_names"] == ["Authorization"]


# ---------------------------------------------------------------------------
# notify
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pack_notify_steps_reach_governed_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reproduce: 63 of 63 answered ``delivered: false, reason: 'no url'``.

    ``notify`` is a contracted capability in ``services/actions`` with a
    Slack arm that predates this work, so the fix is to stop answering it
    inside the engine rather than to grow a second set of senders here.
    """
    dispatched: list[dict[str, Any]] = []

    async def _fake_dispatch(**kwargs: Any) -> dict[str, Any]:
        dispatched.append(kwargs)
        return {"executed": True, "status": "succeeded", "summary": "posted"}

    monkeypatch.setattr(engine_mod.action_bridge, "dispatch_step", _fake_dispatch)

    steps = _pack_steps("notify")
    assert steps
    for _name, step in steps:
        handler = engine_mod._HANDLERS[step.type]
        await handler(step, {"tenant_id": "t", "alert": {"source_ip": "203.0.113.9"}}, None)

    assert len(dispatched) == len(steps)
    assert {d["capability"] for d in dispatched} == {"notify"}
    # The channel decides the vendor arm. Guessing it downstream is the
    # credential-order roulette the SIEM arms had to pin away.
    assert {d["vendor_id"] for d in dispatched} <= {"slack", "teams", "email", "pagerduty"}


@pytest.mark.asyncio
async def test_notify_renders_the_pack_message_template(monkeypatch: pytest.MonkeyPatch) -> None:
    """``message_template`` is the key the packs use; ``message`` was the key
    the handler read, so every pack message was the default string."""
    seen: dict[str, Any] = {}

    async def _fake_dispatch(**kwargs: Any) -> dict[str, Any]:
        seen.update(kwargs)
        return {"executed": True, "status": "succeeded"}

    monkeypatch.setattr(engine_mod.action_bridge, "dispatch_step", _fake_dispatch)

    step = PlaybookStep(
        name="page",
        type=StepType.NOTIFY,
        params={"channel": "pagerduty", "message_template": "Stuffing from {{alert.source_ip}}"},
    )
    await engine_mod._HANDLERS[StepType.NOTIFY](step, {"tenant_id": "t", "alert": {"source_ip": "203.0.113.9"}}, None)
    assert seen["params"]["message"] == "Stuffing from 203.0.113.9"


# ---------------------------------------------------------------------------
# osquery_live_query
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_osquery_step_is_dispatched_rather_than_imported(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reproduce: this raised ``PermanentStepFailure`` in the agents image.

    The handler imported ``app.clients.osctrl_client``, which exists only in
    ``services/actions``. It also read credentials from
    ``GET /connectors/instances/{id}``, whose response model documents that
    ``auth_config`` is deliberately omitted — so even in an image that had
    the clients, the call would have been made with no token.
    """
    seen: dict[str, Any] = {}

    async def _fake_dispatch(**kwargs: Any) -> dict[str, Any]:
        seen.update(kwargs)
        return {"executed": True, "status": "succeeded", "rows": []}

    monkeypatch.setattr(engine_mod.action_bridge, "dispatch_step", _fake_dispatch)

    step = PlaybookStep(
        name="hunt",
        type=StepType.OSQUERY_LIVE_QUERY,
        params={"backend": "fleetdm", "template": "processes_by_name", "template_params": {"name": "mimikatz.exe"}},
    )
    result = await engine_mod._HANDLERS[StepType.OSQUERY_LIVE_QUERY](step, {"tenant_id": "t", "host": "WS-1"}, None)
    assert result["executed"] is True
    assert seen["capability"] == "osquery_live_query"
    assert seen["vendor_id"] == "fleetdm"
    assert seen["target"] == "WS-1"


def test_osquery_is_a_governed_verb_not_an_engine_handler() -> None:
    """The in-engine handler is gone, not renamed."""
    assert StepType.OSQUERY_LIVE_QUERY in engine_mod.RESPONSE_STEP_TYPES
    assert not hasattr(engine_mod, "_handle_osquery_live_query")


# ---------------------------------------------------------------------------
# Preview — the mode an author checks a playbook in
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_every_pack_playbook_completes_in_preview(monkeypatch: pytest.MonkeyPatch) -> None:
    """Phase 5's done-when, for the part this item owns.

    Reproduce, and the finding that made this test worth writing: a preview
    of *any* response step reported FAILED on the tree this started from.
    The engine chose not to call the handler, wrote ``executed: false``
    itself, and then read its own field back as "the verb did not run" — so
    a containment playbook previewed as broken whether or not it was, and
    the one mode an author uses to check a playbook before trusting it
    could not distinguish a sound one. Measured before the fix: every one
    of the 62 packs failed here.

    A preview still reaches no vendor. ``_handle_http`` is the only
    remaining outbound path in the engine and it is off by default, so
    nothing here opens a socket.
    """
    from app.playbook.engine import PlaybookEngine, RunStatus
    from app.playbook.models import Playbook

    async def _no_references(*, tenant_id: str, names: list[str]) -> dict[str, Any]:  # noqa: ARG001
        return {}

    monkeypatch.setattr(engine_mod.references, "resolve", _no_references)
    monkeypatch.delenv("AISOC_PLAYBOOK_HTTP_EXECUTE", raising=False)

    context = {
        "tenant_id": "11111111-1111-1111-1111-111111111111",
        "alert": {"user": "alice@example.com", "source_ip": "203.0.113.9", "host": "WS-1"},
        "case_id": "22222222-2222-2222-2222-222222222222",
    }

    incomplete: list[str] = []
    for path in sorted(_PACKS.rglob("*.playbook.json")):
        raw = json.loads(path.read_text())
        # Authored documentation the runtime model does not bind. The gate
        # records both in INERT_AUTHORED_KEYS for the same reason.
        raw.pop("inputs", None)
        raw.pop("dry_run_support", None)
        run = await PlaybookEngine().run(Playbook.model_validate(raw), dict(context), dry_run=True)
        if run.status is not RunStatus.COMPLETED:
            incomplete.append(f"{path.name}: {run.status.value} — {run.error}")

    assert not incomplete, "pack playbooks that do not complete in preview:\n" + "\n".join(incomplete[:20])
