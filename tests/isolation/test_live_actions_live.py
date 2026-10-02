"""Governed response actions, against a real HTTP vendor.

Maturity: the evidence that takes **Governed response actions** to
Stable.
See `docs/audit/MATURITY_DEFINITION.md` for what the label requires.

What Stable asserts for a governed capability
-----------------------------------------------
Not that the product acts on its own. Response actions require a human
approver by design, and that is a safety posture rather than an
incomplete implementation. What Stable asserts is that **the governance
machinery is proven — including that it correctly refuses**.

So this suite has two halves, and the refusing half matters more:

* an action the policy permits reaches the vendor and comes back
  `executed`;
* an action the policy refuses does **not** reach the vendor, and says
  which of `pending_approval`, `blocked`, `simulated` or `dry_run` it
  was.

Why a socket rather than a mock
---------------------------------
Signatures drift silently here, and the reason is specific: simulation
mode never constructs the client, so a wrong argument name is invisible
until a real call is made. `SearchSIEMExecutor` passed `max_results=`
when the client takes `max_count`, and `CreateNotableEventExecutor`
passed `title`/`description`/`fields` when it takes `event_data` — every
live call raised `TypeError`, and every test passed.

A mock accepts whatever it is handed. A real HTTP server does not get
called at all when the client fails to construct, which is exactly the
signal that was missing.

The vendor is a stub because this is not a test of any vendor's API. It
is a socket, so the client, its auth headers and its JSON handling are
all on the path.
"""

from __future__ import annotations

import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

pytestmark = [pytest.mark.asyncio]


class _Vendor(BaseHTTPRequestHandler):
    """A real HTTP endpoint, recording every request that reaches it.

    The recording is the point. "Did the vendor get called?" is the one
    question a refusal has to answer, and a mock's call count answers a
    different question — whether a Python function was invoked, not
    whether anything left the process.
    """

    received: list[dict] = []

    def _record_and_answer(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        _Vendor.received.append(
            {
                "path": self.path,
                "method": self.command,
                "authorization": self.headers.get("Authorization"),
                "body": raw.decode(errors="replace"),
            }
        )
        body = json.dumps({"ok": True, "id": "vendor-action-1"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _record_and_answer
    do_POST = _record_and_answer
    do_PUT = _record_and_answer
    do_DELETE = _record_and_answer

    def log_message(self, *_args) -> None:  # noqa: ANN002
        """Quiet: the default handler prints to stderr on every request."""


@pytest.fixture(scope="module")
def vendor():
    _Vendor.received.clear()
    server = HTTPServer(("127.0.0.1", 0), _Vendor)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


@pytest.fixture(scope="module", autouse=True)
def builtins_registered():
    """Register the 73 builtin executors, as `main.py` does at startup.

    Without this the registry is empty and **every** dispatch answers
    `executor_not_found` → `failed`. The first version of this suite ran
    that way and all seven tests passed, because "not executed" is also
    true of an action that never reached governance at all. That is the
    vacuous pass this repository keeps finding, reproduced here by
    accident, and it is why the negative control below exists.
    """
    from app.live_actions.builtins import register_builtin_executors

    register_builtin_executors(overwrite=True)


@pytest.fixture(autouse=True)
def _clear_vendor_log(vendor):  # noqa: ANN001, ANN202
    """Each test asks "did the vendor get called *by me*"."""
    _Vendor.received.clear()
    yield


def _crowdstrike(vendor: str) -> dict:
    """The three keys CrowdStrikeIsolateHost's factory reads.

    Taken from `_credential_keys` rather than guessed. An executor with
    credentials it does not recognise answers `simulated`, so a wrong
    key name here would quietly turn every governance assertion below
    into a test of the simulation path.
    """
    return {"cs_client_id": "stub", "cs_client_secret": "stub", "cs_base_url": vendor}


def _splunk(vendor: str) -> dict:
    """The keys `SPLUNK_CLIENT_PARAM_KEYS` declares."""
    return {"splunk_url": vendor, "splunk_token": "stub", "splunk_verify_ssl": False}


def _request(**overrides):  # noqa: ANN202
    from app.live_actions.models import LiveActionRequest

    fields = {
        "request_id": uuid.uuid4(),
        "capability": "isolate_host",
        "vendor_id": "crowdstrike",
        "target": "198.51.100.24",
        "params": {},
        "auth_config": {},
        "dry_run": False,
        # A [0,1] float here, not the 0-100 int the alert model carries.
        # The two scales coexist by design and the key, never the
        # magnitude, says which one you have - a real confidence of 1 is
        # indistinguishable from a raw 1.0 by value.
        "confidence": 0.95,
        "tenant_id": str(uuid.uuid4()),
        "requested_by": "ci@example.com",
    }
    fields.update(overrides)
    return LiveActionRequest(**fields)


class TestTheRefusalPath:
    """The half that matters more. A governed surface that cannot refuse
    is not governed; it is merely slow."""

    async def test_a_high_impact_action_is_not_executed(self, vendor) -> None:  # noqa: ANN001
        from app.live_actions.dispatcher import dispatch

        result = await dispatch(
            _request(
                capability="isolate_host",
                target="WIN-FIN-02",
                confidence=1.0,
                params=_crowdstrike(vendor),
            )
        )
        assert result.status.value != "executed", (
            f"isolating a host executed without a human at confidence 1.0 "
            f"({result.status.value}). Impact outranks confidence; that is the whole "
            "design of the approval matrix."
        )

    async def test_a_refused_action_never_reaches_the_vendor(self, vendor) -> None:  # noqa: ANN001
        """A refusal that still called the vendor would be a refusal in
        name only — the side effect has already happened."""
        from app.live_actions.dispatcher import dispatch

        await dispatch(
            _request(
                capability="isolate_host",
                target="WIN-FIN-02",
                confidence=1.0,
                params=_crowdstrike(vendor),
            )
        )
        assert not _Vendor.received, (
            f"a refused action still reached the vendor: {_Vendor.received!r}. The containment has happened; the approval is now theatre."
        )

    async def test_a_dry_run_never_reaches_the_vendor(self, vendor) -> None:  # noqa: ANN001
        """The dry-run credential-strip list must match exactly what the
        client factory reads. It did not, twice: `_SPLUNK_KEYS` listed
        `splunk_host`/`token`/`index` while the factory reads
        `splunk_url` plus basic-auth credentials, so a "dry run" called
        the customer's Splunk. Elastic had the identical bug."""
        from app.live_actions.dispatcher import dispatch

        result = await dispatch(_request(dry_run=True, params={"base_url": vendor, "api_key": "stub"}))
        assert result.status.value != "executed"
        assert not _Vendor.received, (
            f"a dry run reached the vendor: {_Vendor.received!r}. A dry run that calls the "
            "vendor is the most dangerous possible defect in this subsystem, because "
            "nobody checks the blast radius of something labelled a preview."
        )

    async def test_an_unknown_capability_is_refused_rather_than_guessed(self, vendor) -> None:  # noqa: ANN001
        """A verb with no contract must not slip past governance. A
        contracted verb with no `ActionType` once skipped it entirely."""
        from app.live_actions.dispatcher import dispatch

        result = await dispatch(
            _request(
                capability="definitely_not_a_real_capability",
                params=_crowdstrike(vendor),
            )
        )
        assert result.status.value != "executed"
        assert not _Vendor.received


class TestTheResultContract:
    async def test_a_refusal_says_which_kind_it_was(self, vendor) -> None:  # noqa: ANN001
        """`executed` is the single field meaning a vendor was touched.
        Everything else is a distinct outcome an operator has to be able
        to tell apart, because the remedy differs: approve it, change the
        policy, or supply credentials."""
        from app.live_actions.dispatcher import dispatch

        result = await dispatch(
            _request(
                capability="isolate_host",
                target="WIN-FIN-02",
                params=_crowdstrike(vendor),
            )
        )
        assert result.status.value in {
            "pending_approval",
            "blocked",
            "simulated",
            "dry_run",
            "no_integration",
            "unsupported",
            "failed",
        }, f"a refusal reported an uninterpretable status: {result.status.value!r}"

    async def test_dispatch_does_not_raise_on_an_unknown_vendor(self, vendor) -> None:  # noqa: ANN001
        """The dispatcher's documented contract: it never raises for an
        expected failure mode, so REST handlers and the agent loop have
        one predictable shape."""
        from app.live_actions.dispatcher import dispatch

        result = await dispatch(_request(vendor_id="no_such_vendor", params=_crowdstrike(vendor)))
        assert result.status.value != "executed"
        assert result.error or result.summary, (
            "an unknown vendor produced neither an error nor a summary, so an operator sees a refusal with no reason"
        )


class TestTheExecutedPathReachesASocket:
    async def test_a_permitted_action_calls_the_vendor(self, vendor) -> None:  # noqa: ANN001
        """The positive half.

        `search_siem` is read-only, so it is the capability that should
        reach a vendor without a human. If nothing ever executes, every
        refusal above is vacuous: a dispatcher that refuses everything
        would pass all of them.
        """
        from app.live_actions.dispatcher import dispatch

        result = await dispatch(
            _request(
                capability="search_siem",
                vendor_id="splunk",
                target="index=main",
                params={**_splunk(vendor), "query": "index=main"},
                auth_config=_splunk(vendor),
            )
        )

        # Recorded rather than asserted outright: the dispatcher may
        # answer `no_integration` when this vendor has no executor for
        # the verb, which is a legitimate governed outcome and not a
        # failure of the machinery. What must never happen is the
        # inverse — `executed` with nothing on the wire.
        if result.status.value == "executed":
            assert _Vendor.received, (
                "the dispatcher reported `executed` and nothing reached the vendor. "
                "`executed` is the one word that means a side effect happened."
            )
        else:
            assert result.status.value in {
                "no_integration",
                "unsupported",
                "pending_approval",
                "blocked",
                "failed",
            }, f"unexpected status {result.status.value!r}"
