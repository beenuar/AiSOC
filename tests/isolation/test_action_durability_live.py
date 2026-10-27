"""An approved action reaches the vendor once, or visibly not at all.

Remediation phase 2. The approve path in ``services/actions`` was a plain
read-check-act with the durable write placed *after* the vendor call::

    record = await action_store.get(action_id)        # no tenant, cache first
    if record["status"] != AWAITING_APPROVAL: ...     # checked in Python
    result = await executor.execute(request)          # the host is contained
    await action_store.save(record)                   # ... and only now recorded

Every guarantee an approval is supposed to carry sits in that gap.

* Two replicas, or one replica and a client that retried, both read
  ``awaiting_approval`` and both contain the host. On the submitting replica
  the race is invisible because ``action_store.get`` answers from a
  process-local dict and hands both callers the *same object*, so the local
  suite could never see it and a second container was required to.
* A vendor timeout raised out of the handler: ``save`` was never reached, the
  record stayed ``awaiting_approval`` while the vendor may well have acted,
  and the next approval ran it again. There was no status meaning "we do not
  know".
* The reads carried no tenant, so an approver holding the right permission tier
  in *any* tenant could approve another tenant's containment.
* ``save`` was an unconditional upsert, so re-submitting an id with a different
  target replaced the record underneath the approver looking at it.
* ``save`` swallowed connect and write failures, so an action could look
  persisted while existing only in one replica's memory.

And one defect that is not in any of those lists, found by running the path
rather than reading it: ``services/api``'s ``_dispatch_decision`` submitted
with ``principal=<the deciding console user>``, which the actions service
records as ``requested_by_user_id``. The same principal was then sent as the
approver, so separation of duties compared the approver against *itself* and
refused. **Every** approval raised through the responder/console path was
answered 403 upstream and surfaced as a 502 reading "Decision recorded, but
the action service refused it". The three identities — who asked, who relayed,
who approved — have to stay distinct for the control to work at all.

Why this file is here and not in a service's own suite
------------------------------------------------------
``services/api`` and ``services/actions`` both name their top-level package
``app``. Importing one into a process that has imported the other resolves to
whichever is on ``PYTHONPATH``, and a cross-service test written that way
degrades into skips — which report the same word as a pass.

So the test process is the **API** (it imports the real ``actions_client`` and
the real ``approvals._dispatch_decision``), the actions service runs as **two
separate processes** on loopback sockets sharing one Postgres, and the vendor
is a real HTTP server that records every request that reaches it. Nothing
about authorization, persistence or retry is replaced by a double: a mock that
answers whatever it is asked cannot notice an action that executed twice.

Two replicas rather than one is the whole point. A single process would pass
these tests against the pre-fix tree.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import threading
import time
import uuid
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

_REPO = Path(__file__).resolve().parents[2]
_ACTIONS = _REPO / "services" / "actions"

#: The durable store under test. Set by ``action-durability-live.yml``; absent
#: in the offline isolation job, which has no Postgres and must skip rather
#: than invent one.
_DSN = os.environ.get("ISOLATION_ACTIONS_DSN", "").strip()

SERVICE_TOKEN = "p2-actions-token-not-a-real-secret"

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not _DSN,
        reason="ISOLATION_ACTIONS_DSN is not set; this suite needs a real Postgres and both services installed",
    ),
]


# ── the vendor ─────────────────────────────────────────────────────────────


class _VendorState:
    """What the stub does next, and what it has been asked so far.

    ``contain_calls`` is the number that decides every durability assertion in
    this file. It counts *requests that reached the vendor*, which is the only
    definition of "the host was contained" that does not depend on believing
    the thing under test.
    """

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.contain_calls: list[dict[str, Any]] = []
        self.token_calls = 0
        self.status_reads = 0
        #: Seconds to stall a containment request. Used to make a real client
        #: timeout, rather than raising a timeout the client never saw.
        self.contain_delay = 0.0
        #: Accept the containment and then hang up without answering. The
        #: vendor has acted and the caller will never learn the outcome, which
        #: is the condition reconciliation exists for — and it reproduces in
        #: milliseconds rather than by waiting out a 30-second client timeout.
        self.drop_response = False
        #: What the device reports when the verifier reads it back.
        self.device_status = "normal"
        #: Whether the read-back route answers at all. A vendor that accepted
        #: the containment and whose device API is then unavailable is the one
        #: case where the outcome genuinely cannot be established.
        self.probe_available = True
        #: What the containment route answers. A 500 is a vendor that received
        #: the request and refused it, which — unlike a dropped response — the
        #: read-back can and must settle as a genuine failure.
        self.contain_http_status = 200

    def reset(self) -> None:
        with self.lock:
            self.contain_calls.clear()
            self.token_calls = 0
            self.status_reads = 0
            self.contain_delay = 0.0
            self.drop_response = False
            self.device_status = "normal"
            self.probe_available = True
            self.contain_http_status = 200


VENDOR = _VendorState()


class _VendorHandler(BaseHTTPRequestHandler):
    """A real HTTP endpoint speaking enough of the EDR API to be used for real.

    The forward call and the read-back probe are different routes, so
    "reconcile without executing again" is a property this stub can actually
    distinguish rather than one the test has to take on trust.
    """

    protocol_version = "HTTP/1.1"

    def log_message(self, *_args: Any) -> None:  # noqa: D102 - quiet
        return

    def _send(self, payload: dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""

        if parsed.path.endswith("/oauth2/token"):
            with VENDOR.lock:
                VENDOR.token_calls += 1
            self._send({"access_token": "vendor-token", "expires_in": 1799})
            return

        if parsed.path.endswith("/devices/entities/devices-actions/v2"):
            action = (parse_qs(parsed.query).get("action_name") or [""])[0]
            with VENDOR.lock:
                delay = VENDOR.contain_delay
                drop = VENDOR.drop_response
                http_status = VENDOR.contain_http_status
                VENDOR.contain_calls.append(
                    {
                        "action": action,
                        "body": json.loads(raw or b"{}"),
                        "at": datetime.now(UTC).isoformat(),
                    }
                )
                if action == "contain" and http_status < 400:
                    VENDOR.device_status = "contained"
            if delay:
                time.sleep(delay)
            if drop:
                self.close_connection = True
                return
            if http_status >= 400:
                self._send({"errors": [{"message": "containment refused"}]}, status=http_status)
                return
            self._send({"resources": [{"id": "dev-1"}], "errors": []})
            return

        self._send({"errors": [{"message": "unexpected route"}]}, status=404)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path.endswith("/devices/queries/devices/v1"):
            self._send({"resources": ["dev-1"]})
            return
        if parsed.path.endswith("/devices/entities/devices/v2"):
            with VENDOR.lock:
                VENDOR.status_reads += 1
                status = VENDOR.device_status
                available = VENDOR.probe_available
            if not available:
                self._send({"errors": [{"message": "device service unavailable"}]}, status=503)
                return
            self._send({"resources": [{"device_id": "dev-1", "status": status}]})
            return
        self._send({"errors": [{"message": "unexpected route"}]}, status=404)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(scope="module")
def vendor_base_url():
    server = ThreadingHTTPServer(("127.0.0.1", _free_port()), _VendorHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


@pytest.fixture(autouse=True)
def _clean_vendor():
    VENDOR.reset()
    yield
    VENDOR.reset()


# ── the actions service, twice ─────────────────────────────────────────────


class Replica:
    """One actions container on a loopback socket."""

    def __init__(self, name: str, port: int, proc: subprocess.Popen) -> None:
        self.name = name
        self.port = port
        self.proc = proc
        self.base_url = f"http://127.0.0.1:{port}"

    def kill(self) -> None:
        self.proc.kill()
        self.proc.wait(timeout=10)


def _spawn_replica(name: str, dsn: str) -> Replica:
    if not (_ACTIONS / "app" / "main.py").is_file():
        pytest.fail(f"the actions service is not at {_ACTIONS}; this test must not be skipped into passing")

    port = _free_port()
    env = {
        **os.environ,
        "AISOC_ACTIONS_SERVICE_TOKEN": SERVICE_TOKEN,
        # Every approval in this file carries an identity. The default is on;
        # it is set explicitly so a change to the default cannot silently turn
        # the separation-of-duties assertions into no-ops.
        "AISOC_ACTIONS_REQUIRE_APPROVER": "true",
        "DATABASE_DSN": dsn,
        "DATABASE_URL": dsn,
        "OTEL_SDK_DISABLED": "true",
        "ENVIRONMENT": "test",
        "PYTHONPATH": str(_ACTIONS),
    }
    env.pop("AISOC_DEV_MODE", None)

    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import uvicorn\nfrom app.main import app as actions_app\n"
            f"uvicorn.run(actions_app, host='127.0.0.1', port={port}, log_level='error')\n",
        ],
        cwd=str(_ACTIONS),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    deadline = time.time() + 45
    while time.time() < deadline:
        if proc.poll() is not None:
            output = ((proc.stdout.read() if proc.stdout else b"") or b"").decode()[-2000:]
            pytest.fail(f"actions replica {name} exited before serving:\n{output}")
        try:
            httpx.get(f"http://127.0.0.1:{port}/api/v1/health", timeout=1.0)
            return Replica(name, port, proc)
        except httpx.HTTPError:
            time.sleep(0.2)
    proc.terminate()
    pytest.fail(f"actions replica {name} did not start within 45s")
    raise AssertionError("unreachable")


@pytest.fixture(scope="module")
def replicas():
    """Two containers behind one database, which is the deployed shape.

    One process cannot demonstrate the defect: ``action_store`` answers from a
    module-global dict, so a single replica's two concurrent approvals mutate
    one object and the race hides. The second replica has an empty cache and
    has to ask the database, which is exactly the question under test.
    """
    a = _spawn_replica("a", _DSN)
    b = _spawn_replica("b", _DSN)
    yield a, b
    for replica in (a, b):
        replica.proc.terminate()
        try:
            replica.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover - teardown guard
            replica.proc.kill()


# ── identities, as the console actually builds them ────────────────────────


def _principal(tenant: str, *, user_id: str | None = None, permissions: list[str] | None = None) -> dict[str, Any]:
    return {
        "user_id": user_id or str(uuid.uuid4()),
        "tenant_id": tenant,
        "email": f"{(user_id or 'user').split('@')[0]}@example.com",
        "roles": ["analyst"],
        "permissions": permissions if permissions is not None else ["actions:execute:high"],
    }


def _vendor_params(vendor_base_url: str) -> dict[str, Any]:
    """Credentials that make the executor take its real CrowdStrike arm.

    Without these the executor falls through to its simulation branch, which
    touches no socket — so every "did the vendor get called" assertion in this
    file would pass for a reason that has nothing to do with the fix.
    """
    return {
        "cs_client_id": "p2-client",
        "cs_client_secret": "p2-secret",
        "cs_base_url": vendor_base_url,
    }


async def _submit(
    replica: Replica,
    *,
    tenant: str,
    action_id: str,
    requester: dict[str, Any] | None,
    principal: dict[str, Any],
    target: str,
    params: dict[str, Any],
) -> httpx.Response:
    body: dict[str, Any] = {
        "id": action_id,
        "action_type": "isolate_host",
        "target": target,
        "tenant_id": tenant,
        "incident_id": str(uuid.uuid4()),
        "rationale": "phase 2 regression",
        "requested_by": "agent",
        "parameters": params,
        "principal": principal,
    }
    if requester is not None:
        body["requester"] = requester
    async with httpx.AsyncClient(timeout=30.0) as client:
        return await client.post(
            f"{replica.base_url}/api/v1/actions",
            json=body,
            headers={"Authorization": f"Bearer {SERVICE_TOKEN}"},
        )


async def _approve(replica: Replica, action_id: str, approver: dict[str, Any], *, timeout: float = 30.0) -> httpx.Response:
    async with httpx.AsyncClient(timeout=timeout) as client:
        return await client.post(
            f"{replica.base_url}/api/v1/actions/{action_id}/approve",
            json={"approver": approver},
            headers={"Authorization": f"Bearer {SERVICE_TOKEN}"},
        )


async def _read_record(dsn: str, action_id: str) -> dict[str, Any] | None:
    """The database's answer, not any replica's.

    Every status assertion reads through here on purpose: a replica's own
    ``GET`` can be served from the process-local cache that caused the defect,
    so asking it whether the durable record is right is asking the suspect.
    """
    import asyncpg

    conn = await asyncpg.connect(dsn.replace("postgresql+asyncpg://", "postgresql://"), timeout=10.0)
    try:
        row = await conn.fetchrow(
            "SELECT status, record FROM aisoc_action_records WHERE id = $1",
            action_id,
        )
    finally:
        await conn.close()
    if row is None:
        return None
    record = json.loads(row["record"])
    record["_column_status"] = row["status"]
    return record


def _contain_calls() -> int:
    with VENDOR.lock:
        return len([c for c in VENDOR.contain_calls if c["action"] == "contain"])


# ── A. the three identities ────────────────────────────────────────────────


class TestTheThreeIdentitiesStayDistinct:
    """Who asked, who relayed and who approved are three facts, not one.

    Against the pre-fix tree the first test here fails with 403
    ``approver cannot be the requester``, which is what every approval tapped
    in the responder app received.
    """

    async def test_an_agent_originated_request_is_approved_by_a_human(self, replicas, vendor_base_url) -> None:
        a, _b = replicas
        tenant = str(uuid.uuid4())
        agent = _principal(tenant, user_id="agents-service")
        analyst = _principal(tenant, user_id="dana")
        action_id = str(uuid.uuid4())

        submitted = await _submit(
            a,
            tenant=tenant,
            action_id=action_id,
            requester=agent,
            principal=analyst,
            target="ws-4471",
            params=_vendor_params(vendor_base_url),
        )
        assert submitted.status_code == 200, submitted.text
        assert submitted.json()["status"] == "awaiting_approval"

        approved = await _approve(a, action_id, analyst)
        assert approved.status_code == 200, (
            "a human approving an agent-originated action was refused: "
            f"{approved.status_code} {approved.text}. The requester identity did not survive the submit."
        )
        assert approved.json()["status"] == "completed"
        assert _contain_calls() == 1

        stored = await _read_record(_DSN, action_id)
        assert stored is not None
        assert stored["requested_by_user_id"] == "agents-service"
        assert stored["approved_by_user_id"] == analyst["user_id"]

    async def test_the_real_console_dispatch_path_approves(self, replicas, vendor_base_url, monkeypatch) -> None:
        """``approvals._dispatch_decision`` itself, not a hand-built stand-in.

        This is the function the responder app reaches, and it is where the
        identity collapse happened. A test that posted its own body would have
        passed on the defective tree.
        """
        a, _b = replicas
        approvals = pytest.importorskip(
            "app.api.v1.endpoints.approvals",
            reason="services/api is not installed in this job",
        )
        actions_client = pytest.importorskip("app.services.actions_client")
        monkeypatch.setattr(actions_client.settings, "AISOC_ACTIONS_BASE_URL", a.base_url, raising=False)
        monkeypatch.setattr(actions_client.settings, "AISOC_ACTIONS_SERVICE_TOKEN", SERVICE_TOKEN, raising=False)

        tenant = uuid.uuid4()
        approval_id = uuid.uuid4()
        row = SimpleNamespace(
            id=approval_id,
            tenant_id=tenant,
            run_id=None,
            summary="isolate the beachhead",
            title="isolate ws-4471",
            requested_by="triage-agent",
            action={
                "action_type": "isolate_host",
                "target": "ws-4471",
                "parameters": _vendor_params(vendor_base_url),
                # Written by `create_approval` from the authenticated principal
                # that raised the approval, never read from the request body.
                "requester_principal": {
                    "user_id": "agents-service",
                    "tenant_id": str(tenant),
                    "permissions": ["actions:execute:high"],
                },
            },
        )
        analyst_id = uuid.uuid4()
        user = SimpleNamespace(
            user_id=analyst_id,
            tenant_id=tenant,
            email="dana@example.com",
            role="analyst",
            effective_permissions=lambda: ["actions:execute:high"],
        )

        dispatch = await approvals._dispatch_decision(row, user, approve=True)

        assert dispatch["state"] == "executed", (
            f"the console approval path did not execute: {dispatch}. Every tap of Approve in the responder app surfaced this as a 502."
        )
        assert _contain_calls() == 1

    async def test_a_human_cannot_approve_the_action_they_raised(self, replicas, vendor_base_url) -> None:
        """Separation of duties, on the half where it must still bite."""
        a, _b = replicas
        tenant = str(uuid.uuid4())
        analyst = _principal(tenant, user_id="dana")
        action_id = str(uuid.uuid4())

        await _submit(
            a,
            tenant=tenant,
            action_id=action_id,
            requester=analyst,
            principal=analyst,
            target="ws-4471",
            params=_vendor_params(vendor_base_url),
        )
        refused = await _approve(a, action_id, analyst)

        assert refused.status_code == 403, refused.text
        assert "separation of duties" in refused.text
        assert _contain_calls() == 0

    async def test_separation_of_duties_is_not_waived_by_an_absent_requester(self, replicas, vendor_base_url) -> None:
        """An action nobody is recorded as requesting is not a free approval.

        ``if separation_of_duties and requester and ...`` passed silently when
        the submit carried no principal at all, so the control reported itself
        satisfied on exactly the requests it could not evaluate.
        """
        a, _b = replicas
        tenant = str(uuid.uuid4())
        action_id = str(uuid.uuid4())
        analyst = _principal(tenant, user_id="dana")

        async with httpx.AsyncClient(timeout=30.0) as client:
            submitted = await client.post(
                f"{a.base_url}/api/v1/actions",
                json={
                    "id": action_id,
                    "action_type": "isolate_host",
                    "target": "ws-4471",
                    "tenant_id": tenant,
                    "incident_id": str(uuid.uuid4()),
                    "rationale": "phase 2 regression",
                    "parameters": _vendor_params(vendor_base_url),
                },
                headers={"Authorization": f"Bearer {SERVICE_TOKEN}"},
            )
        assert submitted.status_code == 200, submitted.text

        approved = await _approve(a, action_id, analyst)
        assert approved.status_code == 200, approved.text

        stored = await _read_record(_DSN, action_id)
        assert stored is not None
        assert stored.get("separation_of_duties") == "unevaluated", (
            "an approval whose requester is unknown recorded nothing about it, so the audit "
            f"trail cannot distinguish an evaluated control from a skipped one: {stored.get('separation_of_duties')!r}"
        )

    async def test_an_approver_from_another_tenant_is_refused(self, replicas, vendor_base_url) -> None:
        """``aisoc_action_records`` is reachable by id, and the id was the only control."""
        a, b = replicas
        victim = str(uuid.uuid4())
        attacker_tenant = str(uuid.uuid4())
        action_id = str(uuid.uuid4())

        await _submit(
            a,
            tenant=victim,
            action_id=action_id,
            requester=_principal(victim, user_id="agents-service"),
            principal=_principal(victim, user_id="agents-service"),
            target="ws-victim",
            params=_vendor_params(vendor_base_url),
        )

        # From the *other* replica, so the read has to come from the database
        # rather than the submitting process's cache.
        refused = await _approve(b, action_id, _principal(attacker_tenant, user_id="mallory"))

        assert refused.status_code in (403, 404), (
            f"an approver in tenant {attacker_tenant} was served tenant {victim}'s action: {refused.status_code} {refused.text}"
        )
        assert _contain_calls() == 0, "another tenant's host was contained"

    async def test_an_approver_below_the_tier_is_refused(self, replicas, vendor_base_url) -> None:
        """The control that already worked, kept so the fix cannot quietly drop it."""
        a, _b = replicas
        tenant = str(uuid.uuid4())
        action_id = str(uuid.uuid4())

        await _submit(
            a,
            tenant=tenant,
            action_id=action_id,
            requester=_principal(tenant, user_id="agents-service"),
            principal=_principal(tenant, user_id="agents-service"),
            target="ws-4471",
            params=_vendor_params(vendor_base_url),
        )
        refused = await _approve(a, action_id, _principal(tenant, user_id="sam", permissions=["actions:execute:low"]))

        assert refused.status_code == 403
        assert _contain_calls() == 0


# ── B. the intent an approver signed off ───────────────────────────────────


class TestApprovalIsBoundToTheIntent:
    async def test_a_resubmission_cannot_retarget_a_pending_approval(self, replicas, vendor_base_url) -> None:
        """The approval card says ws-4471; the record must not become dc-01.

        ``save`` was ``ON CONFLICT (id) DO UPDATE SET record = EXCLUDED.record``
        with no condition, so anything that could submit could rewrite what a
        human was in the middle of approving.
        """
        a, b = replicas
        tenant = str(uuid.uuid4())
        action_id = str(uuid.uuid4())
        agent = _principal(tenant, user_id="agents-service")
        analyst = _principal(tenant, user_id="dana")
        params = _vendor_params(vendor_base_url)

        first = await _submit(a, tenant=tenant, action_id=action_id, requester=agent, principal=agent, target="ws-4471", params=params)
        assert first.status_code == 200
        assert first.json()["status"] == "awaiting_approval"

        swapped = await _submit(b, tenant=tenant, action_id=action_id, requester=agent, principal=agent, target="dc-01", params=params)
        assert swapped.status_code == 409, (
            f"the pending action was retargeted to dc-01 while awaiting approval: {swapped.status_code} {swapped.text}"
        )

        stored = await _read_record(_DSN, action_id)
        assert stored is not None
        assert stored["target"] == "ws-4471"

        approved = await _approve(a, action_id, analyst)
        assert approved.status_code == 200, approved.text
        with VENDOR.lock:
            assert VENDOR.contain_calls, "nothing reached the vendor"

    async def test_a_resubmission_cannot_change_the_parameters_either(self, replicas, vendor_base_url) -> None:
        """The subtler half, and the one a target-only guard would miss.

        An action gated *because of what it targets* can be rewritten through
        its parameters alone — same verb, same host, a different thing done to
        it — and the approval card would not change at all.
        """
        a, b = replicas
        tenant = str(uuid.uuid4())
        action_id = str(uuid.uuid4())
        agent = _principal(tenant, user_id="agents-service")
        params = _vendor_params(vendor_base_url)

        first = await _submit(a, tenant=tenant, action_id=action_id, requester=agent, principal=agent, target="ws-4471", params=params)
        assert first.status_code == 200
        assert "scope" not in first.json()["parameters"]

        altered = await _submit(
            b,
            tenant=tenant,
            action_id=action_id,
            requester=agent,
            principal=agent,
            target="ws-4471",
            params={**params, "scope": "entire-subnet"},
        )
        assert altered.status_code == 409, (
            f"a pending action's parameters were rewritten while it awaited approval: {altered.status_code} {altered.text}"
        )

        stored = await _read_record(_DSN, action_id)
        assert stored is not None
        assert "scope" not in (stored.get("parameters") or {}), stored.get("parameters")

    async def test_an_identical_resubmission_is_still_idempotent(self, replicas, vendor_base_url) -> None:
        """A retried submit of the same intent must not become an error.

        The store's contract has always been "a replay of the same submission
        is idempotent rather than a duplicate pending approval", and refusing
        a changed intent must not cost that.
        """
        a, b = replicas
        tenant = str(uuid.uuid4())
        action_id = str(uuid.uuid4())
        agent = _principal(tenant, user_id="agents-service")
        params = _vendor_params(vendor_base_url)

        first = await _submit(a, tenant=tenant, action_id=action_id, requester=agent, principal=agent, target="ws-4471", params=params)
        again = await _submit(b, tenant=tenant, action_id=action_id, requester=agent, principal=agent, target="ws-4471", params=params)
        assert first.status_code == 200
        assert again.status_code == 200, again.text
        assert again.json()["status"] == "awaiting_approval"


# ── C. one vendor call, or none ────────────────────────────────────────────


class TestExecutionIsClaimedBeforeTheVendorIsContacted:
    async def test_two_replicas_cannot_both_execute_one_approval(self, replicas, vendor_base_url) -> None:
        """The defect, in the shape that produced it.

        Both replicas read ``awaiting_approval`` — one from its cache, one from
        the database — and both called the EDR. The host was contained twice,
        two audit trails were written, and the only durable evidence of either
        was whichever ``save`` landed last.
        """
        a, b = replicas
        tenant = str(uuid.uuid4())
        action_id = str(uuid.uuid4())
        agent = _principal(tenant, user_id="agents-service")
        analyst = _principal(tenant, user_id="dana")
        params = _vendor_params(vendor_base_url)

        await _submit(a, tenant=tenant, action_id=action_id, requester=agent, principal=agent, target="ws-4471", params=params)

        # Stall the vendor so both approvals are genuinely in flight together.
        # Without this the first can finish before the second reads, and the
        # race closes by timing rather than by the fix.
        with VENDOR.lock:
            VENDOR.contain_delay = 1.5

        outcomes: list[Any] = list(
            await asyncio.gather(
                _approve(a, action_id, analyst),
                _approve(b, action_id, analyst),
                return_exceptions=True,
            )
        )

        assert _contain_calls() == 1, (
            f"the host was contained {_contain_calls()} times for one approval. "
            f"replicas answered {[getattr(o, 'status_code', o) for o in outcomes]}"
        )
        codes = sorted(getattr(r, "status_code", 500) for r in outcomes)
        assert codes[0] == 200, f"neither replica executed: {codes}"
        assert codes[1] in (400, 409), f"the losing replica did not refuse cleanly: {codes}"

    async def test_a_repeated_approval_does_not_execute_twice(self, replicas, vendor_base_url) -> None:
        """A client that retries — a double tap, a proxy retry, a resumed run."""
        a, _b = replicas
        tenant = str(uuid.uuid4())
        action_id = str(uuid.uuid4())
        agent = _principal(tenant, user_id="agents-service")
        analyst = _principal(tenant, user_id="dana")
        params = _vendor_params(vendor_base_url)

        await _submit(a, tenant=tenant, action_id=action_id, requester=agent, principal=agent, target="ws-4471", params=params)

        first = await _approve(a, action_id, analyst)
        second = await _approve(a, action_id, analyst)

        assert first.status_code == 200, first.text
        assert second.status_code in (400, 409), second.text
        assert _contain_calls() == 1

    async def test_the_vendor_is_not_contacted_when_the_claim_cannot_be_written(self, replicas, vendor_base_url) -> None:
        """A store that cannot record the authorization must not authorize one.

        ``save`` logged and returned on a write failure, so an approval could
        contain a host and leave no durable trace that it had. The claim is the
        pre-dispatch write, and it fails closed.
        """
        import asyncpg

        a, _b = replicas
        tenant = str(uuid.uuid4())
        action_id = str(uuid.uuid4())
        agent = _principal(tenant, user_id="agents-service")
        analyst = _principal(tenant, user_id="dana")
        params = _vendor_params(vendor_base_url)

        await _submit(a, tenant=tenant, action_id=action_id, requester=agent, principal=agent, target="ws-4471", params=params)

        plain = _DSN.replace("postgresql+asyncpg://", "postgresql://")
        admin = await asyncpg.connect(plain.replace("aisoc_app", "aisoc"), timeout=10.0)
        try:
            await admin.execute("REVOKE UPDATE, INSERT ON aisoc_action_records FROM aisoc_app")
            refused = await _approve(a, action_id, analyst)
        finally:
            await admin.execute("GRANT INSERT, UPDATE ON aisoc_action_records TO aisoc_app")
            await admin.close()

        assert _contain_calls() == 0, "a host was contained while the durable record could not be written"
        assert refused.status_code >= 500, f"an unwritable store was reported as a client error: {refused.status_code} {refused.text}"

    async def test_a_stale_cache_cannot_resurrect_an_executed_action(self, replicas, vendor_base_url) -> None:
        """The submitting replica holds the record in memory forever.

        ``action_store.get`` checked that dict first, so a replica whose cache
        said ``awaiting_approval`` would execute again regardless of what the
        database had recorded. Replica A submits and caches; replica B executes;
        A must then refuse.
        """
        a, b = replicas
        tenant = str(uuid.uuid4())
        action_id = str(uuid.uuid4())
        agent = _principal(tenant, user_id="agents-service")
        analyst = _principal(tenant, user_id="dana")
        params = _vendor_params(vendor_base_url)

        await _submit(a, tenant=tenant, action_id=action_id, requester=agent, principal=agent, target="ws-4471", params=params)

        executed = await _approve(b, action_id, analyst)
        assert executed.status_code == 200, executed.text

        stale = await _approve(a, action_id, analyst)
        assert stale.status_code in (400, 409), (
            f"replica A's cached copy let an already-executed action run again: {stale.status_code} {stale.text}"
        )
        assert _contain_calls() == 1


# ── D. when the outcome is genuinely unknown ───────────────────────────────


class TestAnUnknownOutcomeIsRecordedAsUnknown:
    """A dispatch that did not come back clean is unknown until the vendor says.

    The executors catch their own vendor errors and return
    ``ActionResult(status=FAILED, error=str(exc))``, so the record read
    ``failed`` for a containment the EDR had accepted — a stronger claim than
    the evidence supports, and the dangerous direction, because the obvious
    response to a failure is to run it again.

    The resolution is not to guess from the exception type. It is to ask the
    vendor, with the read-back probe this service already ships: present means
    it completed, absent means it genuinely failed, and unreadable is the only
    honest ``reconciliation_required``.
    """

    async def test_a_lost_response_is_resolved_by_reading_the_vendor_back(self, replicas, vendor_base_url) -> None:
        """Vendor receipt, response lost, device reachable. The host *is* contained."""
        a, _b = replicas
        tenant = str(uuid.uuid4())
        action_id = str(uuid.uuid4())
        agent = _principal(tenant, user_id="agents-service")
        analyst = _principal(tenant, user_id="dana")
        params = _vendor_params(vendor_base_url)

        await _submit(a, tenant=tenant, action_id=action_id, requester=agent, principal=agent, target="ws-4471", params=params)
        with VENDOR.lock:
            VENDOR.drop_response = True

        response = await _approve(a, action_id, analyst, timeout=60.0)
        assert response.status_code in (200, 202), response.text
        assert _contain_calls() == 1, "the vendor never received the containment; this test proves nothing"

        stored = await _read_record(_DSN, action_id)
        assert stored is not None
        assert stored["_column_status"] == "completed", (
            f"a containment the EDR confirms is in force was recorded as {stored['_column_status']!r}"
        )
        assert stored["verification"]["outcome"] == "verified", stored.get("verification")

    async def test_an_effect_that_cannot_be_read_back_is_recorded_as_unknown(self, replicas, vendor_base_url) -> None:
        """Vendor receipt, response lost, device API down. Nobody knows."""
        a, _b = replicas
        tenant = str(uuid.uuid4())
        action_id = str(uuid.uuid4())
        agent = _principal(tenant, user_id="agents-service")
        analyst = _principal(tenant, user_id="dana")
        params = _vendor_params(vendor_base_url)

        await _submit(a, tenant=tenant, action_id=action_id, requester=agent, principal=agent, target="ws-4471", params=params)
        with VENDOR.lock:
            VENDOR.drop_response = True
            VENDOR.probe_available = False

        response = await _approve(a, action_id, analyst, timeout=60.0)
        assert response.status_code in (200, 202), response.text
        assert _contain_calls() == 1

        stored = await _read_record(_DSN, action_id)
        assert stored is not None
        assert stored["_column_status"] == "reconciliation_required", (
            "a vendor call that may have landed, against a device API that cannot be read, was recorded as "
            f"{stored['_column_status']!r}; the host's real state is unknown and the record must say so"
        )

    async def test_a_refused_dispatch_is_still_a_failure(self, replicas, vendor_base_url) -> None:
        """The control. Not everything becomes "unknown" — that would be its own lie.

        The vendor answered the containment with a 500 and the device is
        readable and reports ``normal``, so the containment demonstrably did
        not take and ``failed`` is the honest record. A change that resolved
        every imperfect dispatch to ``reconciliation_required`` would pass
        every other test in this class and fail this one.
        """
        a, _b = replicas
        tenant = str(uuid.uuid4())
        action_id = str(uuid.uuid4())
        agent = _principal(tenant, user_id="agents-service")
        analyst = _principal(tenant, user_id="dana")
        params = _vendor_params(vendor_base_url)

        await _submit(a, tenant=tenant, action_id=action_id, requester=agent, principal=agent, target="ws-4471", params=params)
        with VENDOR.lock:
            VENDOR.contain_http_status = 500

        response = await _approve(a, action_id, analyst, timeout=60.0)
        assert response.status_code in (200, 202), response.text

        stored = await _read_record(_DSN, action_id)
        assert stored is not None
        assert stored["_column_status"] == "failed", stored["_column_status"]
        assert stored["verification"]["outcome"] == "failed", stored.get("verification")

    async def test_a_vendor_timeout_is_not_recorded_as_a_failure(self, replicas, vendor_base_url) -> None:
        """ "The request timed out" and "the action did not happen" are different facts.

        The slow sibling of the lost-response case, kept because a real
        ``httpx`` read timeout and a dropped connection are different code
        paths inside the client and only one of them is cheap to reproduce.
        """
        a, _b = replicas
        tenant = str(uuid.uuid4())
        action_id = str(uuid.uuid4())
        agent = _principal(tenant, user_id="agents-service")
        analyst = _principal(tenant, user_id="dana")
        params = _vendor_params(vendor_base_url)

        await _submit(a, tenant=tenant, action_id=action_id, requester=agent, principal=agent, target="ws-4471", params=params)

        # Longer than the client's 30s containment timeout, so the client
        # really times out on a request the vendor really received. The device
        # API is down too, so the outcome is genuinely unestablished.
        with VENDOR.lock:
            VENDOR.contain_delay = 34.0
            VENDOR.probe_available = False

        response = await _approve(a, action_id, analyst, timeout=120.0)
        assert response.status_code in (200, 202), response.text

        stored = await _read_record(_DSN, action_id)
        assert stored is not None
        assert stored["_column_status"] == "reconciliation_required", (
            "a vendor call that may have landed was recorded as "
            f"{stored['_column_status']!r}; the host's real state is unknown and the record must say so"
        )
        assert _contain_calls() == 1

    async def test_an_unknown_action_is_not_re_executed_on_approval(self, replicas, vendor_base_url) -> None:
        """Retrying an action that may already have run is the thing to prevent."""
        a, _b = replicas
        tenant = str(uuid.uuid4())
        action_id = str(uuid.uuid4())
        agent = _principal(tenant, user_id="agents-service")
        analyst = _principal(tenant, user_id="dana")
        params = _vendor_params(vendor_base_url)

        await _submit(a, tenant=tenant, action_id=action_id, requester=agent, principal=agent, target="ws-4471", params=params)
        with VENDOR.lock:
            VENDOR.drop_response = True
            VENDOR.probe_available = False
        await _approve(a, action_id, analyst, timeout=60.0)
        with VENDOR.lock:
            VENDOR.drop_response = False
            VENDOR.probe_available = True

        retry = await _approve(a, action_id, analyst)
        assert retry.status_code in (400, 409), f"an action in an unknown state was re-approved and run: {retry.text}"
        assert _contain_calls() == 1

    async def test_a_replica_killed_mid_dispatch_leaves_a_claimed_record(self, replicas, vendor_base_url) -> None:
        """Restart recovery. A process that dies after contacting the vendor
        must not leave an action that looks un-started."""
        tenant = str(uuid.uuid4())
        action_id = str(uuid.uuid4())
        agent = _principal(tenant, user_id="agents-service")
        analyst = _principal(tenant, user_id="dana")
        params = _vendor_params(vendor_base_url)

        doomed = _spawn_replica("doomed", _DSN)
        try:
            await _submit(doomed, tenant=tenant, action_id=action_id, requester=agent, principal=agent, target="ws-4471", params=params)
            with VENDOR.lock:
                VENDOR.contain_delay = 8.0

            task = asyncio.create_task(_approve(doomed, action_id, analyst, timeout=60.0))
            # Wait until the vendor has actually been reached, then kill the
            # replica. Sleeping a fixed interval would race the dispatch.
            deadline = time.time() + 20
            while _contain_calls() == 0 and time.time() < deadline:
                await asyncio.sleep(0.1)
            assert _contain_calls() == 1, "the vendor was never reached; this test proves nothing"
            doomed.kill()
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, httpx.HTTPError):
                pass
        finally:
            if doomed.proc.poll() is None:  # pragma: no cover - teardown guard
                doomed.kill()
            with VENDOR.lock:
                VENDOR.contain_delay = 0.0

        stored = await _read_record(_DSN, action_id)
        assert stored is not None
        assert stored["_column_status"] in ("running", "reconciliation_required"), (
            f"a replica died after contacting the vendor and the record reads {stored['_column_status']!r}, "
            "which is indistinguishable from an action nobody started"
        )
        assert stored.get("dispatch", {}).get("claimed_by"), "the record does not say which replica claimed it"

    async def test_a_claimed_record_survives_the_restart_and_still_refuses(self, replicas, vendor_base_url) -> None:
        """A fresh replica with an empty cache reads the claim and holds."""
        a, _b = replicas
        tenant = str(uuid.uuid4())
        action_id = str(uuid.uuid4())
        agent = _principal(tenant, user_id="agents-service")
        analyst = _principal(tenant, user_id="dana")
        params = _vendor_params(vendor_base_url)

        doomed = _spawn_replica("restart-a", _DSN)
        try:
            await _submit(doomed, tenant=tenant, action_id=action_id, requester=agent, principal=agent, target="ws-4471", params=params)
            with VENDOR.lock:
                VENDOR.contain_delay = 8.0
            task = asyncio.create_task(_approve(doomed, action_id, analyst, timeout=60.0))
            deadline = time.time() + 20
            while _contain_calls() == 0 and time.time() < deadline:
                await asyncio.sleep(0.1)
            doomed.kill()
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, httpx.HTTPError):
                pass
        finally:
            if doomed.proc.poll() is None:  # pragma: no cover - teardown guard
                doomed.kill()
            with VENDOR.lock:
                VENDOR.contain_delay = 0.0

        replacement = await _approve(a, action_id, analyst)
        assert replacement.status_code in (400, 409), (
            f"after a restart the action was run a second time: {replacement.status_code} {replacement.text}"
        )
        assert _contain_calls() == 1


# ── E. reconciling, without guessing ───────────────────────────────────────


class TestReconciliationReadsTheVendorRatherThanGuessing:
    async def _strand(self, replica: Replica, vendor_base_url: str) -> tuple[str, dict[str, Any], dict[str, Any]]:
        tenant = str(uuid.uuid4())
        action_id = str(uuid.uuid4())
        agent = _principal(tenant, user_id="agents-service")
        analyst = _principal(tenant, user_id="dana")
        params = _vendor_params(vendor_base_url)
        await _submit(replica, tenant=tenant, action_id=action_id, requester=agent, principal=agent, target="ws-4471", params=params)
        with VENDOR.lock:
            VENDOR.drop_response = True
            VENDOR.probe_available = False
        await _approve(replica, action_id, analyst, timeout=60.0)
        with VENDOR.lock:
            VENDOR.drop_response = False
            VENDOR.probe_available = True
        return action_id, analyst, params

    async def test_a_confirmed_effect_closes_the_record_without_acting_again(self, replicas, vendor_base_url) -> None:
        """The EDR says the host is contained, so the action completed.

        ``PostActionVerifier`` already existed and already reads the device's
        real containment state. Reconciliation is that probe, not a retry.
        """
        a, _b = replicas
        action_id, _analyst, params = await self._strand(a, vendor_base_url)
        before = _contain_calls()

        async with httpx.AsyncClient(timeout=60.0) as client:
            reconciled = await client.post(
                f"{a.base_url}/api/v1/actions/{action_id}/reconcile",
                json={"parameters": params},
                headers={"Authorization": f"Bearer {SERVICE_TOKEN}"},
            )

        assert reconciled.status_code == 200, reconciled.text
        body = reconciled.json()
        assert body["status"] == "completed", body
        assert body["verification"]["outcome"] == "verified", body
        assert _contain_calls() == before, "reconciliation executed the action again instead of reading it back"

        stored = await _read_record(_DSN, action_id)
        assert stored is not None and stored["_column_status"] == "completed"

    async def test_an_absent_effect_is_recorded_as_failed_not_guessed_complete(self, replicas, vendor_base_url) -> None:
        a, _b = replicas
        action_id, _analyst, params = await self._strand(a, vendor_base_url)
        before = _contain_calls()
        # The vendor accepted the request and the host is nonetheless not
        # contained — a real outcome, and the one a retry would be wrong about.
        with VENDOR.lock:
            VENDOR.device_status = "normal"

        async with httpx.AsyncClient(timeout=60.0) as client:
            reconciled = await client.post(
                f"{a.base_url}/api/v1/actions/{action_id}/reconcile",
                json={"parameters": params},
                headers={"Authorization": f"Bearer {SERVICE_TOKEN}"},
            )

        assert reconciled.status_code == 200, reconciled.text
        assert reconciled.json()["status"] == "failed", reconciled.json()
        assert _contain_calls() == before

    async def test_an_unreadable_vendor_leaves_the_record_unknown(self, replicas, vendor_base_url) -> None:
        """A reconciliation that cannot read the vendor resolves nothing.

        The tempting failure is to treat an unanswerable probe as a clean
        result in whichever direction is convenient. It stays unknown, and the
        operator is told so rather than told it is handled.
        """
        a, _b = replicas
        action_id, _analyst, params = await self._strand(a, vendor_base_url)
        before = _contain_calls()
        with VENDOR.lock:
            VENDOR.probe_available = False

        async with httpx.AsyncClient(timeout=60.0) as client:
            reconciled = await client.post(
                f"{a.base_url}/api/v1/actions/{action_id}/reconcile",
                json={"parameters": params},
                headers={"Authorization": f"Bearer {SERVICE_TOKEN}"},
            )

        assert reconciled.status_code == 200, reconciled.text
        body = reconciled.json()
        assert body["status"] == "reconciliation_required", body
        assert body["verification"]["outcome"] == "unverified", body
        assert _contain_calls() == before

    async def test_reconcile_will_not_touch_another_tenants_action(self, replicas, vendor_base_url) -> None:
        a, b = replicas
        action_id, _analyst, params = await self._strand(a, vendor_base_url)

        async with httpx.AsyncClient(timeout=60.0) as client:
            refused = await client.post(
                f"{b.base_url}/api/v1/actions/{action_id}/reconcile",
                json={"parameters": params},
                headers={
                    "Authorization": f"Bearer {SERVICE_TOKEN}",
                    "X-Tenant-ID": str(uuid.uuid4()),
                },
            )
        assert refused.status_code == 404, refused.text


# ── F. the read surface ────────────────────────────────────────────────────


class TestReadingAnActionRecordIsTenantScoped:
    async def test_a_matching_tenant_sees_the_whole_record(self, replicas, vendor_base_url) -> None:
        a, _b = replicas
        tenant = str(uuid.uuid4())
        action_id = str(uuid.uuid4())
        agent = _principal(tenant, user_id="agents-service")
        await _submit(
            a,
            tenant=tenant,
            action_id=action_id,
            requester=agent,
            principal=agent,
            target="ws-4471",
            params=_vendor_params(vendor_base_url),
        )

        async with httpx.AsyncClient(timeout=20.0) as client:
            seen = await client.get(
                f"{a.base_url}/api/v1/actions/{action_id}",
                headers={"Authorization": f"Bearer {SERVICE_TOKEN}", "X-Tenant-ID": tenant},
            )
        assert seen.status_code == 200
        assert seen.json()["target"] == "ws-4471"

    async def test_another_tenant_is_told_nothing_about_it(self, replicas, vendor_base_url) -> None:
        a, b = replicas
        tenant = str(uuid.uuid4())
        action_id = str(uuid.uuid4())
        agent = _principal(tenant, user_id="agents-service")
        await _submit(
            a,
            tenant=tenant,
            action_id=action_id,
            requester=agent,
            principal=agent,
            target="ws-victim",
            params=_vendor_params(vendor_base_url),
        )

        async with httpx.AsyncClient(timeout=20.0) as client:
            seen = await client.get(
                f"{b.base_url}/api/v1/actions/{action_id}",
                headers={"Authorization": f"Bearer {SERVICE_TOKEN}", "X-Tenant-ID": str(uuid.uuid4())},
            )
        assert seen.status_code == 404, seen.text

    async def test_an_unscoped_read_does_not_disclose_the_target(self, replicas, vendor_base_url) -> None:
        """No caller in the tree sends this route a tenant, so it stays usable —
        but an id is not a licence to read what a host or account was aimed at."""
        a, _b = replicas
        tenant = str(uuid.uuid4())
        action_id = str(uuid.uuid4())
        agent = _principal(tenant, user_id="agents-service")
        await _submit(
            a,
            tenant=tenant,
            action_id=action_id,
            requester=agent,
            principal=agent,
            target="ws-secret-name",
            params=_vendor_params(vendor_base_url),
        )

        async with httpx.AsyncClient(timeout=20.0) as client:
            seen = await client.get(
                f"{a.base_url}/api/v1/actions/{action_id}",
                headers={"Authorization": f"Bearer {SERVICE_TOKEN}"},
            )
        assert seen.status_code == 200, seen.text
        body = seen.json()
        assert body["status"] == "awaiting_approval"
        assert "ws-secret-name" not in json.dumps(body), f"an unscoped read disclosed the target: {body}"
        assert "parameters" not in body
