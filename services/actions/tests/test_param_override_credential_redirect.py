"""A caller's params may not choose where a tenant's stored credential is sent.

What was wrong
--------------
``resolve_params`` merged the caller's per-action ``params`` *on top of* the
fields translated from the connector's decrypted ``auth_config`` — its
docstring said so plainly: "a key here overrides a translated one". The keys it
translates include the ones that decide **where the request goes** and **what
secret is presented**: ``base_url`` -> ``cs_base_url``, ``client_secret`` ->
``cs_client_secret``, ``token`` -> ``splunk_token``, and so on for every vendor.

``POST /api/v1/playbook-steps/dispatch`` forwards a free-form ``params`` dict
from any session holding ``actions:execute``. So a caller could name
``cs_base_url`` and the platform would decrypt the tenant's CrowdStrike
credential and POST it to a host the caller chose — a credential-redirection
primitive rather than a configuration convenience (GHSA-78jg-x2ch-638f). Read
verbs such as ``get_host`` are ``READ_ONLY`` / ``AUTOMATIC`` / ``MINIMAL``, so
governance auto-executes them at the default tier and nothing else intervened.

Why a stored value wins rather than the override being sanitised
----------------------------------------------------------------
A denylist of dangerous destinations is the wrong shape for this — the osquery
renderer in this same service shipped one that blocked ``--``, ``/*`` and ``;``
and never ``'``. The value is made unrepresentable instead: a key that the
vendor map translates from a stored connection or credential field cannot be
supplied by a caller at all, and the attempt is **refused** rather than
dropped. Dropping it would send the request to the vendor's default host and
report success, which is the "escaped value reaches the endpoint, matches
nothing, reports success" failure this repository has shipped before.

Per-action operational params are untouched, because they are the reason the
merge exists: ``panos_tag``, ``jira_project_key``, ``fgt_address_group`` and
``qradar_closing_reason_id`` choose *what* an action does, never *where* it
goes or *whose secret* it spends.

Why a real socket
-----------------
The finding is not "a dict had the wrong key". It is "the platform presented
the tenant's secret to a host the caller named", and the only way to assert
that is to ask the host what it was paid with. So CrowdStrike is a real HTTP
server here and the whole resolve -> construct -> authenticate path runs.
"""

from __future__ import annotations

import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from app.live_actions import register_builtin_executors
from app.live_actions.dispatcher import dispatch
from app.live_actions.models import LiveActionRequest, LiveActionStatus
from app.services.credential_resolver import (
    CONNECTION_OR_CREDENTIAL_FIELDS,
    OPERATIONAL_FIELDS,
    VENDOR_CREDENTIAL_MAP,
    ProtectedParameterOverride,
    protected_param_keys,
    resolve_params,
)

CLIENT_ID = "MARKER_CLIENT_ID_78jg"
#: A marker, not a credential: it authenticates to nothing and exists so the
#: stub vendor's request log can be searched for it. The whole point of this
#: suite is asserting where this string does and does not travel, so it has to
#: be a literal.
CLIENT_SECRET = "MARKER_SECRET_78jg_xyz789"  # gitleaks:allow

TENANT = uuid.uuid4()


class _Vendor(BaseHTTPRequestHandler):
    """A real HTTP server recording what it was paid with, and at what path."""

    seen: list[dict[str, str]] = []

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace")
        _Vendor.seen.append({"path": self.path, "body": body})
        self._reply(b'{"access_token":"tok","expires_in":1799}')

    def do_GET(self) -> None:  # noqa: N802
        _Vendor.seen.append({"path": self.path, "body": ""})
        self._reply(b'{"resources":[]}')

    def _reply(self, payload: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args) -> None:  # noqa: ANN002
        """Quiet: the default handler prints every request to stderr."""


@pytest.fixture(autouse=True)
def _executors():
    """The real adapters, registered the way ``app.main`` registers them on boot.

    Without this the dispatcher answers ``executor_not_found`` before it ever
    resolves a parameter — and the negative assertions below would then pass
    because nothing ran at all, which is the most flattering way for a
    security test to be wrong. The positive controls are what caught it.
    """
    register_builtin_executors(overwrite=True)


@pytest.fixture
def vendor():
    server = HTTPServer(("127.0.0.1", 0), _Vendor)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    _Vendor.seen.clear()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def _request(**overrides) -> LiveActionRequest:
    """A dispatch shaped exactly as ``actions_client.dispatch_live_action`` sends one."""
    payload = {
        "capability": "get_host",
        "vendor_id": "crowdstrike",
        "target": "anyhost",
        "tenant_id": TENANT,
        "params": {},
        # Connector *schema* field names, which is what the API forwards after
        # decrypting the connector row.
        "auth_config": {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "base_url": "https://api.crowdstrike.invalid",
        },
        "dry_run": False,
        "requested_by": "user:analyst@example.com",
    }
    payload.update(overrides)
    return LiveActionRequest(**payload)


# ---------------------------------------------------------------------------
# The finding
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_caller_cannot_redirect_a_stored_credential_to_a_host_it_names(vendor):  # noqa: ANN001
    """The reported defect, asserted at the vendor rather than at the dict.

    The attacker host is a real server; if the stored secret reaches it, it is
    in ``_Vendor.seen`` and no amount of return-value shaping hides that.
    """
    result = await dispatch(_request(params={"cs_base_url": vendor}))

    paid = [call["body"] for call in _Vendor.seen]
    assert CLIENT_SECRET not in " ".join(paid), f"the stored CrowdStrike secret was sent to the caller's host: {paid}"
    assert _Vendor.seen == [], f"the caller's host was contacted at all: {_Vendor.seen}"
    assert result.status is LiveActionStatus.FAILED, f"a refused redirect did not report as failed: {result.status}"


@pytest.mark.asyncio
async def test_the_refusal_names_the_key_and_never_the_value(vendor):  # noqa: ANN001
    """An operator needs to know which parameter was refused; nobody needs the value.

    The value is attacker-chosen and the response is read back by the console,
    so echoing it would make the refusal itself a reflection point.
    """
    result = await dispatch(_request(params={"cs_base_url": vendor}))

    rendered = json.dumps(result.model_dump(mode="json"))
    assert "cs_base_url" in rendered, f"the refusal does not say what was wrong: {rendered[:400]}"
    assert vendor not in rendered, f"the refusal echoed the caller's host back: {rendered[:400]}"
    assert CLIENT_SECRET not in rendered, "the refusal body carried the stored secret"
    assert CLIENT_ID not in rendered, "the refusal body carried the stored client id"


@pytest.mark.asyncio
async def test_a_credential_field_cannot_be_substituted_either(vendor):  # noqa: ANN001
    """Not only the URL. Swapping the secret makes the platform a signing oracle.

    ``cs_client_secret`` is as much a stored field as ``cs_base_url`` is, and a
    fix that protected only the destination would leave the caller choosing
    which credential the tenant's integration presents.
    """
    result = await dispatch(_request(params={"cs_client_secret": "attacker-supplied"}))

    assert result.status is LiveActionStatus.FAILED
    assert "cs_client_secret" in json.dumps(result.model_dump(mode="json"))


def test_every_mapped_field_is_classified() -> None:
    """A new vendor field must be decided about, not default into either bucket.

    This is the half that stops the protected set going stale. ``_SPLUNK_KEYS``
    once listed ``splunk_host``/``token``/``index`` while the client factory
    read ``splunk_url`` plus basic-auth credentials, and the "dry run" called
    the customer's production Splunk. A hand-maintained list drifts; a
    hand-maintained list with an exhaustiveness gate cannot.
    """
    every_field = {field for mapping in VENDOR_CREDENTIAL_MAP.values() for field in mapping}
    unclassified = {field for field in every_field if field not in OPERATIONAL_FIELDS and field not in CONNECTION_OR_CREDENTIAL_FIELDS}

    assert unclassified == set(), (
        f"these connector fields are in neither classification: {sorted(unclassified)}. "
        "Decide which they are — a field that locates an endpoint, authenticates to one, or chooses "
        "whose estate a credential acts on is protected; a field that chooses what an action does is operational."
    )
    assert not (OPERATIONAL_FIELDS & CONNECTION_OR_CREDENTIAL_FIELDS), "a field cannot be in both classifications"


def test_the_protected_set_covers_every_vendors_endpoint_and_secret() -> None:
    """Spot-checked against the keys the client factories actually read."""
    for vendor_id, expected in (
        ("crowdstrike", {"cs_base_url", "cs_client_id", "cs_client_secret"}),
        ("splunk", {"splunk_url", "splunk_token", "splunk_username", "splunk_password", "splunk_verify_ssl"}),
        ("okta", {"okta_domain", "okta_api_token"}),
        ("servicenow", {"snow_instance_url", "snow_username", "snow_password"}),
        ("pagerduty", {"pd_routing_key"}),
    ):
        assert protected_param_keys(vendor_id) == expected, f"{vendor_id}: {sorted(protected_param_keys(vendor_id))}"


def test_a_connector_id_alias_resolves_to_the_same_protection() -> None:
    """``splunk_enterprise`` is the connector id for the ``splunk`` vendor.

    A caller naming the alias must not slip past the set, which is why this
    goes through ``canonical_vendor`` rather than a raw dict lookup.
    """
    assert protected_param_keys("splunk_enterprise") == protected_param_keys("splunk")
    assert protected_param_keys("azure_defender") == protected_param_keys("defender")


def test_resolve_params_refuses_rather_than_dropping() -> None:
    """Silently dropping would send the request to the vendor default and succeed.

    That is the quieter failure and the worse one: the caller is told the
    action ran, the operator sees a green step, and nothing records that a
    parameter was ignored.
    """
    with pytest.raises(ProtectedParameterOverride) as caught:
        resolve_params("crowdstrike", {"client_id": "a", "client_secret": "b"}, extra={"cs_base_url": "http://evil"})

    assert "cs_base_url" in str(caught.value)
    assert "evil" not in str(caught.value), "the refusal echoed the caller's value"


def test_operational_params_are_still_the_callers_to_choose() -> None:
    """The merge exists for these, and refusing them would be stuck-closed.

    ``jira_project_key`` is named in ``resolve_params``' own docstring as a
    per-action parameter; a playbook step choosing which project to file in is
    the feature, not the bug. Asserted here so the fix is held to keeping it.
    """
    for vendor_id, key in (
        ("jira", "jira_project_key"),
        ("panos", "panos_tag"),
        ("fortigate", "fgt_address_group"),
        ("qradar", "qradar_closing_reason_id"),
    ):
        assert key not in protected_param_keys(vendor_id), f"{key} became protected and is operational"

    out = resolve_params(
        "jira",
        {"base_url": "https://jira.example.com", "api_token": "t", "project_key": "DEFAULT"},
        extra={"jira_project_key": "SOC"},
    )
    assert out["jira_project_key"] == "SOC"
    assert out["jira_base_url"] == "https://jira.example.com"


# ---------------------------------------------------------------------------
# The other half: vendors whose whole connection comes from the caller
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_caller_named_internal_destination_is_refused(vendor):  # noqa: ANN001
    """osctrl, fleetdm and aisoc_direct have no entry in VENDOR_CREDENTIAL_MAP.

    So ``resolve_params`` translates nothing for them, the stored
    ``auth_config`` is dropped, and ``params`` is the *only* source of the
    connection — which leaves the protected-key rule with nothing to compare
    against. Before the guard, a dispatch could name any address and this
    container would request it and reflect the reply into the dispatch report:
    a read-SSRF with response disclosure, which is the second half of what was
    reported.

    Loopback is the sharpest case because ``AISOC_SSRF_ALLOW_PRIVATE``
    deliberately cannot re-admit it, so this assertion does not depend on how
    an operator has set that knob.
    """
    _Vendor.seen.clear()

    result = await dispatch(
        LiveActionRequest(
            capability="osquery_live_query",
            vendor_id="osctrl",
            target="h",
            tenant_id=TENANT,
            params={
                "base_url": vendor,
                "api_token": "caller-supplied",
                "template": "active_connections",
                "target_hosts": ["h1"],
            },
            auth_config=None,
            dry_run=False,
            requested_by="user:analyst@example.com",
        )
    )

    assert _Vendor.seen == [], f"the caller's internal destination was contacted: {_Vendor.seen}"
    assert result.status is LiveActionStatus.FAILED
    assert "base_url" in (result.error or ""), f"the refusal does not name the parameter: {result.error}"


@pytest.mark.asyncio
async def test_the_cloud_metadata_endpoint_is_refused_by_name() -> None:
    """169.254.169.254 is blocked even where private addresses are allowed.

    The link-local range is how an SSRF becomes cloud credentials, so this is
    asserted directly rather than inferred from the private-address rule.
    """
    result = await dispatch(
        LiveActionRequest(
            capability="osquery_live_query",
            vendor_id="osctrl",
            target="h",
            tenant_id=TENANT,
            params={
                "base_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "api_token": "x",
                "template": "active_connections",
                "target_hosts": ["h1"],
            },
            auth_config=None,
            dry_run=False,
            requested_by="user:analyst@example.com",
        )
    )

    assert result.status is LiveActionStatus.FAILED
    assert "base_url" in (result.error or "")


@pytest.mark.asyncio
async def test_a_host_that_merely_fails_to_resolve_is_not_the_guards_business() -> None:
    """A failed DNS lookup must not become a refusal.

    Otherwise every dispatch sits behind a working resolver, and a transient
    DNS fault turns into a refusal to contain a host. The vendor client's own
    connection error is the better diagnostic, and this mirrors the carve-out
    the API's registration-time guard already makes.
    """
    result = await dispatch(
        _request(
            auth_config={"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "base_url": "https://api.crowdstrike.invalid"},
            params={"hostname": "web-01"},
        )
    )

    # It fails, but as a vendor connection error rather than a refusal.
    assert "destination refused" not in (result.error or ""), result.error


# ---------------------------------------------------------------------------
# Positive controls — the route must still reach the real vendor
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_stored_base_url_is_still_the_one_used(vendor):  # noqa: ANN001
    """Stuck-closed reads as working caution, so this is the half that catches it.

    The stored connector URL here *is* the test's server, so a dispatch that
    carries no override must still authenticate against it with the tenant's
    own credential — which is the product working.
    """
    result = await dispatch(
        _request(
            auth_config={"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "base_url": vendor},
            params={},
        )
    )

    bodies = " ".join(call["body"] for call in _Vendor.seen)
    assert f"client_secret={CLIENT_SECRET}" in bodies, f"the tenant's own integration stopped working: {_Vendor.seen}"
    assert result.status is not LiveActionStatus.FAILED, result.error


@pytest.mark.asyncio
async def test_an_operational_param_still_reaches_the_executor(vendor):  # noqa: ANN001
    """A dispatch carrying only operational params is unaffected end to end."""
    result = await dispatch(
        _request(
            auth_config={"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "base_url": vendor},
            params={"hostname": "web-01"},
        )
    )

    assert result.status is not LiveActionStatus.FAILED, result.error
    assert _Vendor.seen, "the vendor was never reached on the legitimate path"
