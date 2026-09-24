"""A dry run must not be able to reach the customer's SIEM.

``_LegacyExecutorAdapter`` implements ``dry_run`` by deleting the adapter's
``_credential_keys`` from the request before delegating, so the legacy executor
falls through to its simulation branch. That only works if the strip list is
*exactly* the set of keys the client factory reads.

It was not. The Splunk adapters stripped ``splunk_host`` / ``splunk_token`` /
``splunk_index`` while ``executors.siem._splunk_client`` reads ``splunk_url``
first and also accepts ``splunk_username`` + ``splunk_password``. A tenant who
configured Splunk through a connector got ``splunk_url`` (that is the key
``credential_resolver`` writes), so the factory still built a client and the
"preview" ran against production. Elastic had the identical mismatch —
``elastic_host`` stripped, ``elastic_url`` read.

Three layers here, because set equality alone would not have caught the
original bug if someone had also "fixed" the constant to match the wrong keys:

1. the declared key tuple equals the keys the factory source actually reads,
   re-derived from the source so it cannot drift;
2. every registered adapter's strip list equals its vendor's declared tuple;
3. behaviourally — strip the keys from a fully populated parameter dict and
   the factory must return ``None``.
"""

from __future__ import annotations

import ast
import inspect
from uuid import uuid4

import pytest
from app.executors import siem
from app.live_actions import builtins, registry
from app.live_actions.models import LiveActionRequest, LiveActionStatus

#: Fully-populated credentials for every SIEM the writeback path can reach.
#: Deliberately includes *both* the modern and legacy spellings and the
#: basic-auth pair — that combination is what a real connector produces and
#: what the old strip list left behind.
FULL_CREDENTIALS: dict[str, object] = {
    "splunk_url": "https://splunk.example.invalid:8089",
    "splunk_host": "https://splunk.example.invalid:8089",
    "splunk_token": "unit-test-placeholder",
    "splunk_username": "svc-aisoc",
    "splunk_password": "unit-test-placeholder",
    "splunk_verify_ssl": True,
    "elastic_url": "https://es.example.invalid:9243",
    "elastic_api_key": "unit-test-placeholder",
    "elastic_username": "svc-aisoc",
    "elastic_password": "unit-test-placeholder",
    "kibana_url": "https://kibana.example.invalid:5601",
    "sentinel_tenant_id": "00000000-0000-0000-0000-000000000001",
    "sentinel_client_id": "00000000-0000-0000-0000-000000000002",
    "sentinel_client_secret": "unit-test-placeholder",
    "sentinel_subscription_id": "00000000-0000-0000-0000-000000000003",
    "sentinel_resource_group": "rg-soc",
    "sentinel_workspace_name": "ws-soc",
    "qradar_url": "https://qradar.example.invalid",
    "qradar_token": "unit-test-placeholder",
    "qradar_verify_ssl": True,
    "mde_tenant_id": "00000000-0000-0000-0000-000000000004",
    "mde_client_id": "00000000-0000-0000-0000-000000000005",
    "mde_client_secret": "unit-test-placeholder",
}

FACTORIES = {
    "splunk": (siem._splunk_client, siem.SPLUNK_CLIENT_PARAM_KEYS),
    "elastic": (siem._elastic_client, siem.ELASTIC_CLIENT_PARAM_KEYS),
    "sentinel": (siem._sentinel_client, siem.SENTINEL_CLIENT_PARAM_KEYS),
    "qradar": (siem._qradar_client, siem.QRADAR_CLIENT_PARAM_KEYS),
}

#: vendor_id -> the declared key tuple every adapter for that vendor must use.
#: Defender is here too: it has no factory (the arms build the client inline),
#: but its adapters strip a key tuple like everyone else, and the ack /
#: suppress arms added it as a third capability.
VENDOR_KEYS = {
    "splunk": siem.SPLUNK_CLIENT_PARAM_KEYS,
    "elastic": siem.ELASTIC_CLIENT_PARAM_KEYS,
    "sentinel": siem.SENTINEL_CLIENT_PARAM_KEYS,
    "qradar": siem.QRADAR_CLIENT_PARAM_KEYS,
    "defender": siem.DEFENDER_CLIENT_PARAM_KEYS,
}


def _keys_read_by(func) -> set[str]:
    """Re-derive the ``params.get("...")`` keys a factory reads, from its source.

    The anti-drift half. A constant that merely agrees with itself proves
    nothing; this parses the factory body so adding a new credential key
    without extending the tuple fails the build.
    """
    tree = ast.parse(inspect.getsource(func).lstrip())
    found: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func_node = node.func
        if not isinstance(func_node, ast.Attribute) or func_node.attr != "get":
            continue
        if not isinstance(func_node.value, ast.Name) or func_node.value.id != "params":
            continue
        if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            found.add(node.args[0].value)
    return found


@pytest.mark.parametrize("vendor", sorted(FACTORIES))
def test_declared_key_tuple_matches_what_the_factory_reads(vendor: str) -> None:
    factory, declared = FACTORIES[vendor]
    assert _keys_read_by(factory) == set(declared), (
        f"{vendor}: the factory reads {sorted(_keys_read_by(factory))} but the exported tuple "
        f"declares {sorted(declared)}. A key the factory reads and the tuple omits is a dry run "
        f"that calls the customer's SIEM."
    )


@pytest.mark.parametrize("vendor", sorted(FACTORIES))
def test_stripping_the_declared_keys_disables_the_factory(vendor: str) -> None:
    """The behavioural claim: after a dry-run strip, no client can be built."""
    factory, declared = FACTORIES[vendor]
    assert factory(dict(FULL_CREDENTIALS)) is not None, "fixture should build a live client before stripping"
    stripped = {k: v for k, v in FULL_CREDENTIALS.items() if k not in set(declared)}
    assert factory(stripped) is None, (
        f"{vendor}: a dry run stripped {sorted(declared)} and the factory still built a client "
        f"from {sorted(stripped)} — this is a live vendor call labelled 'preview'."
    )


def test_every_registered_siem_adapter_strips_its_vendors_full_key_set() -> None:
    builtins.register_builtin_executors(overwrite=True)
    checked = 0
    for descriptor in registry.list_descriptors():
        expected = VENDOR_KEYS.get(descriptor.vendor_id)
        if expected is None:
            continue
        executor = registry.get_executor(descriptor.vendor_id, descriptor.capability)
        # The strip list is how ``_LegacyExecutorAdapter`` implements dry_run.
        # The native read-only executors honour it with an early return before
        # they build a client, so they have no strip list to grade.
        if not isinstance(executor, builtins._LegacyExecutorAdapter):  # noqa: SLF001
            continue
        strip = getattr(executor, "_credential_keys", ())
        detail = f"{descriptor.vendor_id}/{descriptor.capability}: strips {sorted(strip)} vs factory {sorted(expected)}"
        assert set(strip) == set(expected), detail
        checked += 1
    assert checked >= 6, f"expected to grade several SIEM adapters, graded {checked}"


@pytest.mark.asyncio
async def test_dry_run_writeback_never_reaches_a_vendor(monkeypatch) -> None:
    """End to end: a dry run with full credentials must report SIMULATED.

    Each factory is wrapped so that *returning a client* trips the wire — the
    factories are legitimately called during vendor selection, and what must
    never happen is one of them succeeding. If the strip list regresses, this
    fails with the reason rather than by making a real network call that CI
    happens to refuse.
    """
    builtins.register_builtin_executors(overwrite=True)

    def _tripwire(name, real):
        def _wrapped(params):
            client = real(params)
            if client is not None:
                raise AssertionError(f"a dry run built a live client via {name}")
            return None

        return _wrapped

    for name in ("_splunk_client", "_elastic_client", "_sentinel_client", "_qradar_client"):
        monkeypatch.setattr(siem, name, _tripwire(name, getattr(siem, name)))

    executor = registry.get_executor("splunk", "update_alert_disposition")
    assert executor is not None
    result = await executor.execute(
        LiveActionRequest(
            capability="update_alert_disposition",
            vendor_id="splunk",
            target="NOTABLE-1",
            params={**FULL_CREDENTIALS, "disposition": "false_positive"},
            dry_run=True,
            tenant_id=uuid4(),
        )
    )
    assert result.status is LiveActionStatus.SIMULATED
    assert result.details.get("written") is False


@pytest.mark.asyncio
@pytest.mark.parametrize("capability", ["ack_alert", "suppress_alert"])
@pytest.mark.parametrize("vendor", ["splunk", "elastic"])
async def test_dry_run_alert_lifecycle_never_reaches_a_vendor(monkeypatch, vendor: str, capability: str) -> None:
    """The same guarantee for the two verbs that just became reachable.

    They pin ``alert_vendor`` per arm so a tenant with two SIEMs configured
    does not have the target chosen by credential ordering. A pin is a routing
    hint and never a licence to skip the credential check, so a dry run — which
    works by removing the credentials — must still simulate rather than
    resolving to the pinned vendor and calling it.
    """
    builtins.register_builtin_executors(overwrite=True)

    def _tripwire(name, real):
        def _wrapped(params):
            client = real(params)
            if client is not None:
                raise AssertionError(f"a dry run built a live client via {name}")
            return None

        return _wrapped

    for name in ("_splunk_client", "_elastic_client", "_sentinel_client", "_qradar_client"):
        monkeypatch.setattr(siem, name, _tripwire(name, getattr(siem, name)))

    executor = registry.get_executor(vendor, capability)
    assert executor is not None, f"{vendor}/{capability} is not registered"
    result = await executor.execute(
        LiveActionRequest(
            capability=capability,
            vendor_id=vendor,
            target="FINDING-1",
            params=dict(FULL_CREDENTIALS),
            dry_run=True,
            tenant_id=uuid4(),
        )
    )

    assert result.status is LiveActionStatus.SIMULATED
    assert "Simulation mode" in str(result.details.get("note", ""))
