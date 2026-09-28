"""Boot every service with no configuration and watch the sockets.

Why this exists
---------------
``scripts/check_default_egress.py`` reads the *declared* defaults and is
exhaustive over them, but a declared default is not the only way a process
reaches the internet: a module-scope ``httpx.get``, a client constructed at
import with a literal URL, or a lifespan that warms a cache from a CDN are all
invisible to it. This is the other half — the one the claim-to-gate matrix row
actually asks for, and the one the repository had never had: *a defined set of
services makes zero outbound network calls by default.*

How it works
------------
One subprocess per service, because every service ships a package literally
named ``app`` and two of them cannot occupy one interpreter. In each:

1. the socket guard goes in **first**, before any service code is imported;
2. the guard proves itself by dialling a public host and requiring a raise —
   a patch that stopped patching would otherwise report a clean run;
3. ``app.main`` is imported with a minimal environment;
4. the ASGI lifespan is entered and exited, because startup is where a warm-up
   fetch lives.

Every attempt is **recorded as well as refused**. Recording matters more than
refusing: a service that wraps its startup fetch in ``except Exception`` would
swallow the guard's error and look clean, so the verdict is built from the
ledger the guard keeps rather than from whether the process survived.

What counts as a violation
--------------------------
Reaching a *public* host. Loopback passes through untouched — a service dialling
its own Postgres is the product working. Private and internal destinations
(RFC1918, ``.local``/``.internal``, single-label container names like ``redis``)
are refused by the guard so nothing escapes the test host, but they are reported
rather than failed: dialling ``redis:6379`` is what a self-hosted deployment is
supposed to do. Public or private is decided by the same predicate the services
enforce air-gap policy with, lifted out of ``services/api/app/core/airgap.py`` by
the static gate, so the two halves cannot disagree about what "internal" means.

Honest limits
-------------
* Refusing a non-loopback connection can cut a startup path short, so a service
  that dials Kafka before it would have dialled a CDN is only covered up to the
  first refusal. Every refusal is printed, so the truncation is visible rather
  than silently counted as coverage.
* A service whose third-party dependencies are not installed is **skipped with
  the missing module named**, never silently. The covered set is asserted
  non-empty, because a suite that exercises nothing and prints green is the
  precise failure this repository has scars from.
* Neither this nor the static gate says anything about what the *running
  containers* do. That needs egress-blocked integration, which the Helm chart's
  default-deny NetworkPolicy addresses at deploy time and nothing addresses in
  CI.
"""

from __future__ import annotations

import concurrent.futures
import importlib.util
import json
import os
import socket
import subprocess
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[1]

#: How long one service gets to import and run its lifespan. Generous: a
#: service retrying a refused loopback connection with backoff is doing the
#: right thing, and the point is to observe it, not to race it.
PROBE_TIMEOUT_SECONDS = 120

#: The smallest environment that is still an *unconfigured* one. Two secrets
#: and an environment name, because several services refuse to construct their
#: settings without them and a service that will not start is not evidence of
#: anything. Deliberately contains no URL of any kind: every address these
#: probes observe therefore came from the service's own defaults.
MINIMAL_ENV = {
    "ENVIRONMENT": "development",
    "SECRET_KEY": "offline-egress-probe-secret-key-32bytes!",
    "JWT_SECRET": "offline-egress-probe-secret-key-32bytes!",
    "AISOC_SERVICE_TOKEN": "offline-egress-probe-token",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONUNBUFFERED": "1",
}


# --------------------------------------------------------------------------
# The guard. One source, executed in-process by the self-check below and in
# every probe subprocess, so the thing proven and the thing used are the same.
# --------------------------------------------------------------------------

GUARD_SOURCE = r'''
import socket

class EgressBlocked(OSError):
    """Raised instead of opening a socket to anywhere but loopback."""

#: Destinations that are the test host itself. A service talking to these is
#: talking to nothing outside the process tree.
_LOOPBACK = {"127.0.0.1", "::1", "localhost", "0.0.0.0", "::", "", "<broadcast>"}

#: Every destination the guard was asked for, whether or not the caller
#: survived being refused. This ledger, not the exception, is the verdict.
ATTEMPTS = []

_REAL = {
    "connect": socket.socket.connect,
    "connect_ex": socket.socket.connect_ex,
    "create_connection": socket.create_connection,
    "getaddrinfo": socket.getaddrinfo,
}


def _host_of(address):
    if isinstance(address, (tuple, list)) and address:
        return address[0]
    return address


def _normalise(host):
    if host is None:
        return ""
    text = str(host).strip().lower().rstrip(".")
    # IPv6 literals arrive with a scope id on some platforms.
    return text.split("%", 1)[0]


def _check(kind, host):
    """Record, then refuse anything that is not loopback."""
    name = _normalise(host)
    if name in _LOOPBACK:
        return
    ATTEMPTS.append({"kind": kind, "host": name})
    raise EgressBlocked(
        "offline egress guard refused a %s to %r: this test asserts a service "
        "reaches nothing but loopback when it is unconfigured" % (kind, name)
    )


def _connect(self, address):
    if getattr(self, "family", None) == getattr(socket, "AF_UNIX", object()):
        return _REAL["connect"](self, address)
    _check("connect", _host_of(address))
    return _REAL["connect"](self, address)


def _connect_ex(self, address):
    if getattr(self, "family", None) == getattr(socket, "AF_UNIX", object()):
        return _REAL["connect_ex"](self, address)
    _check("connect_ex", _host_of(address))
    return _REAL["connect_ex"](self, address)


def _create_connection(address, *args, **kwargs):
    _check("create_connection", _host_of(address))
    return _REAL["create_connection"](address, *args, **kwargs)


def _getaddrinfo(host, *args, **kwargs):
    _check("getaddrinfo", host)
    return _REAL["getaddrinfo"](host, *args, **kwargs)


def install_guard():
    socket.socket.connect = _connect
    socket.socket.connect_ex = _connect_ex
    socket.create_connection = _create_connection
    socket.getaddrinfo = _getaddrinfo


def remove_guard():
    socket.socket.connect = _REAL["connect"]
    socket.socket.connect_ex = _REAL["connect_ex"]
    socket.create_connection = _REAL["create_connection"]
    socket.getaddrinfo = _REAL["getaddrinfo"]


def guard_is_live():
    """Dial a public host and require a refusal.

    A patch that silently stopped patching turns every probe below into a
    clean run over an unguarded socket, which is indistinguishable from a
    service that behaved. So the guard is made to prove itself first.
    """
    before = len(ATTEMPTS)
    try:
        socket.create_connection(("example.com", 80), timeout=1)
    except EgressBlocked:
        del ATTEMPTS[before:]
        return True
    except Exception:
        del ATTEMPTS[before:]
        return False
    del ATTEMPTS[before:]
    return False
'''


PROBE_SOURCE = (
    GUARD_SOURCE
    + r"""
import asyncio
import json
import sys
import traceback

SERVICE_ROOT = sys.argv[1]
LIFESPAN_TIMEOUT = float(sys.argv[2])

report = {
    "guard_live": False,
    "imported": False,
    "skip_reason": None,
    "lifespan": "not attempted",
    "attempts": [],
    "error": None,
}

install_guard()
report["guard_live"] = guard_is_live()
if not report["guard_live"]:
    print(json.dumps(report))
    raise SystemExit(0)

sys.path.insert(0, SERVICE_ROOT)

try:
    import app.main as service_main
    report["imported"] = True
except ModuleNotFoundError as exc:
    # A third-party package this environment does not have is a skip with a
    # name. A module inside the service itself failing to import is a real
    # defect and is reported as an error, not excused.
    missing = (exc.name or "").split(".")[0]
    if missing and missing != "app":
        report["skip_reason"] = "requires the %r package, which is not installed here" % missing
    else:
        report["error"] = "".join(traceback.format_exception_only(type(exc), exc)).strip()
except BaseException as exc:  # noqa: BLE001 - any failure to boot is the finding
    report["error"] = "".join(traceback.format_exception_only(type(exc), exc)).strip()

if report["imported"]:
    asgi = getattr(service_main, "app", None)
    router = getattr(asgi, "router", None)
    factory = getattr(router, "lifespan_context", None)
    if factory is None:
        report["lifespan"] = "no ASGI app exposed as app.main:app"
    else:
        async def drive():
            context = factory(asgi)
            try:
                await context.__aenter__()
            finally:
                try:
                    await context.__aexit__(None, None, None)
                except BaseException:
                    pass

        try:
            asyncio.run(asyncio.wait_for(drive(), timeout=LIFESPAN_TIMEOUT))
            report["lifespan"] = "completed"
        except BaseException as exc:  # noqa: BLE001 - startup failing offline is expected
            report["lifespan"] = "raised %s" % "".join(traceback.format_exception_only(type(exc), exc)).strip()

report["attempts"] = ATTEMPTS
print(json.dumps(report))
"""
)


# --------------------------------------------------------------------------
# Host classification, borrowed from the static gate so both halves agree.
# --------------------------------------------------------------------------


@lru_cache(maxsize=1)
def _is_private_host():
    """The predicate the services themselves enforce air-gap policy with.

    Loaded through the static gate rather than reimplemented, so "internal"
    means the same thing in both halves of this claim and in the service code
    all three describe.
    """
    gate = REPO / "scripts" / "check_default_egress.py"
    spec = importlib.util.spec_from_file_location("check_default_egress", gate)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.load_shipped_predicate(REPO, module.PREDICATE_MODULE)


# --------------------------------------------------------------------------
# Discovering the services, and probing them.
# --------------------------------------------------------------------------


def discovered_services() -> list[str]:
    """Every service exposing ``app/main.py``, read off disk rather than listed.

    Derived, not enumerated: a hand-kept list is correct the day it is written,
    and this repository has paid for that several times over — 56 of 82 agents
    test files run by nothing, a connector union naming ten types the platform
    does not ingest. A service added tomorrow is covered tomorrow.
    """
    return sorted(p.parents[1].name for p in (REPO / "services").glob("*/app/main.py"))


def _probe(service: str) -> dict:
    root = REPO / "services" / service
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        **MINIMAL_ENV,
    }
    try:
        done = subprocess.run(
            [sys.executable, "-c", PROBE_SOURCE, str(root), str(PROBE_TIMEOUT_SECONDS / 2)],
            capture_output=True,
            text=True,
            timeout=PROBE_TIMEOUT_SECONDS,
            env=env,
            cwd=str(root),
        )
    except subprocess.TimeoutExpired:
        return {"skip_reason": None, "error": f"probe did not finish within {PROBE_TIMEOUT_SECONDS}s", "attempts": []}

    payload = next((ln for ln in reversed(done.stdout.splitlines()) if ln.startswith("{")), None)
    if payload is None:
        tail = (done.stderr or done.stdout or "").strip().splitlines()[-4:]
        return {"skip_reason": None, "error": "probe produced no report: " + " / ".join(tail), "attempts": []}
    result = json.loads(payload)
    result["stderr_tail"] = (done.stderr or "").strip().splitlines()[-3:]
    return result


@lru_cache(maxsize=1)
def probe_results() -> dict[str, dict]:
    """Probe every service once, in parallel, and cache the verdicts."""
    services = discovered_services()
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(services) or 1)) as pool:
        return dict(zip(services, pool.map(_probe, services), strict=True))


def public_attempts(result: dict) -> list[dict]:
    is_private = _is_private_host()
    return [a for a in result.get("attempts", []) if not is_private(a["host"])]


# --------------------------------------------------------------------------
# The tests.
# --------------------------------------------------------------------------


def test_the_socket_guard_actually_blocks() -> None:
    """The guard refuses a public destination, in this very interpreter.

    Run before anything trusts a probe's clean report. A guard that stopped
    guarding makes every result below a clean run over an open socket, which
    reads exactly like a service that behaved.
    """
    # ``Any`` rather than ``object``: this namespace is populated by exec, so
    # its members are callables and classes the type checker cannot see.
    namespace: dict[str, Any] = {}
    exec(compile(GUARD_SOURCE, "<egress guard>", "exec"), namespace)  # noqa: S102 - this module's own source

    namespace["install_guard"]()
    try:
        assert namespace["guard_is_live"](), "the guard did not refuse a connection to a public host"

        with pytest.raises(namespace["EgressBlocked"]):
            socket.create_connection(("example.com", 80), timeout=1)
        with pytest.raises(namespace["EgressBlocked"]):
            socket.getaddrinfo("example.com", 443)
        with pytest.raises(namespace["EgressBlocked"]):
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("93.184.216.34", 80))

        # …and it must stay out of the way of loopback, or every service would
        # look like a violation and the test would prove nothing.
        assert namespace["_normalise"]("LOCALHOST.") == "localhost"
        namespace["_check"]("connect", "127.0.0.1")
        namespace["_check"]("connect", "::1")
    finally:
        namespace["remove_guard"]()

    # The ledger records even when the caller swallows the refusal, which is
    # the property that makes a try/except around a startup fetch detectable.
    assert [a["host"] for a in namespace["ATTEMPTS"]] == ["example.com", "example.com", "93.184.216.34"]


@pytest.mark.parametrize("service", discovered_services())
def test_service_reaches_no_public_host_when_unconfigured(service: str) -> None:
    result = probe_results()[service]

    if result.get("skip_reason"):
        pytest.skip(f"{service}: {result['skip_reason']}")

    assert result.get("guard_live"), f"{service}: the socket guard was not active in the probe, so its clean run means nothing"

    # The ledger is read before anything else, because a service that fails to
    # boot *because* it tried to reach a CDN should be reported as reaching a
    # CDN. Checking the boot error first would hide the specific finding behind
    # the generic one it caused.
    public = public_attempts(result)
    assert not public, (
        f"{service} reached {len(public)} public host(s) with no configuration set: "
        + ", ".join(f"{a['host']} (via {a['kind']})" for a in public)
        + f". Import: {'ok' if result.get('imported') else 'failed'}. Lifespan: {result.get('lifespan')}."
    )

    assert not result.get("error"), f"{service} could not be booted offline: {result['error']}"


def test_the_probe_set_is_not_empty_and_is_reported() -> None:
    """Fail — never skip — when nothing was exercised, and say what was.

    A suite that covers nothing while printing green is the failure this
    repository keeps rediscovering: a playbook linter reporting "2/2 passed"
    over a set it never assembled, a weekly eval green on eight consecutive
    runs with every real step skipped. So the covered set is asserted, and the
    skipped set is printed with its reasons rather than disappearing.
    """
    results = probe_results()
    covered, skipped, broken = [], [], []
    for service, result in sorted(results.items()):
        if result.get("skip_reason"):
            skipped.append((service, result["skip_reason"]))
        elif result.get("error"):
            broken.append((service, result["error"]))
        else:
            covered.append(service)

    print(f"\noffline egress probe — {len(results)} service(s) discovered from services/*/app/main.py")
    for service in covered:
        result = results[service]
        internal = ", ".join(sorted({a["host"] for a in result.get("attempts", [])})) or "nothing"
        print(f"  COVERED  {service:<14} lifespan: {result.get('lifespan')}")
        print(f"           {'':<14} dialled: {internal}")
    for service, reason in skipped:
        print(f"  SKIPPED  {service:<14} {reason}")
    for service, reason in broken:
        print(f"  BROKEN   {service:<14} {reason}")

    assert covered, (
        "no service was exercised — every one of "
        f"{len(results)} was skipped or failed to boot, so a green run here proves nothing. "
        + "; ".join(f"{s}: {r}" for s, r in skipped + broken)
    )


def test_every_discovered_service_is_accounted_for() -> None:
    """Discovery must find the services, and every one must reach a verdict.

    The floor is deliberately low and the direction is the one that breaks: a
    glob that stops matching returns nothing and every assertion above passes
    vacuously.
    """
    services = discovered_services()
    assert len(services) >= 10, f"only {len(services)} service(s) found under services/*/app/main.py; the glob is broken, not the tree"
    assert "api" in services and "threatintel" in services, f"discovery missed a service that certainly has one: {services}"
    assert set(probe_results()) == set(services), "a discovered service reached no verdict"


def test_the_probe_environment_carries_no_urls() -> None:
    """Every address a probe observes must come from the service, not from us.

    A probe env containing ``DATABASE_URL=...`` would let the harness supply
    the very default under test, and a clean result would say nothing about
    what the service ships.
    """
    offenders = {k: v for k, v in MINIMAL_ENV.items() if "://" in v}
    assert not offenders, f"the minimal probe environment supplies URLs, which would mask the defaults under test: {offenders}"

    # The probe itself must name no destination either, or the guard's ledger
    # would record an address the harness supplied. `example.com` is the one
    # exception: it is the host the guard dials to prove it is still guarding,
    # and RFC 2606 reserves it precisely so it can never resolve to anyone.
    urls = [line.strip() for line in PROBE_SOURCE.splitlines() if "://" in line]
    assert not urls, f"the probe source names a destination, which would mask the defaults under test: {urls}"
    assert PROBE_SOURCE.count("example.com") == 1, "the guard's self-check host should be the only host the probe names"
