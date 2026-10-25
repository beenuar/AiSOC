#!/usr/bin/env python3
"""Kill a store and ask what the services say about it.

Gap-closure wave 5.

Only Postgres and the fusion consumer are exercised by chaos today.
The platform also depends on ClickHouse, Neo4j, Qdrant, Redis and
Kafka, and each has a different correct answer when it goes away —
which is the whole point, because a service that treats all five the
same is wrong about four of them.

The question is not "does it crash"
--------------------------------------
Crashing is a *fine* outcome. The failure this grades is the one this
repository keeps finding: a dependency goes away, the service keeps
answering `200`, and nobody learns anything until a number is wrong
weeks later. UEBA's consumer did exactly that — an exception left the
`async for`, `finally` stopped the consumer, and the container sat at
`running` with restarts 0 and `/health` returning 200, permanently.

So each store declares what *should* happen, and the grader checks
that rather than liveness:

``degrade``   the feature stops and readiness says so, while the
              service's own job carries on. Losing the entity graph
              must not take ingest out of the load balancer.
``refuse``    requests that need the store answer an error naming it,
              rather than an empty result that reads as "nothing
              found". A clean empty result from a query that never ran
              is the worst outcome on a forensic search.
``block``     the service's core job genuinely cannot proceed, so
              readiness fails and the orchestrator replaces it.

And recovery is graded too. A service that degrades correctly and then
never reconnects has converted an outage into an outage plus a manual
restart.
"""

from __future__ import annotations

import argparse
import http.server
import json
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

__all__ = ["STORES", "StoreExpectation", "grade_outage"]


@dataclass(frozen=True)
class StoreExpectation:
    """One store, and what losing it is supposed to look like."""

    store: str
    container: str
    #: Services that read it and must keep serving their own job.
    dependents: tuple[str, ...]
    behaviour: str
    #: The readiness field that must flip. Empty means readiness is not
    #: expected to mention it, which is itself a finding worth stating
    #: rather than leaving implicit.
    readiness_key: str
    why: str


STORES: tuple[StoreExpectation, ...] = (
    StoreExpectation(
        store="clickhouse",
        container="clickhouse",
        dependents=("fusion", "api"),
        behaviour="degrade",
        readiness_key="lake_writer",
        why=(
            "The lake is an archive, not the alert path. Fusion must keep promoting alerts "
            "with the archive unavailable, and say the archive is unavailable — a hunt that "
            "returns zero rows because the lake is down reads identically to a hunt that "
            "found nothing."
        ),
    ),
    StoreExpectation(
        store="neo4j",
        container="neo4j",
        dependents=("ingest", "api"),
        behaviour="degrade",
        readiness_key="graph",
        why=(
            "Graph writes at ingest are fire-and-forget by design, so ingest must not slow "
            "or stop. Blast-radius queries must refuse rather than return an empty "
            "neighbourhood, which reads as 'this host touched nothing'."
        ),
    ),
    StoreExpectation(
        store="qdrant",
        container="qdrant",
        dependents=("threatintel",),
        behaviour="degrade",
        readiness_key="vector_store",
        why=(
            "Similarity search is an enrichment. Losing it must not stop IOC ingestion, and "
            "the enrichment response must say the similarity leg was skipped rather than "
            "report no similar actors."
        ),
    ),
    StoreExpectation(
        store="redis",
        container="redis",
        dependents=("api", "agents"),
        behaviour="degrade",
        readiness_key="cache",
        why=(
            "A cache. Every read must fall through to its source. The OIDC state store also "
            "lives here, so sign-ins mid-flight are lost — acceptable, and the user sees an "
            "error rather than a wrong tenant."
        ),
    ),
    StoreExpectation(
        store="kafka",
        container="kafka",
        dependents=("ingest", "fusion", "realtime", "ueba"),
        behaviour="block",
        readiness_key="kafka",
        why=(
            "The spine. Ingest cannot accept what it cannot durably hand on, so accepting a "
            "batch it will drop is worse than refusing it. Readiness must fail so the load "
            "balancer stops sending traffic, and every consumer must say which subscription "
            "it lost rather than sitting at 200 with no partitions."
        ),
    ),
    StoreExpectation(
        store="postgres",
        container="postgres",
        dependents=("api", "fusion", "agents", "actions"),
        behaviour="block",
        readiness_key="database",
        why="The system of record. Nothing meaningful can be served without it.",
    ),
)

BEHAVIOURS = frozenset({"degrade", "refuse", "block"})


@dataclass
class OutageResult:
    store: str
    behaviour: str
    expected: str
    readiness_reported: bool = False
    #: The status line the owning readiness surface answered during the
    #: outage. ``None`` means it answered nothing at all.
    readiness_status: int | None = None
    dependents_up: tuple[str, ...] = ()
    dependents_down: tuple[str, ...] = ()
    recovered: bool = False
    recovery_seconds: float | None = None
    findings: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.findings

    def as_dict(self) -> dict[str, Any]:
        return {
            "store": self.store,
            "expected": self.expected,
            "observed": self.behaviour,
            "readiness_reported": self.readiness_reported,
            "readiness_status": self.readiness_status,
            "dependents_up": list(self.dependents_up),
            "dependents_down": list(self.dependents_down),
            "recovered": self.recovered,
            "recovery_seconds": self.recovery_seconds,
            "findings": self.findings,
            "passed": self.passed,
        }


def grade_outage(
    expectation: StoreExpectation,
    *,
    readiness: dict[str, Any],
    readiness_status: int | None,
    dependents_responding: dict[str, bool],
    recovered: bool,
    recovery_observable: bool = True,
    recovery_seconds: float | None = None,
) -> OutageResult:
    """Grade one outage against what the store's loss is supposed to look like.

    Pure, so the self-test can drive every branch without containers.

    ``readiness_status`` is the status line the owning readiness surface
    answered while the store was down, or ``None`` if it answered nothing at
    all. It is graded rather than discarded: see :meth:`_grade_status_line`.
    """
    result = OutageResult(
        store=expectation.store,
        behaviour=expectation.behaviour,
        expected=expectation.behaviour,
        readiness_status=readiness_status,
        recovered=recovered,
        recovery_seconds=recovery_seconds,
    )
    result.dependents_up = tuple(s for s, ok in dependents_responding.items() if ok)
    result.dependents_down = tuple(s for s, ok in dependents_responding.items() if not ok)

    # Did readiness admit it? This is the measurement that matters most:
    # a dependency that is gone while /health says 200 is indistinguishable
    # from a healthy idle one.
    reported = readiness.get(expectation.readiness_key)
    result.readiness_reported = reported is False or reported == "down" or reported == "degraded"
    if readiness_status is None:
        # Distinct from "answered without the key", and the distinction is
        # the operator's first question: a refusal with a reason and an
        # unreachable socket look identical in a body-only reading.
        result.findings.append(
            f"{expectation.store} is down and the readiness surface answered nothing at all — "
            "no status line and no body, so a service that is refusing with a reason cannot be "
            "told apart from one that is gone"
        )
    elif not result.readiness_reported:
        result.findings.append(
            f"{expectation.store} is down and readiness does not say so "
            f"(`{expectation.readiness_key}` reads {reported!r}) — an operator cannot tell this "
            "apart from a healthy idle service"
        )

    _grade_status_line(expectation, result, readiness_status)

    if expectation.behaviour == "block":
        if result.dependents_up:
            result.findings.append(
                f"{expectation.store} is down and {', '.join(result.dependents_up)} still report ready; "
                "they cannot do their job without it, so staying in the load balancer drops work silently"
            )
    else:
        if result.dependents_down:
            result.findings.append(
                f"{expectation.store} is down and {', '.join(result.dependents_down)} stopped serving; {expectation.why}"
            )

    if not recovery_observable:
        # Separated from "did not recover" because they are different facts
        # and only one of them is about the product. An endpoint that never
        # mentions the key cannot be used to watch a reconnection, and the
        # grader used to score exactly that silence as recovery in 0.0s --
        # `probe.get(key)` returned None, `None not in (False, "down",
        # "degraded")` was true, and three legs reported a recovery nobody
        # had observed. An unknown must never be a pass.
        result.findings.append(
            f"{expectation.store} came back and readiness never reported `{expectation.readiness_key}` "
            "at any point, so reconnection could not be observed — a recovery nobody can see is not "
            "a recovery an operator can rely on"
        )
    elif not recovered:
        result.findings.append(
            f"{expectation.store} came back and the dependents did not reconnect — an outage plus a manual restart is worse than an outage"
        )
    return result


def _grade_status_line(expectation: StoreExpectation, result: OutageResult, status: int | None) -> None:
    """Require the status code the behaviour implies, rather than tolerating it.

    The body said whether the store was named; the status line says whether
    the service asked to be taken out of rotation, and the two are separate
    claims. Grading only the body let a ``block`` store's owner answer ``200``
    beside ``"database": false`` and still pass the readiness half — which is
    the load balancer continuing to send work to a service that cannot do it.

    * ``block``: readiness MUST fail. The orchestrator is the thing that acts
      on this, and it reads the status code, not the JSON.
    * ``degrade`` / ``refuse``: readiness MUST stay 2xx. Failing readiness
      over a store whose loss the service is supposed to survive pulls a
      working service out of the load balancer to fix a feature.
    """
    if status is None:
        return  # already reported, above, as "answered nothing at all"
    ok = 200 <= status < 300
    if expectation.behaviour == "block":
        if ok:
            result.findings.append(
                f"{expectation.store} is down and readiness still answered {status}; a blocking "
                "outage must fail readiness, because the orchestrator acts on the status line and "
                "never on the body"
            )
    elif not ok:
        result.findings.append(
            f"{expectation.store} is down and readiness answered {status}; losing "
            f"{expectation.store} is a {expectation.behaviour}, so refusing readiness over it takes "
            "a service that can still do its job out of the load balancer"
        )


def _resolve_container(service: str) -> str | None:
    """The container id for a compose service, or ``None`` if it is not up.

    Asked of compose rather than assembled from a convention. Every service in
    `docker-compose.yml` pins `container_name: aisoc-<service>`, so the bare
    service name this module records never matched a running container and
    every outage reported `could not stop container 'postgres' -- docker
    unavailable?`. All six store-outage jobs failed that way, naming Docker
    for a defect that was ours.

    `docker compose ps -q` is authoritative: it accounts for the pinned name,
    the project prefix when there is no pinned name, and a service that is
    simply not running. The literal fallbacks exist so the script still works
    when invoked outside a compose project.
    """
    try:
        done = subprocess.run(
            ["docker", "compose", "ps", "-q", service],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        cid = (done.stdout or "").strip().splitlines()
        if done.returncode == 0 and cid:
            return cid[0]
    except Exception:  # noqa: BLE001 - fall through to the literal names
        pass

    for candidate in (f"aisoc-{service}", service):
        try:
            done = subprocess.run(
                ["docker", "inspect", "-f", "{{.Id}}", candidate],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if done.returncode == 0 and (done.stdout or "").strip():
                return candidate
        except Exception:  # noqa: BLE001
            continue
    return None


def _container_action(container: str, action: str) -> bool:
    target = _resolve_container(container)
    if target is None:
        return False
    try:
        subprocess.run(
            ["docker", action, target],
            check=True,
            capture_output=True,
            timeout=60,
        )
        return True
    except Exception:  # noqa: BLE001 - absence of docker is a skip, not a crash
        return False


#: Readiness endpoints are local to the stack under test. The prefix
#: check is the same mitigation `check_codeql_alerts` uses for its own
#: `urlopen`: build from a fixed root and refuse anything that does
#: not start with it, so the `file://` read the scanner warns about is
#: unreachable.
_ALLOWED_PROBE_PREFIXES = ("http://127.0.0.1:", "http://localhost:", "https://127.0.0.1:")


def _probe(url: str, timeout: float = 4.0) -> tuple[int | None, dict[str, Any] | None]:
    """Read a readiness answer: the status line *and* the body.

    Both halves are graded, so both are returned. The status line is what an
    orchestrator acts on; the body is what an operator reads. A grader that
    keeps only one of them can score a service that answers ``200`` beside
    ``{"database": false}`` as correct, which is the load balancer being told
    to keep sending work to something that cannot do it.

    The body is read *including* from an HTTP error response. A block-store
    owner failing readiness with a 503 **and a JSON body naming why** is
    exactly the correct behaviour — the API answers 503 with
    ``{"database": false, ...}`` while Postgres is down. ``urlopen`` raises on
    any 4xx/5xx, so without reading ``HTTPError``'s body the grader scored
    that correct behaviour as silence ("``database`` reads None").

    ``(None, None)`` means nothing answered: connection refused, a timeout, or
    a reply that is not JSON. That is genuinely "nothing was said", and it is
    reported as its own finding rather than folded into "did not mention the
    key" — a refusal with a reason and a dead socket are different facts.
    """
    if not url.startswith(_ALLOWED_PROBE_PREFIXES):
        raise ValueError(
            f"refusing to probe {url!r}: this harness only reads readiness endpoints on the "
            f"local stack it is taking down, which must start with one of {_ALLOWED_PROBE_PREFIXES}"
        )
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310 - prefix-checked above
            return response.status, dict(json.loads(response.read().decode("utf-8")))
    except urllib.error.HTTPError as err:
        try:
            return err.code, dict(json.loads(err.read().decode("utf-8")))
        except (ValueError, OSError):
            # A status line with an unreadable body is still an answer, and
            # saying so is more useful than reporting silence.
            return err.code, None
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return None, None


#: What a readiness key reads when the store behind it is back. Every key this
#: harness grades (`database`, `cache`, `kafka`, `graph`, `lake_writer`,
#: `vector_store`) is a boolean; the string spellings are accepted so a service
#: that reports a tri-state does not read as permanently broken. A key that is
#: *absent* is deliberately not in this set -- see `recovery_observable`.
_RECOVERED_VALUES: frozenset[Any] = frozenset({True, "up", "ok", "ready", "healthy"})


def _responding(url: str, timeout: float = 4.0) -> bool:
    """Is a dependent *serving its job*? Only a 2xx counts.

    Deliberately stricter than :func:`_probe`: dependents are probed at their
    readiness endpoints, where a 503 means "alive but cannot do my job" — for
    a block store that is the required outcome, and counting it as responding
    would grade the correct refusal as a finding.
    """
    if not url.startswith(_ALLOWED_PROBE_PREFIXES):
        raise ValueError(
            f"refusing to probe {url!r}: this harness only reads readiness endpoints on the "
            f"local stack it is taking down, which must start with one of {_ALLOWED_PROBE_PREFIXES}"
        )
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310 - prefix-checked above
            return 200 <= response.status < 300
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return False


def _self_test() -> int:
    """Every branch of the grader, without containers.

    The live path needs a stack; this runs unconditionally, because a
    grader nobody exercised is a grader nobody can trust.
    """
    clickhouse = next(s for s in STORES if s.store == "clickhouse")
    kafka = next(s for s in STORES if s.store == "kafka")

    cases = [
        (
            "degrade: readiness admits it, stays 200, and dependents keep serving",
            grade_outage(
                clickhouse,
                readiness={"lake_writer": False},
                readiness_status=200,
                dependents_responding={"fusion": True, "api": True},
                recovered=True,
            ),
            True,
        ),
        (
            "degrade: readiness stays silent — the UEBA failure shape",
            grade_outage(
                clickhouse,
                readiness={"lake_writer": True},
                readiness_status=200,
                dependents_responding={"fusion": True, "api": True},
                recovered=True,
            ),
            False,
        ),
        (
            "degrade: a dependent stopped serving over an archive it does not need",
            grade_outage(
                clickhouse,
                readiness={"lake_writer": False},
                readiness_status=200,
                dependents_responding={"fusion": False, "api": True},
                recovered=True,
            ),
            False,
        ),
        (
            "degrade: readiness refused with 503 over a store the service survives",
            grade_outage(
                clickhouse,
                readiness={"lake_writer": False},
                readiness_status=503,
                dependents_responding={"fusion": True, "api": True},
                recovered=True,
            ),
            False,
        ),
        (
            "block: readiness fails with 503 and dependents drop out of the load balancer",
            grade_outage(
                kafka,
                readiness={"kafka": False},
                readiness_status=503,
                dependents_responding={"ingest": False, "fusion": False},
                recovered=True,
            ),
            True,
        ),
        (
            "block: the key is named but readiness still answers 200 — the orchestrator reads the status line",
            grade_outage(
                kafka,
                readiness={"kafka": False},
                readiness_status=200,
                dependents_responding={"ingest": False, "fusion": False},
                recovered=True,
            ),
            False,
        ),
        (
            "block: ingest still ready without the spine it writes to",
            grade_outage(
                kafka,
                readiness={"kafka": False},
                readiness_status=503,
                dependents_responding={"ingest": True, "fusion": False},
                recovered=True,
            ),
            False,
        ),
        (
            "readiness answered nothing at all — not the same fact as answering without the key",
            grade_outage(
                kafka,
                readiness={},
                readiness_status=None,
                dependents_responding={"ingest": False, "fusion": False},
                recovered=True,
            ),
            False,
        ),
        (
            "recovery: degraded correctly and never reconnected",
            grade_outage(
                clickhouse,
                readiness={"lake_writer": False},
                readiness_status=200,
                dependents_responding={"fusion": True, "api": True},
                recovered=False,
            ),
            False,
        ),
        (
            "recovery: the key was never reported, so reconnection was unobservable — an unknown is not a pass",
            grade_outage(
                clickhouse,
                readiness={"lake_writer": False},
                readiness_status=200,
                dependents_responding={"fusion": True, "api": True},
                recovered=False,
                recovery_observable=False,
            ),
            False,
        ),
    ]

    failures = 0
    for name, result, should_pass in cases:
        ok = result.passed is should_pass
        print(f"  self-test [{'ok' if ok else 'FAIL'}] {name}")
        if not ok:
            failures += 1
            for finding in result.findings:
                print(f"      {finding}")

    # Failing is not enough: a case that fails for the wrong reason proves
    # nothing about the discrimination it was written to make. These pin the
    # finding each new branch is supposed to produce.
    named = [
        (
            "a block store answering 200 is reported as a status-line defect, not a body one",
            "still answered 200",
            grade_outage(
                kafka,
                readiness={"kafka": False},
                readiness_status=200,
                dependents_responding={"ingest": False, "fusion": False},
                recovered=True,
            ),
        ),
        (
            "a degrade store refusing readiness is reported as taking a working service out of rotation",
            "out of the load balancer",
            grade_outage(
                clickhouse,
                readiness={"lake_writer": False},
                readiness_status=503,
                dependents_responding={"fusion": True, "api": True},
                recovered=True,
            ),
        ),
        (
            "an unobservable recovery is reported as unobservable, not as a failure to reconnect",
            "could not be observed",
            grade_outage(
                clickhouse,
                readiness={"lake_writer": False},
                readiness_status=200,
                dependents_responding={"fusion": True, "api": True},
                recovered=False,
                recovery_observable=False,
            ),
        ),
        (
            "a silent readiness surface is reported as answering nothing, not as omitting a key",
            "answered nothing at all",
            grade_outage(
                kafka,
                readiness={},
                readiness_status=None,
                dependents_responding={"ingest": False, "fusion": False},
                recovered=True,
            ),
        ),
    ]
    for name, fragment, result in named:
        ok = any(fragment in finding for finding in result.findings)
        print(f"  self-test [{'ok' if ok else 'FAIL'}] {name}")
        if not ok:
            failures += 1
            for finding in result.findings:
                print(f"      {finding}")

    # The unobservable case must NOT also claim the dependents failed to
    # reconnect: two findings for one fact is how a report stops being read.
    unobservable = named[2][2]
    exclusive = not any("did not reconnect" in finding for finding in unobservable.findings)
    print(f"  self-test [{'ok' if exclusive else 'FAIL'}] an unobservable recovery is reported once, not twice")
    if not exclusive:
        failures += 1

    # Every store must declare a behaviour the grader implements, or it
    # silently grades nothing.
    for store in STORES:
        if store.behaviour not in BEHAVIOURS:
            print(f"  self-test [FAIL] {store.store} declares unknown behaviour {store.behaviour!r}")
            failures += 1

    failures += _probe_self_test()

    print(f"store_outage: self-test {'OK' if not failures else 'FAILED'} — {len(STORES)} stores declared")
    return 1 if failures else 0


def _probe_self_test() -> int:
    """The probe split, against a real local HTTP server (stdlib, no containers).

    The behaviours under test are the ones the live run depends on:

    * ``_probe`` reads the JSON body of a **503** — a block store failing
      readiness with a reason is correct behaviour, not silence.
    * ``_probe`` returns the **status line** alongside it, because the
      behaviour contract is graded on both halves.
    * ``_responding`` refuses that same 503 — a dependent that is alive but
      cannot do its job is not serving.
    """

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib handler contract
            if self.path == "/ready-200":
                body = json.dumps({"status": "ready", "database": True}).encode()
                self.send_response(200)
            elif self.path == "/ready-503":
                body = json.dumps({"status": "not_ready", "database": False}).encode()
                self.send_response(503)
            else:
                body = b"not json"
                self.send_response(503)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: Any) -> None:  # keep the self-test quiet
            return None

    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    failures = 0
    try:
        cases = [
            ("_probe reads a 200 body", _probe(f"{base}/ready-200") == (200, {"status": "ready", "database": True})),
            (
                "_probe reads the JSON body of a 503 (a refusal with a reason is not silence)",
                _probe(f"{base}/ready-503") == (503, {"status": "not_ready", "database": False}),
            ),
            (
                "_probe keeps the status line of a non-JSON error body (an answer with an unreadable body is still an answer)",
                _probe(f"{base}/ready-junk") == (503, None),
            ),
            ("_probe reports a dead socket as no answer at all", _probe("http://127.0.0.1:1/ready") == (None, None)),
            ("_responding accepts a 200", _responding(f"{base}/ready-200") is True),
            ("_responding refuses a 503 (alive but not doing its job is not serving)", _responding(f"{base}/ready-503") is False),
            ("_responding refuses a dead socket", _responding("http://127.0.0.1:1/ready") is False),
        ]
        for name, ok in cases:
            print(f"  self-test [{'ok' if ok else 'FAIL'}] {name}")
            if not ok:
                failures += 1
    finally:
        server.shutdown()
        thread.join(timeout=5)
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="prove the grader separates the outcomes")
    parser.add_argument("--store", choices=[s.store for s in STORES], help="which store to take down")
    parser.add_argument("--readiness-url", help="readiness endpoint to read while the store is down")
    parser.add_argument("--dependent-url", action="append", default=[], help="name=url, repeatable")
    parser.add_argument("--settle-seconds", type=float, default=15.0)
    args = parser.parse_args(argv)

    if args.self_test:
        return _self_test()
    if not args.store or not args.readiness_url:
        parser.error("--store and --readiness-url are required unless --self-test")

    expectation = next(s for s in STORES if s.store == args.store)
    if _resolve_container(expectation.container) is None:
        print(
            f"store_outage: container {expectation.container!r} is not running in this stack — "
            "the store is probably behind a compose profile this job did not start "
            "(clickhouse and neo4j live behind `--profile full`). Grading nothing is not a pass."
        )
        return 2
    if not _container_action(expectation.container, "stop"):
        print(f"store_outage: could not stop container {expectation.container!r} — docker unavailable?")
        return 2

    try:
        time.sleep(args.settle_seconds)
        readiness_status, readiness_body = _probe(args.readiness_url)
        readiness = readiness_body or {}
        responding: dict[str, bool] = {}
        for pair in args.dependent_url:
            name, _, url = pair.partition("=")
            responding[name] = _responding(url)
    finally:
        _container_action(expectation.container, "start")

    started = time.monotonic()
    recovered = False
    # Whether the readiness surface ever named the key at all during the
    # recovery poll. An endpoint that never mentions it cannot be used to
    # watch a reconnection, and scoring that silence as recovery is the
    # defect this flag exists to make visible rather than to hide.
    recovery_observable = expectation.readiness_key in readiness
    while time.monotonic() - started < 120:
        _status, probe = _probe(args.readiness_url)
        if probe is not None and expectation.readiness_key in probe:
            recovery_observable = True
            if probe[expectation.readiness_key] in _RECOVERED_VALUES:
                recovered = True
                break
        time.sleep(3)

    result = grade_outage(
        expectation,
        readiness=readiness,
        readiness_status=readiness_status,
        dependents_responding=responding,
        recovered=recovered,
        recovery_observable=recovery_observable,
        recovery_seconds=round(time.monotonic() - started, 1) if recovered else None,
    )
    print(json.dumps(result.as_dict(), indent=2))
    return 0 if result.passed else 1


if __name__ == "__main__":
    sys.exit(main())
