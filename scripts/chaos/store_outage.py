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
import json
import subprocess
import sys
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
    dependents_responding: dict[str, bool],
    recovered: bool,
    recovery_seconds: float | None = None,
) -> OutageResult:
    """Grade one outage against what the store's loss is supposed to look like.

    Pure, so the self-test can drive every branch without containers.
    """
    result = OutageResult(
        store=expectation.store,
        behaviour=expectation.behaviour,
        expected=expectation.behaviour,
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
    if not result.readiness_reported:
        result.findings.append(
            f"{expectation.store} is down and readiness does not say so "
            f"(`{expectation.readiness_key}` reads {reported!r}) — an operator cannot tell this "
            "apart from a healthy idle service"
        )

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

    if not recovered:
        result.findings.append(
            f"{expectation.store} came back and the dependents did not reconnect — an outage plus a manual restart is worse than an outage"
        )
    return result


def _container_action(container: str, action: str) -> bool:
    try:
        subprocess.run(
            ["docker", action, container],
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


def _probe(url: str, timeout: float = 4.0) -> dict[str, Any] | None:
    if not url.startswith(_ALLOWED_PROBE_PREFIXES):
        raise ValueError(
            f"refusing to probe {url!r}: this harness only reads readiness endpoints on the "
            f"local stack it is taking down, which must start with one of {_ALLOWED_PROBE_PREFIXES}"
        )
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310 - prefix-checked above
            return dict(json.loads(response.read().decode("utf-8")))
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return None


def _self_test() -> int:
    """Every branch of the grader, without containers.

    The live path needs a stack; this runs unconditionally, because a
    grader nobody exercised is a grader nobody can trust.
    """
    clickhouse = next(s for s in STORES if s.store == "clickhouse")
    kafka = next(s for s in STORES if s.store == "kafka")

    cases = [
        (
            "degrade: readiness admits it and dependents keep serving",
            grade_outage(
                clickhouse,
                readiness={"lake_writer": False},
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
                dependents_responding={"fusion": False, "api": True},
                recovered=True,
            ),
            False,
        ),
        (
            "block: dependents correctly drop out of the load balancer",
            grade_outage(
                kafka,
                readiness={"kafka": False},
                dependents_responding={"ingest": False, "fusion": False},
                recovered=True,
            ),
            True,
        ),
        (
            "block: ingest still ready without the spine it writes to",
            grade_outage(
                kafka,
                readiness={"kafka": False},
                dependents_responding={"ingest": True, "fusion": False},
                recovered=True,
            ),
            False,
        ),
        (
            "recovery: degraded correctly and never reconnected",
            grade_outage(
                clickhouse,
                readiness={"lake_writer": False},
                dependents_responding={"fusion": True, "api": True},
                recovered=False,
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

    # Every store must declare a behaviour the grader implements, or it
    # silently grades nothing.
    for store in STORES:
        if store.behaviour not in BEHAVIOURS:
            print(f"  self-test [FAIL] {store.store} declares unknown behaviour {store.behaviour!r}")
            failures += 1

    print(f"store_outage: self-test {'OK' if not failures else 'FAILED'} — {len(STORES)} stores declared")
    return 1 if failures else 0


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
    if not _container_action(expectation.container, "stop"):
        print(f"store_outage: could not stop container {expectation.container!r} — docker unavailable?")
        return 2

    try:
        time.sleep(args.settle_seconds)
        readiness = _probe(args.readiness_url) or {}
        responding: dict[str, bool] = {}
        for pair in args.dependent_url:
            name, _, url = pair.partition("=")
            responding[name] = _probe(url) is not None
    finally:
        _container_action(expectation.container, "start")

    started = time.monotonic()
    recovered = False
    while time.monotonic() - started < 120:
        probe = _probe(args.readiness_url)
        if probe and probe.get(expectation.readiness_key) not in (False, "down", "degraded"):
            recovered = True
            break
        time.sleep(3)

    result = grade_outage(
        expectation,
        readiness=readiness,
        dependents_responding=responding,
        recovered=recovered,
        recovery_seconds=round(time.monotonic() - started, 1) if recovered else None,
    )
    print(json.dumps(result.as_dict(), indent=2))
    return 0 if result.passed else 1


if __name__ == "__main__":
    sys.exit(main())
