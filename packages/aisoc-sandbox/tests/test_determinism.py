"""The sandbox advertises a deterministic reasoner. Prove it across processes.

The reasoner used ``abs(hash(str))`` for related-case counts, entity risk
scores and hunt-match counts. CPython salts string hashing per process, so
every one of those figures changed on each run while three comments in the
source called them deterministic and the README sold the package on it.

That matters beyond tidiness. The sandbox is the reproducible baseline the
evaluation harness rests on, and a baseline that moves is not a baseline:
two runs of the same scenario could not be compared, so a genuine regression
in reasoning was indistinguishable from the hash seed changing.

These tests run the CLI in separate interpreter processes with deliberately
different PYTHONHASHSEED values, which is the only way to catch this — a
single in-process assertion passes even with the salted hash, because the
salt is fixed for a process's lifetime.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import Any

import pytest

SCENARIOS = [
    "lateral-movement",
    "aws-credential-exfil",
    "phishing-payload",
    "kubernetes-privesc",
    "github-token-theft",
]

# Wall-clock fields are expected to differ between runs. Everything else is
# reasoning output and must not.
#
# This was an exact-name list of four fields, none of which the CLI emits: the
# actual field is `elapsed_ms`. So the test compared a timer and failed
# whenever two runs happened to straddle a millisecond boundary — reporting
# "Something in the reasoner depends on salted hashing again", which sends a
# reader to look for a `hash()` call that is not there.
#
# Matched by suffix rather than by name so a newly-added timing field cannot
# reintroduce the flake. Names are the thing that drifts; the `_ms` convention
# is not.
VOLATILE = {"timestamp_utc", "started_at", "finished_at"}
VOLATILE_SUFFIXES = ("_ms", "_seconds", "_at", "_duration")


def _is_volatile(key: str) -> bool:
    return key in VOLATILE or key.endswith(VOLATILE_SUFFIXES)


def _strip_volatile(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _strip_volatile(v) for k, v in value.items() if not _is_volatile(k)}
    if isinstance(value, list):
        return [_strip_volatile(v) for v in value]
    return value


def _run(scenario: str, seed: str) -> dict[str, Any]:
    env = {**os.environ, "PYTHONHASHSEED": seed}
    proc = subprocess.run(
        [sys.executable, "-m", "aisoc_sandbox.cli", "demo", "--scenario", scenario, "--json"],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    return _strip_volatile(json.loads(proc.stdout))


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_reasoning_is_identical_under_different_hash_seeds(scenario: str) -> None:
    """Two processes, two hash seeds, byte-identical reasoning."""
    first = _run(scenario, "1")
    second = _run(scenario, "987654")
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True), (
        f"{scenario} produced different reasoning under a different PYTHONHASHSEED. "
        f"Something in the reasoner depends on salted hashing again — look for "
        f"hash(), set iteration order, or dict ordering derived from one. If the "
        f"only difference is a timer, add its field to VOLATILE instead."
    )


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_synthetic_figures_are_stable(scenario: str) -> None:
    """Pin the specific values that were unstable, not just the whole blob.

    Whole-payload equality would still pass if these fields disappeared.
    """
    first = _run(scenario, "7")
    second = _run(scenario, "424242")

    def figures(payload: dict[str, Any]) -> list[Any]:
        found: list[Any] = []
        for step in payload["ledger"]:
            evidence = step.get("evidence") or {}
            for key in ("related_cases_30d", "rba_entity_risk", "matches_found"):
                if key in evidence:
                    found.append((step["agent"], key, evidence[key]))
        return found

    a, b = figures(first), figures(second)
    assert a, f"{scenario}: none of the synthetic figures were emitted; the test is vacuous"
    assert a == b


def test_stable_int_does_not_use_builtin_hash() -> None:
    """A direct check on the helper, independent of the CLI."""
    from aisoc_sandbox.investigation import _stable_int

    # Known-answer: blake2b-8 of "aisoc" read big-endian. Pinning the value
    # means swapping the digest silently is caught, since scores derived from
    # it would shift for every existing scenario.
    assert _stable_int("aisoc") == 2585458249718371596
    assert _stable_int("aisoc") == _stable_int("aisoc")
    assert _stable_int("a") != _stable_int("b")
    assert _stable_int("") >= 0
