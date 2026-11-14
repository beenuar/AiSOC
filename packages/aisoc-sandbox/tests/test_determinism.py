"""The sandbox advertises deterministic output. Prove it across processes.

It once used ``abs(hash(str))`` for related-case counts, entity risk scores
and hunt-match counts. CPython salts string hashing per process, so every
one of those figures changed on each run while three comments in the source
called them deterministic and the README sold the package on it.

That matters beyond tidiness. The sandbox is the reproducible baseline the
evaluation harness rests on, and a baseline that moves is not a baseline:
two runs of the same scenario could not be compared, so a genuine regression
was indistinguishable from the hash seed changing.

These tests run the CLI in separate interpreter processes with deliberately
different PYTHONHASHSEED values, which is the only way to catch this — a
single in-process assertion passes even with the salted hash, because the
salt is fixed for a process's lifetime.

A note on what is being stabilised, because it changed
------------------------------------------------------
Those three figures are gone. They were hash-derived integers published
under an ``evidence`` key — a fabricated related-case count is not improved
by being reproducibly fabricated, and stabilising one was always the lesser
half of the problem. ``_stable_int`` went with them, so the known-answer
test that pinned its digest went too: a helper with no callers is not worth
a guard, and the cross-process comparison below is the guard that actually
holds the property.

What this file now pins is the arithmetic in ``aisoc_sandbox.signals`` —
distances, elapsed times, implied speeds. Those are real measurements, and
a demo whose measurements move between runs is no more usable as a baseline
than one whose inventions did.
"""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path
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
def test_computed_figures_are_stable(scenario: str) -> None:
    """Pin the numbers themselves, not just the whole blob.

    Whole-payload equality above would still pass if every figure
    disappeared, which is why this looks for them by name and refuses a
    run that emitted none.
    """

    first = _run(scenario, "7")
    second = _run(scenario, "424242")

    def figures(payload: dict[str, Any]) -> list[Any]:
        found: list[Any] = []
        for step in payload["ledger"]:
            for signal in (step.get("evidence") or {}).get("signals") or []:
                found.append((signal["name"], signal["status"], sorted(signal["inputs"].items(), key=str)))
        return found

    a, b = figures(first), figures(second)
    assert a, f"{scenario}: no signal inputs were emitted at all; this comparison is vacuous"
    assert any(status != "not_computable" for _, status, _ in a), (
        f"{scenario}: every signal was not_computable, so no arithmetic was exercised"
    )
    assert a == b


def test_no_module_derives_a_published_figure_from_a_hash() -> None:
    """The guard that outlived ``_stable_int``, stated structurally.

    The original defect was ``abs(hash(...))`` feeding an evidence chip;
    the fix at the time was a blake2b helper, and the real fix was
    deleting the fabricated figures. Either way a hash has no business
    producing a number this package prints, so the package is asserted
    not to contain one rather than one helper being pinned by digest.
    """

    package = Path(__file__).resolve().parent.parent / "src" / "aisoc_sandbox"
    offenders: list[str] = []
    for module in sorted(package.glob("*.py")):
        tree = ast.parse(module.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "hash":
                offenders.append(f"{module.name}:{node.lineno} calls builtin hash()")
            if isinstance(node, ast.Import) and any(alias.name in {"hashlib", "random"} for alias in node.names):
                offenders.append(f"{module.name}:{node.lineno} imports {', '.join(a.name for a in node.names)}")
            if isinstance(node, ast.ImportFrom) and node.module in {"hashlib", "random"}:
                offenders.append(f"{module.name}:{node.lineno} imports from {node.module}")
    assert not offenders, "a published figure could be derived from a hash or an RNG: " + "; ".join(offenders)
