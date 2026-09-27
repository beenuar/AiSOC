#!/usr/bin/env python3
"""A context source a replay cannot freeze makes every replay report unreliable.

Gap-closure Phase 6.2, and the control Phase 6.3 needs before it adds three
more stores.

The property
------------
``app.workers.triage_persistence.TriageContextReader`` is the seam the replay
freeze acts on. A verdict may depend on durable state only through that
protocol, because ``FrozenTriageContextReader`` is what serves the state as it
stood at the split point. A source read any other way is live during a replay
no matter what the snapshot says, and the report then measures a world the
split point does not describe, while looking exactly like one that worked.

Phase 1 shipped that seam with two methods. Phase 6.2 added a third and Phase
6.3 adds more. Each addition is three edits that have to land together, and
each has its own silent failure:

* the protocol declares the method, and ``LiveTriageContextReader`` implements
  it: **missing here and production has no source at all**;
* ``FrozenTriageContextReader`` implements it: **missing here and the reader
  raises mid-replay, or worse, falls through to a live read**;
* ``ContextSnapshot`` holds the store, ``capture_context`` filters it against
  the split, and ``as_method_note`` publishes what it kept and dropped:
  **missing here and the freeze is real but unaudited, so a reader cannot
  tell how much of the context was checked**.

What this reads, and in both directions
----------------------------------------
Structurally, with ``ast``. Nothing is imported: these modules pull in httpx,
structlog and the whole worker stack to compare a list of method names.

Forward: a protocol method that either implementation lacks.

Reverse, which is the direction that actually drifts: a *snapshot field* that
``capture_context`` does not accept, or that ``as_method_note`` does not
report. A field added to the snapshot and populated by hand somewhere would
otherwise never be filtered against the split, and the method note would keep
printing a confident provenance block that silently omits it.

``skills_under_test`` is the one exemption, and it is named rather than
inferred. It is the skill backtest's deliberate bypass of the split, and it is
required to appear in ``as_method_note`` with its caveat precisely because it
is not filtered. The gate checks that too, so the bypass cannot become silent.
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested  # noqa: E402

self_test_if_requested(__file__)

_PERSISTENCE = "services/agents/app/workers/triage_persistence.py"
_SHADOW = "services/agents/app/replay/shadow.py"

_PROTOCOL = "TriageContextReader"
_LIVE = "LiveTriageContextReader"
_FROZEN = "FrozenTriageContextReader"
_SNAPSHOT = "ContextSnapshot"
_CAPTURE = "capture_context"
_METHOD_NOTE = "as_method_note"

#: Snapshot fields that are bookkeeping about the freeze rather than a store
#: it holds. ``split_at`` is the instant itself; the counters are what the
#: method note exists to publish.
_NOT_A_STORE = frozenset(
    {
        "split_at",
        "undated_statements",
        "undated_skills",
        "dropped_statements",
        "dropped_priors",
        "dropped_skills",
    }
)

#: Stores that deliberately bypass the split filter, with the reason. Each
#: must still appear in the method note, because an unfiltered store that is
#: not published is indistinguishable from a leak.
_DELIBERATE_BYPASS = {
    "skills_under_test": (
        "the skill backtest applies a candidate authored after the window on purpose; the method note names and caveats it"
    ),
}


def _module(root: Path, relative: str) -> ast.Module:
    path = root / relative
    if not path.is_file():
        raise SystemExit(f"FAIL: {relative} is missing; the triage context freeze cannot be checked")
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _class(tree: ast.Module, name: str, relative: str) -> ast.ClassDef:
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == name:
            return node
    raise SystemExit(f"FAIL: class {name} was not found in {relative}")


def _async_methods(node: ast.ClassDef) -> set[str]:
    return {item.name for item in node.body if isinstance(item, ast.AsyncFunctionDef) and not item.name.startswith("_")}


def _annotated_fields(node: ast.ClassDef) -> list[str]:
    return [item.target.id for item in node.body if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name)]


def _function(tree: ast.Module, name: str, relative: str) -> ast.FunctionDef:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise SystemExit(f"FAIL: function {name} was not found in {relative}")


def _keyword_params(fn: ast.FunctionDef) -> set[str]:
    return {arg.arg for arg in (*fn.args.args, *fn.args.kwonlyargs)}


def _method_note_keys(node: ast.ClassDef, relative: str) -> set[str]:
    """Every string key ``as_method_note`` can place in its dict."""
    for item in node.body:
        if not isinstance(item, ast.FunctionDef) or item.name != _METHOD_NOTE:
            continue
        keys: set[str] = set()
        for sub in ast.walk(item):
            if isinstance(sub, ast.Dict):
                keys |= {k.value for k in sub.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)}
            # `note["skills_under_test"] = ...` is a subscript assignment, not
            # a dict literal, and reading only literals would miss exactly the
            # conditional half this gate cares most about.
            elif isinstance(sub, ast.Subscript) and isinstance(sub.slice, ast.Constant) and isinstance(sub.slice.value, str):
                keys.add(sub.slice.value)
        if not keys:
            raise SystemExit(f"FAIL: {_METHOD_NOTE} in {relative} publishes no keys, so the freeze is unaudited")
        return keys
    raise SystemExit(f"FAIL: {_SNAPSHOT}.{_METHOD_NOTE} was not found in {relative}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="prove the gate refuses an empty tree")
    parser.parse_args(argv)

    root = repo_root()
    failures: list[str] = []
    checked = 0

    persistence = _module(root, _PERSISTENCE)
    shadow = _module(root, _SHADOW)

    protocol_methods = _async_methods(_class(persistence, _PROTOCOL, _PERSISTENCE))
    if not protocol_methods:
        raise SystemExit(f"FAIL: {_PROTOCOL} declares no methods, so this gate would certify anything")
    live_methods = _async_methods(_class(persistence, _LIVE, _PERSISTENCE))
    frozen_methods = _async_methods(_class(shadow, _FROZEN, _SHADOW))
    checked += len(protocol_methods)

    for label, implemented, relative in (
        (_LIVE, live_methods, _PERSISTENCE),
        (_FROZEN, frozen_methods, _SHADOW),
    ):
        missing = sorted(protocol_methods - implemented)
        if missing:
            failures.append(
                f"{label} in {relative} does not implement {missing}, which {_PROTOCOL} declares. "
                f"A context source the {'frozen' if label == _FROZEN else 'live'} reader lacks is one "
                f"{'a replay cannot freeze' if label == _FROZEN else 'production never reads'}"
            )
    extra = sorted((live_methods & frozen_methods) - protocol_methods)
    if extra:
        failures.append(
            f"{_LIVE} and {_FROZEN} both implement {extra}, which {_PROTOCOL} does not declare. "
            f"A reader method outside the protocol is one the worker reaches by duck typing, so nothing "
            f"requires the next implementation to have it"
        )

    snapshot = _class(shadow, _SNAPSHOT, _SHADOW)
    stores = [f for f in _annotated_fields(snapshot) if f not in _NOT_A_STORE]
    if not stores:
        raise SystemExit(f"FAIL: {_SNAPSHOT} holds no stores, so this gate would certify anything")
    capture_params = _keyword_params(_function(shadow, _CAPTURE, _SHADOW))
    note_keys = _method_note_keys(snapshot, _SHADOW)
    checked += len(stores)

    for store in stores:
        if store not in capture_params:
            failures.append(
                f"{_SNAPSHOT}.{store} is a store that {_CAPTURE} does not accept, so nothing filters it "
                f"against the split and a replay would read it as whatever the caller built by hand"
            )
        if store in _DELIBERATE_BYPASS:
            if store not in note_keys:
                failures.append(
                    f"{_SNAPSHOT}.{store} bypasses the split filter ({_DELIBERATE_BYPASS[store]}) and "
                    f"{_METHOD_NOTE} does not publish it. An unfiltered store nobody is told about is "
                    f"indistinguishable from a leak"
                )
            continue
        # Exact key names rather than a substring search over the note. A
        # loose match passes on a neighbouring key: dropping `skills_frozen`
        # while `skills_dropped_after_split` remains leaves a note that says
        # what was thrown away and never says what was kept, and an
        # "anything mentioning skills" test reports that clean. Proven by
        # injecting exactly that removal.
        for suffix, why in (
            ("frozen", "how much context the replay was given"),
            ("dropped_after_split", "whether the freeze did anything at all"),
        ):
            if f"{store}_{suffix}" not in note_keys:
                failures.append(
                    f"{_METHOD_NOTE} does not publish `{store}_{suffix}`, so a reader cannot tell {why} for {_SNAPSHOT}.{store}"
                )

    if not checked:
        print("FAIL: the gate compared nothing, which is indistinguishable from a clean result")
        return 1

    if failures:
        print(f"FAIL: {len(failures)} triage-context-freeze problem(s)\n")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print(
        f"OK: {_PROTOCOL} declares {len(protocol_methods)} context source(s), both readers implement all of "
        f"them, and {len(stores)} snapshot store(s) are each filtered by {_CAPTURE} and published by "
        f"{_METHOD_NOTE}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
