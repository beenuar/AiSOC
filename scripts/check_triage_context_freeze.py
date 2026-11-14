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
* the freeze is applied and *published*: **missing here and the freeze is real
  but unaudited, so a reader cannot tell how much of the context was checked**.

Two kinds of freeze
-------------------
Phase 6.3 added sources a snapshot cannot hold, and the gate has to know which
kind each source is or it checks the wrong thing. ``CONTEXT_FREEZE_KINDS`` in
``triage_persistence.py`` declares it, and this gate reads that table rather
than guessing from a name.

``SNAPSHOT``
    The whole set is captured once. ``ContextSnapshot`` holds the store,
    ``capture_context`` filters it against the split, and
    ``ContextSnapshot.as_method_note`` publishes ``<store>_frozen`` and
    ``<store>_dropped_after_split``.

``CUTOFF``
    A per-alert query against a store too large to capture, frozen by an
    ``as_of`` the reader supplies and the server applies. Three properties,
    each with its own silent failure:

    * the protocol method must **not** accept a cutoff from its caller. A
      caller that can pass one is a caller that can forget to, and the replay
      then reads live behind a method note still saying "frozen".
    * ``FrozenTriageContextReader``'s implementation must bind the cutoff to
      ``self._snapshot.split_at``. Passing anything else, or nothing, is a
      live read wearing the frozen reader's name.
    * ``FrozenTriageContextReader.as_method_note`` must publish the same
      ``_frozen`` and ``_dropped_after_split`` pair the snapshot half does. A
      cutoff that matched nothing and a cutoff that threw away fifty rows
      return the same empty list, so the refused count is the only evidence
      the freeze did anything.

What this reads, and in both directions
----------------------------------------
Structurally, with ``ast``. Nothing is imported: these modules pull in httpx,
structlog and the whole worker stack to compare a list of method names.

Forward: a protocol method that either implementation lacks, or that no freeze
kind is declared for.

Reverse, which is the direction that actually drifts: a *snapshot field* that
``capture_context`` does not accept, or that ``as_method_note`` does not
report; a declared freeze kind naming a method the protocol no longer has; a
cutoff store with no counter. A field added to the snapshot and populated by
hand somewhere would otherwise never be filtered against the split, and the
method note would keep printing a confident provenance block that silently
omits it.

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

#: The table in ``triage_persistence.py`` that says how each source is frozen,
#: and the two values it may hold. Read rather than duplicated: a gate with
#: its own copy of the classification would keep passing after the real one
#: changed.
_KIND_TABLE = "CONTEXT_FREEZE_KINDS"
_KIND_SNAPSHOT = "snapshot"
_KIND_CUTOFF = "cutoff"

#: The attribute a cutoff source's frozen implementation must bind its
#: ``as_of`` to. Spelled out because "some attribute of the snapshot" is not
#: the property: ``created_at`` would satisfy a looser check and would not be
#: the split.
_SPLIT_ATTR = "split_at"

#: Parameter names that would let a caller choose a cutoff source's point in
#: time. None may appear on a cutoff protocol method.
_CUTOFF_PARAMS = frozenset({"as_of", "cutoff", "split_at", "since", "before", "at"})

#: The per-store counter names ``FrozenTriageContextReader`` opens, inside the
#: tuple it declares them in. Read from the source so the gate's idea of which
#: cutoff stores exist is the reader's own.
_CUTOFF_STORES_CONST = "_CUTOFF_STORES"

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


def _keyword_params(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    return {arg.arg for arg in (*fn.args.args, *fn.args.kwonlyargs)}


def _method_note_keys(node: ast.ClassDef, relative: str) -> set[str]:
    """Every string key ``as_method_note`` can place in its dict.

    Both literal spellings count. ``ContextSnapshot`` publishes most of its
    keys in one dict and the bypass through a subscript assignment;
    ``FrozenTriageContextReader`` builds ``f"{store}_frozen"`` in a loop, which
    is an f-string rather than a constant, so the suffix is recovered from the
    format spec. A gate that read only constants would report that class as
    publishing nothing and then, worse, could be "fixed" by loosening it.
    """
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
            elif isinstance(sub, ast.Subscript) and isinstance(sub.slice, ast.JoinedStr):
                suffix = _joined_suffix(sub.slice)
                if suffix:
                    keys.add(suffix)
        if not keys:
            raise SystemExit(f"FAIL: {_METHOD_NOTE} in {relative} publishes no keys, so the freeze is unaudited")
        return keys
    raise SystemExit(f"FAIL: {node.name}.{_METHOD_NOTE} was not found in {relative}")


def _joined_suffix(node: ast.JoinedStr) -> str | None:
    """The literal tail of ``f"{store}_frozen"``, as ``_frozen``.

    A key built per store is the only sensible way to write the cutoff half's
    note, and the store name is a loop variable this gate cannot evaluate. The
    suffix is the part that has to be right, and it is a constant.
    """
    tail = node.values[-1] if node.values else None
    if isinstance(tail, ast.Constant) and isinstance(tail.value, str) and tail.value.startswith("_"):
        return tail.value
    return None


def _dict_constant(tree: ast.Module, name: str, relative: str) -> dict[str, str]:
    """A module-level ``dict[str, str]`` literal, read structurally."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.AnnAssign | ast.Assign):
            continue
        targets = [node.target] if isinstance(node, ast.AnnAssign) else node.targets
        if not any(isinstance(t, ast.Name) and t.id == name for t in targets):
            continue
        if not isinstance(node.value, ast.Dict):
            break
        out: dict[str, str] = {}
        for key, value in zip(node.value.keys, node.value.values, strict=True):
            if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                continue
            # Values are the module's own ``SNAPSHOT`` / ``CUTOFF`` names, so
            # resolve one level: a bare string would work too, and both are
            # read here rather than requiring one spelling.
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                out[key.value] = value.value
            elif isinstance(value, ast.Name):
                out[key.value] = _resolve_str_name(tree, value.id) or value.id
        return out
    raise SystemExit(f"FAIL: {name} was not found as a dict literal in {relative}; the freeze kinds are undeclared")


def _resolve_str_name(tree: ast.Module, name: str) -> str | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                return node.value.value
    return None


def _str_tuple(tree: ast.Module, name: str, relative: str) -> tuple[str, ...]:
    for node in ast.walk(tree):
        targets = [node.target] if isinstance(node, ast.AnnAssign) else getattr(node, "targets", [])
        if not isinstance(node, ast.AnnAssign | ast.Assign) or not any(isinstance(t, ast.Name) and t.id == name for t in targets):
            continue
        if isinstance(node.value, ast.Tuple):
            return tuple(e.value for e in node.value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str))
    raise SystemExit(f"FAIL: {name} was not found as a tuple of names in {relative}")


def _awaits_anything(method: ast.AsyncFunctionDef) -> bool:
    """Whether the body awaits, which for a snapshot source means it reaches out.

    This is what stops a freeze kind from being changed to whichever one the
    implementation happens to satisfy. A snapshot source is served from
    memory, so its frozen implementation has nothing to await; reclassifying a
    cutoff source as ``snapshot`` to dodge the ``as_of`` requirement leaves an
    ``await`` behind and is caught here, and reclassifying a snapshot source
    as ``cutoff`` is caught by the ``as_of`` check itself. Without both, the
    table would be a comment rather than a rule.
    """
    return any(isinstance(node, ast.Await) for node in ast.walk(method))


def _binds_split_cutoff(method: ast.AsyncFunctionDef) -> bool:
    """Whether the body passes ``as_of=self.<something>.split_at`` to a call.

    The attribute chain is what makes this a freeze rather than a parameter
    with a suggestive name. ``as_of=datetime.now()`` and ``as_of=None`` both
    parse, both type-check, and both turn a replay into a live read.
    """
    for node in ast.walk(method):
        if not isinstance(node, ast.Call):
            continue
        for keyword in node.keywords:
            if keyword.arg != "as_of":
                continue
            value = keyword.value
            if isinstance(value, ast.Attribute) and value.attr == _SPLIT_ATTR:
                return True
    return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="prove the gate refuses an empty tree")
    parser.parse_args(argv)

    root = repo_root()
    failures: list[str] = []
    checked = 0

    persistence = _module(root, _PERSISTENCE)
    shadow = _module(root, _SHADOW)

    protocol = _class(persistence, _PROTOCOL, _PERSISTENCE)
    protocol_methods = _async_methods(protocol)
    if not protocol_methods:
        raise SystemExit(f"FAIL: {_PROTOCOL} declares no methods, so this gate would certify anything")
    live_methods = _async_methods(_class(persistence, _LIVE, _PERSISTENCE))
    frozen = _class(shadow, _FROZEN, _SHADOW)
    frozen_methods = _async_methods(frozen)
    checked += len(protocol_methods)

    kinds = _dict_constant(persistence, _KIND_TABLE, _PERSISTENCE)
    unknown_kind = sorted(k for k, v in kinds.items() if v not in {_KIND_SNAPSHOT, _KIND_CUTOFF})
    if unknown_kind:
        raise SystemExit(f"FAIL: {_KIND_TABLE} classifies {unknown_kind} as neither {_KIND_SNAPSHOT!r} nor {_KIND_CUTOFF!r}")

    undeclared = sorted(protocol_methods - set(kinds))
    if undeclared:
        failures.append(
            f"{_PROTOCOL} declares {undeclared}, which {_KIND_TABLE} in {_PERSISTENCE} does not classify. "
            f"A context source with no declared freeze kind is one nobody decided how to hold still, and "
            f"this gate cannot tell which half of it to check"
        )
    stale_kind = sorted(set(kinds) - protocol_methods)
    if stale_kind:
        failures.append(
            f"{_KIND_TABLE} in {_PERSISTENCE} classifies {stale_kind}, which {_PROTOCOL} no longer declares. "
            f"A classification for a method that does not exist is a rule nothing is subject to"
        )

    cutoff_methods = sorted(m for m in protocol_methods if kinds.get(m) == _KIND_CUTOFF)
    checked += len(cutoff_methods)
    for name in cutoff_methods:
        declared = next((item for item in protocol.body if isinstance(item, ast.AsyncFunctionDef) and item.name == name), None)
        if declared is not None:
            supplied = sorted(_keyword_params(declared) & _CUTOFF_PARAMS)
            if supplied:
                failures.append(
                    f"{_PROTOCOL}.{name} is a {_KIND_CUTOFF} source and accepts {supplied} from its caller. "
                    f"A caller that can choose the point in time is a caller that can forget to, and the "
                    f"replay then reads live behind a method note that still says frozen"
                )
        implementation = next((item for item in frozen.body if isinstance(item, ast.AsyncFunctionDef) and item.name == name), None)
        if implementation is None:
            # Already reported by the forward check below; not repeated here.
            continue
        if not _binds_split_cutoff(implementation):
            failures.append(
                f"{_FROZEN}.{name} is a {_KIND_CUTOFF} source and does not pass `as_of=<snapshot>.{_SPLIT_ATTR}` "
                f"to anything. Without that the frozen reader queries the live store and the replay measures a "
                f"world the split point does not describe"
            )

    snapshot_methods = sorted(m for m in protocol_methods if kinds.get(m) == _KIND_SNAPSHOT)
    checked += len(snapshot_methods)
    for name in snapshot_methods:
        implementation = next((item for item in frozen.body if isinstance(item, ast.AsyncFunctionDef) and item.name == name), None)
        if implementation is not None and _awaits_anything(implementation):
            failures.append(
                f"{_FROZEN}.{name} is declared a {_KIND_SNAPSHOT} source and awaits something. A snapshot "
                f"source is served from the captured set and has nothing to await, so either it is reaching a "
                f"live store or it is a {_KIND_CUTOFF} source classified as the kind with the weaker check"
            )

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

    # ---- the cutoff half's note -------------------------------------------
    # Same two keys per store, checked the same way and for the same reason.
    # The names are built per store in a loop, so the suffixes rather than the
    # whole keys are what the note is read for; `_joined_suffix` is what makes
    # that readable structurally.
    cutoff_stores = _str_tuple(shadow, _CUTOFF_STORES_CONST, _SHADOW)
    if cutoff_methods and not cutoff_stores:
        failures.append(
            f"{_PROTOCOL} declares {len(cutoff_methods)} {_KIND_CUTOFF} source(s) and {_CUTOFF_STORES_CONST} in "
            f"{_SHADOW} names none, so {_FROZEN} opens no counters and its note publishes nothing about them"
        )
    if cutoff_stores:
        frozen_note_keys = _method_note_keys(frozen, _SHADOW)
        checked += len(cutoff_stores)
        for suffix, why in (
            ("_frozen", "how much context the replay was given"),
            ("_dropped_after_split", "whether the cutoff did anything at all"),
        ):
            if suffix not in frozen_note_keys:
                failures.append(
                    f"{_FROZEN}.{_METHOD_NOTE} does not publish a `<store>{suffix}` key, so a reader cannot "
                    f"tell {why} for the {_KIND_CUTOFF} source(s) {list(cutoff_stores)}. A cutoff that matched "
                    f"nothing and a cutoff that refused fifty rows return the same empty list"
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
        f"them, every one has a declared freeze kind, {len(stores)} snapshot store(s) are each filtered by "
        f"{_CAPTURE} and published by {_SNAPSHOT}.{_METHOD_NOTE}, and {len(cutoff_methods)} cutoff source(s) "
        f"bind their `as_of` to the snapshot's {_SPLIT_ATTR} and are published by {_FROZEN}.{_METHOD_NOTE}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
