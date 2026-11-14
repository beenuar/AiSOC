#!/usr/bin/env python3
"""Prompt-lock drift gate, and the coverage that makes the lock mean something.

Fails CI when a production prompt's text changed without a version bump + lock
regeneration. This is what makes the AGENTS.md "prompt change ⇒ re-grade the
eval harness" rule enforceable: you cannot quietly edit a prompt.

Why the drift check alone was not enough
----------------------------------------
Phase 8 shipped the registry, this gate and a committed lock, and seeded it
with three prompts. The gate worked. It was simply pointed at almost nothing:
one of the three had a reader, and twenty-one system prompts that a model
actually received were declared inline across eleven modules under
``services/agents/app/``. Every one of those could be reworded with no version
bump, no lock change and therefore no re-grade — the exact hole the registry
was written to close, left open for all but one prompt.

A lock over three prompts, one of which ships, is indistinguishable from the
outside from a lock over the prompts that ship. So the drift check is now
paired with a coverage check, run **in both directions**, because a gate that
only looks one way passes while drift accumulates in the other:

``inline-prompt``
    A module-level string constant that reaches a system-message sink. This
    is the direction that leaves a shipped prompt unpinned. Detected by what
    the constant *is* — text the model receives — rather than by its name:
    the original sweep for ``_SYSTEM_PROMPT`` missed
    ``deep_investigation._SYSTEM_PREAMBLE`` and the ten-prompt
    ``contextual._SYSTEM_PROMPTS`` dict, which is precisely how a
    name-matching gate goes quiet.

``unread-prompt``
    A registered prompt nothing asks for. This is the direction that makes a
    lock look like coverage it does not have: ``summary.system`` was
    hash-pinned for a summariser that does not exist in this service. A pin
    on text nobody sends protects nothing and inflates the count a reader
    trusts.

What counts as a system-message sink
------------------------------------
``SystemMessage(content=…)``, a ``("system", …)`` tuple, ``system=…`` passed
to a call, and a ``{"role": "system", "content": …}`` mapping. Every name
appearing anywhere inside the sink expression counts, including through an
f-string or a ``+`` composition — because ``f"{_PREAMBLE}\n\n{guidance}"`` is
exactly how one of the missed prompts reached the model.

Composition itself is fine and is not a finding. A prompt is routinely
extended at call time with text that is not fixed — a per-run injection
nonce, a per-strategy guidance block — and that addition cannot be
hash-pinned because it does not exist until the run does. What the gate
requires is that the *base* of the composition comes from the registry.

Usage
-----

::

    python3 scripts/check_prompt_lock.py            # gate
    python3 scripts/check_prompt_lock.py --write    # regenerate the lock
    python3 scripts/check_prompt_lock.py --list     # every prompt and its readers
    python3 scripts/check_prompt_lock.py --self-test

Exit codes: 0 clean, 1 findings, 2 the scan itself could not run.
"""

from __future__ import annotations

import argparse
import ast
import contextlib
import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
from pathlib import Path

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_main  # noqa: E402

#: The tree whose prompts are pinned. The registry is the only module in it
#: allowed to hold prompt text.
AGENTS_APP = Path("services") / "agents" / "app"
REGISTRY_REL = AGENTS_APP / "llm" / "prompt_registry.py"

#: Below this a module-level string is a label, a key or a short format
#: fragment rather than a prompt. Deliberately generous: the shortest prompt
#: actually shipped is 193 characters, so this is under it without being so
#: low that every log message becomes a finding.
MIN_PROMPT_CHARS = 150

#: Names whose *prefix* a dynamic lookup may claim. ``contextual.py`` resolves
#: its prompt as ``f"contextual.{page}.{action}"`` from a routing table, so no
#: literal name appears anywhere — and requiring one would push that module
#: back to a dict of inline strings, which is the thing being removed. A
#: prefix credit is printed on every run so it is read rather than trusted.
_DYNAMIC_PREFIX_MIN_SEGMENTS = 1


def _load_prompt_registry_module(root: Path):
    """Load prompt_registry.py by path so we don't trigger app/llm/__init__.py
    (which imports contract → structlog). This gate runs in the dep-light lint
    job, which installs only ruff + mypy; prompt_registry.py is stdlib-only."""
    path = root / REGISTRY_REL
    spec = importlib.util.spec_from_file_location("aisoc_prompt_registry_under_check", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


# ─── Inline-prompt detection ─────────────────────────────────────────────────


def _module_level_strings(tree: ast.Module) -> dict[str, int]:
    """Module-level string constants, and dicts of them, by name → char count."""
    out: dict[str, int] = {}
    for node in tree.body:
        targets: list[str] = []
        value: ast.expr | None = None
        if isinstance(node, ast.Assign):
            targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
            value = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            targets, value = [node.target.id], node.value
        if value is None:
            continue
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            size = len(value.value)
        elif isinstance(value, ast.Dict):
            size = sum(len(v.value) for v in value.values if isinstance(v, ast.Constant) and isinstance(v.value, str))
        else:
            continue
        for name in targets:
            out[name] = max(out.get(name, 0), size)
    return out


def _sink_expressions(tree: ast.Module) -> list[ast.expr]:
    """Every expression whose value becomes a system message."""
    sinks: list[ast.expr] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            for kw in node.keywords:
                if kw.arg == "content" and name == "SystemMessage":
                    sinks.append(kw.value)
                elif kw.arg == "system":
                    sinks.append(kw.value)
        elif isinstance(node, ast.Tuple) and len(node.elts) == 2:
            head = node.elts[0]
            if isinstance(head, ast.Constant) and head.value == "system":
                sinks.append(node.elts[1])
        elif isinstance(node, ast.Dict):
            keys = {k.value for k in node.keys if isinstance(k, ast.Constant)}
            if {"role", "content"} <= keys:
                pairs = dict(zip([getattr(k, "value", None) for k in node.keys], node.values, strict=True))
                role = pairs.get("role")
                if isinstance(role, ast.Constant) and role.value == "system":
                    sinks.append(pairs["content"])
    return sinks


def _names_in(expr: ast.expr) -> set[str]:
    """Every identifier reachable inside an expression, f-strings included."""
    return {n.id for n in ast.walk(expr) if isinstance(n, ast.Name)}


def _carriers(tree: ast.Module, seeds: set[str]) -> set[str]:
    """Names that hold prompt text, following assignment to a fixed point.

    A prompt rarely reaches its sink directly. Three of the eleven found in
    the pre-migration tree went through a local first — ``system =
    f"{_SYSTEM_PREAMBLE}…"``, ``system_prompt = _SYSTEM_PROMPT.format(…)``,
    ``system = _SYSTEM_PROMPTS[key]`` — and a gate that only reads the sink
    expression sees a bare local and reports the tree clean. That is the
    shallow half of a one-directional gate: it passes while the thing it
    exists to catch walks past one hop away.

    Names are followed without regard to scope, which over-approximates: two
    functions using ``system`` for unrelated values would taint both. That
    direction is the safe one — it can only ask for a prompt to be
    registered, never excuse one that is not.
    """
    carriers = set(seeds)
    for _ in range(len(list(ast.walk(tree)))):  # bounded; converges in a few passes
        grew = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                targets, value = node.targets, node.value
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                targets, value = [node.target], node.value
            else:
                continue
            if not (_names_in(value) & carriers):
                continue
            for target in targets:
                for name in ast.walk(target):
                    if isinstance(name, ast.Name) and name.id not in carriers:
                        carriers.add(name.id)
                        grew = True
        if not grew:
            break
    return carriers


def find_inline_prompts(root: Path) -> list[str]:
    """Module-level prompt text that reaches a system message without the registry."""
    findings: list[str] = []
    base = root / AGENTS_APP
    if not base.is_dir():
        return findings
    for path in sorted(base.rglob("*.py")):
        rel = path.relative_to(root)
        if rel == REGISTRY_REL:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        constants = {n: size for n, size in _module_level_strings(tree).items() if size >= MIN_PROMPT_CHARS}
        if not constants:
            continue
        carriers = _carriers(tree, set(constants))
        reached: set[str] = set()
        for sink in _sink_expressions(tree):
            reached |= _names_in(sink) & carriers
        # Report the declaring constant, not whichever local carried it.
        for name in sorted(constants):
            if name in reached or _carriers(tree, {name}) & reached:
                findings.append(
                    f"inline-prompt: {rel}:{name} is {constants[name]} characters of prompt text reaching a "
                    f"system message without passing through the registry. Register it and read it back with "
                    f"prompt_text(), or the next edit ships with no version bump and no eval re-grade"
                )
    return findings


# ─── Reader detection ────────────────────────────────────────────────────────


def find_prompt_readers(root: Path) -> tuple[set[str], set[str]]:
    """Return (literal names asked for, prefixes a dynamic lookup claims)."""
    literals: set[str] = set()
    prefixes: set[str] = set()
    base = root / AGENTS_APP
    if not base.is_dir():
        return literals, prefixes
    for path in sorted(base.rglob("*.py")):
        if path.relative_to(root) == REGISTRY_REL:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if name not in {"prompt_text", "get"} or not node.args:
                continue
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                literals.add(arg.value)
            elif isinstance(arg, ast.JoinedStr):
                # f"contextual.{page}.{action}" — credit the literal head.
                head = arg.values[0] if arg.values else None
                if isinstance(head, ast.Constant) and isinstance(head.value, str):
                    stem = head.value.rstrip(".")
                    if stem.count(".") >= _DYNAMIC_PREFIX_MIN_SEGMENTS - 1 and stem:
                        prefixes.add(stem)
    return literals, prefixes


def find_unread_prompts(registered: list[str], literals: set[str], prefixes: set[str]) -> tuple[list[str], list[str]]:
    """Registered prompts with no reader, and the prefix credits that were used."""
    credits: list[str] = []
    unread: list[str] = []
    for name in registered:
        if name in literals:
            continue
        matched = next((p for p in prefixes if name.startswith(p + ".")), None)
        if matched is not None:
            credits.append(f"prefix-credit: {name} — claimed by a dynamic lookup on '{matched}.*'")
            continue
        unread.append(
            f"unread-prompt: '{name}' is registered and hash-pinned and nothing under {AGENTS_APP} asks for it. "
            f"A pin on text the service never sends is the appearance of coverage, not coverage — give it a "
            f"reader or remove it"
        )
    return unread, credits


# ─── Entry point ─────────────────────────────────────────────────────────────


def run(root: Path, *, show_list: bool = False) -> int:
    try:
        module = _load_prompt_registry_module(root)
    except (FileNotFoundError, AttributeError, AssertionError):
        print(f"REFUSED: {REGISTRY_REL} could not be loaded from {root}; there is no registry to check anything against")
        return 2
    registry = module.default_registry()
    names = registry.names()

    print(f"root: {root}")
    print(f"registry: {len(names)} prompt(s) registered")

    # Non-vacuity. An empty registry and a tree with no agents both produce
    # zero findings, and neither says anything about what ships.
    if not names:
        print("REFUSED: the registry declares no prompts; a clean verdict would describe a registry never parsed")
        return 2
    if not (root / AGENTS_APP).is_dir():
        print(f"REFUSED: {AGENTS_APP} is not present, so no call site could be read")
        return 2

    findings: list[str] = []
    drifts = registry.verify_against_lock(_load_prompt_registry_module(root).load_lock())
    findings += [f"lock-drift: {d}" for d in drifts]

    findings += find_inline_prompts(root)

    literals, prefixes = find_prompt_readers(root)
    unread, credits = find_unread_prompts(names, literals, prefixes)
    findings += unread

    if show_list:
        for name in names:
            where = "literal" if name in literals else next((f"via '{p}.*'" for p in prefixes if name.startswith(p + ".")), "NO READER")
            print(f"  {name:36} v{registry.get(name).version}  {where}")
    for credit in credits:
        print(f"  {credit}")

    if findings:
        print(f"\nFAIL: the prompt lock and the prompts that ship disagree ({len(findings)} finding(s))", file=sys.stderr)
        for finding in findings:
            print(f"  - {finding}", file=sys.stderr)
        print(
            "\nA production prompt changed or is unpinned. Register it in "
            "services/agents/app/llm/prompt_registry.py, bump the version if the text moved, "
            "re-grade the eval harness, then run: python3 scripts/check_prompt_lock.py --write",
            file=sys.stderr,
        )
        return 1

    print(f"\nOK: {len(names)} prompt(s) pinned, each with a reader; no inline system prompt under {AGENTS_APP}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Pin every prompt that ships, and ship every prompt that is pinned.")
    parser.add_argument("--write", action="store_true", help="regenerate the lock from the registry")
    parser.add_argument("--list", dest="show_list", action="store_true", help="print every prompt and where it is read")
    parser.add_argument("--self-test", action="store_true", help="prove the gate fails closed and still detects each violation")
    parser.add_argument("--repo-root", type=Path, default=None, help="the tree to inspect")
    args = parser.parse_args(argv)

    if args.self_test:
        with tempfile.TemporaryDirectory(prefix="aisoc-prompt-lock-") as scratch:
            extra = _injected_cases(Path(scratch))
        return self_test_main(Path(__file__).name, [], extra=extra)

    root = (args.repo_root or repo_root()).resolve()
    if args.write:
        mod = _load_prompt_registry_module(root)
        mod.write_lock(mod.default_registry())
        print("prompt lock regenerated")
        return 0
    return run(root, show_list=args.show_list)


# ─── Self-test ───────────────────────────────────────────────────────────────
#
# A gate that has never failed is not known to work. These inject one
# violation of each rule, plus the near misses that would make the gate a
# nuisance, into scratch trees built around a real copy of the registry.

_REGISTRY_STUB = """
import hashlib, json
from dataclasses import dataclass
from pathlib import Path
LOCK_PATH = Path(__file__).resolve().parent / "prompts.lock.json"
@dataclass(frozen=True)
class Prompt:
    name: str; version: str; text: str
    @property
    def sha256(self): return hashlib.sha256(self.text.encode()).hexdigest()
class PromptRegistry:
    def __init__(self): self._p = {}
    def register(self, n, v, t): self._p[n] = Prompt(n, v, t.strip()); return self._p[n]
    def get(self, n):
        if n not in self._p: raise KeyError(n)
        return self._p[n]
    def names(self): return sorted(self._p)
    def as_lock(self): return {n: {"version": p.version, "sha256": p.sha256} for n, p in sorted(self._p.items())}
    def verify_against_lock(self, lock):
        d = []
        cur = self.as_lock()
        for n, e in cur.items():
            lk = lock.get(n)
            if lk is None: d.append(f"prompt '{n}' missing from the lock")
            elif e["sha256"] != lk.get("sha256"): d.append(f"prompt '{n}' text changed")
        return d
def default_registry():
    reg = PromptRegistry()
    reg.register("a.system", "1", "PROMPT_A")
    return reg
def load_lock():
    return json.loads(LOCK_PATH.read_text()) if LOCK_PATH.exists() else {}
"""

_LOCK = json.dumps({"a.system": {"sha256": hashlib.sha256(b"PROMPT_A").hexdigest(), "version": "1"}}) + "\n"
_READER = 'from app.llm.prompt_registry import prompt_text\n\ndef go():\n    return prompt_text("a.system")\n'
_PROMPT = "X" * (MIN_PROMPT_CHARS + 10)
_LOCK_REL = AGENTS_APP / "llm" / "prompts.lock.json"
_EMPTY_REGISTRY = _REGISTRY_STUB.replace('reg.register("a.system", "1", "PROMPT_A")', "pass")


def _tree(root: Path, extra: dict[str, str]) -> Path:
    files = {
        str(REGISTRY_REL): _REGISTRY_STUB,
        str(_LOCK_REL): _LOCK,
        str(AGENTS_APP / "hunt" / "agent.py"): _READER,
        **extra,
    }
    for rel, body in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)  # noqa: S603
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)  # noqa: S603
    return root


def _verdict(root: Path) -> int:
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return main(["--repo-root", str(root)])


def _injected_cases(scratch: Path) -> list[tuple[str, bool]]:
    inline = f'from langchain_core.messages import SystemMessage\n_P = """{_PROMPT}"""\n\ndef go():\n    return SystemMessage(content=_P)\n'
    fstring = f'_PREAMBLE = """{_PROMPT}"""\n\ndef go(extra):\n    return run(system=f"{{_PREAMBLE}}\\n{{extra}}")\n'
    tuple_sink = f'_P = """{_PROMPT}"""\n\ndef go():\n    return [("system", _P)]\n'
    dict_sink = f'_P = """{_PROMPT}"""\n\ndef go():\n    return [{{"role": "system", "content": _P}}]\n'
    short = '_LABEL = "a short format fragment, not a prompt"\n\ndef go():\n    return SystemMessage(content=_LABEL)\n'
    composed = (
        "from app.llm.prompt_registry import prompt_text\n\n"
        'def go(n):\n    return SystemMessage(content=prompt_text("a.system") + rule(n))\n'
    )
    dynamic = 'from app.llm.prompt_registry import prompt_text\n\ndef go(p, a):\n    return prompt_text(f"a.{p}.{a}")\n'

    return [
        (
            "a tree whose every prompt is registered and read passes",
            _verdict(_tree(scratch / "clean", {})) == 0,
        ),
        (
            "inline-prompt: a module constant reaching SystemMessage(content=…) fails",
            _verdict(_tree(scratch / "inline", {str(AGENTS_APP / "a.py"): inline})) == 1,
        ),
        (
            "inline-prompt: one reaching a system= kwarg through an f-string fails",
            _verdict(_tree(scratch / "fstring", {str(AGENTS_APP / "a.py"): fstring})) == 1,
        ),
        (
            "inline-prompt: one reaching a ('system', …) tuple fails",
            _verdict(_tree(scratch / "tuple", {str(AGENTS_APP / "a.py"): tuple_sink})) == 1,
        ),
        (
            "inline-prompt: one reaching a {'role': 'system'} mapping fails",
            _verdict(_tree(scratch / "dict", {str(AGENTS_APP / "a.py"): dict_sink})) == 1,
        ),
        (
            "a short label reaching a system message is not a prompt",
            _verdict(_tree(scratch / "short", {str(AGENTS_APP / "a.py"): short})) == 0,
        ),
        (
            "composing a registered prompt with a runtime value is not a finding",
            _verdict(_tree(scratch / "composed", {str(AGENTS_APP / "a.py"): composed})) == 0,
        ),
        (
            "unread-prompt: a registered prompt nothing asks for fails",
            _verdict(_tree(scratch / "unread", {str(AGENTS_APP / "hunt" / "agent.py"): "def go():\n    return None\n"})) == 1,
        ),
        (
            "a dynamic f-string lookup credits its namespace rather than reading as unread",
            _verdict(_tree(scratch / "dynamic", {str(AGENTS_APP / "hunt" / "agent.py"): dynamic})) == 0,
        ),
        (
            "lock-drift: registered text that does not match the lock fails",
            _verdict(_tree(scratch / "drift", {str(_LOCK_REL): '{"a.system": {"sha256": "0", "version": "1"}}'})) == 1,
        ),
        (
            "an empty registry is refused rather than called clean",
            _verdict(_tree(scratch / "empty-reg", {str(REGISTRY_REL): _EMPTY_REGISTRY})) == 2,
        ),
    ]


if __name__ == "__main__":
    raise SystemExit(main())
