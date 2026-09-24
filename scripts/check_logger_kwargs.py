#!/usr/bin/env python3
"""Refuse a stdlib logger called with a structlog keyword.

`logging.Logger.warning(msg, *args, **kwargs)` accepts exactly four keywords —
`exc_info`, `stack_info`, `stacklevel`, `extra`. Anything else is a
`TypeError`. structlog's bound logger accepts arbitrary keywords and turns
them into the event dict, and both libraries are used in this tree, so
`logger.warning("thing.failed", reason=exc.reason)` is correct in one module
and raises in the next. The two are indistinguishable by eye: the call site
looks identical, and only the binding three hundred lines up decides.

The reason this needs a gate rather than a grep is *where* it hides. #818
found five of these, all in the handler for a refused LLM prompt. An
exception raised inside an `except` block is not caught by a sibling handler,
so the `except Exception` underneath never saw it: the one path whose entire
job was to degrade gracefully was the only path that raised. One of the five
even carried a comment explaining the log line existed because the handler
used to fail silently — the fix for the silent failure was itself throwing.

That is the general shape. A misused keyword on the happy path is found by
the first person to run the code. The same keyword in an exception handler, a
`finally`, or a fallback branch runs only when something has already gone
wrong, converts a handled error into an unhandled one, and is invisible until
the day it matters. So the report sorts by context, and names how many of the
findings sit on a path that only executes when something else already broke.

Deciding stdlib vs structlog is the whole problem, and the parser is written
assuming it has a blind spot:

  * every binding is tracked, not the name `logger` — `LOG`, `log`, `_log`
    and `self._logger` are all in the tree;
  * `from app.core.logging import get_logger` is resolved to the defining
    module and re-asked, because both in-repo `get_logger` helpers return
    structlog while their *name* says nothing;
  * a name rebound later in the module takes the later flavour;
  * a `**kwargs` splat onto a stdlib logger cannot be decided statically, so
    it is reported separately rather than counted as clean;
  * `logging.warning(...)` module-level calls are checked too, since the
    root logger has the same signature.

Three shapes were added after the first version reported a clean tree and the
shapes were then found *in* that tree, which is the only reason to believe
any of the rest works. `logging.getLogger(__name__).warning(...)` with no
intermediate binding is used in `detection_proposals.py`; a class-body
`logger = logging.getLogger(...)` reached later as `self.logger` is used in
`core/config.py`; and an annotation (`x: logging.Logger`, including a
parameter) settles the flavour with no factory call in sight. All three were
invisible to a scanner that only looked at assignments of a name.

Unresolved bindings are reported as `unknown`, never as clean. A scanner that
silently drops what it could not classify is the failure mode this repository
keeps rediscovering — a gate that matched a tool name inside quoted strings
and printed OK about the exact gap it existed to find.

Usage:
    python scripts/check_logger_kwargs.py
    python scripts/check_logger_kwargs.py --self-test
    python scripts/check_logger_kwargs.py --show-unknown
"""

from __future__ import annotations

import argparse
import ast
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

# `logging.Logger._log` forwards exactly these. Everything else is a TypeError.
STDLIB_KWARGS = frozenset({"exc_info", "stack_info", "stacklevel", "extra"})

# Methods a stdlib Logger actually has. structlog adds `msg`, `failure` and
# friends; calling those on a stdlib logger is an AttributeError, which is a
# different defect and not one this gate claims to find.
LOG_METHODS = frozenset({"debug", "info", "warning", "warn", "error", "exception", "critical", "fatal", "log"})

STDLIB = "stdlib"
STRUCTLOG = "structlog"

# Factories, as (module, attribute). The module part is matched against the
# alias actually imported, so `import logging as pylog` still resolves.
_STDLIB_FACTORIES = {("logging", "getLogger"), ("logging", "Logger"), ("logging", "LoggerAdapter"), ("logging", "getLoggerClass")}
_STRUCTLOG_FACTORIES = {
    ("structlog", "get_logger"),
    ("structlog", "getLogger"),
    ("structlog", "wrap_logger"),
    ("structlog.stdlib", "get_logger"),
    ("structlog.stdlib", "BoundLogger"),
}

# An annotation settles the flavour with no factory call in sight, which is
# the only evidence available when a logger arrives as a parameter.
_STDLIB_ANNOTATIONS = {"logging.Logger", "logging.LoggerAdapter", "Logger", "LoggerAdapter"}
_STRUCTLOG_ANNOTATIONS = {
    "structlog.BoundLogger",
    "structlog.stdlib.BoundLogger",
    "structlog.types.FilteringBoundLogger",
    "BoundLogger",
    "FilteringBoundLogger",
}

# Methods that return another logger of the same flavour. `bind` is how every
# structlog call site in this tree narrows a logger, and `getChild` is its
# stdlib counterpart — without them a chained receiver is unresolved, and an
# unresolved receiver is one this gate cannot speak for.
_REBINDING_METHODS = frozenset({"bind", "new", "unbind", "try_unbind", "getChild"})

# Modules whose members collide with a log method name. `math.log` and
# `warnings.warn` are not loggers, and counting them as unresolved makes the
# unresolved bucket look worse than it is.
_NOT_LOGGING_MODULES = frozenset({"math", "cmath", "numpy", "np", "warnings", "statistics"})

_SKIP_DIRS = frozenset({"node_modules", ".venv", "venv", "site-packages", "__pycache__", ".git", "dist", "build"})
# The archived prototype. CodeQL already carries the same exclusion, and the
# project rules forbid editing anything under it, so a finding there is not
# actionable.
_SKIP_PREFIXES = ("plans/",)


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    binding: str
    method: str
    keywords: tuple[str, ...]
    context: str  # "except", "finally", "handler-adjacent" or "normal"
    kind: str  # "stdlib-kwarg" or "unknown-splat"

    def describe(self) -> str:
        where = "" if self.context == "normal" else f" [inside {self.context}]"
        kw = ", ".join(f"{k}=" for k in self.keywords)
        return f"{self.path}:{self.line}: {self.binding}.{self.method}({kw}…){where}"


def repo_root() -> Path:
    """The repository, per git — not per this file's location.

    A sibling gate resolved its root from ``Path(__file__).parent.parent`` and
    would have printed a confident OK about a tree it never opened, because a
    copy of the script run from anywhere else scans whatever happens to sit
    two levels above it.
    """
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
        cwd=Path(__file__).resolve().parent,
    )
    if out.returncode == 0 and out.stdout.strip():
        return Path(out.stdout.strip()).resolve()
    return Path(__file__).resolve().parent.parent


def python_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*.py"):
        rel = path.relative_to(root).as_posix()
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if rel.startswith(_SKIP_PREFIXES):
            continue
        files.append(path)
    return sorted(files)


def _dotted(node: ast.expr) -> str | None:
    """`a.b.c` -> "a.b.c", for Name/Attribute chains only."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


def _class_bodies(tree: ast.Module) -> set[int]:
    """`id()` of every statement sitting directly in a class body."""
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            ids.update(id(stmt) for stmt in node.body)
    return ids


def _tree_root(path: Path, root: Path) -> Path:
    """Nearest ancestor holding a pyproject.toml — the import root for `app.*`."""
    for parent in [path.parent, *path.parent.parents]:
        if (parent / "pyproject.toml").is_file():
            return parent
        if parent == root:
            break
    return root


class _ModuleScan:
    """Logger flavours bound in one module, plus every logging call site."""

    def __init__(self, path: Path, root: Path, resolver: _Resolver) -> None:
        self.path = path
        self.root = root
        self.resolver = resolver
        self.rel = path.relative_to(root).as_posix()
        # alias -> canonical module, e.g. {"logging": "logging", "sl": "structlog"}
        self.module_aliases: dict[str, str] = {}
        # bare name -> (module, attr), e.g. {"getLogger": ("logging", "getLogger")}
        self.name_imports: dict[str, tuple[str, str]] = {}
        # binding -> STDLIB | STRUCTLOG | None
        self.flavours: dict[str, str | None] = {}
        self.exports: dict[str, str | None] = {}

    # -- imports ---------------------------------------------------------
    def collect_imports(self, tree: ast.Module) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.module_aliases[alias.asname or alias.name.split(".")[0]] = alias.name
            elif isinstance(node, ast.ImportFrom):
                module = self._absolute_module(node)
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    self.name_imports[alias.asname or alias.name] = (module, alias.name)

    def _absolute_module(self, node: ast.ImportFrom) -> str:
        if not node.level:
            return node.module or ""
        # Relative import: walk up from this file's package.
        pkg = self.path.parent
        for _ in range(node.level - 1):
            pkg = pkg.parent
        tree_root = _tree_root(self.path, self.root)
        try:
            base = pkg.relative_to(tree_root).as_posix().replace("/", ".")
        except ValueError:
            base = ""
        return f"{base}.{node.module}" if node.module else base

    # -- flavour of an expression ---------------------------------------
    def flavour_of_call(self, call: ast.Call) -> str | None:
        target = call.func
        # `logger.bind(...)` / `logger.getChild(...)` — same logger, narrowed.
        if isinstance(target, ast.Attribute) and target.attr in _REBINDING_METHODS:
            inner = self.flavour_of_expr(target.value)
            if inner is not None:
                return inner
        dotted = _dotted(target)
        if dotted is None:
            return None
        head, _, tail = dotted.rpartition(".")
        if head:
            # `logging.getLogger(...)` / `structlog.stdlib.get_logger(...)`
            root_alias, _, rest = head.partition(".")
            canonical = self.module_aliases.get(root_alias, root_alias)
            module = f"{canonical}.{rest}" if rest else canonical
            if (module, tail) in _STDLIB_FACTORIES:
                return STDLIB
            if (module, tail) in _STRUCTLOG_FACTORIES:
                return STRUCTLOG
            return None
        # A bare call: `get_logger(...)` / `getLogger(...)`.
        imported = self.name_imports.get(tail)
        if imported is None:
            return None
        module, original = imported
        if (module, original) in _STDLIB_FACTORIES:
            return STDLIB
        if (module, original) in _STRUCTLOG_FACTORIES:
            return STRUCTLOG
        # Defined somewhere in this repository — go and read it.
        return self.resolver.flavour_of_export(module, original, self.path)

    def flavour_of_expr(self, node: ast.expr) -> str | None:
        """Flavour of any receiver expression: a name, an attribute, or a call."""
        if isinstance(node, ast.Call):
            return self.flavour_of_call(node)
        dotted = _dotted(node)
        if dotted is None:
            return None
        if dotted.partition(".")[0] in _NOT_LOGGING_MODULES:
            return None
        return self.flavours.get(dotted)

    def flavour_of_annotation(self, annotation: ast.expr | None) -> str | None:
        dotted = _dotted(annotation) if annotation is not None else None
        if dotted is None and isinstance(annotation, ast.Constant) and isinstance(annotation.value, str):
            dotted = annotation.value.strip().strip("\"'")  # `from __future__ import annotations` string form
        if dotted is None:
            return None
        if dotted in _STDLIB_ANNOTATIONS:
            return STDLIB
        if dotted in _STRUCTLOG_ANNOTATIONS:
            return STRUCTLOG
        return None

    def collect_bindings(self, tree: ast.Module) -> None:
        """Every binding that resolves to a logger, anywhere in the module.

        Deliberately not restricted to module scope or to the name `logger`:
        this tree binds `LOG`, `log`, `_log` and `self._logger`, and a
        function-local logger is exactly as capable of raising.
        """
        in_class = _class_bodies(tree)
        for node in ast.walk(tree):
            # A parameter annotated as a logger is the only evidence there is
            # when the logger is handed in rather than created.
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                args = node.args
                for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg]:
                    if arg is None:
                        continue
                    flavour = self.flavour_of_annotation(arg.annotation)
                    if flavour is not None:
                        self.flavours.setdefault(arg.arg, flavour)
                continue

            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            value = node.value
            flavour = self.flavour_of_call(value) if isinstance(value, ast.Call) else None
            if flavour is None and isinstance(node, ast.AnnAssign):
                flavour = self.flavour_of_annotation(node.annotation)
            if flavour is None:
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                name = self._binding_name(target)
                if not name:
                    continue
                # A later rebinding wins, which is what the interpreter does.
                self.flavours[name] = flavour
                if "." not in name:
                    self.exports[name] = flavour
                    # A class-body logger is reached through the instance, and
                    # `self.logger` is a different string from `logger`.
                    if id(node) in in_class:
                        self.flavours[f"self.{name}"] = flavour
                        self.flavours[f"cls.{name}"] = flavour

    @staticmethod
    def _binding_name(target: ast.expr) -> str | None:
        if isinstance(target, ast.Name):
            return target.id
        if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
            return f"{target.value.id}.{target.attr}"
        return None

    def resolve_imported_bindings(self) -> None:
        """`from app.core.logging import logger` inherits that module's flavour."""
        for local, (module, original) in self.name_imports.items():
            if local in self.flavours or not module:
                continue
            flavour = self.resolver.flavour_of_export(module, original, self.path)
            if flavour is not None:
                self.flavours[local] = flavour


class _Resolver:
    """Answers "what flavour is `module.name`?" by reading the defining file."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self._cache: dict[tuple[str, str], str | None] = {}
        self._inflight: set[tuple[str, str]] = set()

    def module_path(self, module: str, importer: Path) -> Path | None:
        if not module:
            return None
        rel = module.replace(".", "/")
        bases = [_tree_root(importer, self.root), self.root]
        for base in bases:
            for candidate in (base / f"{rel}.py", base / rel / "__init__.py"):
                if candidate.is_file():
                    return candidate
        return None

    def flavour_of_export(self, module: str, name: str, importer: Path) -> str | None:
        key = (module, name)
        if key in self._cache:
            return self._cache[key]
        if key in self._inflight:  # import cycle — give up rather than recurse
            return None
        path = self.module_path(module, importer)
        if path is None:
            return None
        self._inflight.add(key)
        try:
            scan = scan_module(path, self.root, self)
            flavour = None
            if scan is not None:
                flavour = scan.exports.get(name)
                if flavour is None:
                    flavour = self._flavour_of_function_return(path, name, scan)
            self._cache[key] = flavour
            return flavour
        finally:
            self._inflight.discard(key)

    def _flavour_of_function_return(self, path: Path, name: str, scan: _ModuleScan) -> str | None:
        """`def get_logger(...): return structlog.get_logger(name)`.

        Both in-repo `get_logger` helpers are this shape, and their names say
        nothing about which library they wrap — which is the point.
        """
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):
            return None
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or node.name != name:
                continue
            for inner in ast.walk(node):
                if isinstance(inner, ast.Return) and isinstance(inner.value, ast.Call):
                    flavour = scan.flavour_of_call(inner.value)
                    if flavour is not None:
                        return flavour
        return None


_SCAN_CACHE: dict[Path, _ModuleScan | None] = {}


def scan_module(path: Path, root: Path, resolver: _Resolver) -> _ModuleScan | None:
    if path in _SCAN_CACHE:
        return _SCAN_CACHE[path]
    _SCAN_CACHE[path] = None  # cycle guard while we parse
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, ValueError):
        return None
    scan = _ModuleScan(path, root, resolver)
    scan.collect_imports(tree)
    scan.collect_bindings(tree)
    _SCAN_CACHE[path] = scan
    return scan


def _context_map(tree: ast.Module) -> dict[int, str]:
    """Line -> the most-defensive enclosing construct.

    `except` beats `finally` beats a `try` body, because a keyword error
    inside an `except` clause replaces the exception being handled and cannot
    be caught by a sibling handler — that is the case worth naming first.
    """
    marks: dict[int, str] = {}

    def mark(body: list[ast.stmt], label: str) -> None:
        for stmt in body:
            for node in ast.walk(stmt):
                line = getattr(node, "lineno", None)
                if line is not None and marks.get(line) not in ("except",):
                    marks[line] = label

    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            mark(node.finalbody, "finally")
            mark(node.orelse, "try/else")
            for handler in node.handlers:
                mark(handler.body, "except")
    return marks


def scan_file(path: Path, root: Path, resolver: _Resolver, tally: dict[str, int] | None = None) -> list[Finding]:
    scan = scan_module(path, root, resolver)
    if scan is None:
        if tally is not None:
            tally["unparseable"] += 1
        return []
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, ValueError):
        if tally is not None:
            tally["unparseable"] += 1
        return []
    scan.resolve_imported_bindings()
    contexts = _context_map(tree)

    # Module-level `logging.warning(...)` hits the root logger, same signature.
    root_logger_aliases = {alias for alias, module in scan.module_aliases.items() if module == "logging"}

    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        method = node.func.attr
        if method not in LOG_METHODS:
            continue
        receiver = node.func.value
        if isinstance(receiver, ast.Call):
            # `logging.getLogger(__name__).warning(...)` — no binding to look
            # up, and the shape is in this tree. A scanner that only reads
            # assignments never sees it.
            binding = f"{_dotted(receiver.func) or '<expr>'}(…)"
            flavour: str | None = scan.flavour_of_call(receiver)
        else:
            binding = _dotted(receiver) or ""
            if not binding:
                continue
            if binding.partition(".")[0] in _NOT_LOGGING_MODULES:
                continue  # `math.log`, `warnings.warn` — not loggers
            flavour = STDLIB if binding in root_logger_aliases else scan.flavours.get(binding)
        if tally is not None:
            tally[flavour or "unresolved"] += 1
        if flavour != STDLIB:
            continue
        bad = tuple(sorted(kw.arg for kw in node.keywords if kw.arg and kw.arg not in STDLIB_KWARGS))
        splat = any(kw.arg is None for kw in node.keywords)
        context = contexts.get(node.lineno, "normal")
        if bad:
            findings.append(Finding(scan.rel, node.lineno, binding, method, bad, context, "stdlib-kwarg"))
        elif splat:
            findings.append(Finding(scan.rel, node.lineno, binding, method, ("**kwargs",), context, "unknown-splat"))
    return findings


def run(root: Path, show_unknown: bool = False) -> int:
    files = python_files(root)
    resolver = _Resolver(root)
    _SCAN_CACHE.clear()

    errors: list[Finding] = []
    unknown: list[Finding] = []
    tally: dict[str, int] = defaultdict(int)
    for path in files:
        for finding in scan_file(path, root, resolver, tally):
            (errors if finding.kind == "stdlib-kwarg" else unknown).append(finding)

    print(f"check_logger_kwargs: root {root}")
    print(f"  scanned {len(files)} Python file(s) (plans/ excluded)")
    # "No findings" and "resolved nothing" print the same word otherwise, and
    # the second is how a gate certifies a gap it never looked at.
    print(
        f"  classified {tally[STDLIB] + tally[STRUCTLOG] + tally['unresolved']} logging call(s): "
        f"{tally[STDLIB]} stdlib, {tally[STRUCTLOG]} structlog, {tally['unresolved']} unresolved receiver(s)"
    )
    if tally[STDLIB] == 0:
        print("check_logger_kwargs: FAIL — classified no stdlib logger at all, so a clean result would be vacuous")
        return 1

    if unknown:
        print(f"  {len(unknown)} call(s) splat **kwargs onto a stdlib logger and cannot be decided statically")
        if show_unknown:
            for finding in unknown:
                print(f"    - {finding.describe()}")

    if not errors:
        print("check_logger_kwargs: OK — no stdlib logger is called with a structlog keyword")
        return 0

    defensive = [f for f in errors if f.context != "normal"]
    print("check_logger_kwargs: FAIL")
    print(f"  {len(errors)} stdlib logger call(s) pass a keyword the stdlib Logger will reject with TypeError")
    print(f"  {len(defensive)} of them sit on a path that only runs when something has already gone wrong")
    for finding in sorted(errors, key=lambda f: (f.context == "normal", f.path, f.line)):
        print(f"    - {finding.describe()}")
    print("  Fix by folding the value into the message (%-style), or bind a structlog logger if that is what was meant.")
    return 1


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

_FIXTURES: dict[str, str] = {
    # A structlog-flavoured helper, imported by two of the cases below. Its
    # name says nothing about which library it wraps, which is the point.
    "pkg/shared_logging.py": (
        "import structlog\n\n\ndef get_logger(name):\n    return structlog.get_logger(name)\n\n\nlogger = structlog.get_logger()\n"
    ),
    "pkg/stdlib_logging.py": ("import logging\n\nlogger = logging.getLogger(__name__)\n"),
}

_CASES: list[tuple[str, str, bool]] = [
    (
        "stdlib logger with a structlog keyword",
        "import logging\nlogger = logging.getLogger(__name__)\nlogger.warning('x.failed', reason='r')\n",
        True,
    ),
    (
        "the same keyword inside an except block",
        "import logging\nlogger = logging.getLogger(__name__)\n"
        "try:\n    pass\nexcept ValueError as exc:\n    logger.warning('x.refused', reason=str(exc))\n",
        True,
    ),
    (
        "structlog logger with the same keyword",
        "import structlog\nlogger = structlog.get_logger()\nlogger.warning('x.failed', reason='r')\n",
        False,
    ),
    (
        "stdlib logger with keywords the stdlib accepts",
        "import logging\nlogger = logging.getLogger(__name__)\nlogger.error('boom', exc_info=True, extra={'a': 1}, stacklevel=2)\n",
        False,
    ),
    (
        "stdlib logger, %-style positional",
        "import logging\nlogger = logging.getLogger(__name__)\nlogger.warning('x.failed reason=%s', 'r')\n",
        False,
    ),
    (
        "binding is not called `logger`",
        "import logging\nLOG = logging.getLogger(__name__)\nLOG.info('x', count=1)\n",
        True,
    ),
    (
        "logger on self, bound in __init__",
        "import logging\n\n\nclass C:\n    def __init__(self):\n        self._log = logging.getLogger(__name__)\n\n"
        "    def go(self):\n        self._log.error('x', code=1)\n",
        True,
    ),
    (
        "aliased logging module",
        "import logging as pylog\nlogger = pylog.getLogger(__name__)\nlogger.warning('x', reason='r')\n",
        True,
    ),
    (
        "from-imported getLogger",
        "from logging import getLogger\nlogger = getLogger(__name__)\nlogger.warning('x', reason='r')\n",
        True,
    ),
    (
        "root logger via the module",
        "import logging\nlogging.warning('x', reason='r')\n",
        True,
    ),
    (
        "logger imported from a structlog-flavoured module",
        "from pkg.shared_logging import logger\nlogger.warning('x', reason='r')\n",
        False,
    ),
    (
        "logger imported from a stdlib-flavoured module",
        "from pkg.stdlib_logging import logger\nlogger.warning('x', reason='r')\n",
        True,
    ),
    (
        "in-repo get_logger that returns structlog",
        "from pkg.shared_logging import get_logger\nlogger = get_logger(__name__)\nlogger.warning('x', reason='r')\n",
        False,
    ),
    (
        "rebound to stdlib after a structlog binding",
        "import logging\nimport structlog\nlogger = structlog.get_logger()\n"
        "logger = logging.getLogger(__name__)\nlogger.warning('x', reason='r')\n",
        True,
    ),
    (
        "an unrelated object with a .error method",
        "class R:\n    def error(self, msg, **kw):\n        pass\n\n\nresponse = R()\nresponse.error('x', reason='r')\n",
        False,
    ),
    # The three shapes the first version of this scanner could not see. Each
    # exists in the repository, which is why they are here.
    (
        "inline factory call as the receiver",
        "import logging as _logging\n_logging.getLogger(__name__).warning('x', reason='r')\n",
        True,
    ),
    (
        "inline structlog factory as the receiver",
        "import structlog\nstructlog.get_logger(__name__).warning('x', reason='r')\n",
        False,
    ),
    (
        "class-body logger reached through self",
        "import logging\n\n\nclass C:\n    logger = logging.getLogger('c')\n\n"
        "    def go(self):\n        self.logger.warning('x', reason='r')\n",
        True,
    ),
    (
        "logger handed in as an annotated parameter",
        "import logging\n\n\ndef go(logger: logging.Logger) -> None:\n    logger.warning('x', reason='r')\n",
        True,
    ),
    (
        "structlog logger handed in as an annotated parameter",
        "import structlog\n\n\ndef go(logger: structlog.BoundLogger) -> None:\n    logger.warning('x', reason='r')\n",
        False,
    ),
    (
        "annotated attribute with no factory call",
        "import logging\n\n\nclass C:\n    log: logging.Logger\n\n    def go(self):\n        self.log.error('x', code=1)\n",
        True,
    ),
    (
        "structlog logger narrowed with .bind()",
        "import structlog\nlogger = structlog.get_logger()\nlog = logger.bind(a=1)\nlog.warning('x', reason='r')\n",
        False,
    ),
    (
        "stdlib logger narrowed with .getChild()",
        "import logging\nlogger = logging.getLogger(__name__)\nchild = logger.getChild('sub')\nchild.warning('x', reason='r')\n",
        True,
    ),
    (
        "math.log is not a logger",
        "import math\nmath.log(2.0)\n",
        False,
    ),
]


def self_test() -> int:
    import tempfile

    failures: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "pkg").mkdir()
        (root / "pyproject.toml").write_text("[tool.stub]\n", encoding="utf-8")
        for rel, body in _FIXTURES.items():
            (root / rel).write_text(body, encoding="utf-8")

        for index, (name, source, should_flag) in enumerate(_CASES):
            case = root / f"case_{index}.py"
            case.write_text(source, encoding="utf-8")
            _SCAN_CACHE.clear()
            found = [f for f in scan_file(case, root, _Resolver(root)) if f.kind == "stdlib-kwarg"]
            case.unlink()
            ok = bool(found) == should_flag
            if not ok:
                failures.append(f"{name}: expected {'a finding' if should_flag else 'no finding'}, got {[f.describe() for f in found]}")
            print(f"  self-test [{'ok' if ok else 'FAIL'}] {name}")

        # The context labeller must actually label, or the "how many are on a
        # path that only runs when something already broke" line is decoration.
        case = root / "ctx.py"
        case.write_text(_CASES[1][1], encoding="utf-8")
        _SCAN_CACHE.clear()
        contexts = {f.context for f in scan_file(case, root, _Resolver(root))}
        case.unlink()
        ctx_ok = contexts == {"except"}
        if not ctx_ok:
            failures.append(f"context labelling: expected {{'except'}}, got {contexts}")
        print(f"  self-test [{'ok' if ctx_ok else 'FAIL'}] an except-block finding is labelled as one")

        # A scanner that reports zero because it read nothing is the failure
        # this file is about. Prove the walker sees the fixtures it was given.
        seen = len(python_files(root))
        walk_ok = seen >= len(_FIXTURES)
        if not walk_ok:
            failures.append(f"file walk found {seen} file(s), expected at least {len(_FIXTURES)}")
        print(f"  self-test [{'ok' if walk_ok else 'FAIL'}] the walker reports the files it scanned")

    if failures:
        print("\ncheck_logger_kwargs --self-test: FAIL")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(f"\ncheck_logger_kwargs --self-test: OK — {len(_CASES) + 2} cases")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo-root", type=Path, default=None)
    parser.add_argument("--self-test", action="store_true", help="prove the scanner separates the two libraries")
    parser.add_argument("--show-unknown", action="store_true", help="list **kwargs splats that cannot be decided")
    args = parser.parse_args()

    if args.self_test:
        return self_test()
    root = (args.repo_root or repo_root()).resolve()
    if not (root / "services").is_dir():
        print(f"{root} does not look like the AiSOC repository (no services/)")
        return 1
    return run(root, show_unknown=args.show_unknown)


if __name__ == "__main__":
    sys.exit(main())
