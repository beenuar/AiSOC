#!/usr/bin/env python3
"""Gate: the published playbook schema and the engine that runs playbooks
must describe the same product.

``schemas/playbook.schema.json`` is the contract authors are told to trust.
When it drifts from ``services/agents/app/playbook/``, a playbook validates
and then fails at runtime — the worst shape for a schema to have, because the
failure lands on the person who did exactly what the documentation said.

Before this gate the two had drifted in every available direction at once:

  * two schema files existed with different step vocabularies (15 types and
    9 types) against an engine with 22, and the drafter silently fell back
    from one to the other;
  * 11 step types were declared by a schema and implemented nowhere;
  * 13 step types were accepted by the engine and declared by no schema;
  * 12 of those had no handler and the engine reported them ``SUCCESS``,
    including ``approval`` — a human gate that auto-passed;
  * 32 of 64 shipped playbooks failed the published schema, while the lint
    job printed ``2/2 passed`` because it only ever looked at two files.

Every comparison here runs in **both** directions. A check that only asks
"does the schema declare something the engine lacks" passes forever while
drift accumulates in the direction things actually change — the engine grows
a verb and nobody tells the schema. That is how a sibling gate in this repo
reported "OK" on a YAML file declaring 17 labels against Go code with 28.

The fifth vocabulary, and why the file list is not written down
---------------------------------------------------------------
This gate used to name the two TypeScript facts it cared about: the union in
``packages/types``. It never opened ``apps/web``, where the playbook editor
declared a nine-member union of its own under a header comment claiming it
mirrored the engine's twenty-two. Keying its form registry
``Record<StepType, StepSchema>`` on that local union meant exhaustiveness was
satisfied with thirteen forms missing, so the compiler was quiet and the gate
was looking somewhere else. The one step type an operator could actually
click was the one nothing checked.

Naming ``apps/web/.../stepSchemas.ts`` here would fix that file and leave the
next one free. So the TypeScript half is a **scan**: every ``.ts``/``.tsx``
file in the tree is parsed for collections of step-type literals, and any
collection that overlaps the engine's vocabulary is required either to match
it exactly or to be a recorded subset with a reason. A sixth vocabulary is a
failing build wherever somebody puts it.

What the scan credits, and what it cannot see
---------------------------------------------
``--list`` prints every collection it found and the verdict it reached, which
is the only way to tell a gate that found nothing from one that looked
nowhere. Two limits, stated because an unstated limit is a blind spot:

* A collection overlapping the vocabulary by fewer than two members is not
  treated as a vocabulary. ``new Set<StepType>(['close_case'])`` is a
  predicate about one verb, not a restatement of the list.
* The parser reads array elements, object keys and string-literal union
  members. A vocabulary assembled at runtime — by ``.map()`` over something
  else, or spread from another module — is not a literal and is not seen.
  Deriving one from ``STEP_SCHEMAS`` is how the editor's palette and canvas
  metadata are written, and that is the shape this gate wants to encourage:
  derived lists cannot drift, so not seeing them costs nothing.

Run:
    python3 scripts/check_playbook_schema_parity.py
    python3 scripts/check_playbook_schema_parity.py --list
    python3 scripts/check_playbook_schema_parity.py --self-test
"""

from __future__ import annotations

import argparse
import inspect
import json
import re
import sys
from dataclasses import dataclass, field, replace
from pathlib import Path

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root

#: Playbook-level keys the schema declares that the runtime model does not
#: bind. Both are authored documentation rather than engine inputs, and the
#: schema says so in their ``description``. This list is a named exemption,
#: not a silent pass: anything else appearing in one and not the other is an
#: error. Keep it empty-by-default in spirit — an entry here is a promise
#: that the key is inert, and the schema text must say the same.
INERT_AUTHORED_KEYS: frozenset[str] = frozenset({"inputs", "dry_run_support"})

#: Execution classes usable in the schema's ``x-aisoc-execution`` map.
#:
#: ``governed`` means the step is handed to the action registry in
#: ``services/actions``, which grades it against the capability contract and
#: the tenant's autonomy policy before anything reaches a vendor. It is in
#: ``_RUNS`` because a handler exists and makes a real outbound call — what
#: it does *not* claim is that a vendor was necessarily touched, which the
#: step's own ``executed`` field answers per run.
#:
#: ``simulated`` is retained in the vocabulary deliberately. It is the class
#: for a handler that answers from inside the engine without reaching an
#: executor, which is what ``block_ip`` and ``isolate_host`` used to do, and
#: dropping the word would make that state unspellable rather than absent.
_RUNS = frozenset({"executed", "governed", "simulated"})
_EXECUTION_CLASSES = _RUNS | {"unimplemented"}

#: Verbs the engine dispatches through the action registry. Compared against
#: ``engine.RESPONSE_STEP_TYPES`` in both directions, because a step marked
#: ``governed`` that the engine answers locally would be the old defect with
#: a new label on it.
_GOVERNED = "governed"

#: Directories the TypeScript scan never enters. Build output and vendored
#: packages are copies of something else; grading them would report the same
#: drift twice and, worse, make the gate's verdict depend on whether somebody
#: had run a build.
_TS_SKIP_DIRS = frozenset({"node_modules", ".git", "dist", "build", ".next", ".turbo", "coverage", "storybook-static"})

#: How much of a literal collection has to be step types before the gate
#: treats it as a statement about the vocabulary. One is a predicate about one
#: verb (``new Set<StepType>(['close_case'])``); two or more is a list.
_VOCABULARY_MIN_OVERLAP = 2

#: Literal collections of step types that are deliberately partial, keyed
#: ``<path>::<symbol>`` with the reason. Shrink-only and checked in both
#: directions: an entry naming a collection that no longer exists fails, and
#: so does one that has since become complete. Empty is the goal — every entry
#: is a place a future reader has to be told "yes, on purpose".
RECORDED_TS_SUBSETS: dict[str, str] = {}


@dataclass(frozen=True)
class TsVocabulary:
    """One literal collection of step-type names found in TypeScript."""

    path: str
    symbol: str
    line: int
    kind: str
    members: frozenset[str]
    #: ``member -> execution class`` where the collection annotates one.
    execution: dict[str, str] = field(default_factory=dict)

    @property
    def ref(self) -> str:
        return f"{self.path}::{self.symbol}"


class GateError(RuntimeError):
    """The gate could not inspect what it is supposed to inspect.

    Raised instead of returning "no problems found", because a gate that
    cannot read its inputs and prints OK is worse than no gate at all.
    """


@dataclass(frozen=True)
class Registries:
    """Every declaration of the playbook vocabulary, read from its source."""

    schema_step_types: frozenset[str]
    model_step_types: frozenset[str]
    handler_step_types: frozenset[str]
    inline_step_types: frozenset[str]
    #: Verbs the engine routes to the action registry rather than answering
    #: locally (``engine.RESPONSE_STEP_TYPES``).
    response_step_types: frozenset[str]
    #: The ``StepType`` union published in ``packages/types``.
    typescript_step_types: frozenset[str]
    #: Every literal collection of step types found anywhere in TypeScript,
    #: discovered rather than listed — see the module docstring.
    ts_vocabularies: tuple[TsVocabulary, ...]
    #: How many TypeScript files the scan opened to find them, and how many it
    #: could not finish reading and proved irrelevant instead.
    ts_files_scanned: int
    #: Files the reader could not finish, each proved to hold no vocabulary.
    ts_files_skipped: tuple[str, ...]
    execution: dict[str, str]
    schema_timeout_max: int
    schema_timeout_min: int
    schema_retry_max: int
    engine_timeout_max: int
    engine_timeout_min: int
    engine_retry_max: int
    schema_triggers: frozenset[str]
    validator_triggers: frozenset[str]
    schema_playbook_keys: frozenset[str]
    model_playbook_keys: frozenset[str]
    schema_files: tuple[str, ...] = ()
    scanned_playbooks: tuple[str, ...] = field(default=())

    @property
    def runnable(self) -> frozenset[str]:
        """Step types the engine can actually act on."""
        return self.handler_step_types | self.inline_step_types


# ---------------------------------------------------------------------------
# Collection — read each registry from the file that owns it
# ---------------------------------------------------------------------------


def _find_repo_root(explicit: str | None) -> Path:
    """Resolve the tree to inspect, and prove it is the right one.

    Resolving from ``__file__`` alone is how a gate ends up confidently
    reporting OK about a tree it never opened: copy the script somewhere, or
    run it from an installed package, and it grades whatever happens to sit
    two directories up. Every marker below must exist or we refuse to run.
    """
    root = Path(explicit).resolve() if explicit else repo_root()
    markers = (
        Path("schemas/playbook.schema.json"),
        Path("services/agents/app/playbook/engine.py"),
        Path("services/agents/app/playbook/models.py"),
        Path("scripts/validate_playbooks.py"),
    )
    missing = [str(m) for m in markers if not (root / m).exists()]
    if missing:
        raise GateError(
            f"{root} does not look like the AiSOC repository — missing: "
            f"{', '.join(missing)}. Pass --repo-root to point at the tree to check."
        )
    return root


def _load_schema(root: Path) -> dict:
    return json.loads((root / "schemas" / "playbook.schema.json").read_text())


def _schema_step_types(schema: dict) -> frozenset[str]:
    try:
        enum = schema["definitions"]["PlaybookStep"]["properties"]["type"]["enum"]
    except (KeyError, TypeError) as exc:
        raise GateError(f"schema step-type enum not found at the expected path: {exc}") from exc
    if not enum:
        raise GateError("schema step-type enum is empty; refusing to compare against nothing")
    return frozenset(enum)


def _schema_execution(schema: dict) -> dict[str, str]:
    raw = schema.get("x-aisoc-execution")
    if not isinstance(raw, dict):
        raise GateError("schema has no `x-aisoc-execution` map; the engine's behaviour would be undeclared")
    mapping = {k: v for k, v in raw.items() if k != "description"}
    if not mapping:
        raise GateError("`x-aisoc-execution` is empty; refusing to compare against nothing")
    return mapping


def _schema_step_bounds(schema: dict) -> tuple[int, int, int]:
    try:
        props = schema["definitions"]["PlaybookStep"]["properties"]
        return (
            int(props["timeout_seconds"]["maximum"]),
            int(props["timeout_seconds"]["minimum"]),
            int(props["retry_max"]["maximum"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise GateError(f"schema step bounds not found at the expected path: {exc}") from exc


def _import_engine(root: Path):
    """Import the real engine module rather than parsing it.

    Parsing would let a handler table that is built at import time disagree
    with what the parser sees. The import is cheap: the engine documents
    "zero external dependencies beyond httpx + stdlib".
    """
    agents = str(root / "services" / "agents")
    if agents not in sys.path:
        sys.path.insert(0, agents)
    try:
        from app.playbook import bounds, engine, models  # type: ignore[import-not-found]
    except Exception as exc:  # noqa: BLE001 — surfaced, never swallowed
        raise GateError(
            f"could not import the playbook engine from {agents}: {type(exc).__name__}: {exc}. "
            "Install httpx and pydantic, or the gate is grading nothing."
        ) from exc
    return engine, models, bounds


def _inline_step_types(engine_mod, models_mod) -> frozenset[str]:
    """Step types handled inside the run loop rather than via ``_HANDLERS``.

    ``condition`` never reaches the handler table — it branches in the loop
    body. Reading the source keeps that visible to the gate; if someone
    deletes the branch, the type stops counting as runnable here too.
    """
    try:
        source = inspect.getsource(engine_mod.PlaybookEngine.run)
    except (OSError, TypeError, AttributeError) as exc:
        raise GateError(f"could not read PlaybookEngine.run source to find inline step handling: {exc}") from exc
    found = {st.value for st in models_mod.StepType if f"StepType.{st.name}" in source}
    return frozenset(found)


def _model_playbook_keys(models_mod) -> frozenset[str]:
    return frozenset(models_mod.Playbook.model_fields.keys())


#: ``| "value"`` members of a TypeScript string-literal union.
_TS_UNION_MEMBER = re.compile(r'^\s*\|\s*"([a-z_]+)"', re.MULTILINE)


def _typescript_step_types(root: Path) -> frozenset[str]:
    """The ``StepType`` union published in ``packages/types``.

    A fourth vocabulary lived here undetected because nothing imports the
    package: 28 members (``notify_email``, ``create_ticket_jira``,
    ``collect_forensics`` …) matching neither the schema nor the engine. An
    unimported wrong contract is still a wrong contract — it is what the next
    person to import it will build against.

    Parsed rather than transpiled so the gate needs no Node toolchain, which
    is why the union is written one ``| "member"`` per line.
    """
    path = root / "packages" / "types" / "src" / "playbook.ts"
    if not path.is_file():
        raise GateError(f"{path} is missing; the published TypeScript vocabulary cannot be compared")
    text = path.read_text()
    marker = "export type StepType ="
    start = text.find(marker)
    if start == -1:
        raise GateError(f"{path} declares no `export type StepType` union to compare against the engine")
    end = text.find(";", start)
    members = frozenset(_TS_UNION_MEMBER.findall(text[start:end]))
    if not members:
        raise GateError(f"{path} declares a StepType union the gate could not parse; refusing to compare against nothing")
    return members


# ---------------------------------------------------------------------------
# TypeScript scan — find every literal collection of step types in the tree
# ---------------------------------------------------------------------------
#
# Parsed with a small hand-written reader rather than transpiled: the gate runs
# in a Python job with jsonschema, pydantic and httpx installed and nothing
# else, and requiring a Node toolchain to check a TypeScript fact would mean
# the check gets dropped from the job that can afford it.


def _closing_quote(text: str, start: int) -> int:
    """Index of the quote closing the one at ``start``, or -1 if there is none
    before the end of the line."""
    quote = text[start]
    i, n = start + 1, len(text)
    while i < n:
        ch = text[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "\n":
            return -1
        if ch == quote:
            return i
        i += 1
    return -1


def _mask_ts(text: str) -> tuple[str, list[tuple[int, int, str]], str]:
    """Blank comments and string interiors, keeping every offset.

    Returns the masked text, ``(open_quote_index, close_quote_index, value)``
    for each quoted string literal, and a non-empty reason when the file could
    not be read to the end. Structure is read from the mask so a brace inside
    a string or a comment cannot move the depth count; values are read from
    the list so the mask can be blank.

    Template literals are tracked with a stack because they nest: a
    ``${ … }`` interpolation is code again, and that code may contain another
    template. The first version of this treated a backtick as a plain quote,
    so ``` `a ${xs.map((k) => `\\`${k}\\``)} b` ``` desynchronised it and the
    remainder of the file — including the registry the gate exists to read —
    was swallowed into an unterminated string. Nothing said so; the scan
    simply found one declaration in that file instead of two and reported
    agreement. A parser that can silently stop reading is the same defect as a
    gate that never opened the file, which is why running out of input inside
    a string is now returned as a reason and refused by the caller rather than
    tolerated.
    """
    masked = list(text)
    strings: list[tuple[int, int, str]] = []
    #: ``["tpl", start]`` inside a template literal, ``["expr", depth]``
    #: inside one of its ``${ }`` interpolations.
    stack: list[list] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]

        if stack and stack[-1][0] == "tpl":
            if ch == "\\" and i + 1 < n:
                masked[i] = " "
                if text[i + 1] != "\n":
                    masked[i + 1] = " "
                i += 2
                continue
            if ch == "$" and i + 1 < n and text[i + 1] == "{":
                stack.append(["expr", 0])
                i += 2
                continue
            if ch == "`":
                stack.pop()
                i += 1
                continue
            if ch != "\n":
                masked[i] = " "
            i += 1
            continue

        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                masked[i] = " "
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            if end == -1:
                return "".join(masked), strings, f"unterminated block comment opened at offset {i}"
            for j in range(i, end + 2):
                if text[j] != "\n":
                    masked[j] = " "
            i = end + 2
            continue
        if ch in "\"'":
            # A quoted string may not contain a raw newline, so a quote with
            # no partner before the end of the line is not opening one — it is
            # an apostrophe in JSX text, or inside a regex literal such as
            # `/couldn\'t load the alert envelope/i`. Reading those as string
            # openers desynchronised the reader and swallowed the rest of the
            # file, which is the one outcome a scanner must not have.
            #
            # JSX and regex literals are why there is no attempt to lex `/`
            # here: `</div>` and `/>` are far more common in this tree than
            # division is, and a reader that guessed would be wrong more often
            # than the thing it was trying to fix.
            closed = _closing_quote(text, i)
            if closed == -1:
                i += 1
                continue
            chars: list[str] = []
            j = i + 1
            while j < closed:
                if text[j] == "\\":
                    chars.append(text[j + 1])
                    masked[j] = masked[j + 1] = " "
                    j += 2
                    continue
                chars.append(text[j])
                masked[j] = " "
                j += 1
            strings.append((i, closed, "".join(chars)))
            i = closed + 1
            continue
        if ch == "`":
            stack.append(["tpl", i])
            i += 1
            continue
        if stack and stack[-1][0] == "expr":
            if ch == "{":
                stack[-1][1] += 1
            elif ch == "}":
                if stack[-1][1] == 0:
                    stack.pop()
                    i += 1
                    continue
                stack[-1][1] -= 1
        i += 1

    if stack:
        return "".join(masked), strings, f"ran out of input inside a template literal opened at offset {stack[0][1]}"
    return "".join(masked), strings, ""


_OPEN_TO_CLOSE = {"{": "}", "[": "]", "(": ")"}


def _matching(masked: str, start: int) -> int:
    """Index of the bracket closing the one at ``start``, or -1."""
    opener = masked[start]
    closer = _OPEN_TO_CLOSE[opener]
    depth = 0
    for i in range(start, len(masked)):
        if masked[i] == opener:
            depth += 1
        elif masked[i] == closer:
            depth -= 1
            if depth == 0:
                return i
    return -1


def _depth_map(masked: str, start: int, end: int) -> list[int]:
    """Bracket depth at each offset in ``[start, end)``, relative to ``start``."""
    depths: list[int] = []
    depth = 0
    for i in range(start, end):
        ch = masked[i]
        if ch in "{[(":
            depth += 1
        elif ch in "}])":
            depth -= 1
            depths.append(depth)
            continue
        depths.append(depth)
    return depths


_IDENT = re.compile(r"[A-Za-z_$][\w$]*")
_DECL = re.compile(r"\b(?:export\s+)?(?:const|let|var|type)\s+([A-Za-z_$][\w$]*)")
#: Skipped between the ``=`` and the literal, so `new Set([...])`,
#: `Object.freeze({...})` and `new Map<K, V>([...])` all reach their literal.
_WRAPPERS = re.compile(r"\s*(?:new\s+)?(?:[A-Za-z_$][\w$.]*)?\s*(?:<[^<>]*>)?\s*\(\s*")


def _literal_start(masked: str, after: int) -> int:
    """Offset of the literal a declaration is initialised with, or -1.

    Walks past the type annotation to the assignment, then past any wrapping
    call. A union has no ``=``-then-bracket shape and is handled separately.
    """
    end = min(len(masked), after + 400)
    eq = -1
    i = after
    while i < end:
        if masked[i] == "=" and masked[i : i + 2] != "=>" and masked[i : i + 2] != "==" and masked[i - 1] not in "=!<>":
            eq = i
            break
        if masked[i] == ";":
            return -1
        i += 1
    if eq == -1:
        return -1
    pos = eq + 1
    for _ in range(3):  # at most a couple of nested wrappers
        while pos < len(masked) and masked[pos] in " \t\r\n":
            pos += 1
        if pos < len(masked) and masked[pos] in "{[":
            return pos
        match = _WRAPPERS.match(masked, pos)
        if not match or match.end() == pos:
            return -1
        pos = match.end()
    return -1


def _object_entries(masked: str, strings: list[tuple[int, int, str]], start: int, end: int) -> dict[str, tuple[int, int]]:
    """Top-level ``key: value`` spans of the object literal at ``[start, end]``."""
    depths = _depth_map(masked, start, end)
    by_start = {s: (e, v) for s, e, v in strings}
    entries: dict[str, tuple[int, int]] = {}
    i = start + 1
    while i < end:
        if depths[i - start] != 1 or masked[i] in " \t\r\n,":
            i += 1
            continue
        if masked[i] in "\"'`":
            close, value = by_start.get(i, (-1, ""))
            if close == -1:
                i += 1
                continue
            key, after = value, close + 1
        else:
            match = _IDENT.match(masked, i)
            if not match:
                i += 1
                continue
            key, after = match.group(0), match.end()
        colon = after
        while colon < end and masked[colon] in " \t\r\n":
            colon += 1
        if colon >= end or masked[colon] != ":":
            i = after
            continue
        value_start = colon + 1
        while value_start < end and masked[value_start] in " \t\r\n":
            value_start += 1
        if value_start < end and masked[value_start] in "{[(":
            value_end = _matching(masked, value_start)
            if value_end == -1:
                break
        else:
            value_end = value_start
            while value_end < end and (depths[value_end - start] != 1 or masked[value_end] != ","):
                value_end += 1
        entries[key] = (value_start, value_end)
        i = value_end + 1
    return entries


def _top_level_strings(masked: str, strings: list[tuple[int, int, str]], start: int, end: int) -> list[str]:
    """String literals sitting directly inside the bracket at ``start``."""
    depths = _depth_map(masked, start, end)
    return [value for s, _e, value in strings if start < s < end and depths[s - start] == 1]


def _union_members(masked: str, strings: list[tuple[int, int, str]], after: int) -> list[str]:
    """Members of a ``type X = | "a" | "b";`` union declared at ``after``."""
    end = masked.find(";", after)
    if end == -1:
        return []
    span = masked[after:end]
    if "=" not in span or "|" not in span:
        return []
    return [value for s, _e, value in strings if after < s < end]


def _execution_property(entries: dict[str, dict[str, str]]) -> str | None:
    """The property, if any, by which a registry annotates execution class.

    Found by the shape of its values rather than by its name: a property
    present on every entry whose values are all execution classes is the
    execution annotation, whatever it is called. Reading it by name would let
    a rename silently drop the check that the editor's claims match the
    schema's.
    """
    if not entries:
        return None
    common = set.intersection(*(set(props) for props in entries.values()))
    found = [name for name in sorted(common) if all(props[name] in _EXECUTION_CLASSES for props in entries.values())]
    return found[0] if len(found) == 1 else None


#: Any bare word, used only by the fallback below. Deliberately not restricted
#: to quoted strings: the editor's registry is an object literal with bare
#: identifier keys, so a quoted-only scan would have proved a file irrelevant
#: on the strength of not looking at the shape the vocabulary is actually
#: written in. Over-counting here is harmless — it only ever turns a silent
#: skip into a loud refusal.
_ANY_WORD = re.compile(r"[A-Za-z_][\w]*")


def _scan_ts_file(path: Path, rel: str, engine_members: frozenset[str]) -> tuple[list[TsVocabulary], str]:
    """Every literal collection of strings declared in one TypeScript file.

    Returns the collections and, when the file could not be read to the end, a
    reason. The reason is not swallowed: ``_typescript_vocabularies`` proves
    the file is irrelevant before skipping it, because a half-read file and a
    clean one both produce "no vocabulary found here".
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    masked, strings, unreadable = _mask_ts(text)
    if unreadable:
        # The reader is not a JavaScript engine — JSX text with an apostrophe
        # in it is the case it cannot finish. Skipping is only safe if the
        # file provably holds no vocabulary, and a vocabulary has to contain
        # at least two step-type literals in the raw bytes. Counting those is
        # a sound over-approximation: it cannot miss one.
        literals = {m.group(0) for m in _ANY_WORD.finditer(text)} & engine_members
        if len(literals) >= _VOCABULARY_MIN_OVERLAP:
            raise GateError(
                f"{rel}: the TypeScript reader could not parse the file to the end ({unreadable}), and it "
                f"mentions {len(literals)} step-type names ({', '.join(sorted(literals))}). Anything declared after "
                f"that point is invisible, so the gate refuses to report agreement over it."
            )
        return [], unreadable
    found: list[TsVocabulary] = []
    for decl in _DECL.finditer(masked):
        symbol = decl.group(1)
        line = masked.count("\n", 0, decl.start()) + 1
        if decl.group(0).lstrip().startswith(("type", "export type")):
            members = _union_members(masked, strings, decl.end())
            if members:
                found.append(TsVocabulary(rel, symbol, line, "union", frozenset(members)))
            continue
        start = _literal_start(masked, decl.end())
        if start == -1:
            continue
        end = _matching(masked, start)
        if end == -1:
            continue
        if masked[start] == "[":
            members = _top_level_strings(masked, strings, start, end)
            if members:
                found.append(TsVocabulary(rel, symbol, line, "array", frozenset(members)))
            continue
        spans = _object_entries(masked, strings, start, end)
        if not spans:
            continue
        # Each entry's own properties, so an execution annotation can be
        # recognised by the shape of its values.
        props: dict[str, dict[str, str]] = {}
        for key, (value_start, value_end) in spans.items():
            if masked[value_start : value_start + 1] != "{":
                continue
            inner = _object_entries(masked, strings, value_start, value_end)
            by_start = {s: v for s, _e, v in strings}
            props[key] = {name: by_start[vs] for name, (vs, _ve) in inner.items() if vs in by_start}
        execution_prop = _execution_property(props) if len(props) == len(spans) else None
        execution = {key: props[key][execution_prop] for key in spans} if execution_prop else {}
        found.append(TsVocabulary(rel, symbol, line, "object", frozenset(spans), execution))
    return found, ""


def _typescript_vocabularies(root: Path, engine_members: frozenset[str]) -> tuple[tuple[TsVocabulary, ...], int, tuple[str, ...]]:
    """Every TypeScript collection in the tree that talks about step types.

    Returns the candidates, the number of files opened and the number proved
    irrelevant after the reader could not finish them — because "found
    nothing" and "scanned nothing" print the same word, and the second is the
    state this gate was in with respect to ``apps/web``.
    """
    scanned = 0
    skipped: list[str] = []
    candidates: list[TsVocabulary] = []
    for path in sorted(root.rglob("*.ts*")):
        if path.suffix not in {".ts", ".tsx"} or any(part in _TS_SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        scanned += 1
        rel = str(path.relative_to(root))
        try:
            vocabularies, unreadable = _scan_ts_file(path, rel, engine_members)
        except (OSError, RecursionError) as exc:
            raise GateError(f"could not read {rel}: {exc}") from exc
        if unreadable:
            skipped.append(f"{rel} ({unreadable})")
        for vocabulary in vocabularies:
            if len(vocabulary.members & engine_members) >= _VOCABULARY_MIN_OVERLAP:
                candidates.append(vocabulary)
    if not scanned:
        raise GateError(f"no TypeScript files under {root}; the web vocabulary cannot be compared and a pass would mean nothing")
    if not candidates:
        raise GateError(
            f"scanned {scanned} TypeScript files and found no declaration of the step vocabulary. "
            "The published union and the editor's form registry are both meant to be here; "
            "refusing to report agreement having compared nothing."
        )
    return tuple(candidates), scanned, tuple(skipped)


def _validator_triggers(root: Path) -> frozenset[str]:
    """``scripts/validate_playbooks.py`` keeps its own trigger allow-list."""
    scripts = str(root / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    try:
        import validate_playbooks  # type: ignore[import-not-found]
    except Exception as exc:  # noqa: BLE001
        raise GateError(f"could not import scripts/validate_playbooks.py: {type(exc).__name__}: {exc}") from exc
    triggers = getattr(validate_playbooks, "SUPPORTED_TRIGGERS", None)
    if not triggers:
        raise GateError("validate_playbooks.SUPPORTED_TRIGGERS is missing or empty")
    return frozenset(triggers)


def _schema_files(root: Path) -> tuple[str, ...]:
    hits = [
        p
        for p in root.rglob("playbook.schema.json")
        if "node_modules" not in p.parts and ".git" not in p.parts and ".venv-gate" not in p.parts
    ]
    return tuple(sorted(str(p.relative_to(root)) for p in hits))


def _playbook_files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*.playbook.json") if "node_modules" not in p.parts and ".git" not in p.parts)


def collect(root: Path) -> Registries:
    schema = _load_schema(root)
    engine_mod, models_mod, bounds_mod = _import_engine(root)
    s_tmax, s_tmin, s_rmax = _schema_step_bounds(schema)
    model_step_types = frozenset(st.value for st in models_mod.StepType)
    ts_vocabularies, ts_files_scanned, ts_files_skipped = _typescript_vocabularies(root, model_step_types)
    return Registries(
        schema_step_types=_schema_step_types(schema),
        model_step_types=model_step_types,
        handler_step_types=frozenset(st.value for st in engine_mod._HANDLERS),
        inline_step_types=_inline_step_types(engine_mod, models_mod),
        response_step_types=frozenset(st.value for st in engine_mod.RESPONSE_STEP_TYPES),
        typescript_step_types=_typescript_step_types(root),
        ts_vocabularies=ts_vocabularies,
        ts_files_scanned=ts_files_scanned,
        ts_files_skipped=ts_files_skipped,
        execution=_schema_execution(schema),
        schema_timeout_max=s_tmax,
        schema_timeout_min=s_tmin,
        schema_retry_max=s_rmax,
        engine_timeout_max=bounds_mod.ABSOLUTE_MAX_TIMEOUT_SECONDS,
        engine_timeout_min=bounds_mod.MIN_TIMEOUT_SECONDS,
        engine_retry_max=bounds_mod.ABSOLUTE_MAX_RETRIES,
        schema_triggers=frozenset(schema["properties"]["trigger"]["properties"]["on"]["enum"]),
        validator_triggers=_validator_triggers(root),
        schema_playbook_keys=frozenset(schema["properties"].keys()),
        model_playbook_keys=_model_playbook_keys(models_mod),
        schema_files=_schema_files(root),
    )


# ---------------------------------------------------------------------------
# Comparison — pure, so the self-test can perturb it
# ---------------------------------------------------------------------------


def compare(reg: Registries, *, recorded_subsets: dict[str, str] | None = None) -> list[str]:
    """Every check, in both directions. Returns human-readable failures.

    ``recorded_subsets`` is a parameter rather than a read of the module
    global so the self-test drives the same value production does; a ratchet
    whose exemptions can only be exercised by editing the file is a ratchet
    nobody has seen work.
    """
    recorded_subsets = RECORDED_TS_SUBSETS if recorded_subsets is None else recorded_subsets
    errors: list[str] = []

    if not reg.schema_step_types or not reg.model_step_types:
        # Defence against a future refactor making the whole gate vacuous.
        return ["one of the step-type registries is empty; the comparison would pass on nothing"]

    # 1. schema enum <-> StepType, both ways.
    for missing in sorted(reg.schema_step_types - reg.model_step_types):
        errors.append(
            f"schema declares step type {missing!r} that StepType does not implement — "
            f"a playbook using it validates and then fails to parse at runtime. "
            f"Build it or remove it from the schema."
        )
    for missing in sorted(reg.model_step_types - reg.schema_step_types):
        errors.append(
            f"StepType implements {missing!r} and the schema does not declare it — "
            f"an author following the published contract cannot use it, and the "
            f"drafter has to collapse it onto some other verb. Declare it or delete it."
        )

    # 2. execution map <-> schema enum, both ways.
    exec_keys = frozenset(reg.execution)
    for missing in sorted(reg.schema_step_types - exec_keys):
        errors.append(f"step type {missing!r} is declared but `x-aisoc-execution` does not say what the engine does with it")
    for extra in sorted(exec_keys - reg.schema_step_types):
        errors.append(f"`x-aisoc-execution` describes {extra!r}, which the schema does not declare as a step type")

    bad = {k: v for k, v in reg.execution.items() if v not in _EXECUTION_CLASSES}
    for k, v in sorted(bad.items()):
        errors.append(f"`x-aisoc-execution[{k}]` is {v!r}; expected one of {sorted(_EXECUTION_CLASSES)}")

    # 3. execution claims <-> the engine's real handler table, both ways.
    claims_to_run = frozenset(k for k, v in reg.execution.items() if v in _RUNS)
    for k in sorted(claims_to_run - reg.runnable):
        errors.append(
            f"`x-aisoc-execution` claims {k!r} runs, but the engine has no handler for it — "
            f"this is the claim the schema exists to make true."
        )
    for k in sorted(reg.runnable - claims_to_run):
        errors.append(
            f"the engine has a handler for {k!r} but `x-aisoc-execution` marks it "
            f"{reg.execution.get(k, '(absent)')!r} — the schema is understating what the product does."
        )

    # 2b. the published TypeScript vocabulary <-> StepType, both ways.
    #     `packages/types` is what an integrator builds against, and it had
    #     drifted into an entirely separate 28-member vocabulary that nothing
    #     imported and nothing checked.
    for missing in sorted(reg.model_step_types - reg.typescript_step_types):
        errors.append(
            f"`StepType` implements {missing!r} and `packages/types/src/playbook.ts` does not publish it — "
            f"an integrator typing against the package cannot express a step the engine runs."
        )
    for extra in sorted(reg.typescript_step_types - reg.model_step_types):
        errors.append(
            f"`packages/types/src/playbook.ts` publishes step type {extra!r}, which `StepType` does not implement — "
            f"code that type-checks against the package would be rejected by the server."
        )

    # 2c. every TypeScript declaration of the vocabulary <-> StepType, both
    #     ways, over whatever the scan found rather than a list of files kept
    #     here. The editor's nine-member union survived because this gate knew
    #     the name of one TypeScript file and that was not the one an operator
    #     clicked.
    if not reg.ts_vocabularies:
        return errors + ["no TypeScript declaration of the step vocabulary was found; the comparison would pass on nothing"]

    for vocabulary in reg.ts_vocabularies:
        recorded = recorded_subsets.get(vocabulary.ref)
        missing = reg.model_step_types - vocabulary.members
        invented = vocabulary.members - reg.model_step_types
        if not missing and not invented:
            if recorded:
                errors.append(
                    f"a recorded subset lists {vocabulary.ref} as deliberate and it now declares the "
                    f"whole vocabulary; remove the entry rather than leaving it to excuse a future gap."
                )
            continue
        if recorded and not invented:
            continue
        for member in sorted(missing):
            errors.append(
                f"{vocabulary.ref} ({vocabulary.kind}, line {vocabulary.line}) omits step type {member!r} that "
                f"`StepType` implements — a vocabulary that is a subset of the engine's is a verb the product "
                f"runs and this surface cannot express. Complete it, or record it in RECORDED_TS_SUBSETS with a reason."
            )
        for member in sorted(invented):
            errors.append(
                f"{vocabulary.ref} ({vocabulary.kind}, line {vocabulary.line}) declares step type {member!r} that "
                f"`StepType` does not implement — code written against it would be rejected by the server."
            )

    # 2d. execution classes declared in TypeScript <-> `x-aisoc-execution`,
    #     both ways. A surface that tells an author a step will run when the
    #     schema says it is unimplemented is the same lie in a nearer place.
    for vocabulary in reg.ts_vocabularies:
        if not vocabulary.execution:
            continue
        for member, declared in sorted(vocabulary.execution.items()):
            published = reg.execution.get(member)
            if published is None:
                errors.append(f"{vocabulary.ref} annotates {member!r} as {declared!r} and `x-aisoc-execution` does not describe it at all.")
            elif declared != published:
                errors.append(
                    f"{vocabulary.ref} tells an author {member!r} is {declared!r} while `x-aisoc-execution` "
                    f"says {published!r} — the surface and the contract disagree about what will happen."
                )
        for member in sorted(frozenset(reg.execution) - frozenset(vocabulary.execution)):
            errors.append(
                f"{vocabulary.ref} annotates execution for some step types and not for {member!r}, so what the "
                f"engine does with it is unstated exactly where somebody is choosing it."
            )

    for ref in sorted(set(recorded_subsets) - {v.ref for v in reg.ts_vocabularies}):
        errors.append(f"a recorded subset lists {ref!r}, which the scan did not find; remove the entry")

    # 3b. `governed` claims <-> the engine's response-verb set, both ways.
    #     A step labelled `governed` that the engine answers from inside its
    #     own process is the exact defect this label replaced: `block_ip` used
    #     to return `{"simulated": true}` and reach no executor. And a verb the
    #     engine routes to the registry while the schema calls it something
    #     else understates the governance an author is relying on.
    claims_governed = frozenset(k for k, v in reg.execution.items() if v == _GOVERNED)
    for k in sorted(claims_governed - reg.response_step_types):
        errors.append(
            f"`x-aisoc-execution` marks {k!r} governed, but the engine does not route it "
            f"through the action registry — a local answer wearing the label of a dispatched one."
        )
    for k in sorted(reg.response_step_types - claims_governed):
        errors.append(
            f"the engine dispatches {k!r} through the action registry but `x-aisoc-execution` "
            f"marks it {reg.execution.get(k, '(absent)')!r}."
        )

    # 4. bounds, both ways (a schema ceiling below the engine's rejects valid
    #    playbooks; above it promises headroom Pydantic will refuse).
    if reg.schema_timeout_max != reg.engine_timeout_max:
        errors.append(
            f"step timeout ceiling disagrees: schema {reg.schema_timeout_max} vs "
            f"bounds.ABSOLUTE_MAX_TIMEOUT_SECONDS {reg.engine_timeout_max}"
        )
    if reg.schema_timeout_min != reg.engine_timeout_min:
        errors.append(
            f"step timeout floor disagrees: schema {reg.schema_timeout_min} vs bounds.MIN_TIMEOUT_SECONDS {reg.engine_timeout_min}"
        )
    if reg.schema_retry_max != reg.engine_retry_max:
        errors.append(f"retry ceiling disagrees: schema {reg.schema_retry_max} vs bounds.ABSOLUTE_MAX_RETRIES {reg.engine_retry_max}")

    # 5. trigger vocabulary <-> the pack validator's allow-list, both ways.
    for missing in sorted(reg.schema_triggers - reg.validator_triggers):
        errors.append(f"schema allows trigger.on={missing!r} that validate_playbooks.py rejects")
    for missing in sorted(reg.validator_triggers - reg.schema_triggers):
        errors.append(f"validate_playbooks.py allows trigger.on={missing!r} that the schema rejects")

    # 6. playbook-level keys <-> Playbook model fields, both ways.
    for missing in sorted(reg.schema_playbook_keys - reg.model_playbook_keys - INERT_AUTHORED_KEYS):
        errors.append(
            f"schema declares playbook key {missing!r} that the Playbook model drops on load — "
            f"add the field, remove the key, or list it in INERT_AUTHORED_KEYS and say so in its description"
        )
    for missing in sorted(reg.model_playbook_keys - reg.schema_playbook_keys):
        errors.append(f"Playbook model has field {missing!r} that the schema does not declare, so `additionalProperties: false` rejects it")

    # 7. exactly one schema file. Two is how the vocabularies diverged.
    if len(reg.schema_files) > 1:
        errors.append(
            f"more than one playbook.schema.json in the tree ({', '.join(reg.schema_files)}) — "
            f"a second copy is a second source of truth and the drafter silently fell back to it once already"
        )

    return errors


# ---------------------------------------------------------------------------
# Content check — the contract must be true of what ships
# ---------------------------------------------------------------------------


def validate_shipped_playbooks(root: Path) -> tuple[list[str], list[Path]]:
    try:
        import jsonschema
    except ImportError as exc:
        raise GateError("jsonschema is not installed; the content half of this gate cannot run") from exc

    schema = _load_schema(root)
    validator = jsonschema.Draft7Validator(schema)
    files = _playbook_files(root)
    if not files:
        raise GateError("no *.playbook.json found; refusing to report success having validated nothing")

    errors: list[str] = []
    for path in files:
        rel = path.relative_to(root)
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            errors.append(f"{rel}: JSON parse error: {exc}")
            continue
        for err in sorted(validator.iter_errors(data), key=lambda e: list(e.path)):
            loc = ".".join(str(p) for p in err.path) or "(root)"
            errors.append(f"{rel}: {loc}: {err.message}")
    return errors, files


# ---------------------------------------------------------------------------
# Self-test — prove the gate fires, in each direction
# ---------------------------------------------------------------------------


def self_test(reg: Registries) -> list[str]:
    """Inject drift in each direction and assert the gate notices.

    A gate nobody has seen fail is indistinguishable from a gate that cannot.
    """
    failures: list[str] = []

    def expect(label: str, perturbed: Registries, needle: str) -> None:
        errs = compare(perturbed)
        if not any(needle in e for e in errs):
            failures.append(f"self-test: {label}: injected drift was NOT detected (needle {needle!r}); got {errs or 'no errors'}")

    baseline = compare(reg)
    if baseline:
        failures.append(f"self-test: the unperturbed tree already fails, so a pass proves nothing: {baseline}")

    victim = sorted(reg.schema_step_types)[0]
    absent = "step_type_that_exists_nowhere"

    expect(
        "schema declares a type the engine lacks",
        replace(
            reg,
            schema_step_types=reg.schema_step_types | {absent},
            execution={**reg.execution, absent: "unimplemented"},
        ),
        "does not implement",
    )
    expect(
        "engine implements a type the schema lacks",
        replace(reg, model_step_types=reg.model_step_types | {absent}),
        "the schema does not declare it",
    )
    expect(
        "the published TypeScript union lost a verb the engine runs",
        replace(reg, typescript_step_types=reg.typescript_step_types - {victim}),
        "does not publish it",
    )
    expect(
        # The shape the file was actually in: a vocabulary of its own.
        "the published TypeScript union invented a verb",
        replace(reg, typescript_step_types=reg.typescript_step_types | {"create_ticket_jira"}),
        "which `StepType` does not implement",
    )

    # The scanned half. Perturbing a discovered vocabulary rather than a
    # named field is the point: these are the directions that let the
    # editor's nine-member union sit unnoticed behind a green build.
    if not reg.ts_vocabularies:
        failures.append("self-test: no TypeScript vocabulary was discovered; the scan directions cannot be tested")
    else:
        sample = reg.ts_vocabularies[0]

        def with_vocabulary(vocabulary: TsVocabulary) -> Registries:
            rest = tuple(v for v in reg.ts_vocabularies if v.ref != vocabulary.ref)
            return replace(reg, ts_vocabularies=(vocabulary, *rest))

        expect(
            # Precisely the defect: a surface declaring a subset of the
            # vocabulary, exhaustive against itself and short of the engine.
            "a scanned TypeScript surface declares fewer step types than the engine runs",
            with_vocabulary(replace(sample, members=sample.members - {victim})),
            "omits step type",
        )
        expect(
            "a scanned TypeScript surface invents a step type",
            with_vocabulary(replace(sample, members=sample.members | {absent})),
            "does not implement",
        )
        expect(
            "the scan finds no declaration at all",
            replace(reg, ts_vocabularies=()),
            "would pass on nothing",
        )
        # The recorded-subset ratchet, in both directions. Driven through
        # `compare`'s parameter rather than the module global so the test
        # perturbs the same value production reads.
        shrunk = replace(sample, members=sample.members - {victim})
        excused = compare(
            replace(reg, ts_vocabularies=(shrunk, *reg.ts_vocabularies[1:])),
            recorded_subsets={shrunk.ref: "recorded for the self-test"},
        )
        if any("omits step type" in e for e in excused):
            failures.append("self-test: a recorded subset was still reported as drift, so the exemption does nothing")
        stale = compare(reg, recorded_subsets={sample.ref: "recorded for the self-test"})
        if not any("remove the entry rather than leaving it" in e for e in stale):
            failures.append("self-test: a recorded subset that now declares the whole vocabulary was not reported as stale")
        ghost = compare(reg, recorded_subsets={"nowhere.ts::Ghost": "recorded for the self-test"})
        if not any("which the scan did not find" in e for e in ghost):
            failures.append("self-test: a recorded subset naming a collection that does not exist was not reported")

        annotated = next((v for v in reg.ts_vocabularies if v.execution), None)
        if annotated is None:
            failures.append(
                "self-test: no scanned vocabulary annotates an execution class, so the surface-vs-schema "
                "directions are untested — the editor is supposed to carry one"
            )
        else:
            member = sorted(annotated.execution)[0]
            expect(
                "a surface promises an execution the schema does not",
                with_vocabulary(replace(annotated, execution={**annotated.execution, member: "executed"}))
                if annotated.execution[member] != "executed"
                else with_vocabulary(replace(annotated, execution={**annotated.execution, member: "unimplemented"})),
                "the surface and the contract disagree",
            )
            expect(
                "a surface annotates some step types and silently omits one",
                with_vocabulary(replace(annotated, execution={k: v for k, v in annotated.execution.items() if k != member})),
                "is unstated exactly where somebody is choosing it",
            )
            expect(
                "a surface annotates a step type the schema never declared",
                with_vocabulary(replace(annotated, execution={**annotated.execution, absent: "executed"})),
                "does not describe it at all",
            )
    expect(
        "declared type with no execution annotation",
        replace(reg, execution={k: v for k, v in reg.execution.items() if k != victim}),
        "does not say what the engine does with it",
    )
    expect(
        "execution annotation for an undeclared type",
        replace(reg, execution={**reg.execution, absent: "executed"}),
        "which the schema does not declare",
    )
    runs_now = sorted(k for k, v in reg.execution.items() if v in _RUNS)
    if not runs_now:
        failures.append("self-test: no step type is annotated as running; cannot test the handler directions")
    else:
        running = runs_now[0]
        expect(
            "annotation claims execution the engine cannot deliver",
            replace(reg, handler_step_types=reg.handler_step_types - {running}, inline_step_types=reg.inline_step_types - {running}),
            "the engine has no handler for it",
        )
        expect(
            "engine gained a handler the annotation calls unimplemented",
            replace(reg, execution={**reg.execution, running: "unimplemented"}),
            "understating what the product does",
        )

    governed_now = sorted(k for k, v in reg.execution.items() if v == _GOVERNED)
    if not governed_now:
        failures.append("self-test: no step type is annotated governed; cannot test the registry directions")
    else:
        dispatched = governed_now[0]
        expect(
            # The precise shape of the bug this label replaced: a verb that
            # says it goes through the action registry and is answered inside
            # the engine instead.
            "annotation claims governed dispatch the engine does not do",
            replace(reg, response_step_types=reg.response_step_types - {dispatched}),
            "a local answer wearing the label of a dispatched one",
        )
        expect(
            "engine dispatches a verb the annotation calls merely executed",
            replace(reg, execution={**reg.execution, dispatched: "executed"}),
            "through the action registry but `x-aisoc-execution`",
        )
    expect("timeout ceiling drift", replace(reg, schema_timeout_max=reg.engine_timeout_max + 1), "timeout ceiling disagrees")
    expect("retry ceiling drift", replace(reg, schema_retry_max=reg.engine_retry_max + 1), "retry ceiling disagrees")
    expect(
        "schema allows a trigger the validator rejects",
        replace(reg, schema_triggers=reg.schema_triggers | {"webhook"}),
        "that validate_playbooks.py rejects",
    )
    expect(
        "validator allows a trigger the schema rejects",
        replace(reg, validator_triggers=reg.validator_triggers | {"webhook"}),
        "that the schema rejects",
    )
    expect("schema key the model drops", replace(reg, schema_playbook_keys=reg.schema_playbook_keys | {"ghost_key"}), "drops on load")
    expect(
        "model field the schema rejects", replace(reg, model_playbook_keys=reg.model_playbook_keys | {"ghost_field"}), "does not declare"
    )
    expect(
        "a second schema file reappears", replace(reg, schema_files=(*reg.schema_files, "playbook.schema.json")), "second source of truth"
    )

    return failures


# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo-root", default=None, help="Tree to inspect (default: the repo this script lives in)")
    parser.add_argument("--self-test", action="store_true", help="Prove the gate detects injected drift in each direction")
    parser.add_argument(
        "--list",
        action="store_true",
        help="Print every declaration of the vocabulary the scan credited, and what it credited it as",
    )
    args = parser.parse_args()

    try:
        root = _find_repo_root(args.repo_root)
        reg = collect(root)
        content_errors, scanned = validate_shipped_playbooks(root)
    except GateError as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 2

    # Name what was inspected. A gate that does not say what it read cannot
    # be distinguished from one that read nothing.
    print(f"repo root          {root}")
    print(f"schema             {', '.join(reg.schema_files) or '(none)'}")
    print("engine             services/agents/app/playbook/engine.py")
    print(
        f"step types         schema {len(reg.schema_step_types)} | StepType {len(reg.model_step_types)} "
        f"| runnable {len(reg.runnable)} | packages/types {len(reg.typescript_step_types)}"
    )
    counts = {c: sum(1 for v in reg.execution.values() if v == c) for c in sorted(_EXECUTION_CLASSES)}
    print("execution          " + " | ".join(f"{k} {v}" for k, v in counts.items()))
    print(f"bounds             timeout {reg.schema_timeout_min}..{reg.schema_timeout_max}s | retries <={reg.schema_retry_max}")
    print(f"playbooks scanned  {len(scanned)}")
    unreadable = len(reg.ts_files_skipped)
    annotating = sum(1 for v in reg.ts_vocabularies if v.execution)
    print(
        f"typescript         {reg.ts_files_scanned} files read "
        f"({unreadable} unparseable, each proved to hold no vocabulary) | "
        f"{len(reg.ts_vocabularies)} declaration(s) of the vocabulary | "
        f"{annotating} annotating execution"
    )
    print()

    if args.list:
        # What it credits, not what it flags. A gate that only prints its
        # complaints cannot be told apart from one whose scan matched nothing.
        print("declarations of the step vocabulary found in TypeScript:")
        for vocabulary in sorted(reg.ts_vocabularies, key=lambda v: v.ref):
            verdict = "complete" if vocabulary.members == reg.model_step_types else "DIFFERS from StepType"
            annotation = f", execution for {len(vocabulary.execution)}" if vocabulary.execution else ""
            where = f"{vocabulary.ref} ({vocabulary.kind}, line {vocabulary.line})"
            print(f"  {verdict:<22} {len(vocabulary.members):>3} members{annotation}  {where}")
        print(
            f"  (a collection overlapping the vocabulary by fewer than {_VOCABULARY_MIN_OVERLAP} members is "
            f"not treated as one; runtime-derived lists are not literals and are not seen)"
        )
        if reg.ts_files_skipped:
            print()
            print("files the reader could not finish, each checked for step-type literals before being skipped:")
            for note in reg.ts_files_skipped:
                print(f"  {note}")
        print()

    errors = compare(reg)

    if args.self_test:
        st = self_test(reg)
        if st:
            print("SELF-TEST FAILED")
            for f in st:
                print(f"  {f}")
            return 1
        print("self-test OK — every direction detected its injected drift, and the clean tree passed")
        print()

    if content_errors:
        print(f"{len(content_errors)} shipped playbook(s) do not match the published schema:")
        for e in content_errors[:40]:
            print(f"  {e}")
        if len(content_errors) > 40:
            print(f"  ... and {len(content_errors) - 40} more")

    if errors:
        print(f"{len(errors)} schema/engine disagreement(s):")
        for e in errors:
            print(f"  {e}")

    if errors or content_errors:
        return 1

    print("OK — schema and engine agree in both directions, and every shipped playbook matches the schema.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
