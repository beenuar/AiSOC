#!/usr/bin/env python3
"""A declared wire type matches the schema the service actually publishes.

Why this exists
---------------
`check_console_route_contract.py` proves a console path reaches a route. It
says nothing about what comes back, and that is the half that drifted: issue
#1648 found `POST /api/v1/hunt/search` sending `took_ms`, `raw`, `highlights`,
`event_type`, `source`, `query` and `notice` while the hand-written client
type declared `took`, `fields`, `highlight` and a `severity` no response has
ever carried — seven names, none of them shared, and the eighth (`notice`)
reached through an inline cast.

Nothing caught it because `request<T>(path)` *asserts* `T` rather than
validating it, so the type checker believed `results.took` existed right up
to `TypeError: Cannot read properties of undefined` in the browser. A
hand-written client type is a second declaration of a contract, and a second
declaration drifts.

It also had no spec coverage of any kind. `docs/openapi.yaml` is exported
from `services/api` alone, and this route is served by `services/agents`
through a Next rewrite — so every gate keyed on the published document
covered precisely nothing here.

What is compared
----------------
A `@wire` tag on an exported interface names the operation whose response it
describes:

    @wire agents POST /api/v1/hunt/search          the response body
    @wire agents POST /api/v1/hunt/search#hits[]   the item shape of `hits`

The service's own OpenAPI document is read by importing its app, the way
`check_console_route_contract.py` does — not by scanning decorators, because
`app.routes` is not the route table and what it holds changes with the
FastAPI minor.

Then, for every annotated interface, **in both directions**:

  schema -> interface   a field the service sends that the interface does
                        not declare. This is the direction that drifts and
                        the direction a one-sided gate misses: `took_ms`,
                        `source`, `query` and `event_type` were all of this
                        kind.
  interface -> schema   a field the interface declares that no response
                        carries. `took`, `fields`, `highlight` and
                        `severity` were all of this kind, and each one is a
                        value a component will read as `undefined`.
  required/optional     a field the service may omit must be optional in
                        TypeScript, and one it always sends must not be.
  type kind             `highlights: list[str]` against `highlight?: string`
                        agreed on nothing, but a gate comparing names alone
                        would have caught only the `s`.

And the annotation has to be load-bearing: a whole-response `@wire` type
must be the type argument of the `request<...>` call for that path, so
annotating a type and then not using it is not a way to pass.

Nothing is skipped
------------------
Every resolution failure is an error, never a pass. An unknown service, a
path the service does not publish, an operation with no resolvable JSON
success schema, a `$ref` that does not resolve, a property path that does
not exist, an interface the parser cannot read, a field typed `any` — each
exits non-zero. A gate whose "unknown" bucket is a pass is the shape this
repository keeps rediscovering, most recently in a raw-SQL checker that
bucketed every unrecognised table as "not compared".

Stated limit
------------
This proves the annotated types. It does not pin every response the console
reads; the unpinned count is printed every run so the gap is visible rather
than silent, and each newly pinned type is one fewer place the next #1648
can happen.

Usage
-----
    python3 scripts/check_console_wire_contract.py
    python3 scripts/check_console_wire_contract.py --list
    python3 scripts/check_console_wire_contract.py --self-test
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import signal
import subprocess
import sys
from dataclasses import dataclass, field

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from gate_toolkit import SELF_TEST_FLAG, repo_root, self_test_main  # noqa: E402

CONSOLE_SRC = "apps/web/src"
API_CLIENT = "apps/web/src/lib/api.ts"

#: Services this gate can introspect, by the name a `@wire` tag may use.
SERVICES = ("api", "agents")

#: `@wire <service> <METHOD> <path>` with an optional `#prop[]/prop` fragment
#: naming a shape nested inside the response. The trailing `*/` is optional
#: because a one-line JSDoc comment is a perfectly ordinary way to write the
#: tag, and a pattern that only knew the multi-line form would have ignored
#: it in silence — which is how a gate ends up covering nothing.
_WIRE = re.compile(
    r"@wire\s+(?P<service>\w+)\s+(?P<method>[A-Z]+)\s+(?P<path>/\S*?)(?:#(?P<fragment>\S+?))?\s*(?:\*/)?\s*$",
    re.MULTILINE,
)

_INTERFACE = re.compile(r"^export interface (?P<name>\w+)\s*\{(?P<body>.*?)^\}", re.MULTILINE | re.DOTALL)

#: `request<Type>("/path"` — the call sites a whole-response tag must own.
_REQUEST_CALL = re.compile(r"request<(?P<type>[\w\[\]]+)>\(\s*[\"'`](?P<path>/api/v1/[^\"'`]*)")


def _run_isolated(argv: list[str], *, cwd: pathlib.Path, timeout: int):
    """Run a probe in its own process group, and kill the group on timeout.

    Same reasoning as `check_console_route_contract._run_isolated`: killing
    the group closes every inherited pipe rather than only the child's, and
    `stdin` is closed so a probe that decides to prompt dies instead of
    waiting.
    """
    process = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
        argv,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            process.kill()
        process.communicate()
        return None
    return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)


def _openapi(root: pathlib.Path, service: str) -> dict | None:
    """One service's whole OpenAPI document, or None if it could not be read."""
    script = "import json,sys;sys.path.insert(0,'.');from app.main import app;print('<<<SPEC>>>'+json.dumps(app.openapi()))"
    try:
        out = _run_isolated([sys.executable, "-c", script], cwd=root / "services" / service, timeout=120)
    except OSError:
        return None
    if out is None or out.returncode != 0:
        return None
    for line in out.stdout.splitlines():
        if line.startswith("<<<SPEC>>>"):
            try:
                return json.loads(line[len("<<<SPEC>>>") :])
            except json.JSONDecodeError:
                return None
    return None


# ---------------------------------------------------------------------------
# TypeScript side
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TsField:
    name: str
    optional: bool
    kinds: frozenset[str]


@dataclass
class Annotation:
    interface: str
    service: str
    method: str
    path: str
    fragment: str | None
    source_file: str
    fields: dict[str, TsField]


_TS_PRIMITIVES = {
    "string": "string",
    "number": "number",
    "boolean": "boolean",
    "null": "null",
    "undefined": "null",
}


def _ts_kinds(type_text: str) -> frozenset[str] | None:
    """Coarse kinds a TypeScript type can hold, or None if unreadable.

    Deliberately coarse. The question is whether a consumer that reads this
    field gets something of the shape it expects, not whether two type
    systems agree in detail — and a comparison too clever to explain is one
    nobody trusts enough to keep.
    """
    kinds: set[str] = set()
    for part in type_text.split("|"):
        part = part.strip().rstrip(";").strip()
        if not part:
            continue
        if part.endswith("[]") or part.startswith(("Array<", "ReadonlyArray<")):
            kinds.add("array")
        elif part.startswith(("Record<", "Partial<Record<", "{")):
            kinds.add("object")
        elif (part.startswith('"') and part.endswith('"')) or (part.startswith("'") and part.endswith("'")):
            kinds.add("string")
        elif part in _TS_PRIMITIVES:
            kinds.add(_TS_PRIMITIVES[part])
        elif part in {"any", "unknown"}:
            # A field whose declared type promises nothing cannot be
            # compared, and calling that agreement would be the "unknown
            # bucket is a pass" defect in one line.
            return None
        elif part[:1].isupper():
            kinds.add("object")
        else:
            return None
    return frozenset(kinds) if kinds else None


def _parse_interface(body: str) -> dict[str, TsField] | None:
    """Fields of an interface body, or None if anything in it is unreadable."""
    # Strip block comments and line comments; neither declares a field.
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.DOTALL)
    body = re.sub(r"//[^\n]*", "", body)

    fields: dict[str, TsField] = {}
    for raw_line in body.split("\n"):
        line = raw_line.strip()
        if not line or line in {"{", "}"}:
            continue
        match = re.match(r"^(?P<name>[A-Za-z_$][\w$]*)(?P<opt>\?)?\s*:\s*(?P<type>.+?);?$", line)
        if not match:
            return None
        kinds = _ts_kinds(match.group("type"))
        if kinds is None:
            return None
        fields[match.group("name")] = TsField(
            name=match.group("name"),
            optional=bool(match.group("opt")),
            kinds=kinds,
        )
    return fields or None


def _annotations(root: pathlib.Path) -> tuple[list[Annotation], list[str]]:
    """Every `@wire`-tagged exported interface in the console."""
    found: list[Annotation] = []
    errors: list[str] = []
    src = root / CONSOLE_SRC
    if not src.is_dir():
        return found, errors
    for path in sorted(src.rglob("*.ts*")):
        if "node_modules" in path.parts or path.name.endswith(".d.ts"):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if "@wire" not in text:
            continue
        where = path.relative_to(root).as_posix()
        for tag in _WIRE.finditer(text):
            # The interface a tag describes is the next one declared after it.
            declaration = _INTERFACE.search(text, tag.end())
            if declaration is None:
                errors.append(f"{where}: a @wire tag for {tag.group('path')} is followed by no exported interface")
                continue
            fields = _parse_interface(declaration.group("body"))
            if fields is None:
                errors.append(
                    f"{where}: cannot read the fields of `{declaration.group('name')}`. "
                    "Refusing to report an interface clean that this gate could not parse."
                )
                continue
            found.append(
                Annotation(
                    interface=declaration.group("name"),
                    service=tag.group("service"),
                    method=tag.group("method").lower(),
                    path=tag.group("path"),
                    fragment=tag.group("fragment"),
                    source_file=where,
                    fields=fields,
                )
            )
    return found, errors


# ---------------------------------------------------------------------------
# OpenAPI side
# ---------------------------------------------------------------------------


def _deref(spec: dict, schema: dict) -> dict | None:
    seen = 0
    while "$ref" in schema:
        seen += 1
        if seen > 10:
            return None
        ref = schema["$ref"]
        if not ref.startswith("#/components/schemas/"):
            return None
        schema = spec.get("components", {}).get("schemas", {}).get(ref.rsplit("/", 1)[-1])
        if schema is None:
            return None
    return schema


def _success_schema(spec: dict, operation: dict) -> tuple[dict | None, str]:
    """The one JSON schema a successful call to this operation returns.

    Not hardcoded to `200`: `POST /api/v1/hunt/saved` declares `201`, and a
    gate that looked only at `200` would have found nothing there and called
    it covered.
    """
    responses = operation.get("responses", {})
    codes = [c for c in responses if c.isdigit() and 200 <= int(c) < 300]
    bodies = [(c, responses[c].get("content", {}).get("application/json", {}).get("schema")) for c in sorted(codes)]
    bodies = [(c, s) for c, s in bodies if s]
    if not bodies:
        return None, "declares no JSON response body on any 2xx status"
    if len(bodies) > 1:
        return None, f"declares a JSON body on several 2xx statuses ({', '.join(c for c, _ in bodies)})"
    resolved = _deref(spec, bodies[0][1])
    if resolved is None:
        return None, f"has a {bodies[0][0]} schema whose $ref does not resolve"
    return resolved, ""


def _walk_fragment(spec: dict, schema: dict, fragment: str) -> tuple[dict | None, str]:
    """Follow `hits[]/raw`-style steps into a response schema."""
    for step in fragment.split("/"):
        is_item = step.endswith("[]")
        key = step[:-2] if is_item else step
        properties = schema.get("properties", {})
        if key not in properties:
            return None, f"has no property `{key}`"
        node = _deref(spec, properties[key])
        if node is None:
            return None, f"property `{key}` has a $ref that does not resolve"
        if is_item:
            items = node.get("items")
            if not items:
                return None, f"property `{key}` is not an array with a declared item schema"
            node = _deref(spec, items)
            if node is None:
                return None, f"the item schema of `{key}` has a $ref that does not resolve"
        schema = node
    return schema, ""


def _schema_kinds(spec: dict, schema: dict) -> frozenset[str]:
    kinds: set[str] = set()
    for branch in schema.get("anyOf", []) + schema.get("oneOf", []):
        resolved = _deref(spec, branch)
        if resolved is not None:
            kinds |= _schema_kinds(spec, resolved)
    declared = schema.get("type")
    if isinstance(declared, str):
        kinds.add({"integer": "number"}.get(declared, declared))
    elif "enum" in schema:
        for member in schema["enum"]:
            kinds.add({str: "string", bool: "boolean", int: "number", float: "number"}.get(type(member), "object"))
    elif "$ref" in schema:
        resolved = _deref(spec, schema)
        if resolved is not None:
            kinds |= _schema_kinds(spec, resolved)
    return frozenset(kinds)


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------


@dataclass
class Report:
    checked: list[str] = field(default_factory=list)
    mismatches: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    unpinned: list[tuple[str, str]] = field(default_factory=list)
    fields_compared: int = 0


def _compare(annotation: Annotation, spec: dict, schema: dict, report: Report) -> None:
    where = f"{annotation.interface} (@wire {annotation.service} {annotation.method.upper()} {annotation.path}"
    where += f"#{annotation.fragment})" if annotation.fragment else ")"

    properties: dict = schema.get("properties", {})
    required = set(schema.get("required", []))
    if not properties:
        report.errors.append(f"{where}: the resolved schema declares no properties, so nothing was compared")
        return

    # The direction that drifts, and the one a one-sided gate never runs.
    for name in sorted(set(properties) - set(annotation.fields)):
        report.mismatches.append(f"{where}: the service sends `{name}` and the interface does not declare it")

    for name in sorted(set(annotation.fields) - set(properties)):
        report.mismatches.append(
            f"{where}: the interface declares `{name}` and no response carries it — every read of it resolves to undefined"
        )

    for name in sorted(set(properties) & set(annotation.fields)):
        declared = annotation.fields[name]
        node = _deref(spec, properties[name])
        if node is None:
            report.errors.append(f"{where}: property `{name}` has a $ref that does not resolve")
            continue
        report.fields_compared += 1

        sends_always = name in required
        if sends_always and declared.optional:
            report.mismatches.append(
                f"{where}: `{name}` is always sent, so declaring it optional makes callers guard a case that cannot happen"
            )
        if not sends_always and not declared.optional and "null" not in declared.kinds:
            report.mismatches.append(f"{where}: `{name}` may be absent, so declaring it required is the assertion that crashed in #1648")

        wire_kinds = _schema_kinds(spec, node)
        if not wire_kinds:
            report.errors.append(f"{where}: could not determine the type of `{name}` from the schema")
            continue
        # `null` is carried by optionality on the TypeScript side as well as
        # by a union member, so compare the non-null shapes.
        if wire_kinds - {"null"} and declared.kinds - {"null"} and not (wire_kinds & declared.kinds) - {"null"}:
            report.mismatches.append(
                f"{where}: `{name}` is {'|'.join(sorted(wire_kinds))} on the wire and {'|'.join(sorted(declared.kinds))} in the interface"
            )

    report.checked.append(where)


def _unpinned_calls(root: pathlib.Path, pinned_types: set[str]) -> list[tuple[str, str]]:
    """`request<T>(path)` call sites whose response type no `@wire` tag pins."""
    client = root / API_CLIENT
    if not client.is_file():
        return []
    out: list[tuple[str, str]] = []
    for match in _REQUEST_CALL.finditer(client.read_text(encoding="utf-8")):
        type_name = match.group("type")
        if type_name in pinned_types or type_name in {"void", "unknown", "Blob"}:
            continue
        # Template segments are reported as `{}` so the inventory reads as
        # paths rather than as fragments of the source that produced them.
        path = re.sub(r"\$\{[^}]*\}?", "{}", match.group("path").split("?")[0])
        out.append((" ".join(path.split()), type_name))
    return sorted(set(out))


def inspect(root: pathlib.Path) -> Report:
    report = Report()
    annotations, parse_errors = _annotations(root)
    report.errors.extend(parse_errors)
    if not annotations:
        return report

    specs: dict[str, dict | None] = {}
    for service in sorted({a.service for a in annotations}):
        if service not in SERVICES:
            report.errors.append(f"@wire names service `{service}`, which this gate cannot introspect")
            continue
        specs[service] = _openapi(root, service)

    for annotation in annotations:
        spec = specs.get(annotation.service)
        if spec is None:
            report.errors.append(
                f"{annotation.interface}: could not read the OpenAPI document of services/{annotation.service}. "
                "That is an unreadable contract, not a clean one."
            )
            continue
        operation = spec.get("paths", {}).get(annotation.path, {}).get(annotation.method)
        if operation is None:
            report.errors.append(
                f"{annotation.interface}: services/{annotation.service} publishes no {annotation.method.upper()} {annotation.path}"
            )
            continue
        schema, why = _success_schema(spec, operation)
        if schema is None:
            report.errors.append(f"{annotation.interface}: {annotation.method.upper()} {annotation.path} {why}")
            continue
        if annotation.fragment:
            schema, why = _walk_fragment(spec, schema, annotation.fragment)
            if schema is None:
                report.errors.append(f"{annotation.interface}: the response of {annotation.method.upper()} {annotation.path} {why}")
                continue
        _compare(annotation, spec, schema, report)

    # A whole-response tag has to be the type the client actually asks for,
    # or the annotation is decoration and the real call still asserts
    # whatever it likes.
    client = root / API_CLIENT
    if client.is_file():
        text = client.read_text(encoding="utf-8")
        calls = {(m.group("path").split("?")[0], m.group("type")) for m in _REQUEST_CALL.finditer(text)}
        for annotation in annotations:
            if annotation.fragment:
                continue
            paths_called = {t for p, t in calls if p == annotation.path}
            if paths_called and annotation.interface not in paths_called:
                report.mismatches.append(
                    f"{annotation.interface} is tagged for {annotation.path}, but the client asks for "
                    f"{' / '.join(sorted(paths_called))} there — the tag proves nothing about the real call"
                )

    report.unpinned = _unpinned_calls(root, {a.interface for a in annotations})
    return report


def _verdict(report: Report, *, verbose: bool = False) -> int:
    if not report.checked and not report.errors and not report.mismatches:
        print(
            "check_console_wire_contract: found no @wire-tagged interface, which means the "
            "console source was not read. Refusing to report that as clean.",
            file=sys.stderr,
        )
        return 2
    if not report.fields_compared and not report.errors and not report.mismatches:
        print(
            "check_console_wire_contract: compared zero fields. A gate that opened nothing "
            "reports the same word as one that found nothing.",
            file=sys.stderr,
        )
        return 2

    if report.errors:
        print("check_console_wire_contract: could not resolve a declared contract:", file=sys.stderr)
        for line in report.errors:
            print(f"  {line}", file=sys.stderr)
        return 2

    if verbose:
        for line in report.checked:
            print(f"  checked {line}")
        for path, type_name in report.unpinned:
            print(f"  unpinned {path} -> {type_name}")

    if report.mismatches:
        print(
            f"check_console_wire_contract: {len(report.mismatches)} field(s) disagree between a "
            "console wire type and the schema its service publishes:",
            file=sys.stderr,
        )
        for line in report.mismatches:
            print(f"  {line}", file=sys.stderr)
        return 1

    print(
        f"check_console_wire_contract: OK — {len(report.checked)} wire type(s), "
        f"{report.fields_compared} field(s) compared in both directions against the services' own "
        f"OpenAPI documents. Stated limit: {len(report.unpinned)} request<T> call site(s) in "
        f"{API_CLIENT} declare a response type no @wire tag pins; --list names them."
    )
    return 0


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

_FAKE_SPEC: dict = {
    "paths": {
        "/api/v1/thing": {
            "post": {
                "responses": {
                    "201": {
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Thing"}}},
                    }
                }
            }
        }
    },
    "components": {
        "schemas": {
            "Thing": {
                "properties": {
                    "took_ms": {"type": "integer"},
                    "label": {"type": "string"},
                    "notes": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "rows": {"type": "array", "items": {"$ref": "#/components/schemas/Row"}},
                },
                "required": ["took_ms", "label", "rows"],
            },
            "Row": {"properties": {"raw": {"type": "object"}}, "required": ["raw"]},
        }
    },
}


def _probe(ts_fields: dict[str, TsField], fragment: str | None = None) -> Report:
    report = Report()
    annotation = Annotation(
        interface="Probe",
        service="agents",
        method="post",
        path="/api/v1/thing",
        fragment=fragment,
        source_file="probe.ts",
        fields=ts_fields,
    )
    operation = _FAKE_SPEC["paths"]["/api/v1/thing"]["post"]
    schema, _ = _success_schema(_FAKE_SPEC, operation)
    assert schema is not None
    if fragment:
        schema, _ = _walk_fragment(_FAKE_SPEC, schema, fragment)
        assert schema is not None
    _compare(annotation, _FAKE_SPEC, schema, report)
    return report


def _ts(name: str, type_text: str, optional: bool = False) -> TsField:
    kinds = _ts_kinds(type_text)
    assert kinds is not None, type_text
    return TsField(name=name, optional=optional, kinds=kinds)


def self_test() -> int:
    root = repo_root()
    report = inspect(root)

    agreeing = {
        "took_ms": _ts("took_ms", "number"),
        "label": _ts("label", "string"),
        "notes": _ts("notes", "string | null", optional=True),
        "rows": _ts("rows", "Row[]"),
    }

    # Both directions, each proven by a single edit to an agreeing set.
    missing_from_ts = dict(agreeing)
    del missing_from_ts["took_ms"]
    renamed_in_ts = {**missing_from_ts, "took": _ts("took", "number")}

    wrong_kind = {**agreeing, "rows": _ts("rows", "string")}
    wrong_optional = {**agreeing, "label": _ts("label", "string", optional=True)}
    wrong_required = {**agreeing, "notes": _ts("notes", "string")}

    extra: list[tuple[str, bool]] = [
        ("the real tree's wire types all match their schema", not report.mismatches and not report.errors),
        (
            f"it read a real corpus ({len(report.checked)} wire type(s), {report.fields_compared} field(s))",
            len(report.checked) >= 2 and report.fields_compared >= 10,
        ),
        ("an agreeing interface reports nothing", not _probe(agreeing).mismatches),
        (
            "a field the service sends and the interface omits is caught",
            any("sends `took_ms`" in m for m in _probe(missing_from_ts).mismatches),
        ),
        (
            "the #1648 shape — one name each side — is caught in both directions at once",
            {"sends", "declares"} <= {w for m in _probe(renamed_in_ts).mismatches for w in ("sends", "declares") if w in m},
        ),
        ("a type-kind disagreement is caught", any("in the interface" in m for m in _probe(wrong_kind).mismatches)),
        (
            "an always-sent field declared optional is caught",
            any("always sent" in m for m in _probe(wrong_optional).mismatches),
        ),
        (
            "a sometimes-absent field declared required is caught",
            any("may be absent" in m for m in _probe(wrong_required).mismatches),
        ),
        (
            "a nested item shape resolves through `rows[]`",
            not _probe({"raw": _ts("raw", "Record<string, unknown>")}, fragment="rows[]").mismatches,
        ),
        # No skipping. Each of these must be an error, not a quiet pass.
        ("an unreadable field type refuses the interface", _parse_interface("  x: any;\n") is None),
        ("an unparseable interface body refuses", _parse_interface("  this is not a field\n") is None),
        (
            "a path the service does not publish is an error",
            _success_schema(_FAKE_SPEC, {"responses": {"204": {}}})[0] is None,
        ),
        (
            "a $ref that does not resolve is an error",
            _deref(_FAKE_SPEC, {"$ref": "#/components/schemas/Nope"}) is None,
        ),
        (
            "a fragment naming a property that does not exist is an error",
            _walk_fragment(_FAKE_SPEC, _FAKE_SPEC["components"]["schemas"]["Thing"], "nope[]")[0] is None,
        ),
        (
            "a 201-only operation is resolved, not skipped",
            _success_schema(_FAKE_SPEC, _FAKE_SPEC["paths"]["/api/v1/thing"]["post"])[0] is not None,
        ),
        ("an empty comparison is refused rather than reported clean", _verdict(Report()) == 2),
        # Both JSDoc spellings, because a pattern that reads only one of them
        # ignores the other in silence and reports the tree clean.
        (
            "a one-line JSDoc tag is read, not ignored",
            [m.group("path", "fragment") for m in _WIRE.finditer("/** @wire agents POST /api/v1/x#hits[] */\n")]
            == [("/api/v1/x", "hits[]")],
        ),
        (
            "a multi-line JSDoc tag is read",
            [m.group("path", "fragment") for m in _WIRE.finditer(" * @wire agents POST /api/v1/x\n")] == [("/api/v1/x", None)],
        ),
    ]

    return self_test_main(pathlib.Path(__file__).name, ["--check"], extra)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--list", action="store_true", help="name every wire type checked and every unpinned call")
    parser.add_argument(SELF_TEST_FLAG, action="store_true", dest="self_test")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    return _verdict(inspect(repo_root()), verbose=args.list)


if __name__ == "__main__":
    raise SystemExit(main())
