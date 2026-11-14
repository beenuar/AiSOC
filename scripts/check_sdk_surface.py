#!/usr/bin/env python3
"""Three green SDK jobs, and the parity they imply does not exist. Prove it.

Why this exists
---------------
``docs/audit/CLAIM_TO_GATE_MATRIX.md`` carries "Plugin SDK Python/TS/Go" as a
PARTIAL row against ``ci.yml :: sdk-*``. Three jobs run, three ticks appear,
and a reader concludes three clients were checked against the API. What the
three jobs actually establish:

``sdk-go-test``
    ``packages/sdk-go`` ships ``go.mod`` and ``aisoc/models.go``, and that
    file is type declarations — no functions, no ``net/http``. ``go build``,
    ``go vet`` and ``go test`` over a file of ``type`` and ``const`` blocks
    pass trivially and would pass just as well if the API did not exist.
    Line 1 of it read "provides a typed Go client for the AiSOC REST API".
    The tick was real and the client was not.

``sdk-ts-test``
    ``packages/sdk-ts/package.json`` declared
    ``"codegen": "openapi-typescript ../../docs/openapi.yaml -o
    src/openapi.d.ts"`` and described the package as "auto-generated from the
    OpenAPI schema". ``src/openapi.d.ts`` did not exist, was not ignored, and
    no workflow ran ``pnpm codegen``. ``src/types.ts`` opened by saying its
    types were "kept in sync with docs/openapi.yaml via the ``pnpm codegen``
    script which regenerates src/openapi.d.ts" — a sync mechanism with no
    artifact and no caller, cited by two comments as the reason to trust the
    file.

``sdk-python-test``
    Runs the client's own tests, which mock the HTTP layer. A mock answers
    whatever the client asks, so a request to a route the API does not serve
    is indistinguishable from one it does.

That last point is the whole problem, and it is not hypothetical. Writing this
gate found **four operations both hand-written clients called that the API does
not serve**: ``DELETE /api/v1/cases/{id}`` (``cases.py`` declares no delete
route at all), ``PATCH /api/v1/playbooks/{id}`` (the route is ``PUT``), and
``GET /api/v1/detections`` plus ``GET /api/v1/detections/{id}`` — the real
prefix is ``/api/v1/detection/rules``, so the entire ``detections`` namespace
404'd in both languages. Two of the four had a passing test pinning them: a
test that mocks the transport and asserts the client called what the client
calls is a producer compared against a copy of itself.

``docs/openapi.yaml`` carries 403 paths and 502 operations. The two clients
reach 32 of them between them. That gap is a deliberate scope decision and not
a defect — an ergonomic client is a curated subset. What *is* a defect is a
client calling something absent, a language quietly losing a namespace the
other two advertise, and a generated artifact cited in prose that was never
generated. None of those is visible to a compiler.

What it checks
--------------
``endpoint-not-in-spec``
    Every ``(method, path)`` an SDK client calls must be an operation
    ``docs/openapi.yaml`` declares. This is the direction that breaks a user:
    the call compiles, type-checks, passes its mocked test and returns 404 or
    405 against a real deployment. Path parameters are compared by position,
    not by name — ``/alerts/{alert_id}`` and ``/alerts/{id}`` are the same
    route, and an SDK naming its own local variable differently is not drift.

``namespace-regressed``
    ``packages/sdk-surface.json`` names the resource namespaces the SDKs
    promise. A language the manifest does not record a gap for must actually
    reach that namespace. This is what catches a namespace removed, renamed
    or quietly re-pathed in one language while the other two keep it.

``gap-filled``
    The same list read the other way. A recorded gap must still be a gap: if
    a language now implements the namespace, the entry has to go. A gate that
    only checks the first direction passes while the exemption list rots into
    a permanent licence, which is how ``sdk-go`` came to have three green
    jobs. Same for the client-level gap — ``sdk-go`` is recorded as having no
    HTTP client, and the day some file in it imports ``net/http`` that record
    is stale and this fails.

``codegen-target-missing``
    A ``package.json`` declaring ``codegen`` with an ``-o <file>`` target must
    have that file on disk. A declaration is a claim that the file is
    generated from the spec, and two comments cited this one as the reason to
    trust hand-written types. Either the artifact exists, or the declaration
    and the prose citing it go.

Nothing is imported beyond the standard library, and the spec is read with a
line parser rather than PyYAML. Several gates here run on a bare interpreter
before any ``pip install``, and this one has no reason to be the exception:
the parser was checked against ``yaml.safe_load`` over the real 34,319-line
spec and returns the identical 502 operations.

Usage
-----

::

    python3 scripts/check_sdk_surface.py              # gate
    python3 scripts/check_sdk_surface.py --list       # what each client reaches
    python3 scripts/check_sdk_surface.py --self-test

Exit status is 0 when the three clients agree with the spec and the manifest,
1 when they do not, and 2 when the gate cannot render a verdict at all —
no spec operations, no parsed endpoints, or no manifest. The third is
separate on purpose: "the clients are clean" and "the parser matched nothing"
are different answers and must not print the same word.

Note that the corpus comes from ``git ls-files``, which does not list
untracked files. Run this with your changes staged.
"""

from __future__ import annotations

import argparse
import ast
import contextlib
import io
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_main  # noqa: E402

#: The manifest naming what the SDKs promise, and every recorded gap.
MANIFEST = "packages/sdk-surface.json"

#: HTTP methods an OpenAPI path item may declare. ``parameters`` and
#: ``summary`` are keys at the same depth and are not operations.
_HTTP_METHODS = frozenset({"get", "put", "post", "delete", "options", "head", "patch", "trace"})

#: ``self._get("/x")`` and ``self._http.post("/graphql")`` are both request
#: sites; the leading underscore is a helper on the resource base class rather
#: than a different verb. Mapped by attribute name because the Python client
#: routes every call through one of these.
_PY_REQUEST_ATTRS = {
    "get": "GET",
    "post": "POST",
    "put": "PUT",
    "patch": "PATCH",
    "delete": "DELETE",
    "_get": "GET",
    "_post": "POST",
    "_put": "PUT",
    "_patch": "PATCH",
    "_delete": "DELETE",
}

#: ``this.request<Page<Alert>>("GET", "/api/v1/alerts")`` and
#: ``sub["request"]("POST", "/graphql")`` — the second is how the TypeScript
#: client reaches GraphQL, so the optional ``"]`` is not cosmetic. The generic
#: argument is skipped with ``[^(;]*?`` rather than a balanced match because
#: ``<Page<Alert>>`` and ``<{ status: string }>`` both appear and neither
#: contains a parenthesis or a semicolon.
_TS_REQUEST = re.compile(
    r"""request\s*(?:["']\s*\])?\s*(?:<[^(;]*?>)?\s*\(\s*
        ["'](?P<method>GET|POST|PUT|PATCH|DELETE)["']\s*,\s*
        (?:"(?P<dq>[^"]+)"|'(?P<sq>[^']+)'|`(?P<tpl>[^`]+)`)""",
    re.VERBOSE,
)

#: ``"codegen": "openapi-typescript ../../docs/openapi.yaml -o src/openapi.d.ts"``
_CODEGEN_TARGET = re.compile(r"(?:-o|--output)[\s=]+(?P<target>[^\s\"']+)")

#: A Go package that imports this is talking to something over HTTP. Used to
#: decide whether the recorded "no client" gap for ``sdk-go`` is still true,
#: so the day one is written the manifest fails rather than staying stale.
_GO_HTTP_IMPORT = re.compile(r'^\s*(?:[\w.]+\s+)?"net/http"', re.MULTILINE)


def _tracked(root: Path, *patterns: str) -> list[Path]:
    """Tracked files matching ``patterns``, per git.

    git rather than ``Path.glob`` so ``node_modules`` and build output cannot
    contribute a package manifest, and so the corpus is the set under review.
    """
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", "ls-files", "-z", "--", *patterns],
        capture_output=True,
        text=True,
        check=False,
        cwd=root,
    )
    if out.returncode != 0:
        return []
    return [root / name for name in out.stdout.split("\0") if name]


def normalise(path: str) -> str:
    """Collapse every path parameter to a positional placeholder.

    OpenAPI names path parameters and an SDK names its own local variable, so
    ``/alerts/{alert_id}``, ``/alerts/{id}`` and ``/alerts/${encodeURIComponent(x)}``
    are one route addressed three ways. Comparing the names would report drift
    on every client that chose a shorter argument name.
    """
    return re.sub(r"\{[^{}]*\}", "{}", path)


def spec_operations(text: str) -> set[tuple[str, str]]:
    """Every ``(METHOD, path)`` the OpenAPI document declares.

    A line parser, not PyYAML, so the gate runs on a bare interpreter. The
    shape it relies on is the one an OpenAPI document has by construction:
    ``paths:`` at column 0, each path a key two spaces in, each operation a
    key four spaces in. Checked against ``yaml.safe_load`` over the real spec
    — both return the same 502 operations — and a document that does not have
    that shape yields nothing, which the caller refuses rather than reports.
    """
    operations: set[tuple[str, str]] = set()
    in_paths = False
    current: str | None = None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[:1].isspace():
            in_paths = line.startswith("paths:")
            current = None
            continue
        if not in_paths:
            continue
        key = re.match(r"^(?P<indent>\s+)(?P<key>\S+?):\s*$", line)
        if key is None:
            continue
        depth = len(key.group("indent"))
        name = key.group("key").strip("\"'")
        if depth == 2 and name.startswith("/"):
            current = name
        elif depth == 4 and current is not None and name.lower() in _HTTP_METHODS:
            operations.add((name.upper(), normalise(current)))
    return operations


def python_endpoints(source: str) -> set[tuple[str, str]]:
    """Request sites in the Python client, read with ``ast``.

    f-strings are the interesting case: ``f"/api/v1/alerts/{alert_id}"`` is a
    ``JoinedStr`` whose formatted values are the path parameters, so each one
    becomes a placeholder and the literal segments are kept verbatim.
    """
    endpoints: set[tuple[str, str]] = set()
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        method = _PY_REQUEST_ATTRS.get(node.func.attr)
        if method is None or not node.args:
            continue
        target = node.args[0]
        if isinstance(target, ast.Constant) and isinstance(target.value, str):
            path = target.value
        elif isinstance(target, ast.JoinedStr):
            path = "".join(str(part.value) if isinstance(part, ast.Constant) else "{}" for part in target.values)
        else:
            # The base-class helpers pass a `path` variable through to httpx.
            # There is no literal to read there, and the literal is at the
            # call site one frame up, which this loop also visits.
            continue
        if path.startswith("/"):
            endpoints.add((method, normalise(path)))
    return endpoints


def typescript_endpoints(source: str) -> set[tuple[str, str]]:
    """Request sites in the TypeScript client, read with a regex.

    A regex rather than a parser because the alternative is shipping a
    TypeScript grammar to read a two-argument call, and the call is written
    one way throughout: a method string literal followed by a path literal or
    template. ``${...}`` interpolations become placeholders.
    """
    endpoints: set[tuple[str, str]] = set()
    for match in _TS_REQUEST.finditer(source):
        raw = match.group("dq") or match.group("sq") or match.group("tpl")
        path = re.sub(r"\$\{[^{}]*\}", "{}", raw)
        if path.startswith("/"):
            endpoints.add((match.group("method"), normalise(path)))
    return endpoints


def go_has_http_client(root: Path, package: str) -> bool:
    """Whether any Go file in ``package`` speaks HTTP.

    The test for "is there a client here", used to decide whether the
    recorded gap is still honest. Deliberately not "does the package
    compile" — that is what the existing job already answers, over a file of
    type declarations, which is how this row came to be PARTIAL.
    """
    sources = [path for path in _tracked(root, package) if path.suffix == ".go"]
    return any(_GO_HTTP_IMPORT.search(path.read_text(encoding="utf-8", errors="replace")) for path in sources)


def codegen_declarations(root: Path) -> list[tuple[str, str, str]]:
    """``(manifest, script, target)`` for every declared codegen output."""
    declared: list[tuple[str, str, str]] = []
    for path in _tracked(root, "*package.json"):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        scripts = document.get("scripts")
        if not isinstance(scripts, dict):
            continue
        for name, command in scripts.items():
            if "codegen" not in name or not isinstance(command, str):
                continue
            target = _CODEGEN_TARGET.search(command)
            if target is not None:
                declared.append((path.relative_to(root).as_posix(), name, target.group("target")))
    return declared


def scan(root: Path) -> dict:
    """Read the spec, the clients and the manifest. No verdict here."""
    manifest_path = root / MANIFEST
    if not manifest_path.is_file():
        return {"error": f"{MANIFEST} is missing; the gate has nothing to compare the clients against"}
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return {"error": f"{MANIFEST} is not valid JSON: {exc}"}

    spec_relative = manifest.get("spec", "docs/openapi.yaml")
    spec_path = root / spec_relative
    operations = spec_operations(spec_path.read_text(encoding="utf-8")) if spec_path.is_file() else set()

    clients: dict[str, dict] = {}
    for language, declared in (manifest.get("clients") or {}).items():
        relative = declared.get("path")
        record: dict = {"path": relative, "gap": declared.get("gap"), "endpoints": set(), "read": False}
        if relative:
            path = root / relative
            if path.is_file():
                source = path.read_text(encoding="utf-8")
                record["read"] = True
                if language == "python":
                    record["endpoints"] = python_endpoints(source)
                elif language == "typescript":
                    record["endpoints"] = typescript_endpoints(source)
        clients[language] = record

    return {
        "root": root,
        "manifest": manifest,
        "spec": spec_relative,
        "operations": operations,
        "clients": clients,
        "codegen": codegen_declarations(root),
    }


def evaluate(scanned: dict) -> tuple[list[str], list[str]]:
    """``(findings, credits)`` — what is wrong, and what the verdict rests on."""
    root: Path = scanned["root"]
    manifest: dict = scanned["manifest"]
    operations: set[tuple[str, str]] = scanned["operations"]
    clients: dict[str, dict] = scanned["clients"]
    findings: list[str] = []
    credits: list[str] = []

    # endpoint-not-in-spec — the direction that breaks a user.
    for language, record in sorted(clients.items()):
        endpoints: set[tuple[str, str]] = record["endpoints"]
        if not endpoints:
            continue
        credits.append(
            f"{language}: {len(endpoints)} endpoint(s) parsed from {record['path']}, {len(endpoints & operations)} present in the spec"
        )
        for method, path in sorted(endpoints - operations):
            findings.append(
                f"endpoint-not-in-spec: {language} calls {method} {path}, which {scanned['spec']} does not declare. "
                f"It compiles, type-checks and passes a mocked test, and answers 404 or 405 against a deployment"
            )

    # namespace-regressed / gap-filled — the manifest, read both ways.
    namespaces: dict = manifest.get("namespaces") or {}
    for name, declared in sorted(namespaces.items()):
        prefixes = declared.get("prefixes") or []
        gaps = declared.get("gaps") or {}
        for language, record in sorted(clients.items()):
            reaches = any(path == prefix or path.startswith(prefix + "/") for _method, path in record["endpoints"] for prefix in prefixes)
            client_gap = record["gap"]
            recorded = gaps.get(language) or client_gap
            if reaches and recorded:
                where = f"namespaces.{name}.gaps.{language}" if gaps.get(language) else f"clients.{language}.gap"
                findings.append(
                    f"gap-filled: {MANIFEST} records {language} as not reaching '{name}' ({recorded}), but it does. "
                    f"Remove {where} — a recorded gap that is no longer a gap is a licence nobody reviews"
                )
            elif not reaches and not recorded:
                findings.append(
                    f"namespace-regressed: {language} reaches no endpoint under {prefixes} for namespace '{name}', "
                    f"and {MANIFEST} records no gap for it. Either restore the namespace or record the gap with a reason"
                )

    # A client-level gap is the honest record for a package with no client at
    # all, and it has to stop being true the moment one is written.
    for language, record in sorted(clients.items()):
        gap = record["gap"]
        if not gap:
            continue
        package = (manifest.get("clients") or {}).get(language, {}).get("package")
        credits.append(f"{language}: recorded gap — {gap}")
        if language == "go" and package and go_has_http_client(root, package):
            findings.append(
                f"gap-filled: {MANIFEST} records clients.{language}.gap because {package} has no HTTP client, "
                f"but a file in it now imports net/http. Remove the gap and declare the namespaces it reaches"
            )

    # codegen-target-missing — a generated artifact cited in prose.
    for relative, script, target in scanned["codegen"]:
        resolved = (root / relative).parent / target
        credits.append(f"codegen: {relative} declares '{script}' -> {target}")
        if not resolved.is_file():
            findings.append(
                f"codegen-target-missing: {relative} declares a '{script}' script writing {target}, and that file "
                f"does not exist. Either generate and commit it, or delete the '{script}' declaration and correct "
                f"the prose that cites it as the reason the hand-written types are trustworthy"
            )

    return findings, credits


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the SDK clients against the OpenAPI spec and the surface manifest.")
    parser.add_argument("--self-test", action="store_true", help="prove the gate fails closed and still detects each violation")
    parser.add_argument("--list", action="store_true", help="print what each client reaches, then the verdict")
    parser.add_argument("--repo-root", type=Path, default=None, help="the tree to inspect")
    args = parser.parse_args(argv)

    if args.self_test:
        with tempfile.TemporaryDirectory(prefix="aisoc-sdk-surface-") as scratch:
            extra = _injected_cases(Path(scratch))
        return self_test_main(Path(__file__).name, [], extra=extra)

    root = (args.repo_root or repo_root()).resolve()
    scanned = scan(root)
    if "error" in scanned:
        print(f"REFUSED: {scanned['error']}")
        return 2

    operations: set[tuple[str, str]] = scanned["operations"]
    clients: dict[str, dict] = scanned["clients"]
    parsed = sum(len(record["endpoints"]) for record in clients.values())

    print(f"root: {root}")
    print(f"spec: {scanned['spec']} — {len(operations)} operation(s) across {len({path for _m, path in operations})} path(s)")

    # Non-vacuity. "The clients are clean" and "the parser matched nothing"
    # are different answers, and a gate that prints the first for the second
    # is the failure this tree keeps finding.
    if not operations:
        print(f"REFUSED: no operations parsed from {scanned['spec']}; a clean verdict here would describe a spec the gate never read")
        return 2
    if not parsed:
        declared = [language for language, record in clients.items() if record["path"]]
        print(
            f"REFUSED: no endpoints parsed from any SDK client (declared: {declared or 'none'}); there is nothing to check against the spec"
        )
        return 2
    if not (scanned["manifest"].get("namespaces") or {}):
        print(f"REFUSED: {MANIFEST} declares no namespaces; three-way parity over an empty list is vacuous")
        return 2

    findings, credits = evaluate(scanned)

    if args.list:
        for language, record in sorted(clients.items()):
            for method, path in sorted(record["endpoints"]):
                print(f"  {language:11} {method:6} {path}")

    for credit in credits:
        print(f"  {credit}")

    if findings:
        print(f"\nFAIL: the SDK surface disagrees with the spec or the manifest ({len(findings)} finding(s))")
        for finding in findings:
            print(f"  - {finding}")
        return 1

    reached = {endpoint for record in clients.values() for endpoint in record["endpoints"]}
    print(
        f"\nOK: {len(clients)} declared client(s), {parsed} endpoint(s) parsed, all present in {scanned['spec']}; "
        f"{len(scanned['manifest']['namespaces'])} namespace(s) either implemented or a recorded gap "
        f"({len(reached)} of {len(operations)} spec operations reached)"
    )
    return 0


# ─── Self-test ───────────────────────────────────────────────────────────────
#
# The empty-tree refusal comes from the toolkit. These are the cases only this
# gate can express: a violation of each rule it enforces, injected into a copy
# of the real manifest, because a gate that has never failed is not known to
# work.

_SPEC = """openapi: 3.1.0
paths:
  /api/v1/alerts:
    get:
      summary: List
  /api/v1/alerts/{alert_id}:
    get:
      summary: Get
components:
  schemas: {}
"""

_MANIFEST = {
    "spec": "docs/openapi.yaml",
    "clients": {
        "python": {"path": "client.py", "package": "pkg"},
        "go": {"path": None, "package": "pkg-go", "gap": "no HTTP client"},
    },
    "namespaces": {"alerts": {"prefixes": ["/api/v1/alerts"], "gaps": {"go": "no client"}}},
}


def _with_orphan_namespace() -> dict:
    """The manifest plus a namespace the client reaches nothing under."""
    manifest = json.loads(json.dumps(_MANIFEST))
    manifest["namespaces"]["orphan"] = {"prefixes": ["/api/v1/orphan"]}
    return manifest


def _tree(root: Path, spec: str, client: str, manifest: dict, extra: dict[str, str] | None = None) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)  # noqa: S603
    (root / "docs").mkdir(exist_ok=True)
    (root / "docs" / "openapi.yaml").write_text(spec, encoding="utf-8")
    (root / "client.py").write_text(client, encoding="utf-8")
    (root / MANIFEST).parent.mkdir(parents=True, exist_ok=True)
    (root / MANIFEST).write_text(json.dumps(manifest), encoding="utf-8")
    for relative, body in (extra or {}).items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)  # noqa: S603
    return root


def _verdict(root: Path) -> int:
    """``main`` over ``root`` with its output swallowed.

    The probes below care only about the exit status, and eight verdicts
    printed in full would bury the self-test's own result.
    """
    with contextlib.redirect_stdout(io.StringIO()):
        return main(["--repo-root", str(root)])


def _injected_cases(scratch: Path) -> list[tuple[str, bool]]:
    clean = 'x._get("/api/v1/alerts")\nx._get(f"/api/v1/alerts/{aid}")\n'
    codegen = json.dumps({"scripts": {"codegen": "openapi-typescript ../x.yaml -o src/openapi.d.ts"}})
    filled = json.loads(json.dumps(_MANIFEST))
    filled["namespaces"]["alerts"]["gaps"]["python"] = "not implemented"

    return [
        (
            "a client calling only declared operations passes",
            _verdict(_tree(scratch / "clean", _SPEC, clean, _MANIFEST)) == 0,
        ),
        (
            "endpoint-not-in-spec: a call to an operation the spec omits fails",
            _verdict(_tree(scratch / "absent", _SPEC, clean + 'x._delete("/api/v1/alerts/{aid}")\n', _MANIFEST)) == 1,
        ),
        (
            "namespace-regressed: a declared namespace no language reaches fails",
            _verdict(_tree(scratch / "regressed", _SPEC, clean, _with_orphan_namespace())) == 1,
        ),
        (
            "gap-filled: a recorded gap the language now implements fails",
            _verdict(_tree(scratch / "filled", _SPEC, clean, filled)) == 1,
        ),
        (
            "gap-filled: a recorded 'no Go client' gap fails once one imports net/http",
            _verdict(
                _tree(
                    scratch / "gogap",
                    _SPEC,
                    clean,
                    _MANIFEST,
                    extra={"pkg-go/aisoc/client.go": 'package aisoc\n\nimport "net/http"\n\nvar c *http.Client\n'},
                )
            )
            == 1,
        ),
        (
            "codegen-target-missing: a declared codegen output that is absent fails",
            _verdict(_tree(scratch / "codegen", _SPEC, clean, _MANIFEST, extra={"pkg/package.json": codegen})) == 1,
        ),
        (
            "a declared codegen output that exists passes",
            _verdict(
                _tree(
                    scratch / "codegen-ok",
                    _SPEC,
                    clean,
                    _MANIFEST,
                    extra={"pkg/package.json": codegen, "pkg/src/openapi.d.ts": "export type paths = Record<string, never>;\n"},
                )
            )
            == 0,
        ),
        (
            "a spec with no operations is refused rather than called clean",
            _verdict(_tree(scratch / "vacuous", "openapi: 3.1.0\npaths: {}\n", clean, _MANIFEST)) == 2,
        ),
    ]


if __name__ == "__main__":
    raise SystemExit(main())
