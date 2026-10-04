#!/usr/bin/env python3
"""A service credential read by production code must be produced by first run.

The hole this closes
--------------------
``AISOC_AGENTS_SERVICE_TOKEN`` was read by eight modules in ``services/agents``
and one in ``services/api``, verified by ``alert_writeback.service_token_valid``
— which reads that variable and no other, with no fallback to the shared
``AISOC_SERVICE_TOKEN`` — and produced by **nothing**. It was absent from
``scripts/ensure_env.py``, from ``.env.example`` and from every compose
manifest. So on every default install:

* organisation memory (``/feedback/context-statements``)
* tenant skills (``/tenant-skills/resolved/active``)
* recent analyst dispositions (``/feedback/recent-dispositions``)
* identity context (``/graph/identity-context``)
* knowledge-base runbooks (``/kb/runbooks/for-triage``)
* the MCP toolset, the playbook action bridge and SIEM writeback

were off. Each reader logs its own ``no_service_token`` warning and returns an
empty result, and an empty result is indistinguishable from "this tenant has
none" at every surface above it.

Nothing failed. That is the shape worth gating: a credential whose absence
disables a capability quietly is exactly the credential nobody notices is
missing.

What is asserted
----------------
For every ``AISOC_*_SERVICE_TOKEN`` / ``*_INTERNAL_TOKEN`` variable that
production code under ``services/*/app/`` reads:

1. ``scripts/ensure_env.py`` generates it, or it is declared below as
   deliberately operator-supplied with a reason.
2. ``.env.example`` lists it, so an operator reading the template knows it
   exists.
3. Every compose service built from a source tree that reads it receives it
   in ``docker-compose.yml``. The source-tree-to-service mapping is derived
   from each service's ``build.context``, not hand-written, because a
   hand-written map is the thing that stops matching.

The direction that drifts is code gaining a reader, so that is the direction
this runs in: a new ``os.getenv("AISOC_FOO_SERVICE_TOKEN")`` fails here until
first run produces it and compose delivers it.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

#: The credential family. A shared secret two AiSOC processes present to each
#: other — as opposed to a vendor API key, which an operator supplies and no
#: amount of first-run generation can invent.
TOKEN_NAME_RE = re.compile(r"^[A-Z0-9_]*(?:SERVICE_TOKEN|INTERNAL_TOKEN)$")

#: Variables in the family that first run deliberately does not generate.
#: Each is a *narrowing override* of a token that is generated: setting one
#: replaces the shared secret for a single hop, which is an operator's choice
#: and meaningless to invent a value for.
#: Only variables a literal ``os.getenv("NAME")`` reads are listed. The
#: per-service overrides resolved through an f-string —
#: ``os.getenv(f"AISOC_{SERVICE_NAME}_SERVICE_TOKEN")`` in each service's
#: ``tenant_scope`` — are deliberately out of the literal scan's reach and
#: are not listed here: a row nothing reads is checked below and removed.
OPERATOR_SUPPLIED: dict[str, str] = {
    "AISOC_CONNECTORS_SERVICE_TOKEN": "per-service override for AISOC_SERVICE_TOKEN",
    "AISOC_THREATINTEL_SERVICE_TOKEN": "per-service override for AISOC_SERVICE_TOKEN",
    "AISOC_FUSION_SERVICE_TOKEN": "per-service override for AISOC_SERVICE_TOKEN",
    "AISOC_INGEST_SERVICE_TOKEN": "per-service override for AISOC_SERVICE_TOKEN",
    "AISOC_INTERNAL_TOKEN": "bearer for the opt-in chatops fan-out; unset means no ChatOps notification",
}

#: Service source trees whose compose delivery is not asserted, with the
#: reason. Kept as a named list so an exemption is a visible edit.
UNMAPPED_SOURCE_DIRS: dict[str, str] = {}

#: ``variable -> the per-service override that satisfies it``.
#:
#: Each service's ``tenant_scope.resolve_service_token`` prefers
#: ``AISOC_<SERVICE>_SERVICE_TOKEN`` and falls back to the shared
#: ``AISOC_SERVICE_TOKEN``, so delivering the override is delivering the
#: credential. Without this the gate would demand the shared secret on a
#: service that deliberately holds its own — `actions`, which can isolate a
#: host, is not supposed to share one with the read-mostly services.
SATISFIED_BY_OVERRIDE: dict[str, str] = {
    "AISOC_SERVICE_TOKEN": "AISOC_{SERVICE}_SERVICE_TOKEN",
}


def _readers(root: Path) -> dict[str, set[str]]:
    """``variable -> {service source directory}``, from the AST.

    AST rather than a regex over the text so a variable named in a docstring
    explaining the defect is not counted as a reader — the mistake this
    repository has made twice with text scans over compose files.
    """
    found: dict[str, set[str]] = {}
    services = root / "services"
    if not services.is_dir():
        return found
    for path in sorted(services.glob("*/app/**/*.py")):
        if "test" in path.parts:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        service_dir = path.relative_to(services).parts[0]
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            is_getenv = (isinstance(func, ast.Attribute) and func.attr == "getenv") or (isinstance(func, ast.Name) and func.id == "getenv")
            if not is_getenv or not node.args:
                continue
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str) and TOKEN_NAME_RE.match(first.value):
                found.setdefault(first.value, set()).add(service_dir)
    return found


#: Hostnames that only resolve inside the deployment's own network. A request
#: to one of these is a service-to-service call, and every route on the far
#: side authenticates.
INTERNAL_HOSTS: frozenset[str] = frozenset(
    {
        "api",
        "agents",
        "connectors",
        "actions",
        "fusion",
        "ingest",
        "enrichment",
        "threatintel",
        "realtime",
        "ueba",
        "purple-team",
        "honeytokens",
        "mcp",
        "slack-bot",
        "ingest-worker",
    }
)

#: Helpers whose name says they build a request's headers. A call to one is
#: resolved one level, into its own body, rather than assumed to be either
#: credentialed or not.
_HEADER_HELPER_RE = re.compile(r"(?:^|_)headers?$")


#: A settings attribute whose name ends this way holds the address of a peer
#: inside the deployment. ``settings.CONNECTORS_SERVICE_URL`` is as much a
#: statement that the target is internal as the literal ``http://connectors:``
#: is, and reading only literals missed the federated-search proxy entirely.
_INTERNAL_SETTING_RE = re.compile(r"^[A-Z0-9_]*(SERVICE_URL|_URL)$")


def _names_internal_host(node: ast.AST) -> bool:
    """Whether anything under ``node`` names a host inside the deployment."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            for host in INTERNAL_HOSTS:
                if f"//{host}:" in sub.value or f"//{host}/" in sub.value:
                    return True
        if isinstance(sub, ast.Attribute) and _INTERNAL_SETTING_RE.match(sub.attr):
            root_name = sub.value
            if isinstance(root_name, ast.Name) and root_name.id in {"settings", "config", "cfg"}:
                service = sub.attr.rsplit("_SERVICE_URL", 1)[0].rsplit("_URL", 1)[0].lower().replace("_", "-")
                if service in INTERNAL_HOSTS:
                    return True
    return False


def _url_is_internal(node: ast.AST, module: ast.Module) -> bool:
    """Whether this URL expression names a service inside the deployment.

    Two shapes reach here: a literal or f-string carrying ``//<host>:`` for one
    of :data:`INTERNAL_HOSTS`, and an f-string built from a helper call like
    ``_api_url()``, which is how every service here spells "the peer I am
    configured to reach".

    The helper is **resolved into its body** rather than matched on its name.
    Naming alone said that the Trellix connector's ``_alerts_url()`` was an
    internal peer, when it builds a customer's own vendor URL. A gate that
    reports a vendor call as an uncredentialed internal one teaches people to
    ignore it.
    """
    if _names_internal_host(node):
        return True

    # `url = _connectors_query_url(...)` then `client.post(url, ...)`. The
    # federated-search proxy is spelled exactly this way, and reading only the
    # argument expression saw a bare name and concluded nothing.
    if isinstance(node, ast.Name):
        for assign in ast.walk(module):
            if isinstance(assign, ast.Assign) and any(isinstance(t, ast.Name) and t.id == node.id for t in assign.targets):
                if _url_is_internal(assign.value, module):
                    return True
        return False

    for sub in ast.walk(node):
        if not isinstance(sub, ast.Call):
            continue
        func = sub.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        if not name:
            continue
        for defn in ast.walk(module):
            if isinstance(defn, ast.FunctionDef | ast.AsyncFunctionDef) and defn.name == name:
                if _names_internal_host(defn):
                    return True
    return False


def _carries_credential(call: ast.Call, module: ast.Module) -> bool:
    """Whether this request passes an Authorization header.

    Resolved one level through a ``_headers()``-shaped helper, because every
    service that does this correctly factors the credential into one, and a
    gate that only read the call site would report each of them as a finding.
    """
    headers = next((kw.value for kw in call.keywords if kw.arg == "headers"), None)
    if headers is None:
        return False

    if any(
        isinstance(sub, ast.Constant) and isinstance(sub.value, str) and sub.value.lower() == "authorization" for sub in ast.walk(headers)
    ):
        return True

    # `headers=_headers(tenant)` or `headers=self._auth_headers()`.
    if isinstance(headers, ast.Call):
        func = headers.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        if _HEADER_HELPER_RE.search(name):
            for node in ast.walk(module):
                if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == name:
                    if any(
                        isinstance(sub, ast.Constant) and isinstance(sub.value, str) and sub.value.lower() == "authorization"
                        for sub in ast.walk(node)
                    ):
                        return True
                    # A helper that delegates to the shared builder rather
                    # than spelling the header itself. One hop further,
                    # because consolidating three copies into one module is
                    # the fix, and a gate that then reports the consolidated
                    # callers would argue against its own remedy.
                    return any(
                        isinstance(sub, ast.Call)
                        and _HEADER_HELPER_RE.search(sub.func.attr if isinstance(sub.func, ast.Attribute) else getattr(sub.func, "id", ""))
                        for sub in ast.walk(node)
                    )
            # A helper this module does not define, named like a header
            # builder. Imported from somewhere that does build one.
            return True
    # `headers=dict(base, **extra)` and similar: a name we cannot resolve is
    # not evidence of a credential, but flagging every one of them would make
    # the gate unusable. Resolved names only.
    if isinstance(headers, ast.Name):
        for node in ast.walk(module):
            # `headers = {...}` and `headers["Authorization"] = ...` alike.
            # The second shape is how a caller adds the credential only when
            # it has one, and reading only the first reported the ingest
            # client as uncredentialed when it is not.
            if isinstance(node, ast.Assign) and any(
                (isinstance(t, ast.Name) and t.id == headers.id)
                or (isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name) and t.value.id == headers.id)
                for t in node.targets
            ):
                if any(
                    isinstance(sub, ast.Constant) and isinstance(sub.value, str) and sub.value.lower() == "authorization"
                    for sub in ast.walk(node)
                ):
                    return True
    return False


def _uncredentialed_internal_calls(root: Path) -> tuple[list[str], int]:
    """Service-to-service requests that carry no credential, and how many were read.

    The direction the older half of this gate could not run in. It asks
    whether a *variable* reaches a process; this asks whether the request that
    needed it carries one. Two defects shipped underneath that gap: eleven
    investigation pivots sent only ``X-Tenant-ID``, a header the API's auth
    does not read, and the federated-search proxy posted to the connectors
    service with no Authorization at all. Both were answered 401 on every
    deployment, and both read to the model and the console as "nothing found".
    """
    findings: list[str] = []
    examined = 0
    services = root / "services"
    if not services.is_dir():
        return findings, 0

    for path in sorted(services.glob("*/app/**/*.py")):
        if "test" in path.parts:
            continue
        try:
            module = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(module):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr not in {"get", "post", "put", "patch", "delete", "request", "stream"}:
                continue
            if not node.args:
                continue
            url = node.args[1] if node.func.attr in {"request", "stream"} and len(node.args) > 1 else node.args[0]
            if not _url_is_internal(url, module):
                continue
            examined += 1
            if _carries_credential(node, module):
                continue
            rel = path.relative_to(root)
            findings.append(
                f"{rel}:{node.lineno} calls a service inside the deployment and passes no Authorization header. "
                "Every route on the far side authenticates, so this is a 401 that reaches the caller as an "
                "empty result. Pass the service token and the tenant it is acting for."
            )
    return findings, examined


def _generated(root: Path) -> set[str]:
    """Keys of ``ensure_env.GENERATED``, read by AST.

    Importing would run the module, which is cheap but would also mean this
    gate could not report on a tree whose ``ensure_env.py`` does not import.
    """
    path = root / "scripts" / "ensure_env.py"
    if not path.exists():
        return set()
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        # Carried alongside the name rather than read back off `node`, which
        # `ast.walk` types as the base `AST`: the isinstance checks above narrow
        # inside their own branch and not after the if/elif closes.
        target: str | None = None
        assigned: ast.expr | None = None
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            target = node.target.id
            assigned = node.value
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target = node.targets[0].id
            assigned = node.value
        if target == "GENERATED" and isinstance(assigned, ast.Dict):
            return {k.value for k in assigned.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)}
    return set()


def _env_example_names(root: Path) -> set[str]:
    path = root / ".env.example"
    if not path.exists():
        return set()
    names = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip().lstrip("#").strip()
        name, sep, _ = line.partition("=")
        if sep and re.fullmatch(r"[A-Z][A-Z0-9_]*", name.strip()):
            names.add(name.strip())
    return names


def _compose_delivery(root: Path) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """``(source dir -> compose services, compose service -> variables it gets)``.

    The first map comes from each service's ``build.context``, so adding a
    second compose service for one source tree is covered without an edit
    here.
    """
    import yaml  # noqa: PLC0415 — the gate needs a YAML parser; the readers scan do not

    services = (yaml.safe_load((root / "docker-compose.yml").read_text(encoding="utf-8")) or {}).get("services") or {}
    by_source: dict[str, set[str]] = {}
    delivered: dict[str, set[str]] = {}
    for name, service in services.items():
        build = (service or {}).get("build")
        context = build.get("context") if isinstance(build, dict) else build
        if isinstance(context, str) and context.startswith("./services/"):
            by_source.setdefault(context.removeprefix("./services/").strip("/"), set()).add(name)
        environment = (service or {}).get("environment") or {}
        keys = environment.keys() if isinstance(environment, dict) else [str(e).partition("=")[0] for e in environment]
        delivered[name] = set(keys)
    return by_source, delivered


def check(root: Path | None = None) -> list[str]:
    root = root or repo_root()
    readers = _readers(root)
    if not readers:
        return [
            "scanned services/*/app and found no service-credential reader at all. "
            "A clean result over an empty scan is the failure this gate exists to prevent."
        ]

    generated = _generated(root)
    declared = _env_example_names(root)
    by_source, delivered = _compose_delivery(root)
    findings: list[str] = []

    for variable, source_dirs in sorted(readers.items()):
        where = ", ".join(f"services/{d}" for d in sorted(source_dirs))
        if variable not in generated and variable not in OPERATOR_SUPPLIED:
            findings.append(
                f"{variable} is read by {where} and produced by nothing. "
                "Add it to scripts/ensure_env.py::GENERATED, or to OPERATOR_SUPPLIED here with a reason."
            )
            continue
        if variable not in declared:
            findings.append(f"{variable} is read by {where} and is not listed in .env.example.")
        if variable in OPERATOR_SUPPLIED:
            continue
        for source_dir in sorted(source_dirs):
            if source_dir in UNMAPPED_SOURCE_DIRS:
                continue
            targets = by_source.get(source_dir)
            if not targets:
                findings.append(
                    f"services/{source_dir} reads {variable} and no compose service builds from it, "
                    "so nothing could deliver the value. Add it to UNMAPPED_SOURCE_DIRS with a reason if that is right."
                )
                continue
            override = SATISFIED_BY_OVERRIDE.get(variable)
            for target in sorted(targets):
                names = delivered.get(target, set())
                if variable in names:
                    continue
                if override and override.format(SERVICE=source_dir.replace("-", "_").upper()) in names:
                    continue
                findings.append(
                    f"compose service `{target}` builds services/{source_dir}, which reads {variable}, "
                    "and its `environment:` does not pass it — so the value cannot reach the process."
                )

    for variable, reason in sorted(OPERATOR_SUPPLIED.items()):
        if variable not in readers:
            findings.append(f"{variable} is declared operator-supplied ({reason}) and nothing reads it. Remove the row.")
    for source_dir, reason in sorted(UNMAPPED_SOURCE_DIRS.items()):
        if not (root / "services" / source_dir).is_dir():
            findings.append(f"services/{source_dir} is exempted ({reason}) and does not exist. Remove the row.")

    uncredentialed, examined = _uncredentialed_internal_calls(root)
    if examined == 0:
        findings.append(
            "scanned services/*/app and found no service-to-service HTTP call at all. "
            "A clean result over an empty scan is the failure this gate exists to prevent."
        )
    findings.extend(uncredentialed)

    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="render the verdict (default)")
    parser.parse_args(argv)

    root = repo_root()
    findings = check(root)
    readers = _readers(root)
    if findings:
        print(f"FAIL — {len(findings)} finding(s):", file=sys.stderr)
        for finding in findings:
            print(f"  - {finding}", file=sys.stderr)
        return 1
    _, examined = _uncredentialed_internal_calls(root)
    print(
        f"OK: {len(readers)} service credentials read by production code are all produced by first run "
        f"and delivered by compose, and all {examined} service-to-service request(s) carry one."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
