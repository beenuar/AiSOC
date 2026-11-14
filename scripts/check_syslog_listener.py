#!/usr/bin/env python3
"""The syslog listener has to be reachable, wired, and tenant-safe.

Depth plan 4.2. Before this, AiSOC's only syslog path was
``POST /v1/inbox/cef``, which needs something in front of it that already
speaks HTTP — so the appliance could not reach AiSOC, only a forwarder
could. The listener closes that, and three of its properties are the kind
this repository keeps rediscovering the absence of:

**It is wired.** A package that parses four formats perfectly and is
constructed by nothing is indistinguishable from a feature until someone
traces the call graph. ``main.go`` has to construct it *and* start it.

**Readiness names it.** A receiver is legitimately silent for hours, so
"no messages" proves nothing either way — a listener that failed to bind
and one nobody is sending to look identical unless readiness says which.

**The tenant comes from a credential.** Syslog carries no authenticated
principal and no header, so anything read off the wire is sender-
controlled. A tenant taken from a hostname, an app name or a structured-
data parameter is a cross-tenant write that needs no attacker effort at
all. The sink must read it from the resolved token and from nowhere else.

Plus the mechanical half: all four formats are actually distinguished, and
both templates the listener projects through exist and are mintable.

Parsed with ``ast`` and plain text rather than by running Go, because this
runs in the lint job where no Go toolchain is installed — and a gate that
skips when it cannot find a compiler is a gate that silently stops
checking.

Usage:
    python3 scripts/check_syslog_listener.py
    python3 scripts/check_syslog_listener.py --self-test
"""

from __future__ import annotations

import argparse
import ast
import re
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import TREE_SHAPES, refuses_an_empty_tree, repo_root  # noqa: E402

REPO_ROOT = repo_root()

SYSLOG_PKG = Path("services/ingest/internal/syslog")
MAIN_GO = Path("services/ingest/main.go")
TEMPLATE_DIR = Path("services/ingest/internal/normalizer/templates")
INBOX_ENDPOINT = Path("services/api/app/api/v1/endpoints/inbox.py")

#: The four the plan names, with the constant each is declared as. A parser
#: that collapses two of them into one is the defect: a LEEF 2.0 line read
#: with CEF's rules yields a record that looks structurally fine and has
#: every attribute in one key.
REQUIRED_FORMATS: dict[str, str] = {
    "RFC 5424": "FormatRFC5424",
    "RFC 3164": "FormatRFC3164",
    "CEF": "FormatCEF",
    "LEEF": "FormatLEEF",
}

#: Templates the listener projects through. Named here rather than derived,
#: because deriving them from the sink would make the gate agree with
#: whatever the sink happens to say.
REQUIRED_TEMPLATES = ("syslog", "cef-syslog", "leef-syslog")

#: Fields a sender controls. None of them may reach the tenant.
SENDER_CONTROLLED = ("Hostname", "AppName", "ProcID", "MsgID", "Message", "StructuredData", "Extension", "Raw")


def _read(root: Path, rel: Path) -> str:
    path = root / rel
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _go_sources(root: Path) -> str:
    """Every non-test Go file in the syslog package, concatenated."""
    directory = root / SYSLOG_PKG
    if not directory.is_dir():
        return ""
    parts = [p.read_text(encoding="utf-8", errors="replace") for p in sorted(directory.glob("*.go")) if not p.name.endswith("_test.go")]
    return "\n".join(parts)


def _strip_go_comments(source: str) -> str:
    """Comments out, so a gate does not match its own explanation.

    The listener's own comments quote the field names this gate forbids —
    they say *why* the tenant does not come from them — and a checker that
    cannot tell code from prose about the code fires on the documentation.
    """
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    return "\n".join(re.sub(r"//.*$", "", line) for line in source.splitlines())


def _mintable_ids(root: Path) -> set[str]:
    source = _read(root, INBOX_ENDPOINT)
    if not source:
        return set()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets: list[ast.expr] = list(node.targets)
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        for target in targets:
            if isinstance(target, ast.Name) and target.id == "ALLOWED_TEMPLATE_IDS" and isinstance(node.value, ast.Tuple):
                return {e.value for e in node.value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)}
    return set()


def evaluate(root: Path) -> list[str]:
    failures: list[str] = []

    sources = _go_sources(root)
    if not sources.strip():
        failures.append(
            f"no Go sources under {SYSLOG_PKG}. The only syslog path is then POST /v1/inbox/cef, which needs a "
            f"forwarder that already speaks HTTP — so an appliance cannot reach AiSOC, only something in front of it can."
        )
        return failures

    code = _strip_go_comments(sources)

    # 1. All four formats are distinguished. The constant existing is not
    # enough — it is declared in one file and assigned in another, and a
    # parser that stopped *reaching* a branch still mentions its name.
    for label, constant in REQUIRED_FORMATS.items():
        if not re.search(rf"Format\s*=\s*{constant}\b", code):
            failures.append(
                f"{label} is never assigned ({constant} appears in no `Format = ...` in {SYSLOG_PKG}). "
                f"A parser that collapses two of the four formats produces records that look structurally "
                f"fine and are wrong in every field."
            )

    # 2. Wired into the service, constructed *and* started.
    main_go = _strip_go_comments(_read(root, MAIN_GO))
    if not main_go:
        failures.append(f"{MAIN_GO} is not readable, so nothing can be said about whether the listener runs.")
    else:
        if "syslog.New(" not in main_go:
            failures.append(
                f"{MAIN_GO} never calls syslog.New. A package that parses four formats perfectly and is "
                f"constructed by nothing is indistinguishable from a feature until someone traces the call graph."
            )
        if not re.search(r"syslogListener\.Start\(", main_go):
            failures.append(f"{MAIN_GO} constructs the listener but never starts it, so no socket is ever read.")
        if not re.search(r"RegisterSubscription\(\s*\"syslog\"", main_go):
            failures.append(
                f"{MAIN_GO} does not register the listener with /readyz. A receiver is legitimately silent for "
                f"hours, so a listener that failed to bind and one nobody is sending to are indistinguishable "
                f"unless readiness names it."
            )

    # 3. The tenant comes from the credential.
    sink = _strip_go_comments(_read(root, SYSLOG_PKG / "sink.go"))
    if not sink:
        failures.append(f"{SYSLOG_PKG}/sink.go is missing, so there is nothing resolving a tenant for the listener.")
    else:
        if "tok.TenantID" not in sink:
            failures.append(
                f"{SYSLOG_PKG}/sink.go does not read the tenant from the resolved token. Syslog carries no "
                f"authenticated principal and no header, so the token is the only thing a sender does not control."
            )
        # Three syntaxes, because Go offers three and a detector that knows
        # one reports OK over the other two. This gate shipped knowing only
        # the first: a runtime negative control that moved the tenant to
        # `msg.Hostname` through a struct field and a call argument passed
        # it cleanly while the published event carried the sender's value.
        tenant_sinks = (
            # tenantID := msg.Hostname  /  tenantID = msg.Hostname
            r"[Tt]enant\w*\s*:?=\s*[^\n]*\bmsg\.{field}\b",
            # TenantID: msg.Hostname   (a struct literal field)
            r"TenantID\s*:\s*[^\n,]*\bmsg\.{field}\b",
            # tmpl.Apply(fields, msg.Hostname, ...) — the tenant is Apply's
            # second argument, so anything derived from the message there is
            # the tenant whatever the local variable is called.
            r"\.Apply\([^\n]*\bmsg\.{field}\b",
        )
        for field in SENDER_CONTROLLED:
            for pattern in tenant_sinks:
                if re.search(pattern.format(field=field), sink):
                    failures.append(
                        f"{SYSLOG_PKG}/sink.go derives the tenant from msg.{field}, which the sender controls. "
                        f"That is a cross-tenant write requiring no attacker effort at all."
                    )
                    break

    # 4. The templates it projects through exist and are mintable.
    mintable = _mintable_ids(root)
    for template in REQUIRED_TEMPLATES:
        if not (root / TEMPLATE_DIR / f"{template}.yaml").is_file():
            failures.append(
                f"{TEMPLATE_DIR}/{template}.yaml is missing, so messages of that format cannot be normalised "
                f"and the listener refuses the whole batch rather than filing them under the wrong vendor."
            )
        if mintable and template not in mintable:
            failures.append(
                f"'{template}' is not in ALLOWED_TEMPLATE_IDS ({INBOX_ENDPOINT}), so no token can be minted for it "
                f"and an operator following the setup guide gets a 400."
            )

    return failures


def _self_test() -> int:
    results: list[tuple[str, bool]] = []

    baseline = evaluate(REPO_ROOT)
    results.append(("the undisturbed tree is clean, so a caught case means something", not baseline))
    for line in baseline[:6]:
        print(f"        {line}")

    cases = (
        ("a parser that stopped distinguishing LEEF from CEF", "FORMAT"),
        ("a listener nothing constructs", "UNWIRED"),
        ("a listener constructed but never started", "UNSTARTED"),
        ("a listener readiness does not name", "UNPROBED"),
        ("a tenant assigned from a sender-controlled field", "TENANT_ASSIGN"),
        ("a tenant set through a struct literal field", "TENANT_STRUCT"),
        ("a tenant passed straight into the template's tenant argument", "TENANT_ARG"),
        ("a template the listener projects through that nothing ships", "TEMPLATE"),
        ("a template no token can be minted for", "UNMINTABLE"),
    )

    for label, kind in cases:
        tmp = Path(tempfile.mkdtemp(prefix="aisoc-syslog-selftest-"))
        try:
            for rel in (SYSLOG_PKG, TEMPLATE_DIR, MAIN_GO.parent, INBOX_ENDPOINT.parent):
                src = REPO_ROOT / rel
                if src.is_dir():
                    shutil.copytree(src, tmp / rel, dirs_exist_ok=True)
            kv = tmp / SYSLOG_PKG / "kv.go"
            main_go = tmp / MAIN_GO
            sink = tmp / SYSLOG_PKG / "sink.go"

            if kind == "FORMAT" and kv.is_file():
                kv.write_text(kv.read_text(encoding="utf-8").replace("FormatLEEF", "FormatCEF"), encoding="utf-8")
            elif kind == "UNWIRED" and main_go.is_file():
                main_go.write_text(main_go.read_text(encoding="utf-8").replace("syslog.New(", "syslogDisabled("), encoding="utf-8")
            elif kind == "UNSTARTED" and main_go.is_file():
                main_go.write_text(
                    main_go.read_text(encoding="utf-8").replace("syslogListener.Start(ctx)", "_ = syslogListener"), encoding="utf-8"
                )
            elif kind == "UNPROBED" and main_go.is_file():
                main_go.write_text(
                    main_go.read_text(encoding="utf-8").replace('h.RegisterSubscription("syslog"', 'noop("syslog"'),
                    encoding="utf-8",
                )
            elif kind == "TENANT_ASSIGN" and sink.is_file():
                sink.write_text(
                    sink.read_text(encoding="utf-8").replace("tenantID := tok.TenantID.String()", "tenantID := msg.Hostname"),
                    encoding="utf-8",
                )
            elif kind == "TENANT_STRUCT" and sink.is_file():
                sink.write_text(
                    sink.read_text(encoding="utf-8").replace("TenantID:             tenantID,", "TenantID:             msg.Hostname,"),
                    encoding="utf-8",
                )
            elif kind == "TENANT_ARG" and sink.is_file():
                sink.write_text(
                    sink.read_text(encoding="utf-8").replace(
                        "tmpl.Apply(msg.Fields(), tenantID, connectorRef, receivedAt)",
                        "tmpl.Apply(msg.Fields(), msg.Hostname, connectorRef, receivedAt)",
                    ),
                    encoding="utf-8",
                )
            elif kind == "TEMPLATE":
                (tmp / TEMPLATE_DIR / "leef-syslog.yaml").unlink(missing_ok=True)
            elif kind == "UNMINTABLE":
                endpoint = tmp / INBOX_ENDPOINT
                endpoint.write_text(endpoint.read_text(encoding="utf-8").replace('    "leef-syslog",\n', "", 1), encoding="utf-8")

            results.append((f"catches {label}", bool(evaluate(tmp))))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    details: list[str] = []
    for shape in TREE_SHAPES:
        refused, detail = refuses_an_empty_tree(Path(__file__).name, shape=shape)
        results.append((f"refuses a {shape} tree rather than reporting it clean", refused))
        details.append(f"{shape}: {detail}")

    ok = True
    for description, passed in results:
        ok &= passed
        print(f"  {'PASS' if passed else 'FAIL'}  {description}")
    for line in "\n".join(details).splitlines():
        print(f"        {line}")
    print()
    if not ok:
        print(f"{Path(__file__).name}: self-test FAILED")
        return 1
    print(f"{Path(__file__).name}: self-test OK")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--self-test", action="store_true", help="inject one violation per rule and require each to be caught")
    args = parser.parse_args()
    if args.self_test:
        return _self_test()

    if not (REPO_ROOT / MAIN_GO).is_file():
        print(f"check_syslog_listener: {MAIN_GO} is not there — nothing to render a verdict about.", file=sys.stderr)
        return 2

    failures = evaluate(REPO_ROOT)
    if failures:
        print("The syslog listener (depth plan 4.2) is incomplete:\n", file=sys.stderr)
        for line in failures:
            print(f"  - {line}", file=sys.stderr)
        print(f"\n{len(failures)} problem(s).", file=sys.stderr)
        return 1

    print(
        f"OK — the syslog listener reads {len(REQUIRED_FORMATS)} wire formats, is started by the service, "
        f"is named by /readyz, takes its tenant from a minted token, and projects through "
        f"{len(REQUIRED_TEMPLATES)} shipped templates."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
