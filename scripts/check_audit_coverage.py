#!/usr/bin/env python3
"""The audit log can answer who did what, and with which credential.

Three properties, each of which was false.

**Attribution.** An API key owned by a user resolves to that user's email, so
an entry read `alice@corp.com deleted the rule` whether Alice did it at the
console or a key she minted a year ago did it from a script she no longer
runs. Those call for different responses — revoke a key, or disable a person
— and the log could not tell an investigator which had happened. Every
`emit_audit` call that names an actor must also pass `api_key_prefix`.

**Readership.** `tenant_admin` did not hold `audit_log:read`. Only
`platform_admin` and `admin` did, and both hold `*` across every tenant — so
on a multi-tenant deployment the only principals who could answer "who
changed this?" for a customer were the operator's own staff. SOC 2 CC7.2 and
ISO 27001 A.12.4 both require the control owner to review their own trail.

**Coverage.** Six endpoint modules emit audit out of roughly a hundred. This
gate does not pretend that is fixed — it measures it and ratchets, so the
number can only improve, and prints the modules that would most change the
figure rather than a bare count nobody can act on.

The ratchet is deliberately set at the measured value rather than at an
aspiration. A gate whose threshold the tree cannot meet gets disabled, and a
disabled gate is worth less than an honest one.
"""

from __future__ import annotations

import argparse
import ast
import pathlib
import sys
from dataclasses import dataclass, field

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from gate_toolkit import SELF_TEST_FLAG, repo_root, self_test_main  # noqa: E402

API_ROOT = "services/api"
ENDPOINTS = "services/api/app/api/v1/endpoints"

#: Methods that change state. A GET is a read; auditing every one of them
#: would bury the entries that matter under traffic.
MUTATING = frozenset({"post", "put", "patch", "delete"})

#: Reads that are audited anyway, because the read *is* the sensitive act:
#: running SQL against the tenant lake, and reading the audit log itself.
SENSITIVE_READ_MODULES = ("lake.py", "audit.py")

#: The floor, measured rather than aspired to. It may only rise.
MIN_AUDITING_MODULES = 7

#: Roles that must be able to read their own tenant's trail.
MUST_READ_AUDIT = ("tenant_admin",)


@dataclass
class Report:
    modules_total: int = 0
    modules_auditing: int = 0
    unattributed: list[str] = field(default_factory=list)
    missing_readers: list[str] = field(default_factory=list)
    unaudited_sensitive_reads: list[str] = field(default_factory=list)
    biggest_gaps: list[tuple[str, int]] = field(default_factory=list)


def _endpoint_modules(root: pathlib.Path) -> list[pathlib.Path]:
    directory = root / ENDPOINTS
    if not directory.is_dir():
        return []
    return sorted(p for p in directory.glob("*.py") if p.name != "__init__.py")


def _mutating_route_count(tree: ast.Module) -> int:
    count = 0
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            call = decorator if isinstance(decorator, ast.Call) else None
            func = call.func if call else decorator
            if isinstance(func, ast.Attribute) and func.attr in MUTATING:
                count += 1
                break
    return count


def _unattributed_calls(tree: ast.Module, rel: str) -> list[str]:
    """`emit_audit` calls that name an actor but not the credential."""
    offenders = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if getattr(node.func, "id", getattr(node.func, "attr", "")) != "emit_audit":
            continue
        kwargs = {k.arg for k in node.keywords if k.arg}
        # A call with no actor at all is a system event; it has no credential
        # to record and must not be reported as missing one.
        if not kwargs & {"actor_id", "actor_email"}:
            continue
        if "api_key_prefix" in kwargs or _actor_names_its_scheme(node):
            continue
        offenders.append(f"{rel}:{node.lineno}")
    return offenders


#: Prefixes that make an actor self-attributing. `scim:acme-idp` already
#: says which credential acted, so demanding `api_key_prefix` beside it
#: would be asking for a field that does not apply — the SCIM path has no
#: API key. Reported as a false positive by the gate's first run.
SELF_ATTRIBUTING_PREFIXES = ("scim:", "api-key:", "service:", "system:", "webhook:")


def _actor_names_its_scheme(call: ast.Call) -> bool:
    """True when `actor_email` begins with a literal credential scheme."""
    for keyword in call.keywords:
        if keyword.arg != "actor_email":
            continue
        value = keyword.value
        # An f-string's leading literal is its first JoinedStr part.
        if isinstance(value, ast.JoinedStr) and value.values:
            head = value.values[0]
            if isinstance(head, ast.Constant) and isinstance(head.value, str):
                return head.value.startswith(SELF_ATTRIBUTING_PREFIXES)
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            return value.value.startswith(SELF_ATTRIBUTING_PREFIXES)
    return False


def _roles_reading_audit(root: pathlib.Path) -> set[str]:
    """Parsed from the role map rather than imported.

    Importing would need the service's whole dependency set on `sys.path`,
    and the question is about the file this repository ships.
    """
    path = root / API_ROOT / "app" / "core" / "security.py"
    if not path.is_file():
        return set()
    tree = ast.parse(path.read_text(encoding="utf-8"))
    holders: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        for key, value in zip(node.keys, node.values, strict=False):
            if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                continue
            if not isinstance(value, ast.List):
                continue
            perms = {e.value for e in value.elts if isinstance(e, ast.Constant)}
            if "*" in perms or "audit_log:read" in perms:
                holders.add(key.value)
    return holders


def inspect(root: pathlib.Path) -> Report:
    report = Report()
    gaps: list[tuple[str, int]] = []

    for path in _endpoint_modules(root):
        rel = path.relative_to(root).as_posix()
        source = path.read_text(encoding="utf-8", errors="replace")
        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue
        report.modules_total += 1
        audits = "emit_audit(" in source
        if audits:
            report.modules_auditing += 1
            report.unattributed.extend(_unattributed_calls(tree, rel))
        else:
            mutating = _mutating_route_count(tree)
            if mutating:
                gaps.append((rel, mutating))

        if path.name in SENSITIVE_READ_MODULES and not audits:
            report.unaudited_sensitive_reads.append(rel)

    report.biggest_gaps = sorted(gaps, key=lambda pair: -pair[1])[:8]
    holders = _roles_reading_audit(root)
    report.missing_readers = [role for role in MUST_READ_AUDIT if role not in holders]
    return report


def _verdict(report: Report) -> int:
    if report.modules_total == 0:
        print(
            "check_audit_coverage: no endpoint modules found — refusing to report a tree with nothing in it as clean",
            file=sys.stderr,
        )
        return 2

    failed = False

    if report.unattributed:
        print(
            "check_audit_coverage: emit_audit call(s) that name an actor but not the "
            "credential, so the entry cannot distinguish a session from an API key:",
            file=sys.stderr,
        )
        for site in report.unattributed:
            print(f"  {site}", file=sys.stderr)
        failed = True

    if report.missing_readers:
        print(
            f"check_audit_coverage: {', '.join(report.missing_readers)} cannot read their own "
            "tenant's audit log. The read is tenant-scoped at the query layer, so granting "
            "`audit_log:read` shows them their own history and nothing else.",
            file=sys.stderr,
        )
        failed = True

    if report.unaudited_sensitive_reads:
        print(
            "check_audit_coverage: module(s) whose *reads* are the sensitive act and which "
            f"emit no audit: {', '.join(report.unaudited_sensitive_reads)}",
            file=sys.stderr,
        )
        failed = True

    if report.modules_auditing < MIN_AUDITING_MODULES:
        print(
            f"check_audit_coverage: {report.modules_auditing} endpoint module(s) emit audit, "
            f"below the ratchet of {MIN_AUDITING_MODULES}. The floor may only rise.",
            file=sys.stderr,
        )
        failed = True

    if failed:
        return 1

    print(
        f"check_audit_coverage: OK — {report.modules_auditing} of {report.modules_total} "
        f"endpoint module(s) emit audit (floor {MIN_AUDITING_MODULES}); every actor-bearing "
        f"call records the credential; {', '.join(MUST_READ_AUDIT)} can read their own trail."
    )
    if report.biggest_gaps:
        # Printed on success as well. A bare ratchet tells nobody where to
        # go next, and this figure is low enough that "where next" is the
        # useful output.
        print("  Largest unaudited surfaces, by state-changing route count:")
        for rel, count in report.biggest_gaps:
            print(f"    {count:3}  {rel}")
    return 0


def self_test() -> int:
    import tempfile

    extra: list[tuple[str, bool]] = []

    with tempfile.TemporaryDirectory(prefix="aisoc-audit-gate-") as tmp:
        base = pathlib.Path(tmp)
        endpoints = base / ENDPOINTS
        endpoints.mkdir(parents=True)
        (base / API_ROOT / "app" / "core").mkdir(parents=True)
        (base / API_ROOT / "app" / "core" / "security.py").write_text(
            'ROLE_PERMISSIONS = {"tenant_admin": ["audit_log:read"]}\n', encoding="utf-8"
        )

        (endpoints / "a.py").write_text("async def go():\n    await emit_audit(actor_id=u.id, action='x')\n", encoding="utf-8")
        report = inspect(base)
        extra.append(("detects an actor-bearing call with no credential", bool(report.unattributed)))

        (endpoints / "a.py").write_text(
            "async def go():\n    await emit_audit(actor_id=u.id, action='x', api_key_prefix=u.api_key_prefix)\n",
            encoding="utf-8",
        )
        report = inspect(base)
        extra.append(("accepts one that records it", not report.unattributed))

        (endpoints / "a.py").write_text("async def go():\n    await emit_audit(action='system.rotate')\n", encoding="utf-8")
        report = inspect(base)
        extra.append(
            (
                "does not fault a system event, which has no credential to record",
                not report.unattributed,
            )
        )

        (base / API_ROOT / "app" / "core" / "security.py").write_text(
            'ROLE_PERMISSIONS = {"tenant_admin": ["alerts:read"]}\n', encoding="utf-8"
        )
        report = inspect(base)
        extra.append(("detects a tenant_admin who cannot read their own trail", bool(report.missing_readers)))

        (base / API_ROOT / "app" / "core" / "security.py").write_text('ROLE_PERMISSIONS = {"tenant_admin": ["*"]}\n', encoding="utf-8")
        report = inspect(base)
        extra.append(("accepts a wildcard as covering it", not report.missing_readers))

    # And against the real tree, so an empty corpus cannot pass.
    report = inspect(repo_root())
    extra.append(
        (
            f"counts what it scanned ({report.modules_auditing} of {report.modules_total} modules)",
            report.modules_total > 50,
        )
    )
    return self_test_main(pathlib.Path(__file__).name, ["--check"], extra)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument(SELF_TEST_FLAG, action="store_true", dest="self_test")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    return _verdict(inspect(repo_root()))


if __name__ == "__main__":
    raise SystemExit(main())
