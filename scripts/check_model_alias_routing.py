#!/usr/bin/env python3
"""Every LLM call site resolves its model through a gateway alias.

Parity plan 2.5.

Why this exists
---------------
The gateway (`infra/litellm/config.yaml`) publishes `aisoc-<role>` aliases
so one deployment can run a hosted provider, another a local model, and a
third nothing at all, without any call site knowing which. A call site that
names a provider model directly defeats that for everybody.

It had, twice, and both failed the same way. The detection-tuning loop
passed `model="gpt-4o-mini"`, so on CORE it reached LiteLLM, which knows
the aliases and not that id, and every call answered `Invalid model name`
and fell through to the deterministic path. The NL-query route checked the
air-gap guard against a hardcoded `https://api.openai.com/...` rather than
the URL the request would use, so the guard was refusing a call that never
leaves the deployment.

Neither broke a test, because both degrade to a working deterministic
answer. That is the shape this gate is for: a model path that silently
never runs looks exactly like one that runs and is cautious.

What counts as a violation
--------------------------
A string literal naming a known hosted model, passed as a `model=` keyword
or a `"model":` dict key, in a non-test module under `services/`.

Deliberately not flagged: a price table keyed by model id, a test fixture,
a model name in prose or a comment, and `model_pins.py` / `model_aliases.py`
themselves, which exist to name concrete models.
"""

from __future__ import annotations

import argparse
import ast
import pathlib
import sys
from dataclasses import dataclass, field

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from gate_toolkit import SELF_TEST_FLAG, repo_root, self_test_main  # noqa: E402

#: Prefixes that identify a provider model rather than a gateway alias.
HOSTED_PREFIXES = (
    "gpt-",
    "o1-",
    "o3-",
    "claude-",
    "gemini-",
    "text-embedding-",
    "mistral-",
    "deepseek-",
)

#: Files whose job is to name concrete models. Each must still exist, so a
#: rename cannot leave a silent exemption behind.
ALLOWED_FILES = {
    "services/agents/app/llm/model_pins.py": "declares the pins an operator overrides",
    "services/api/app/services/model_aliases.py": "the resolver itself",
    "services/agents/app/llm/routing.py": "the agents-side resolver",
    "services/api/app/services/cost_dashboard.py": "a price table keyed by model id, not a call",
    "services/api/app/services/llm_resolver.py": "resolves a tenant's own BYOK model",
    "services/agents/app/security/llm_resolver.py": "resolves a tenant's own BYOK model",
}


@dataclass
class Report:
    scanned: int = 0
    call_sites: int = 0
    violations: list[tuple[str, int, str]] = field(default_factory=list)
    stale_allowlist: list[str] = field(default_factory=list)


def _is_test(path: pathlib.Path) -> bool:
    parts = path.parts
    return "tests" in parts or path.name.startswith("test_") or path.name.endswith("_test.py") or path.name == "conftest.py"


def _hosted(value: object) -> bool:
    return isinstance(value, str) and any(value.startswith(p) for p in HOSTED_PREFIXES)


def inspect(root: pathlib.Path) -> Report:
    report = Report()
    services = root / "services"
    if not services.is_dir():
        return report

    for path in sorted(services.rglob("*.py")):
        if _is_test(path) or "__pycache__" in path.parts:
            continue
        rel = path.relative_to(root).as_posix()
        if rel in ALLOWED_FILES:
            continue
        report.scanned += 1
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except (SyntaxError, OSError):
            continue

        for node in ast.walk(tree):
            # `f(model="gpt-4o-mini")`
            if isinstance(node, ast.Call):
                for keyword in node.keywords:
                    if keyword.arg != "model":
                        continue
                    report.call_sites += 1
                    if isinstance(keyword.value, ast.Constant) and _hosted(keyword.value.value):
                        report.violations.append((rel, node.lineno, str(keyword.value.value)))
            # `{"model": "gpt-4o-mini"}`
            elif isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values, strict=False):
                    if not (isinstance(key, ast.Constant) and key.value == "model"):
                        continue
                    report.call_sites += 1
                    if isinstance(value, ast.Constant) and _hosted(value.value):
                        report.violations.append((rel, node.lineno, str(value.value)))

    report.stale_allowlist = [rel for rel in ALLOWED_FILES if not (root / rel).is_file()]
    return report


def _verdict(report: Report) -> int:
    if report.scanned == 0:
        print(
            "check_model_alias_routing: scanned no service modules, so nothing was checked. That is a broken probe, not a clean tree.",
            file=sys.stderr,
        )
        return 2

    if report.stale_allowlist:
        print("check_model_alias_routing: allowlisted files that no longer exist:", file=sys.stderr)
        for rel in report.stale_allowlist:
            print(f"  {rel}", file=sys.stderr)
        return 1

    if report.violations:
        print(
            f"check_model_alias_routing: {len(report.violations)} call site(s) name a provider "
            "model directly rather than an `aisoc-<role>` gateway alias. On CORE the gateway "
            "answers `Invalid model name` and the caller degrades silently:",
            file=sys.stderr,
        )
        for rel, line, model in report.violations:
            print(f"  {rel}:{line}  model={model!r}", file=sys.stderr)
        print("Use `resolve_model_alias(<role>)` and add the role to infra/litellm/config.yaml.", file=sys.stderr)
        return 1

    print(
        f"check_model_alias_routing: OK — {report.call_sites} model argument(s) across "
        f"{report.scanned} module(s) resolve through a gateway alias; "
        f"{len(ALLOWED_FILES)} file(s) allowlisted with a reason."
    )
    return 0


def self_test() -> int:
    import tempfile

    extra: list[tuple[str, bool]] = []
    with tempfile.TemporaryDirectory(prefix="aisoc-alias-") as tmp:
        base = pathlib.Path(tmp) / "services" / "probe" / "app"
        base.mkdir(parents=True)
        (base / "bad.py").write_text('call(model="gpt-4o-mini")\n', encoding="utf-8")
        (base / "bad_dict.py").write_text('body = {"model": "claude-3-5-sonnet"}\n', encoding="utf-8")
        (base / "good.py").write_text('call(model=resolve_model_alias("triage"))\n', encoding="utf-8")
        (base / "also_good.py").write_text('call(model="aisoc-triage")\n', encoding="utf-8")
        tests = pathlib.Path(tmp) / "services" / "probe" / "tests"
        tests.mkdir(parents=True)
        (tests / "test_x.py").write_text('call(model="gpt-4o")\n', encoding="utf-8")

        report = inspect(pathlib.Path(tmp))
        flagged = {pathlib.Path(r).name for r, _, _ in report.violations}
        extra += [
            ("a hosted model in a model= keyword is flagged", "bad.py" in flagged),
            ("a hosted model in a model dict key is flagged", "bad_dict.py" in flagged),
            ("a resolved alias is not", "good.py" not in flagged),
            ("a literal aisoc- alias is not", "also_good.py" not in flagged),
            ("a test fixture is not", "test_x.py" not in flagged),
        ]

    report = inspect(repo_root())
    extra.append(
        (
            f"it read a real corpus ({report.scanned} modules, {report.call_sites} model arguments)",
            report.scanned > 100 and report.call_sites > 5,
        )
    )
    extra.append(("the real tree has no direct provider model", not report.violations))
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
