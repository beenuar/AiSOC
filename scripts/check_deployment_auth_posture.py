#!/usr/bin/env python3
"""Every documented way to start AiSOC produces a production-class posture.

Why this exists
---------------
The API resolves a request with no bearer token to a demo administrator when
three conditions hold, and the fix for that made two of them explicit. This
gate answers the remaining question, which is the one that actually bit:
*what do the documented paths produce?*

They produced the worst answer available. ``ENVIRONMENT`` defaulted to
``development`` in ``docker-compose.yml`` and in ``.env.example``, which
``scripts/ensure_env.py`` copies verbatim into ``.env`` on first run, so
``make up`` and both installers started a stack in a development-class
environment without anyone choosing one. ``AISOC_DEV_MODE`` defaulted to ``1``
on ten services. And ``docker-compose.prod.yml``, which sets all of it
correctly, was selected by nothing: the Makefile never passes ``-f`` and
neither installer mentions either variable.

So the defect was never in the code that reads these flags. It was that the
default value of a string decided whether a host was anonymous, and no test
asked what the default was.

What it checks
--------------
Statically, with no Docker, because a gate that needs a daemon does not run in
the jobs that matter. It resolves ``${VAR:-default}`` against the env file the
documented path uses, for every service in the compose file, and requires:

* no service resolves a development-class ``ENV`` or ``ENVIRONMENT``;
* no service resolves a truthy ``AISOC_DEV_MODE``;
* nothing sets ``AISOC_DEV_AUTH_BYPASS`` outside the dev overlay;
* every service that reads the bypass is told its published bind addresses,
  since a service that is never told cannot refuse;
* and, in the other direction, the dev overlay *does* set all three, so this
  cannot pass on a tree where the developer path was deleted rather than
  made explicit.

The last one matters more than it looks. Four of the five rules here are
satisfied by removing the feature, and a gate that can be satisfied by
deletion is not measuring what it claims to.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
import tempfile
from dataclasses import dataclass, field

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from gate_toolkit import SELF_TEST_FLAG, repo_root, self_test_main  # noqa: E402

#: Mirrors ``AUTH_BYPASS_ENVIRONMENTS`` in services/api/app/core/config.py.
#: Restated rather than imported because this gate runs on a bare interpreter
#: with no service on the path; `test_deployment_auth_posture.py` asserts the
#: two agree, so the copy cannot drift silently.
DEV_ENVIRONMENTS = frozenset({"development", "dev", "local", "demo"})

TRUTHY = frozenset({"1", "true", "yes", "on"})

#: The variable that enables the anonymous shim. Only the dev overlay may set
#: it, and it must.
BYPASS_VAR = "AISOC_DEV_AUTH_BYPASS"

#: The variable that tells a service where the deployment published it.
PUBLISHED_VAR = "AISOC_PUBLISHED_BIND_ADDRS"

#: The compose file every documented path starts from.
BASE_COMPOSE = "docker-compose.yml"

#: The overlay that turns the developer conveniences back on, deliberately.
DEV_OVERLAY = "infra/compose/docker-compose.dev.yml"

#: The env file `scripts/ensure_env.py` copies into `.env` on first run.
ENV_TEMPLATE = ".env.example"

#: Workflows exempt from the "generate the secrets before booting" rule,
#: with the reason. Only for a job that boots nothing real.
WORKFLOW_BOOT_EXEMPT: dict[str, str] = {}

#: Files that start the stack for a reader following the documentation.
#: Each is scanned for an assignment that would put a documented path back
#: into a development-class environment.
ENTRY_POINTS = ("Makefile", "install.sh", "install.ps1")


@dataclass
class Finding:
    where: str
    detail: str

    def render(self) -> str:
        return f"{self.where}: {self.detail}"


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    services_scanned: int = 0
    variables_resolved: int = 0


def _env_file_values(text: str) -> dict[str, str]:
    """The uncommented assignments in a dotenv file."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        values[key.strip()] = value.strip().strip("\"'")
    return values


_INTERPOLATION = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?-((?:[^{}]|\{[^{}]*\})*))?\}")


def resolve(expression: str, env: dict[str, str], depth: int = 0) -> str:
    """What compose would substitute, given ``env``.

    Handles the nested form the console binding uses,
    ``${AISOC_CONSOLE_BIND_ADDR:-${AISOC_BIND_ADDR:-127.0.0.1}}``, which is
    why this is a small recursive resolver rather than one regex pass.
    """
    if depth > 8:
        return expression

    def substitute(match: re.Match[str]) -> str:
        name, default = match.group(1), match.group(2)
        value = env.get(name, "")
        if value:
            return value
        return resolve(default or "", env, depth + 1)

    return _INTERPOLATION.sub(substitute, expression).strip()


def _compose_environments(text: str) -> dict[str, dict[str, str]]:
    """Each service's ``environment:`` block, as raw (unresolved) strings.

    A hand-rolled scan rather than a YAML parse: this gate has to run on a
    bare interpreter in jobs that install nothing, and the shape it needs is
    two levels of indentation under a known key.
    """
    services: dict[str, dict[str, str]] = {}
    current: str | None = None
    in_services = False
    in_environment = False
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if indent == 0:
            # A top-level key. Only `services:` holds services; counting the
            # entries under `volumes:` and `networks:` as well reported 45
            # where the file declares 32, and a gate whose corpus count is
            # wrong cannot be trusted when it says it scanned enough.
            in_services = line.strip().rstrip(":") == "services"
            current = None
            in_environment = False
            continue
        if not in_services:
            continue
        if indent == 2 and line.rstrip().endswith(":"):
            current = line.strip().rstrip(":")
            services.setdefault(current, {})
            in_environment = False
            continue
        if current is None:
            continue
        if indent == 4:
            in_environment = line.strip() == "environment:"
            continue
        if in_environment and indent >= 6 and ":" in line:
            key, _, value = line.strip().partition(":")
            services[current][key.strip()] = value.strip()
    return services


def _is_dev_environment(value: str) -> bool:
    return value.strip().lower() in DEV_ENVIRONMENTS


def _is_truthy(value: str) -> bool:
    return value.strip().lower() in TRUTHY


def inspect(root: pathlib.Path) -> Report:
    report = Report()
    compose_path = root / BASE_COMPOSE
    if not compose_path.is_file():
        return report

    compose = compose_path.read_text(encoding="utf-8", errors="replace")
    template = root / ENV_TEMPLATE
    env = _env_file_values(template.read_text(encoding="utf-8", errors="replace")) if template.is_file() else {}

    services = _compose_environments(compose)
    report.services_scanned = len(services)

    for service, variables in sorted(services.items()):
        for key in ("ENV", "ENVIRONMENT"):
            if key not in variables:
                continue
            report.variables_resolved += 1
            value = resolve(variables[key], env)
            if _is_dev_environment(value):
                report.findings.append(
                    Finding(
                        f"{BASE_COMPOSE} :: {service}",
                        f"{key} resolves to {value!r} with {ENV_TEMPLATE} as the env file, "
                        "which permits the anonymous auth shim. Default it to 'production' "
                        f"and put the development value in {DEV_OVERLAY}.",
                    )
                )

        if "AISOC_DEV_MODE" in variables:
            report.variables_resolved += 1
            value = resolve(variables["AISOC_DEV_MODE"], env)
            if _is_truthy(value):
                report.findings.append(
                    Finding(
                        f"{BASE_COMPOSE} :: {service}",
                        f"AISOC_DEV_MODE resolves to {value!r}. It selects several unrelated "
                        "development behaviours and must not be on by default.",
                    )
                )

        if BYPASS_VAR in variables:
            report.variables_resolved += 1
            value = resolve(variables[BYPASS_VAR], env)
            if _is_truthy(value):
                report.findings.append(
                    Finding(
                        f"{BASE_COMPOSE} :: {service}",
                        f"{BYPASS_VAR} resolves to {value!r}. Only {DEV_OVERLAY} may set it.",
                    )
                )

        # A service that reads the bypass has to know whether anyone else can
        # reach it. It binds 0.0.0.0 inside its container, so it cannot work
        # that out alone, and one that is never told cannot refuse.
        reads_bypass = "AISOC_DEV_MODE" in variables or "ENVIRONMENT" in variables or "ENV" in variables
        if reads_bypass and PUBLISHED_VAR not in variables:
            report.findings.append(
                Finding(
                    f"{BASE_COMPOSE} :: {service}",
                    f"reads the auth-bypass flags but is not given {PUBLISHED_VAR}, so it cannot refuse the bypass on a published address.",
                )
            )

    for name in ENTRY_POINTS:
        path = root / name
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in re.finditer(
            r"^[^#\n]*?\b(?:export\s+|\$env:)?(ENV|ENVIRONMENT|AISOC_DEV_MODE|AISOC_DEV_AUTH_BYPASS)\s*=\s*[\"']?([A-Za-z0-9_]+)",
            text,
            re.M,
        ):
            key, value = match.group(1), match.group(2)
            report.variables_resolved += 1
            bad = _is_dev_environment(value) if key in ("ENV", "ENVIRONMENT") else _is_truthy(value)
            if bad:
                line = text[: match.start()].count("\n") + 1
                report.findings.append(
                    Finding(
                        f"{name}:{line}",
                        f"sets {key}={value}, which puts a documented path into a development-class posture.",
                    )
                )

    # A workflow that boots the stack without generating secrets provisions an
    # environment no real deployment has. With ENVIRONMENT defaulting to
    # production, ingest refuses to start without JWT_SECRET and the API
    # refuses without METRICS_TOKEN — which is the services being right, and
    # exactly why a copied `.env.example` is no longer enough.
    workflows = root / ".github" / "workflows"
    if workflows.is_dir():
        for path in sorted(workflows.glob("*.yml")):
            text = path.read_text(encoding="utf-8", errors="replace")
            # Only a real invocation counts; the phrase appears in prose too.
            boots = any(
                line.strip().startswith(("docker compose", "- run: docker compose", "$(COMPOSE)"))
                and " up" in line
                and not line.lstrip().startswith("#")
                for line in text.splitlines()
            )
            if not boots:
                continue
            report.variables_resolved += 1
            if "ensure_env.py" in text or "make env" in text or "make up" in text:
                continue
            if path.name in WORKFLOW_BOOT_EXEMPT:
                continue
            report.findings.append(
                Finding(
                    f".github/workflows/{path.name}",
                    "boots the stack but never runs scripts/ensure_env.py, so it provisions "
                    "an environment with every generated secret empty. ingest refuses to "
                    "start without JWT_SECRET and the API without METRICS_TOKEN.",
                )
            )

    overlay = root / DEV_OVERLAY
    if not overlay.is_file():
        report.findings.append(
            Finding(
                DEV_OVERLAY,
                "the developer overlay is missing. Four of the five rules here are "
                "satisfied by deleting the developer path rather than making it "
                "explicit, so its absence is a finding.",
            )
        )
    else:
        text = overlay.read_text(encoding="utf-8", errors="replace")
        for required, predicate, description in (
            ("ENVIRONMENT", _is_dev_environment, "a development-class environment"),
            ("AISOC_DEV_MODE", _is_truthy, "AISOC_DEV_MODE on"),
            (BYPASS_VAR, _is_truthy, f"{BYPASS_VAR} on"),
        ):
            found = re.search(rf"^\s*{required}\s*:\s*[\"']?([^\"'\s#]+)", text, re.M)
            report.variables_resolved += 1
            if found is None or not predicate(found.group(1)):
                report.findings.append(
                    Finding(
                        DEV_OVERLAY,
                        f"does not set {description}. The overlay is what makes the "
                        "developer experience deliberate instead of default; without it "
                        "this gate would pass on a tree where the shim was simply removed.",
                    )
                )

    return report


def _verdict(report: Report) -> int:
    if report.services_scanned == 0:
        print(
            f"check_deployment_auth_posture: no services found in {BASE_COMPOSE} — refusing to report a tree with nothing in it as clean",
            file=sys.stderr,
        )
        return 2
    if report.variables_resolved == 0:
        print(
            "check_deployment_auth_posture: scanned "
            f"{report.services_scanned} service(s) and resolved no auth-posture variable at "
            "all. Either the compose file stopped declaring them or the scanner broke; "
            "both need a human.",
            file=sys.stderr,
        )
        return 2

    if report.findings:
        print(
            f"check_deployment_auth_posture: {len(report.findings)} documented path(s) produce a development-class posture:",
            file=sys.stderr,
        )
        for finding in report.findings:
            print(f"  {finding.render()}", file=sys.stderr)
        return 1

    print(
        f"check_deployment_auth_posture: OK — {report.variables_resolved} variable(s) across "
        f"{report.services_scanned} service(s); every documented path is production-class and "
        f"{DEV_OVERLAY} turns the developer conveniences back on deliberately."
    )
    return 0


# ── Self-test ───────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Case:
    description: str
    compose: str
    env_example: str = "ENVIRONMENT=production\n"
    overlay: str | None = None
    makefile: str = "up:\n\tdocker compose up -d\n"
    workflow: str | None = None
    expect: str | None = None


_GOOD_OVERLAY = f"services:\n  api:\n    environment:\n      ENVIRONMENT: development\n      AISOC_DEV_MODE: 1\n      {BYPASS_VAR}: 1\n"

_GOOD_COMPOSE = (
    "services:\n"
    "  api:\n"
    "    environment:\n"
    "      ENVIRONMENT: ${ENVIRONMENT:-production}\n"
    f"      {PUBLISHED_VAR}: ${{AISOC_BIND_ADDR:-127.0.0.1}}\n"
)


def self_test_cases() -> tuple[Case, ...]:
    return (
        Case(
            "the shipped default: ENVIRONMENT falls through to development",
            f"services:\n  api:\n    environment:\n      ENVIRONMENT: ${{ENVIRONMENT:-development}}\n      {PUBLISHED_VAR}: 127.0.0.1\n",
            # No ENVIRONMENT in the env file, so the compose fallback is what
            # the service sees. That is the case this rule is about, and an
            # earlier draft of it set the variable here, which made the
            # fallback unreachable and the case vacuous.
            env_example="POSTGRES_PASSWORD=x\n",
            overlay=_GOOD_OVERLAY,
            expect="resolves to 'development'",
        ),
        Case(
            "the env template supplying the development value, with a safe compose default",
            f"services:\n  api:\n    environment:\n      ENVIRONMENT: ${{ENVIRONMENT:-production}}\n      {PUBLISHED_VAR}: 127.0.0.1\n",
            env_example="ENVIRONMENT=development\n",
            overlay=_GOOD_OVERLAY,
            expect="resolves to 'development'",
        ),
        Case(
            "AISOC_DEV_MODE defaulting to 1",
            f"services:\n  fusion:\n    environment:\n      AISOC_DEV_MODE: ${{AISOC_DEV_MODE:-1}}\n      {PUBLISHED_VAR}: 127.0.0.1\n",
            overlay=_GOOD_OVERLAY,
            expect="AISOC_DEV_MODE resolves to '1'",
        ),
        Case(
            "the bypass flag set in the base compose file rather than the overlay",
            "services:\n  api:\n    environment:\n      ENVIRONMENT: production\n"
            f"      {BYPASS_VAR}: 1\n      {PUBLISHED_VAR}: 127.0.0.1\n",
            overlay=_GOOD_OVERLAY,
            expect=f"{BYPASS_VAR} resolves to '1'",
        ),
        Case(
            "a service that reads the flags but is never told where it is published",
            "services:\n  api:\n    environment:\n      ENVIRONMENT: ${ENVIRONMENT:-production}\n",
            overlay=_GOOD_OVERLAY,
            expect=f"not given {PUBLISHED_VAR}",
        ),
        Case(
            "an installer exporting a development environment",
            _GOOD_COMPOSE,
            overlay=_GOOD_OVERLAY,
            makefile="up:\n\texport ENVIRONMENT=development\n\tdocker compose up -d\n",
            expect="puts a documented path into a development-class posture",
        ),
        Case(
            "the developer overlay deleted rather than made explicit",
            _GOOD_COMPOSE,
            overlay=None,
            expect="the developer overlay is missing",
        ),
        Case(
            "an overlay that no longer turns the bypass on",
            _GOOD_COMPOSE,
            overlay="services:\n  api:\n    environment:\n      ENVIRONMENT: development\n      AISOC_DEV_MODE: 1\n",
            expect=f"does not set {BYPASS_VAR} on",
        ),
        # ── and the direction it must not fire in ───────────────────────────
        Case(
            "a production-class default with a deliberate developer overlay",
            _GOOD_COMPOSE,
            overlay=_GOOD_OVERLAY,
            expect=None,
        ),
        Case(
            "the nested console binding, which a single regex pass cannot resolve",
            "services:\n  api:\n    environment:\n      ENVIRONMENT: ${ENVIRONMENT:-production}\n"
            f"      {PUBLISHED_VAR}: ${{AISOC_CONSOLE_BIND_ADDR:-${{AISOC_BIND_ADDR:-127.0.0.1}}}}\n",
            overlay=_GOOD_OVERLAY,
            expect=None,
        ),
        Case(
            "a workflow that boots the stack without generating the secrets",
            _GOOD_COMPOSE,
            overlay=_GOOD_OVERLAY,
            workflow="jobs:\n  smoke:\n    steps:\n      - run: cp .env.example .env\n      - run: docker compose up -d\n",
            expect="never runs scripts/ensure_env.py",
        ),
        Case(
            "the same workflow, generating them",
            _GOOD_COMPOSE,
            overlay=_GOOD_OVERLAY,
            workflow="jobs:\n  smoke:\n    steps:\n      - run: python3 scripts/ensure_env.py\n      - run: docker compose up -d\n",
            expect=None,
        ),
        Case(
            "a workflow that only mentions the command in prose",
            _GOOD_COMPOSE,
            overlay=_GOOD_OVERLAY,
            workflow="# what `docker compose up -d` pulls for the console\njobs:\n  build:\n    steps:\n      - run: echo hi\n",
            expect=None,
        ),
        Case(
            "a comment mentioning ENVIRONMENT=development in an entry point",
            _GOOD_COMPOSE,
            overlay=_GOOD_OVERLAY,
            makefile="up:\n\t# ENVIRONMENT=development is the overlay's job\n\tdocker compose up -d\n",
            expect=None,
        ),
    )


def _case_results(tmp: pathlib.Path) -> list[tuple[str, bool]]:
    results: list[tuple[str, bool]] = []
    for index, case in enumerate(self_test_cases()):
        tree = tmp / f"case{index}"
        (tree / "infra" / "compose").mkdir(parents=True)
        (tree / BASE_COMPOSE).write_text(case.compose, encoding="utf-8")
        (tree / ENV_TEMPLATE).write_text(case.env_example, encoding="utf-8")
        (tree / "Makefile").write_text(case.makefile, encoding="utf-8")
        if case.overlay is not None:
            (tree / DEV_OVERLAY).write_text(case.overlay, encoding="utf-8")
        if case.workflow is not None:
            (tree / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
            (tree / ".github" / "workflows" / "probe.yml").write_text(case.workflow, encoding="utf-8")
        report = inspect(tree)
        blob = " | ".join(f.render() for f in report.findings)
        if case.expect is None:
            passed = not report.findings
            detail = f"expected nothing, got: {blob}" if not passed else ""
        else:
            passed = case.expect in blob
            detail = f"expected {case.expect!r}, got: {blob or '(nothing)'}" if not passed else ""
        results.append((f"{case.description}{f' — {detail}' if detail else ''}", passed))
    return results


def _corpus_result(root: pathlib.Path) -> tuple[str, bool]:
    report = inspect(root)
    return (
        f"counts what it scanned ({report.variables_resolved} variables across {report.services_scanned} services)",
        report.services_scanned > 0 and report.variables_resolved > 0,
    )


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="aisoc-posture-") as tmp:
        extra = _case_results(pathlib.Path(tmp))
    extra.append(_corpus_result(repo_root()))
    return self_test_main(pathlib.Path(__file__).name, ["--check"], extra)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="render a verdict (default)")
    parser.add_argument(SELF_TEST_FLAG, action="store_true", dest="self_test")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    return _verdict(inspect(repo_root()))


if __name__ == "__main__":
    raise SystemExit(main())
