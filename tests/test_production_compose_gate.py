"""`docker-compose.prod.yml` must be production by construction.

Discussion #629 reported that the deployment page pointed at a production
compose file that did not exist, so the only stack an operator could start was
the development one — where `ENVIRONMENT` defaults to `development`,
`development` is in `AUTH_BYPASS_ENVIRONMENTS`, and `dev_auth.py` resolves an
unauthenticated request to a demo user whose role is `admin`.

A file that merely *documents* the right settings would have the same problem
one release later. These assertions are about the file rather than the docs:
the bypass must be unreachable, no service may start on a credential published
in this repository, and no datastore may be bound to the host.

Every assertion is run against `docker-compose.yml` as well, which must fail
them. That is what distinguishes these from a test that would pass on an empty
file.
"""

from __future__ import annotations

import ast
import importlib.util
import os
import pathlib
import re
import subprocess
import sys

import pytest
import yaml

REPO = pathlib.Path(__file__).resolve().parents[1]
PROD = REPO / "docker-compose.prod.yml"
DEV = REPO / "docker-compose.yml"

#: Mirrors AUTH_BYPASS_ENVIRONMENTS and DEV_ENVIRONMENTS. Any of these in
#: ENV/ENVIRONMENT/APP_ENV relaxes an auth or secret requirement somewhere.
DEV_ENVIRONMENTS = frozenset({"development", "dev", "local", "demo", "test"})

#: Stores that must never be reachable from the host in production. The
#: development file binds each to 127.0.0.1, which is right there and wrong
#: here.
DATASTORES = ("postgres", "redis", "kafka", "zookeeper", "qdrant", "neo4j", "clickhouse", "opensearch")


class _ComposeLoader(yaml.SafeLoader):
    """Understands `!reset` and `!override`, which the production file needs."""


def _strip_tag(loader, node):  # noqa: ANN001, ANN202 - loader plumbing
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node, deep=True)
    return loader.construct_scalar(node)


for _tag in ("!reset", "!override"):
    _ComposeLoader.add_constructor(_tag, _strip_tag)


def _services(path: pathlib.Path) -> dict:
    return (yaml.load(path.read_text(encoding="utf-8"), Loader=_ComposeLoader) or {}).get("services") or {}  # noqa: S506


def _env_items(service: dict) -> list[tuple[str, str]]:
    """`environment:` as pairs, accepting either shape Compose allows."""
    env = (service or {}).get("environment") or {}
    if isinstance(env, dict):
        return [(str(k), str(v)) for k, v in env.items()]
    pairs = []
    for entry in env:
        key, _, value = str(entry).partition("=")
        pairs.append((key, value))
    return pairs


#: `${VAR:-default}` — the default is what a deployment with no `.env` gets.
_DEFAULTED = re.compile(r"^\$\{[A-Z_]+:-([^}]*)\}$")


def _resolves_to_dev(value: str) -> bool:
    """True if this value is dev-class with no environment set.

    Both spellings count. A literal `development` is dev-class, and so is
    `${ENVIRONMENT:-development}` on a host with nothing exported — which is
    the state the development stack is designed to start in, and the state a
    production stack must not be able to reach.
    """
    raw = value.strip()
    match = _DEFAULTED.match(raw)
    candidate = match.group(1) if match else raw
    return candidate.strip().lower() in DEV_ENVIRONMENTS


def _dev_environments(services: dict) -> list[str]:
    found = []
    for name, service in services.items():
        for key, value in _env_items(service):
            if key in ("ENV", "ENVIRONMENT", "APP_ENV") and _resolves_to_dev(value):
                found.append(f"{name}:{key}={value}")
    return found


def _published_datastores(services: dict) -> list[str]:
    return [name for name in DATASTORES if (services.get(name) or {}).get("ports")]


def _unguarded_secrets(services: dict) -> list[str]:
    """Secret-shaped variables that carry a default instead of demanding a value.

    `${VAR:?message}` makes Compose refuse to start and name the variable.
    `${VAR:-default}` starts on the default, which for this repository means a
    literal anyone can read in the development file.
    """
    pattern = re.compile(r"\$\{([A-Z_]*(?:PASSWORD|SECRET|TOKEN|KEY)[A-Z_]*):-")
    found = []
    for name, service in services.items():
        for key, value in _env_items(service):
            for variable in pattern.findall(str(value)):
                found.append(f"{name}:{key} defaults {variable}")
        command = (service or {}).get("command")
        if command:
            for variable in pattern.findall(str(command)):
                found.append(f"{name}:command defaults {variable}")
    return found


@pytest.fixture(scope="module")
def prod() -> dict:
    assert PROD.is_file(), (
        "docker-compose.prod.yml does not exist. apps/docs/docs/deployment/docker.md "
        "has told operators to run it since the page was written (discussion #629)."
    )
    return _services(PROD)


class TestTheDocumentedCommandIsTheOneThatWorks:
    """The deployment page and this file must name the same invocation.

    The production stack was written with `include:` and a single `-f`, which
    resolves on Compose 5.x and is rejected by 2.x with
    `services.<name> conflicts with imported resource` — `include` imports a
    model, and overriding a service it imported is an error. Measured against
    v2.29.7 and v2.39.4: both fail. So the documented production command
    worked on almost no installation, and nothing noticed because the smoke
    job only ever drove `docker-compose.yml`.

    These are static assertions rather than a subprocess call, so they hold on
    a runner with no Docker; the compose-smoke workflow exercises the real
    binary.
    """

    def test_the_production_file_does_not_import_the_base(self) -> None:
        document = yaml.load(PROD.read_text(encoding="utf-8"), Loader=_ComposeLoader)  # noqa: S506
        assert "include" not in (document or {}), (
            "`include:` plus an override of an imported service is rejected by every "
            "released Compose 2.x. Use two `-f` flags instead."
        )

    def test_the_docs_give_both_files_in_order(self) -> None:
        page = (REPO / "apps" / "docs" / "docs" / "deployment" / "docker.md").read_text(encoding="utf-8")
        assert "-f docker-compose.yml -f docker-compose.prod.yml" in page, (
            "the deployment page must give both files, base first — the overlay alone "
            "does not resolve on Compose 2.x"
        )
        assert "-f docker-compose.prod.yml up" not in page.replace(
            "-f docker-compose.yml -f docker-compose.prod.yml up", ""
        ), "the page still shows the single-file form somewhere"

    def test_the_smoke_workflow_drives_the_same_command(self) -> None:
        """A workflow that exercises a different invocation than the docs
        publish proves nothing about the documented one."""
        flow = (REPO / ".github" / "workflows" / "compose-smoke.yml").read_text(encoding="utf-8")
        if "docker-compose.prod.yml" in flow:
            assert "-f docker-compose.yml -f docker-compose.prod.yml" in flow
            assert flow.count("-f docker-compose.prod.yml") == flow.count(
                "-f docker-compose.yml -f docker-compose.prod.yml"
            ), "some invocation still passes the overlay alone"


class TestTheBypassIsUnreachable:
    def test_no_service_runs_in_a_dev_class_environment(self, prod: dict) -> None:
        assert not _dev_environments(prod)

    def test_the_development_file_would_fail_this(self) -> None:
        """The contrast is the point: this is what production differs from."""
        assert _dev_environments(_services(DEV)), (
            "docker-compose.yml no longer resolves to a dev-class environment with an empty "
            ".env, so this gate is comparing production against nothing and proves less than "
            "it claims"
        )

    def test_environment_and_dev_mode_are_literals_not_variables(self, prod: dict) -> None:
        """An interpolated value here could be re-enabled from a stray `.env`.

        The whole point of the file is that the bypass cannot be switched back
        on by configuration, so these two keys are fixed rather than defaulted.
        """
        for name, service in prod.items():
            env = (service or {}).get("environment") or {}
            for key in ("ENVIRONMENT", "AISOC_DEV_MODE"):
                if key in env:
                    assert "${" not in str(env[key]), f"{name}:{key} is interpolated; it must be a fixed value"


class TestNothingStartsOnAPublishedCredential:
    def test_no_secret_carries_a_default(self, prod: dict) -> None:
        assert not _unguarded_secrets(prod), (
            "these would start on a default rather than refusing: a deployment that boots on "
            "a credential published in this repository looks healthy and is not"
        )

    def test_grafana_cannot_start_on_its_documented_default(self, prod: dict) -> None:
        """`GF_SECURITY_ADMIN_PASSWORD` defaults to `admin` in development.

        Grafana is on the `monitoring` profile, so it is not in CORE — which
        is exactly why the first pass of this file missed it. A profiled
        service is still a production service the moment someone asks for the
        profile, and a dashboard over production telemetry on the password
        printed in its own documentation is not a smaller problem for being
        opt-in.
        """
        value = dict(_env_items(prod.get("grafana") or {})).get("GF_SECURITY_ADMIN_PASSWORD", "")
        assert ":?" in value, f"grafana would start on a default admin password: {value!r}"

    def test_no_dev_secret_literal_reaches_a_service(self, prod: dict) -> None:
        """Asserted on values, not on the file text.

        A first attempt grepped the raw file and matched the comment that
        explains the defect, which is the difference between reading what
        ships and reading what it says about itself.
        """
        leaked = [
            f"{name}:{key}"
            for name, service in prod.items()
            for key, value in _env_items(service)
            if "_dev_secret" in value and ":-" not in value
        ]
        assert not leaked


#: The only two things that need to be reachable from outside. The console
#: proxies every upstream server-side (`apps/web/next.config.js` rewrites API,
#: agents, fusion, realtime, enrichment and osquery-tls), so a browser only
#: ever talks to `web`; `ingest-worker` accepts events from agents and SIEMs.
REACHABLE = frozenset({"web", "ingest-worker"})


def _publishers(services: dict) -> dict[str, list[str]]:
    return {
        name: [str(entry) for entry in (service or {}).get("ports") or []]
        for name, service in services.items()
        if (service or {}).get("ports")
    }


#: Services in the overlay whose `ports:` carries a Compose merge tag. Without
#: one the value is *merged* with the base rather than replacing it, so a bare
#: `ports: []` reads as "change nothing" and the inherited binding survives —
#: which is exactly what happened on the first attempt at this file.
_TAGGED_PORTS = re.compile(r"^  ([a-z0-9-]+):\n(?:    .*\n)*?    ports: (![a-z]+)", re.M)


def _overlay_port_overrides() -> dict[str, str]:
    """Which services override `ports`, and with which merge tag."""
    text = PROD.read_text(encoding="utf-8")
    tagged = dict(_TAGGED_PORTS.findall(text))
    declared = {name for name, _ in re.findall(r"^  ([a-z0-9-]+):\n(?:    .*\n)*?    (ports:)", text, re.M)}
    return {name: tagged.get(name, "") for name in declared}


def _merged_services() -> dict:
    """Base services with the overlay's port overrides applied.

    The production file `include`s the base, so reading it alone sees only the
    keys it restates — a check for "what publishes a port" would then miss
    every binding the overlay never mentions, and pass while the stack exposes
    them. Merged here rather than shelled out to `docker compose config`,
    because a gate that needs a Docker daemon skips where there isn't one, and
    a skip reports nothing while looking green.
    """
    merged = {name: dict(service or {}) for name, service in _services(DEV).items()}
    overlay = _services(PROD)
    overrides = _overlay_port_overrides()
    for name, service in overlay.items():
        target = merged.setdefault(name, {})
        if "ports" in (service or {}) and name in overrides:
            target["ports"] = (service or {}).get("ports") or []
        for key, value in (service or {}).items():
            if key != "ports":
                target[key] = value
    return merged


class TestOnlyTheConsoleAndIngestAreReachable:
    """The first pass of this file only unpublished the datastores.

    Nineteen application and observability services were still bound to the
    host — including Grafana on its documented admin/admin default — because
    the assertion was written about datastores rather than about the surface.
    A gate that names a category catches that category; the property wanted
    here is the complement, so it is asserted as one.
    """

    def test_nothing_else_publishes_a_port(self) -> None:
        extra = {n: p for n, p in _publishers(_merged_services()).items() if n not in REACHABLE}
        assert not extra, f"these are reachable from the host and need not be: {extra}"

    def test_the_two_that_should_be_reachable_still_are(self) -> None:
        """The other direction. Unpublishing everything would pass the test
        above and ship a deployment with no console and no way to send it
        events."""
        published = set(_publishers(_merged_services()))
        assert published == REACHABLE, f"expected exactly {sorted(REACHABLE)}, found {sorted(published)}"

    def test_every_port_override_carries_a_merge_tag(self) -> None:
        """A bare `ports: []` merges instead of replacing, so it changes nothing.

        This is not hypothetical: the first version of the production file used
        `ports: []` throughout, `docker compose config` still showed Postgres,
        Redis, Kafka and Qdrant bound to the host, and the file read as though
        it had unpublished them.
        """
        untagged = [name for name, tag in _overlay_port_overrides().items() if not tag]
        assert not untagged, f"these override `ports` without !reset or !override, so it does not apply: {untagged}"

    def test_ingest_does_not_publish_its_metrics_listener(self) -> None:
        """`ingest-worker` binds :8081 and :9090 in development. Prometheus
        scrapes the second over the compose network, so binding it to the host
        exposes the counters and buys nothing."""
        ports = _publishers(_merged_services()).get("ingest-worker", [])
        assert len(ports) == 1, f"expected only the ingest endpoint, found {ports}"
        assert "9090" not in str(ports[0])

    def test_the_development_file_would_fail_this(self) -> None:
        extra = {n for n in _publishers(_services(DEV)) if n not in REACHABLE}
        assert extra, "docker-compose.yml publishes nothing extra, so this gate compares against nothing"


class TestServicesComeBackAfterAReboot:
    """A production stack that does not restart is a production stack that is
    down until somebody notices.

    Checked across the merged file rather than the overlay, because the five
    that lacked a policy — Prometheus, Alertmanager, Tempo, the OTel collector
    and kafka-ui — were all services the overlay only touched to unpublish.
    """

    def test_every_service_declares_a_restart_policy(self) -> None:
        merged = _merged_services()
        missing = [name for name, service in merged.items() if not (service or {}).get("restart")]
        assert not missing, f"these would stay down after a crash or reboot: {missing}"

    def test_the_debug_topic_browser_is_not_one_of_them(self) -> None:
        """kafka-ui is deliberately `no`: it is brought up to look at something
        and shut down again, and restarting it on boot would leave an
        unauthenticated topic browser running beside production data."""
        assert str((_merged_services().get("kafka-ui") or {}).get("restart")) == "no"


#: `services/api/app/core/config.py`, whose `warn_if_insecure_defaults` every
#: production boot runs through `enforce_secure_defaults`.
API_CONFIG = REPO / "services" / "api" / "app" / "core" / "config.py"


def _settings_fatal_when_empty() -> set[str]:
    """Settings whose *emptiness* refuses a production boot.

    Read out of `warn_if_insecure_defaults` rather than listed here, because a
    list here is a second copy of the rule and would drift from the one the
    container actually runs. Every check of the shape ``not s.<NAME>`` means
    "empty is fatal outside development"; the checks comparing against a known
    placeholder are a different rule and are not this gate's business.
    """
    tree = ast.parse(API_CONFIG.read_text(encoding="utf-8"))
    fn = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "warn_if_insecure_defaults")
    names: set[str] = set()
    for node in ast.walk(fn):
        if (
            isinstance(node, ast.UnaryOp)
            and isinstance(node.op, ast.Not)
            and isinstance(node.operand, ast.Attribute)
            and isinstance(node.operand.value, ast.Name)
            and node.operand.value.id == "s"
            and node.operand.attr.isupper()
        ):
            names.add(node.operand.attr)
    return names


class TestTheApiCanActuallyBoot:
    """`ENVIRONMENT: production` turns every insecure default into a refusal.

    That is the point of this file, and it is also a trap: a secret the API
    hard-fails on that no service block passes through does not produce a
    compose error, it produces a crash loop. Observed against this stack —
    `docker compose -f docker-compose.prod.yml up -d` reported every container
    started, and the API restarted forever on

        InsecureProductionDefaultsError: Refusing to boot in production with
        insecure defaults:
          - METRICS_TOKEN is empty in a non-development environment
          - JWT_SECRET is empty or set to the well-known placeholder

    because neither was in the api service's `environment`. The sixteen
    assertions already in this file all passed on that tree: they check that
    the secrets the file *does* declare are undefaulted, never that the set is
    complete. This one closes that direction.
    """

    def test_every_secret_the_api_refuses_to_boot_without_is_declared(self, prod: dict) -> None:
        required = _settings_fatal_when_empty()
        assert required, "parsed no settings out of warn_if_insecure_defaults, so this gate checks nothing"

        declared = {key for key, _ in _env_items(prod.get("api") or {})}
        missing = sorted(required - declared)
        assert not missing, (
            f"docker-compose.prod.yml sets ENVIRONMENT=production for api but does not pass {missing}; "
            "the API will crash-loop on InsecureProductionDefaultsError while compose reports it started"
        )

    def test_each_one_is_required_rather_than_defaulted(self, prod: dict) -> None:
        """A default here would boot production on it instead of refusing."""
        required = _settings_fatal_when_empty()
        env = dict(_env_items(prod.get("api") or {}))
        defaulted = sorted(name for name in required if _DEFAULTED.match(env.get(name, "")))
        assert not defaulted, f"these carry a default, so a deployment with no value for them starts anyway: {defaulted}"


class TestNoDatastoreIsBoundToTheHost:
    def test_production_publishes_no_datastore(self, prod: dict) -> None:
        assert not _published_datastores(prod)

    def test_the_development_file_would_fail_this(self) -> None:
        assert _published_datastores(_services(DEV)), (
            "docker-compose.yml no longer publishes a datastore port, so this gate is comparing production against nothing"
        )

    def test_the_unauthenticated_kafka_ui_is_off_the_full_profile(self, prod: dict) -> None:
        """It browses every topic and has no authentication of its own.

        Moved rather than deleted, so an operator can still ask for it by name
        — the objection is to it starting beside production data unasked.
        """
        profiles = (prod.get("kafka-ui") or {}).get("profiles") or []
        assert "full" not in profiles, "`--profile full` would start kafka-ui beside production data"
        assert profiles, "kafka-ui has no profile at all, so it now starts in the default stack"


# ─── `${VAR:?}` cannot look at a value ───────────────────────────────────────
#
# The sixteen assertions above all read this file statically, and every one of
# them passed while the stack booted on `aisoc_dev_secret`. Compose's `:?`
# operator rejects an **unset or empty** variable; it has no way to compare
# one. `.env.example` shipped `POSTGRES_PASSWORD=aisoc_dev_secret` and
# `docker-compose.yml` defaults the same variable to the same literal, so the
# one input `${POSTGRES_PASSWORD:?… the development default is a published
# literal}` names is the one input it accepts.
#
# `TestNothingStartsOnAPublishedCredential` above is therefore about the
# *shape* of the guard. What follows is about the value, and it runs the real
# program rather than reading the file that describes it.


def _load_checker():
    spec = importlib.util.spec_from_file_location("check_published_secrets", REPO / "scripts" / "check_published_secrets.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_checker(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """`--check-env` in a subprocess, with a controlled environment.

    A subprocess rather than a function call: `--check-env` reads
    `os.environ`, and the thing worth asserting is the exit status the
    preflight container produces, not a return value.
    """
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, str(REPO / "scripts" / "check_published_secrets.py"), "--check-env"],
        capture_output=True,
        text=True,
        check=False,
        env={"PATH": os.environ.get("PATH", ""), "AISOC_REPO_ROOT": str(REPO), **env},
    )


class TestAPublishedValueCannotSatisfyAGuard:
    def test_the_harvest_finds_the_literals_this_repository_publishes(self) -> None:
        published = _load_checker().published_literals(REPO)
        # Named explicitly. The harvest is derived from the tree so it cannot
        # go stale, but a regex that silently stops matching would make it
        # derive nothing and every check below would pass.
        for literal in ("aisoc_dev_secret", "aisoc_app_dev_secret", "redis_dev_secret", "clickhouse_dev_secret"):
            assert literal in published, f"{literal} is published in this tree and was not harvested"

    def test_a_real_secret_is_accepted(self) -> None:
        """The other direction. A checker that refused everything would pass
        the test below and ship a production stack that cannot start."""
        result = _run_checker({"POSTGRES_PASSWORD": "9b20969c058203d8a725c09800645f4666f913d80590c094"})
        assert result.returncode == 0, result.stderr

    @pytest.mark.parametrize(
        ("variable", "value"),
        [
            ("POSTGRES_PASSWORD", "aisoc_dev_secret"),
            ("AISOC_APP_DB_PASSWORD", "aisoc_app_dev_secret"),
            ("REDIS_PASSWORD", "redis_dev_secret"),
            ("CLICKHOUSE_PASSWORD", "clickhouse_dev_secret"),
            ("SECRET_KEY", "dev_secret_key_change_in_production"),
            ("GRAFANA_ADMIN_PASSWORD", "admin"),
            # The value, not the variable. Reusing one variable's published
            # literal on another is the same disclosure.
            ("NEO4J_PASSWORD", "aisoc_dev_secret"),
            # And inside a DSN, which is where three of them used to live.
            ("REDIS_URL", "redis://:redis_dev_secret@redis:6379/0"),
        ],
    )
    def test_a_published_value_is_refused(self, variable: str, value: str) -> None:
        result = _run_checker({variable: value})
        assert result.returncode == 1, f"{variable}={value} was accepted:\n{result.stdout}{result.stderr}"
        assert variable in result.stderr

    def test_the_checker_refuses_rather_than_reporting_clean_over_an_empty_tree(self, tmp_path: pathlib.Path) -> None:
        """`published_literals` over a tree with no compose files harvests
        nothing, and nothing matches nothing. Reporting OK there would make
        the preflight a no-op in any deployment whose mount went wrong."""
        result = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [sys.executable, str(REPO / "scripts" / "check_published_secrets.py"), "--check-env"],
            capture_output=True,
            text=True,
            check=False,
            env={"PATH": os.environ.get("PATH", ""), "AISOC_REPO_ROOT": str(tmp_path)},
        )
        assert result.returncode != 0
        assert "harvested no published values" in result.stderr

    def test_every_guard_reaches_the_preflight(self) -> None:
        """A guard added later without extending the preflight is how this
        rots: the variable would be required-non-empty and unchecked."""
        checker = _load_checker()
        guarded = checker.guarded_variables(PROD)
        preflight = _services(PROD).get(checker.PREFLIGHT_SERVICE) or {}
        received = {key for key, _ in _env_items(preflight)}
        assert guarded - received == set(), f"guarded but never checked: {sorted(guarded - received)}"

    def test_nothing_starts_before_the_preflight(self) -> None:
        checker = _load_checker()
        overlay = _services(PROD)
        ungated = sorted(
            name
            for name, service in overlay.items()
            if name != checker.PREFLIGHT_SERVICE and checker.PREFLIGHT_SERVICE not in ((service or {}).get("depends_on") or {})
        )
        assert not ungated, f"these start without waiting for the credential check: {ungated}"

    def test_every_base_service_is_covered_by_the_overlay(self) -> None:
        """`depends_on` can only be added to a service the overlay names. A
        service defined only in the base file inherits nothing from here, and
        one such service starting ahead of the check is the whole hole."""
        checker = _load_checker()
        overlay = set(_services(PROD))
        missing = sorted(set(_services(DEV)) - overlay - {checker.PREFLIGHT_SERVICE})
        assert not missing, f"defined in docker-compose.yml and not restated here, so ungated: {missing}"
