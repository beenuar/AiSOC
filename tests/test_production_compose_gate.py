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

import pathlib
import re

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
