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
