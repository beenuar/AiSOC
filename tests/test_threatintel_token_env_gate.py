"""Every service that reads the threat-intel token receives it in compose.

SEC-15 made the `/api/v1/actors/*` gate fail closed, and NC-7 made
`ensure_env.py` generate `AISOC_THREATINTEL_SERVICE_TOKEN` — but a generated
value that never reaches a container is a 503 for every caller on the
default stack: the enforcing service cannot verify what it never received,
and the calling agent cannot present what it never received. That is the
generated-but-unforwarded class the Cyble key shipped with (#1898), so the
gate is the same shape: derive the readers from the tree, assert compose
forwards the variable to each of them.
"""

from __future__ import annotations

import pathlib

import yaml

REPO = pathlib.Path(__file__).resolve().parents[1]
COMPOSE = REPO / "docker-compose.yml"
SERVICES = REPO / "services"
TOKEN = "AISOC_THREATINTEL_SERVICE_TOKEN"


class _ComposeLoader(yaml.SafeLoader):
    """Tolerates the `!reset` / `!override` tags the compose overlays use."""


def _strip_tag(loader, node):  # noqa: ANN001, ANN202 - loader plumbing
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node, deep=True)
    return loader.construct_scalar(node)


for _tag in ("!reset", "!override"):
    _ComposeLoader.add_constructor(_tag, _strip_tag)


def _services_reading_the_token() -> set[str]:
    """Service directories whose Python reads the token from the environment."""
    readers: set[str] = set()
    for path in SERVICES.rglob("*.py"):
        if "tests" in path.parts or "_vendor" in path.parts:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if TOKEN in text:
            readers.add(path.relative_to(SERVICES).parts[0])
    return readers


def _compose_env(service: str) -> set[str]:
    compose = yaml.load(COMPOSE.read_text(), Loader=_ComposeLoader)
    declared = compose["services"].get(service)
    if declared is None:
        return set()
    env = declared.get("environment") or {}
    if isinstance(env, dict):
        return set(env)
    return {entry.split("=", 1)[0].strip() for entry in env}


def test_the_reader_set_is_what_we_think() -> None:
    """Guard the guard: if nothing reads the token, this gate asserts nothing."""
    readers = _services_reading_the_token()
    assert "threatintel" in readers, f"the enforcer no longer reads {TOKEN}; found readers: {sorted(readers)}"
    assert "agents" in readers, f"the attribution client no longer reads {TOKEN}; found readers: {sorted(readers)}"


def test_compose_forwards_the_token_to_every_reader() -> None:
    compose_names = set(yaml.load(COMPOSE.read_text(), Loader=_ComposeLoader)["services"])
    missing = []
    for service in sorted(_services_reading_the_token()):
        # Service dirs and compose service names mostly coincide; a reader
        # with no compose service (a library dir, a worker folded into
        # another container) has nothing to forward to here.
        if service not in compose_names:
            continue
        if TOKEN not in _compose_env(service):
            missing.append(service)
    assert not missing, (
        f"these services read {TOKEN} but docker-compose.yml does not forward "
        f"it to them, so the fail-closed actor gate 503s on the default stack: {missing}"
    )
