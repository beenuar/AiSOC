"""The enrichment container must receive the env that enables Cyble.

The Cyble Vision enricher is not optional scaffolding: `enricher.New` builds a
`NewCybleClient` for it (`services/enrichment/internal/enricher/enricher.go`),
`config.go` reads `CYBLE_API_KEY` / `CYBLE_BASE_URL`, and `main.go` gates the
provider on `CybleAPIKey != ""`. So the only thing standing between an operator
who sets `CYBLE_API_KEY` in `.env` and a working provider is whether compose
forwards that variable into the container.

It did not. `docker-compose.yml` forwarded the six free-tier provider keys
(VirusTotal, AbuseIPDB, GreyNoise, Shodan, URLScan, IPInfo) and stopped there,
so the Cyble credential never reached the process: boot logged `cyble=false`
no matter what the operator put in `.env`, with nothing to say why.

This gate is derived from `config.go` rather than hard-coded, so it also covers
any future `CYBLE_*` the config grows: every Cyble credential the config reads
must be forwarded by the enrichment service in `docker-compose.yml`.
"""

from __future__ import annotations

import pathlib
import re

import yaml

REPO = pathlib.Path(__file__).resolve().parents[1]
COMPOSE = REPO / "docker-compose.yml"
CONFIG_GO = REPO / "services" / "enrichment" / "internal" / "config" / "config.go"

#: `getEnv("CYBLE_...", ...)` — the credential names config.go actually reads.
_CYBLE_GETENV = re.compile(r'getEnv\(\s*"(CYBLE_[A-Z0-9_]+)"')


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


def _enrichment_environment() -> set[str]:
    """The env var NAMES the enrichment service declares, list or dict form."""
    compose = yaml.load(COMPOSE.read_text(), Loader=_ComposeLoader)
    env = compose["services"]["enrichment"].get("environment") or {}
    if isinstance(env, dict):
        return set(env)
    # List form: "KEY=value" / "KEY".
    return {entry.split("=", 1)[0].strip() for entry in env}


def _cyble_credentials() -> set[str]:
    return set(_CYBLE_GETENV.findall(CONFIG_GO.read_text()))


def test_config_reads_a_cyble_credential() -> None:
    """Guard the guard: if the names move, this gate must not silently pass."""
    creds = _cyble_credentials()
    assert "CYBLE_API_KEY" in creds, f"config.go no longer reads CYBLE_API_KEY; this gate is asserting nothing. found: {sorted(creds)}"


def test_enrichment_forwards_every_cyble_credential() -> None:
    forwarded = _enrichment_environment()
    missing = sorted(_cyble_credentials() - forwarded)
    assert not missing, (
        "config.go gates the Cyble enricher on these env vars, but the "
        "enrichment service in docker-compose.yml does not forward them, so "
        "Cyble can never be enabled on the shipped stack: " + ", ".join(missing)
    )
