"""The placeholder detector and the file it inspects must not drift apart.

`scripts/doctor.sh` carried this check inline for a long time::

    grep -qE '^[A-Z_]*(SECRET|PASSWORD|KEY)=(change_me|changeme|)$' .env

and `.env.example` shipped
``AISOC_CREDENTIAL_KEY=replace-me-with-a-freshly-generated-fernet-key`` and
``SECRET_KEY=change-this-to-a-random-secret-key-at-least-32-chars``. The grep
matched neither. So the gate built to catch a shipped placeholder reported
clean on the one ``.env`` that broke the product — following the documented
``cp .env.example .env`` produced an API that answered HTTP 500 on every
connector save, while *skipping* the documented step produced a working one.

Two lists maintained by hand and compared by nothing. These tests compare them,
in both directions:

* every value ``.env.example`` ships is either flagged by the detector or named
  below as a deliberate working default, so a new placeholder cannot be added
  without teaching the detector about it;
* the historical placeholder strings still match, so the detector cannot be
  narrowed back to the shape that missed them;
* the three secrets ``scripts/ensure_env.py`` generates are shipped **empty**,
  because empty is the only value the credential vault treats as "not
  configured" and therefore the only safe thing to ship.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
ENV_EXAMPLE = REPO / ".env.example"
SCRIPTS = REPO / "scripts"

sys.path.insert(0, str(SCRIPTS))


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check_env_placeholders = _load("check_env_placeholders")
ensure_env = _load("ensure_env")


#: Non-empty values `.env.example` ships that are **settings**, not prose for
#: the reader to replace. Each one is a value the stack actually runs with, so
#: flagging it would put a permanent warning on a correct deployment.
#:
#: Adding a row here is the deliberate act that says "this is a real default".
#: Anything not here and not caught by the detector fails the partition test
#: below, which is the whole point: a new placeholder has nowhere to hide.
DELIBERATE_DEFAULTS: dict[str, str] = {
    "AISOC_VERSION": "the image tag compose pulls; `latest` tracks main",
    "ENVIRONMENT": "selects the dev auth bypass; documented and read by compose",
    "LOG_LEVEL": "a log level, not a secret",
    "AISOC_CONSOLE_URL": "the address `make bootstrap` prints; localhost is right for a laptop",
    "AISOC_REALTIME_TICKET_TTL_SECONDS": "a duration",
    "CONNECTORS_SERVICE_URL": "the compose hostname of the connectors service",
    "CONNECTORS_SERVICE_TIMEOUT_SECONDS": "a duration",
    "POSTGRES_PASSWORD": "dev Postgres password; works out of the box, documented as changeable",
    "AISOC_APP_DB_PASSWORD": "dev password for the runtime DB role; same reasoning",
    "DATABASE_URL": "a DSN built from the two passwords above",
    "DATABASE_MIGRATION_URL": "the owner-role DSN used only by the migration runner",
    "REDIS_URL": "dev Redis DSN",
    "CLICKHOUSE_URL": "dev ClickHouse DSN",
    "KAFKA_BOOTSTRAP_SERVERS": "a host:port",
    "OPENSEARCH_URL": "a URL",
    "QDRANT_URL": "a URL",
    "OPENAI_MODEL": "a logical task alias the gateway defines",
    "LITELLM_MASTER_KEY": "the local gateway's own key; the gateway is in-network only",
    "LLM_GATEWAY_URL": "the compose hostname of the gateway",
    "TAXII_FEEDS": "a real public MITRE ATT&CK TAXII endpoint",
    "CISA_KEV_ENABLED": "a boolean",
    "ABUSE_CH_ENABLED": "a boolean",
    "CYBLE_VISION_BASE_URL": "a real vendor API base URL",
    "CYBLE_VISION_FEEDS": "a feed name list",
    "ANOMALI_BASE_URL": "a real vendor API base URL",
    "CROWDSTRIKE_BASE_URL": "a real vendor API base URL",
    "SPLUNK_PORT": "the Splunk management port",
    "SPLUNK_SCHEME": "a URL scheme",
    "SPLUNK_VERIFY_SSL": "a boolean, and the secure default",
    "AWS_REGION": "a region",
    "NEXT_PUBLIC_API_URL": "a localhost URL",
    "NEXT_PUBLIC_REALTIME_URL": "a localhost URL",
    "NEXT_PUBLIC_WS_URL": "a localhost URL",
}

#: The exact strings the old grep failed to match. Pinned as a regression test:
#: the detector may be broadened, never narrowed back past these.
HISTORICAL_PLACEHOLDERS = (
    "replace-me-with-a-freshly-generated-fernet-key",
    "change-this-to-a-random-secret-key-at-least-32-chars",
    "sk-your-openai-api-key-here",
    "change_me",
    "changeme",
)


def _example_entries() -> list[tuple[int, str, str]]:
    entries = check_env_placeholders.parse_env(ENV_EXAMPLE.read_text(encoding="utf-8"))
    assert entries, ".env.example parsed to zero assignments — the parser or the file is wrong"
    return entries


# ── The two lists, compared ──────────────────────────────────────────────────


def test_every_shipped_value_is_either_a_placeholder_or_a_declared_default() -> None:
    """The partition that stops the two lists drifting.

    A contributor adding ``FOO_TOKEN=put-yours-here`` to `.env.example` has to
    make the detector match it or declare it a real default. There is no third
    option, which is what the old arrangement silently allowed.
    """
    undeclared: list[str] = []
    for lineno, key, value in _example_entries():
        if not value.strip():
            continue  # empty is the correct value for every optional credential
        if check_env_placeholders.is_placeholder(value):
            continue
        if key in DELIBERATE_DEFAULTS:
            continue
        undeclared.append(f"  .env.example:{lineno}  {key}={value.strip()}")

    assert not undeclared, (
        "these .env.example values are neither recognised as placeholders nor declared as real defaults:\n"
        + "\n".join(undeclared)
        + "\n\nIf it is prose for the reader to replace, add a pattern to "
        "scripts/check_env_placeholders.py::PLACEHOLDER_PATTERNS.\n"
        "If it is a value the stack runs with, add it to DELIBERATE_DEFAULTS in this file with a reason."
    )


@pytest.mark.parametrize("value", HISTORICAL_PLACEHOLDERS)
def test_the_detector_still_catches_every_placeholder_this_repo_has_shipped(value: str) -> None:
    assert check_env_placeholders.is_placeholder(value), (
        f"{value!r} shipped in .env.example and the doctor check missed it. "
        "Narrowing the detector past this point re-opens the original defect."
    )


def test_a_declared_default_is_not_flagged() -> None:
    """The other direction: a real value must not produce a warning.

    A check that cries wolf on a correct deployment teaches operators to ignore
    it, which is how the original grep's `=$` arm — matching every legitimately
    empty optional credential — made the whole check noise.
    """
    for value in ("aisoc_dev_secret", "http://localhost:3000", "sk-aisoc-local", "true", "us-east-1"):
        assert not check_env_placeholders.is_placeholder(value), f"{value!r} is a working value and must not be reported as a placeholder"


def test_empty_is_not_a_placeholder() -> None:
    assert not check_env_placeholders.is_placeholder("")
    assert not check_env_placeholders.is_placeholder("   ")


# ── What the template is allowed to ship ─────────────────────────────────────


@pytest.mark.parametrize("key", sorted(ensure_env.GENERATED))
def test_generated_secrets_ship_empty(key: str) -> None:
    """Empty, not prose — the distinction the credential vault actually makes.

    `get_vault()` falls back to an ephemeral development key only when the key
    is empty. A non-empty invalid key reaches `Fernet()` and raises, and the
    connector routes turn that into HTTP 500. So the template shipping
    ``AISOC_CREDENTIAL_KEY=replace-me-…`` meant the documented quick start
    produced a broken vault and skipping it produced a working one.
    """
    values = [value.strip() for _lineno, name, value in _example_entries() if name == key]
    assert values, f"{key} is generated by ensure_env.py but is not present in .env.example"
    assert values[-1] == "", (
        f".env.example ships {key}={values[-1]!r}. It must ship empty: the vault treats empty as "
        "'not configured' and takes its documented development path, while any other invalid value "
        "raises and surfaces as HTTP 500 at the connector wizard."
    )


def test_ensure_env_fills_exactly_the_empty_and_placeholder_secrets(tmp_path: Path) -> None:
    """End-to-end over the real template: copy, generate, and check the result."""
    env = tmp_path / ".env"
    assert ensure_env.main(["--env", str(env), "--example", str(ENV_EXAMPLE)]) == 0

    values = {name: value.strip() for _lineno, name, value in check_env_placeholders.parse_env(env.read_text(encoding="utf-8"))}
    for key in ensure_env.GENERATED:
        assert values.get(key), f"ensure_env left {key} empty"
        assert not check_env_placeholders.is_placeholder(values[key])

    # The credential key has to satisfy Fernet, which is the whole point.
    from cryptography.fernet import Fernet

    Fernet(values["AISOC_CREDENTIAL_KEY"].encode("ascii"))

    # Idempotent: a second run must not rotate a key an operator is already using.
    before = env.read_text(encoding="utf-8")
    assert ensure_env.main(["--env", str(env), "--example", str(ENV_EXAMPLE)]) == 0
    assert env.read_text(encoding="utf-8") == before, "a second `make env` rotated a secret that was already set"


def test_ensure_env_replaces_a_placeholder_it_finds(tmp_path: Path) -> None:
    """The upgrade path: an operator who already has the broken `.env`."""
    env = tmp_path / ".env"
    env.write_text("AISOC_CREDENTIAL_KEY=replace-me-with-a-freshly-generated-fernet-key\n", encoding="utf-8")
    assert ensure_env.main(["--env", str(env), "--example", str(ENV_EXAMPLE)]) == 0

    values = {name: value.strip() for _lineno, name, value in check_env_placeholders.parse_env(env.read_text(encoding="utf-8"))}
    from cryptography.fernet import Fernet

    Fernet(values["AISOC_CREDENTIAL_KEY"].encode("ascii"))


def test_the_checker_refuses_a_file_that_is_not_there(tmp_path: Path) -> None:
    """A gate that reports OK over a tree it never opened is worse than none."""
    assert check_env_placeholders.main([str(tmp_path / "nope.env")]) == 1
