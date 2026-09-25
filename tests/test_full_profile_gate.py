"""Full-profile defects that every test suite passed and a real deployment did not.

`tests/test_first_run_gate.py` covers the same genre for CORE. This file covers
`make up-full`, which had never been brought up end to end by anyone: the
acceptance pass that found these reported that `up-full` printed
"Full profile up." while two of its twenty-one services were dead and a third
was serving on a port nothing forwarded to.

Every check below is a compose-manifest assertion, because every defect lived
in the gap between a manifest and the code that reads it — an env var the
service ignores, a memory limit smaller than the process, a published port the
listener never binds. None of them is visible to a unit test of either side,
and a container can report `running` through all of them.
"""

from __future__ import annotations

import pathlib

import pytest
import yaml  # type: ignore[import-untyped]  # PyYAML ships no stubs; only used to read compose here

REPO = pathlib.Path(__file__).resolve().parents[1]
ROOT_COMPOSE = REPO / "docker-compose.yml"

_MIB = 1024 * 1024


def _compose() -> dict:
    return yaml.safe_load(ROOT_COMPOSE.read_text())


def _services() -> dict:
    return _compose()["services"]


def _env(service: dict) -> dict[str, str]:
    """Normalise compose's two environment spellings to one mapping."""
    raw = service.get("environment") or {}
    if isinstance(raw, list):
        out: dict[str, str] = {}
        for item in raw:
            key, _, value = str(item).partition("=")
            out[key] = value
        return out
    return {k: "" if v is None else str(v) for k, v in raw.items()}


def _to_bytes(limit: str | int | None) -> int | None:
    """Parse a compose `mem_limit` (`2g`, `512m`, or a raw byte count)."""
    if limit is None:
        return None
    if isinstance(limit, int):
        return limit
    text = str(limit).strip().lower()
    for suffix, mult in (("g", 1024**3), ("m", 1024**2), ("k", 1024)):
        if text.endswith(suffix):
            return int(float(text[:-1]) * mult)
    return int(text)


def _published(service: dict) -> set[int]:
    """Container-side ports this service publishes, in either port syntax."""
    out: set[int] = set()
    for entry in service.get("ports") or []:
        if isinstance(entry, dict):
            if entry.get("target") is not None:
                out.add(int(entry["target"]))
            continue
        # "127.0.0.1:8088:8003" / "8088:8003" / "8003"
        out.add(int(str(entry).strip('"').split(":")[-1]))
    return out


# ── OpenSearch: a 512m heap is not a 512m process ──────────────────────────
#
# Shipped as `mem_limit: 1g` with `-Xmx512m`. OpenSearch 2.11 loads ~20 bundled
# plugins and settles at ~1.05GB RSS with that heap, so the container was
# OOM-killed during bootstrap every single time (exit 137, OOMKilled=true,
# ~10s in). The full profile shipped a store that could not start, and
# `make up-full` reported success because its wait loop only inspects the
# health of *running* containers — an exited one is absent from the listing
# and a restarting one reports no health at all.
def test_opensearch_memory_limit_exceeds_its_heap() -> None:
    svc = _services()["opensearch"]
    env = _env(svc)
    opts = next(
        (v for k, v in env.items() if k == "OPENSEARCH_JAVA_OPTS"),
        " ".join(str(e) for e in (svc.get("environment") or []) if "JAVA_OPTS" in str(e)),
    )
    assert "-Xmx512m" in opts, (
        "This bound assumes a 512m heap. If the heap changed, re-measure the steady-state RSS and move the floor with it."
    )

    limit = _to_bytes(svc.get("mem_limit"))
    assert limit is not None, "opensearch must declare a mem_limit"
    assert limit >= 1800 * _MIB, (
        f"opensearch mem_limit is {limit // _MIB}MiB. Measured steady state with "
        "a 512m heap is ~1075MiB, so anything at or near 1GiB is OOM-killed at "
        "boot. Keep real headroom above the measurement."
    )


# ── A dependant that needs readiness cannot express it without a healthcheck ─
#
# threatintel calls os_store.initialize() in its FastAPI lifespan with no
# try/except, so starting before OpenSearch answers kills the container.
# `condition: service_started` is satisfied the instant the container exists —
# including for the ~40s before the node listens, and for a node about to die —
# so the only honest condition is service_healthy, which needs a healthcheck on
# the target.
def test_service_healthy_dependencies_have_a_healthcheck_to_wait_on() -> None:
    services = _services()
    missing: list[str] = []
    for name, svc in services.items():
        depends = svc.get("depends_on") or {}
        if not isinstance(depends, dict):
            continue
        for dep, spec in depends.items():
            if not isinstance(spec, dict):
                continue
            if spec.get("condition") != "service_healthy":
                continue
            if not (services.get(dep) or {}).get("healthcheck"):
                missing.append(f"{name} waits on {dep} being healthy, but {dep} declares no healthcheck")
    assert not missing, "; ".join(missing)


# ── A CORE service may not require a store that only the full profile starts ─
#
# This used to assert the opposite: that threatintel waited on a *healthy*
# OpenSearch, because its lifespan called `os_store.initialize()` with no
# try/except and starting early killed the container.
#
# threatintel is in CORE now — it is what puts real CISA KEV data in front of a
# new user — and OpenSearch is not. Keeping the dependency would have made
# `make up` start a 2 GB JVM for a full-text index CORE does not read. So the
# unguarded call was fixed instead, which is the stronger property: the service
# no longer aborts, rather than being sequenced so it does not have to. These
# two tests pin both halves — the manifest must not reintroduce the dependency,
# and the code must keep the call guarded, because either alone would let the
# crash loop back in.
def test_no_core_service_depends_on_a_full_profile_service() -> None:
    services = _services()
    core = {name for name, svc in services.items() if not svc.get("profiles")}
    offenders: list[str] = []
    for name in sorted(core):
        for dep in services[name].get("depends_on") or {}:
            if (services.get(dep) or {}).get("profiles"):
                offenders.append(f"{name} (CORE) depends on {dep}, which only starts under {services[dep]['profiles']}")
    assert not offenders, (
        "\n".join(offenders) + "\n\nCompose starts a profiled dependency anyway, so this does not fail loudly — "
        "it silently enlarges CORE by whatever that service costs."
    )


def test_threatintels_optional_stores_are_guarded_in_code() -> None:
    """The manifest check above is only safe because these calls cannot raise out."""
    lifespan = (REPO / "services/threatintel/app/main.py").read_text()
    pipeline = (REPO / "services/threatintel/app/feeds/pipeline.py").read_text()

    assert "await os_store.initialize()" in lifespan
    init_block = lifespan.split("await os_store.initialize()")[0]
    assert init_block.rstrip().endswith("try:"), (
        "services/threatintel/app/main.py calls os_store.initialize() outside a try — an unreachable "
        "OpenSearch then kills a CORE service on boot."
    )

    for call in ("self._os.bulk_index_iocs(new_iocs)", "self._os.bulk_index_actors(actors)"):
        assert call in pipeline, f"{call} moved; re-point this gate"
        before = pipeline.split(call)[0]
        assert "try:" in before.rsplit("\n\n", 1)[-1], (
            f"{call} is not inside a try block. It is the first sink written, so an exception there "
            "aborts the batch before Qdrant — the store CORE actually reads — is touched at all."
        )


# ── The API reads CLICKHOUSE_HOST, and nothing under services/api reads a URL ─
#
# The api service was handed `CLICKHOUSE_URL` alone. No module under
# services/api/app reads that name, so the settings stayed at their defaults
# (localhost:9000, user `default`, no password) and /lake/sql answered every
# query with `Connection refused (localhost:9000)` — while fusion archived to
# the same store perfectly well over the native port.
CLICKHOUSE_SETTINGS = ("CLICKHOUSE_HOST", "CLICKHOUSE_PORT", "CLICKHOUSE_DATABASE", "CLICKHOUSE_USER", "CLICKHOUSE_PASSWORD")


def test_api_receives_the_clickhouse_settings_its_code_actually_reads() -> None:
    env = _env(_services()["api"])
    missing = [k for k in CLICKHOUSE_SETTINGS if k not in env]
    assert not missing, (
        f"api is missing {missing}. app/core/config.py declares these five and no "
        "module reads CLICKHOUSE_URL, so supplying only the URL silently leaves "
        "the lake client pointed at localhost."
    )


def test_no_service_is_given_only_a_clickhouse_url() -> None:
    """A service that gets CLICKHOUSE_URL and nothing else is a silent misconfiguration."""
    for name, svc in _services().items():
        env = _env(svc)
        if "CLICKHOUSE_URL" not in env:
            continue
        if name == "ueba":
            continue  # reads CLICKHOUSE_URL directly; see services/ueba/app/core/config.py
        assert "CLICKHOUSE_HOST" in env, (
            f"{name} is given CLICKHOUSE_URL but no CLICKHOUSE_HOST. If it uses the "
            "shared settings shape it will fall back to localhost and fail closed "
            "with a connection error that names the wrong host."
        )


# ── A published port nothing binds ─────────────────────────────────────────
#
# connectors publishes container port 8003, but app/scripts/serve.py binds
# `PORT`, defaulting to 8087. With PORT unset the listener sat on a port no
# mapping forwarded to: `connectors:8003` was refused from inside the network,
# the published host port answered nothing, and the API's catalog proxy fell
# back to the 26-entry snapshot bundled in its image while the registry had 84.
def test_connectors_binds_the_port_it_publishes() -> None:
    svc = _services()["connectors"]
    env = _env(svc)
    assert "PORT" in env, (
        "connectors/app/scripts/serve.py defaults PORT to 8087. Leaving it unset binds a port the compose mapping does not forward to."
    )
    assert int(env["PORT"]) in _published(svc), f"connectors binds PORT={env['PORT']} but publishes {sorted(_published(svc))}."


# ── A required key no service was given ────────────────────────────────────
#
# .env.example names AISOC_CREDENTIAL_KEY one of the three required values and
# explains how to generate one, but no compose service forwarded it. Setting it
# therefore had no effect: the connector scheduler raised CredentialVaultError
# at startup, logged `connector.scheduler.start_failed`, and the container went
# on to report `Application startup complete` and serve /health 200 with no
# scheduler at all. No connector could ever auto-poll.
def test_credential_vault_key_reaches_the_services_that_need_it() -> None:
    services = _services()
    for name in ("api", "connectors"):
        env = _env(services[name])
        assert "AISOC_CREDENTIAL_KEY" in env, (
            f"{name} is not given AISOC_CREDENTIAL_KEY. The API owns the vault write "
            "path and the connectors scheduler decrypts with the same key; a "
            "credential saved in the console is undecryptable at poll time without it."
        )


# ── One signing key, honoured from .env ────────────────────────────────────
#
# api pinned SECRET_KEY to a bare literal, so a value set in .env was ignored
# and the JWT signing key silently stayed on the dev default. It also has to
# match whatever connectors verifies with: the API forwards the console token
# there, and a mismatch turns every proxied catalog call into a 401 that the
# caller reports as "connectors service unreachable".
def test_secret_key_is_overridable_and_consistent_across_services() -> None:
    services = _services()
    keys = {}
    for name in ("api", "connectors"):
        env = _env(services[name])
        assert "SECRET_KEY" in env, f"{name} must be given SECRET_KEY"
        value = env["SECRET_KEY"]
        assert value.startswith("${SECRET_KEY"), f"{name} pins SECRET_KEY to the literal {value!r}, so a value set in .env is ignored."
        keys[name] = value
    assert len(set(keys.values())) == 1, (
        f"api and connectors resolve different SECRET_KEY defaults ({keys}). The "
        "console token the API forwards will fail its signature check."
    )


@pytest.mark.parametrize("service", ["clickhouse", "neo4j", "qdrant", "opensearch"])
def test_full_profile_stores_are_reachable_over_a_published_port(service: str) -> None:
    """scripts/doctor.sh probes these over the host port it resolves from compose.

    The previous probe shelled into the container and ran `wget`, which answers
    "is wget installed" as much as "is the store up" — the opensearch image
    ships curl and no wget, the qdrant image ships neither, and both were
    reported as not answering while serving 200 on every request.
    """
    assert _published(_services()[service]), f"{service} publishes no port, so the doctor cannot probe it from the host."
