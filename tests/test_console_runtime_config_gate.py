"""Gate: the console's upstream addresses must follow the environment it runs in.

A self-hoster deploying with Compose on one host reported that setting the
documented variables changed nothing. It could not have: `next build` freezes
*both* halves of the console's routing.

* Everything prefixed `NEXT_PUBLIC_` is inlined into the JavaScript bundle as
  a string literal when the image is built, so setting it on a container that
  *pulled* that image is read by nobody.
* The destinations returned by `rewrites()` in `next.config.js` are compiled
  into `.next/routes-manifest.json`. `next start` loads the config again — it
  even logs that it did — but production routing is served from the manifest,
  so `API_URL` was inert too.

The stack appeared to work only because the value baked into the published
image, `http://api:8000`, happens to be the service's DNS name on the bundled
Compose network. Any other topology — a different Compose project, an API on
another host, or Kubernetes, where the chart's Services are `<release>-api` —
resolved a hostname that does not exist, and no variable could re-point it.

These tests pin the property that was missing rather than the mechanism that
supplies it: *an operator's chosen upstream is the one the console proxies
to.* The first exercises the real resolver against the real `next.config.js`;
the rest hold the deployment contract that carries it — an image that runs the
resolver, a Compose file that passes addresses the running container can read
instead of ones it cannot, and a bind address a server deployment can change.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess

import pytest
import yaml  # type: ignore[import-untyped]  # PyYAML ships no stubs; only used to read compose here

REPO = pathlib.Path(__file__).resolve().parent.parent
WEB = REPO / "apps" / "web"
COMPOSE = REPO / "docker-compose.yml"
RESOLVER = WEB / "scripts" / "resolve-runtime-routes.mjs"
ENTRYPOINT = WEB / "docker-entrypoint.sh"
DOCKERFILE = WEB / "Dockerfile"

# RFC 5737 TEST-NET-1. Chosen because it is guaranteed not to be the loopback
# address the image is built against, which is the whole point of the report:
# the console has to be pointable somewhere that is not localhost.
OPERATOR_API = "http://192.0.2.10:8000"


@pytest.fixture(scope="module")
def compose() -> dict:
    return yaml.safe_load(COMPOSE.read_text())


def _web_env(compose: dict) -> dict[str, str]:
    env = compose["services"]["web"].get("environment") or {}
    if isinstance(env, list):  # compose accepts `- KEY=value` too
        return dict(item.split("=", 1) for item in env if "=" in item)
    return {str(k): str(v) for k, v in env.items()}


def test_operator_chosen_api_address_is_the_one_the_console_proxies_to(
    tmp_path: pathlib.Path,
) -> None:
    """The defect itself: a manifest compiled against one API host must end up
    pointing at the host the container is *started* with.

    The real `next.config.js` and the real resolver are used — reimplementing
    either here would only prove that a copy agrees with itself, which is the
    failure mode this repository has already been bitten by. The manifest is a
    fixture in the shape `next build` emits, with the destination the published
    image actually carries.
    """
    # `or ""` rather than a None check: `shutil.which` is typed Optional, and
    # narrowing it through `pytest.fail` depends on that being inferred
    # NoReturn, which the type-check baseline does not do.
    node = shutil.which("node") or ""
    if not node:
        pytest.fail(
            "node is required to run apps/web/scripts/resolve-runtime-routes.mjs. "
            "Skipping would hide whether the console can be re-pointed at all."
        )

    # Mirror the repository layout the resolver locates itself against:
    # <root>/apps/web/{next.config.js,scripts/,.next/} and <root>/VERSION.
    app = tmp_path / "apps" / "web"
    (app / "scripts").mkdir(parents=True)
    (app / ".next").mkdir()
    shutil.copy(WEB / "next.config.js", app / "next.config.js")
    shutil.copy(RESOLVER, app / "scripts" / RESOLVER.name)
    (tmp_path / "VERSION").write_text((REPO / "VERSION").read_text())

    manifest = app / ".next" / "routes-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "version": 3,
                "rewrites": {
                    "beforeFiles": [],
                    "afterFiles": [
                        {
                            "source": "/api/v1/:path*",
                            "destination": "http://api:8000/api/v1/:path*",
                            "regex": "^/api/v1(?:/((?:[^/]+?)(?:/(?:[^/]+?))*))?(?:/)?$",
                        }
                    ],
                    "fallback": [],
                },
            }
        )
    )

    result = subprocess.run(  # noqa: S603 — fixed argv, no shell
        [node, str(app / "scripts" / RESOLVER.name)],
        env={"PATH": "/usr/bin:/bin:/usr/local/bin", "API_URL": OPERATOR_API},
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, (
        f"the resolver exited {result.returncode} instead of re-pointing the proxy.\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )

    written = json.loads(manifest.read_text())
    destination = written["rewrites"]["afterFiles"][0]["destination"]
    assert destination == f"{OPERATOR_API}/api/v1/:path*", (
        "the console still proxies to the address compiled into the image "
        f"({destination!r}) after the operator asked for {OPERATOR_API!r}. "
        "Setting API_URL on a pulled image has to take effect, or a "
        "single-host deployment can never reach its own API."
    )


def test_resolver_refuses_to_start_when_a_chosen_address_cannot_be_applied(
    tmp_path: pathlib.Path,
) -> None:
    """Booting anyway would serve a console silently pointed at the wrong host.

    An operator who set an address and did not get it is misconfigured in a way
    no retry clears, so this is a permanent condition that must stop and name
    itself rather than degrade quietly to the built-in defaults.
    """
    node = shutil.which("node") or ""
    if not node:
        pytest.fail("node is required to exercise the resolver's failure posture.")

    app = tmp_path / "apps" / "web"
    (app / "scripts").mkdir(parents=True)
    shutil.copy(WEB / "next.config.js", app / "next.config.js")
    shutil.copy(RESOLVER, app / "scripts" / RESOLVER.name)
    (tmp_path / "VERSION").write_text((REPO / "VERSION").read_text())
    # No .next/routes-manifest.json — the manifest cannot be applied.

    result = subprocess.run(  # noqa: S603 — fixed argv, no shell
        [node, str(app / "scripts" / RESOLVER.name)],
        env={"PATH": "/usr/bin:/bin:/usr/local/bin", "API_URL": OPERATOR_API},
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode != 0, (
        "the resolver started the console on the built-in addresses after failing to apply an address the operator explicitly set"
    )
    assert "API_URL" in result.stderr, f"the failure has to name the variable it could not apply; stderr was {result.stderr!r}"


def test_web_image_resolves_upstreams_before_the_server_starts() -> None:
    """The resolver only helps if the image actually runs it."""
    assert ENTRYPOINT.is_file(), (
        f"{ENTRYPOINT.relative_to(REPO)} is missing, so nothing re-points the compiled rewrite table when the container starts"
    )
    assert RESOLVER.name in ENTRYPOINT.read_text(), "the entrypoint does not invoke the resolver"

    dockerfile = DOCKERFILE.read_text()
    assert "ENTRYPOINT" in dockerfile and "docker-entrypoint.sh" in dockerfile, (
        "apps/web/Dockerfile does not wire docker-entrypoint.sh as its ENTRYPOINT, so `next start` runs against the build-time manifest"
    )


def test_compose_gives_the_console_addresses_it_can_actually_read(
    compose: dict,
) -> None:
    """`NEXT_PUBLIC_*` under `environment:` is read by nothing.

    The Compose file set `NEXT_PUBLIC_API_URL` and `NEXT_PUBLIC_WS_URL` on a
    service that pulls its image. Next inlines those at build time, so an
    operator editing them to point at their own host saw no change and had no
    way to tell the setting was inert — which is exactly what was reported.
    """
    env = _web_env(compose)

    inert = sorted(k for k in env if k.startswith("NEXT_PUBLIC_"))
    assert not inert, (
        f"docker-compose.yml sets {inert} on the `web` service. Next inlines "
        "NEXT_PUBLIC_* into the bundle at build time, so on the pulled image "
        "this service runs they do nothing but mislead. The browser needs no "
        "absolute URL — it calls same-origin paths that this server proxies."
    )

    for required in ("API_URL", "AGENTS_URL", "REALTIME_URL"):
        assert required in env, f"the `web` service sets no {required}, so the console can only reach the hosts its image was built against"


def test_helm_points_the_console_at_the_chart_s_own_services() -> None:
    """The same defect is worse on Kubernetes, which is where this user is going.

    The chart creates `<release>-api`, `<release>-agents` and
    `<release>-realtime`, while the published image is built against the
    Compose network's `http://api:8000`. No such host exists in a cluster, and
    the chart set no upstream addresses at all — so every console request
    resolved nowhere. Parsed from the template rather than rendered with
    `helm`, which is not installed in the job that runs these tests.
    """
    template = (REPO / "infra" / "helm" / "aisoc" / "templates" / "deployment.yaml").read_text()

    for upstream in ("API_URL", "AGENTS_URL", "REALTIME_URL"):
        assert upstream in template, (
            f"the Helm chart never sets {upstream} on the web deployment, so "
            "the console proxies to the hostnames its image was built with — "
            "which do not resolve in a cluster"
        )

    assert 'include "aisoc.fullname"' in template, (
        "the upstream addresses must be built from the release's own Service names; a hard-coded hostname is the defect this is fixing"
    )


def test_single_host_deployment_can_publish_the_console(compose: dict) -> None:
    """Loopback-only is right for a laptop and fatal for a server.

    Every published port was the literal `127.0.0.1`, so a single-host install
    was unreachable from the browser it was meant to be used from, and nothing
    in `.env` could change that. The console gets its own knob because
    same-origin proxying means one port is enough — the datastores and their
    shipped development passwords stay on loopback.
    """
    published = [port for service in compose["services"].values() for port in (service.get("ports") or []) if isinstance(port, str)]
    assert published, "no published ports found — has the compose schema changed?"

    hardcoded = [p for p in published if p.startswith("127.0.0.1:")]
    assert not hardcoded, (
        f"{len(hardcoded)} port(s) publish to a hard-coded 127.0.0.1 "
        f"({hardcoded[:3]}…). A deployment on a host that is not the "
        "operator's laptop cannot be reached, and no variable changes it."
    )

    console = compose["services"]["web"]["ports"]
    assert any("AISOC_CONSOLE_BIND_ADDR" in str(p) for p in console), (
        "the console has no bind address of its own, so making it reachable "
        "would mean moving every binding — including Postgres, Redis and "
        "Kafka with the development passwords this file ships"
    )

    defaults_to_loopback = all("127.0.0.1" in p for p in published)
    assert defaults_to_loopback, (
        "a port stopped defaulting to loopback. An install must not expose itself to whatever network the host is attached to by omission."
    )
