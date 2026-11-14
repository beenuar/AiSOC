#!/usr/bin/env python3
"""A *running* container is watched, not just its declared defaults.

Why this exists
---------------

Two gates already cover part of "runs entirely on your infrastructure".
``scripts/check_default_egress.py`` reads every service's declared settings
defaults, and ``tests/test_no_default_egress.py`` puts a socket guard in front
of each service's import and ASGI lifespan. Both are honest about what they
are not, and ``tests/test_no_default_egress.py`` says it in as many words:

    Neither this nor the static gate says anything about what the *running
    containers* do. That needs egress-blocked integration, which the Helm
    chart's default-deny NetworkPolicy addresses at deploy time and nothing
    addresses in CI.

That sentence is what this closes. A declaration can be right and an import
path can be clean while the built image reaches out anyway — a base image's
entrypoint, a package that phones home on first use, a scheduler thread that
only starts under the real command, a client constructed after startup rather
than during it. None of those are visible to either existing half, because
neither of them ever runs the container.

How it works
------------

The probe is an observation, not just a block, because a block alone cannot
tell "made no call" apart from "made a call that failed":

1. A docker network is created with ``--internal``. Docker installs no route
   off the host for it, so nothing on that network can reach the internet
   whatever it tries. This is the containment half, and it is what makes the
   probe safe to run on a shared machine.
2. A DNS sinkhole container joins that network and is made the *only*
   resolver the service container has. It logs every question asked of it and
   answers every one of them ``NXDOMAIN``.
3. The service container is started from the image built for this commit,
   with the same deliberately-empty environment the static halves use — no
   URL of any kind, so every address observed came from the service itself.
4. After the startup window the sinkhole's log is read and every name is
   classified with the same public/private predicate the services enforce
   air-gap policy with. A public name is a finding. An internal one
   (``redis``, ``postgres``, ``*.internal``) is reported and passes, because
   dialling your own Postgres is the product working.

Proving the probe can see
-------------------------

A probe that observes nothing and a service that does nothing look identical,
which is this repository's most-repeated failure shape, and it is not
hypothetical here: the API's unconfigured startup dials Postgres on loopback,
which needs no name resolution, so a correct run legitimately records **zero**
lookups. Zero is exactly what a broken sinkhole records too.

Two things separate them, and both are required rather than optional:

``--negative-control``
    A canary container is started with the *identical* network and ``--dns``
    flags the service gets, and asked to resolve a public name. The sinkhole
    must see it. This tests the property actually in doubt — that a container
    placed on this network resolves through this sinkhole — rather than
    whether some particular service happens to dial its configured URL during
    startup, which is a different claim and a much weaker control.

evidence of execution
    A service container that emitted no log line and asked for no name is
    reported as a finding, not a pass. Whatever it proves, it is not that the
    image declines to phone home.

Honest limits
-------------

* A dial straight to a **public IP literal** never asks DNS, so this probe
  does not observe it. The ``--internal`` network still prevents it from
  leaving the host, and ``check_default_egress.py`` reads the declared
  defaults where such a literal would have to be written down, but between
  them that case is prevented and statically checked rather than observed.
* The window is bounded. A service that would phone home on a timer longer
  than ``--seconds`` is not covered, and the window is printed so the bound
  is legible rather than implied.
* Only services named on the command line are covered, and the gate refuses
  an empty set rather than passing vacuously.

Usage
-----
::

    python3 scripts/check_container_egress.py --service api --service fusion
    python3 scripts/check_container_egress.py --service api --negative-control
    python3 scripts/check_container_egress.py --self-test

Exit codes: 0 clean, 1 findings, 2 the check itself could not run.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

#: Lifted from ``services/api/app/core/airgap.py``. Kept as a literal rather
#: than imported because this gate runs in a job with no service package on
#: the path; ``test_check_container_egress.py`` asserts it still matches the
#: service's own tuple so the two cannot drift.
PRIVATE_SUFFIXES = (
    ".local",
    ".internal",
    ".lan",
    ".intranet",
    ".corp",
    ".home",
    ".localdomain",
    "localhost",
)

#: How long a service gets to start and do whatever it does on startup.
DEFAULT_WINDOW_SECONDS = 45

#: The smallest environment that is still an *unconfigured* one, matching
#: ``tests/test_no_default_egress.py``. No URL of any kind: every address the
#: probe observes therefore came from the service's own defaults.
MINIMAL_ENV = {
    "ENVIRONMENT": "development",
    "SECRET_KEY": "offline-egress-probe-secret-key-32bytes!",
    "JWT_SECRET": "offline-egress-probe-secret-key-32bytes!",
    "AISOC_SERVICE_TOKEN": "offline-egress-probe-token",
    "PYTHONUNBUFFERED": "1",
}

#: The name the canary resolves. RFC 2606 reserved, so it is unregistrable and
#: could not be reached even if the network had a route out — which it does
#: not: the sinkhole answers NXDOMAIN and ``--internal`` drops the packet.
NEGATIVE_CONTROL_HOST = "egress-control.example.com"

#: A DNS server that answers everything NXDOMAIN and prints every question it
#: was asked, one name per line. Stdlib only, so it runs in any python image.
SINKHOLE_SOURCE = r"""
import socket, sys

def qname(packet):
    i, labels = 12, []
    while i < len(packet):
        length = packet[i]
        if length == 0:
            break
        labels.append(packet[i + 1 : i + 1 + length].decode("utf-8", "replace"))
        i += 1 + length
    return ".".join(labels)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 53))
print("SINKHOLE-READY", flush=True)
while True:
    try:
        packet, peer = sock.recvfrom(4096)
    except Exception as exc:
        print("SINKHOLE-ERROR %r" % (exc,), flush=True)
        continue
    if len(packet) < 13:
        continue
    name = qname(packet)
    if name:
        print("QUERY %s" % name, flush=True)
    # NXDOMAIN: flags QR=1, RD copied, RCODE=3. Question echoed, no answers.
    header = packet[:2] + b"\x81\x83" + packet[4:6] + b"\x00\x00\x00\x00\x00\x00"
    try:
        sock.sendto(header + packet[12:], peer)
    except Exception:
        pass
"""


def is_private_host(host: str) -> bool:
    """The air-gap predicate, applied to a name the sinkhole was asked for."""
    if not host:
        return False
    host = host.lower().strip().rstrip(".")
    if "." not in host:
        # A bare label is a compose / k8s service name — internal by
        # definition, and the same rule the services themselves apply.
        return True
    for suffix in PRIVATE_SUFFIXES:
        if host == suffix.lstrip(".") or host.endswith(suffix):
            return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified


def parse_queries(sinkhole_log: str) -> list[str]:
    """Every name the sinkhole was asked for, in order, deduplicated."""
    seen: list[str] = []
    for line in sinkhole_log.splitlines():
        if not line.startswith("QUERY "):
            continue
        name = line[len("QUERY ") :].strip().lower().rstrip(".")
        if name and name not in seen:
            seen.append(name)
    return seen


def classify(queries: list[str]) -> tuple[list[str], list[str]]:
    """``(public, internal)`` — only the first is a finding."""
    public = [q for q in queries if not is_private_host(q)]
    internal = [q for q in queries if is_private_host(q)]
    return public, internal


def _run(cmd: list[str], *, check: bool = False, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, check=check, timeout=timeout)


class Probe:
    """One ``--internal`` network, one sinkhole, torn down whatever happens."""

    def __init__(self, tag: str) -> None:
        self.network = f"aisoc-egress-{tag}"
        self.sinkhole = f"aisoc-egress-dns-{tag}"
        self.started: list[str] = []

    def __enter__(self) -> Probe:
        # `--internal` is the containment: Docker installs no route off the
        # host, so whatever the service tries cannot leave this machine.
        _run(["docker", "network", "create", "--internal", self.network], check=True)
        _run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                self.sinkhole,
                "--network",
                self.network,
                "python:3.11-slim",
                "python",
                "-c",
                SINKHOLE_SOURCE,
            ],
            check=True,
        )
        self.started.append(self.sinkhole)
        for _ in range(60):
            if "SINKHOLE-READY" in _run(["docker", "logs", self.sinkhole]).stdout:
                return self
            time.sleep(1)
        raise RuntimeError("the DNS sinkhole never reported ready")

    def __exit__(self, *_exc: object) -> None:
        # Only ever removes what this probe started. Another agent's stack on
        # the same daemon is none of its business.
        for name in reversed(self.started):
            _run(["docker", "rm", "-f", name])
        _run(["docker", "network", "rm", self.network])

    def sinkhole_ip(self) -> str:
        out = _run(
            ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", self.sinkhole],
            check=True,
        ).stdout.strip()
        if not out:
            raise RuntimeError("the sinkhole container reported no address")
        return out

    def _attach_flags(self) -> list[str]:
        """The network flags every probed container gets, canary included.

        One definition, used by both, so the canary proves the wiring the
        service actually inherits rather than a lookalike of it.
        """
        return ["--network", self.network, "--dns", self.sinkhole_ip()]

    def observe(self, service: str, image: str, env: dict[str, str], seconds: int) -> tuple[list[str], str]:
        """Run ``image`` for ``seconds`` and return (queried names, its log)."""
        before = set(parse_queries(_run(["docker", "logs", self.sinkhole]).stdout))
        name = f"aisoc-egress-svc-{service}-{uuid.uuid4().hex[:8]}"
        cmd = ["docker", "run", "-d", "--name", name, *self._attach_flags()]
        for key, value in env.items():
            cmd += ["-e", f"{key}={value}"]
        cmd.append(image)
        started = _run(cmd)
        if started.returncode != 0:
            raise RuntimeError(f"could not start {image}: {started.stderr.strip()}")
        self.started.append(name)
        time.sleep(seconds)
        logs = _run(["docker", "logs", name])
        service_log = logs.stdout + logs.stderr
        # Only what *this* container asked for. Attributing an earlier
        # container's lookup to this one would be a finding against the wrong
        # service, and on a clean run would be a finding against nobody.
        queries = [q for q in parse_queries(_run(["docker", "logs", self.sinkhole]).stdout) if q not in before]
        _run(["docker", "rm", "-f", name])
        self.started.remove(name)
        return queries, service_log

    def canary(self) -> list[str]:
        """Resolve a public name from a container wired exactly like a probed one."""
        before = set(parse_queries(_run(["docker", "logs", self.sinkhole]).stdout))
        _run(
            [
                "docker",
                "run",
                "--rm",
                *self._attach_flags(),
                "python:3.11-slim",
                "python",
                "-c",
                f"import socket\ntry:\n    socket.gethostbyname({NEGATIVE_CONTROL_HOST!r})\nexcept OSError:\n    pass\n",
            ],
            timeout=180,
        )
        return [q for q in parse_queries(_run(["docker", "logs", self.sinkhole]).stdout) if q not in before]


def image_for(service: str, root: Path) -> str:
    """The image tag ``docker compose build`` produces for ``service``.

    Read from the running daemon rather than guessed, because a guessed tag
    that does not exist would make this gate fail for a reason that has
    nothing to do with egress.
    """
    out = _run(["docker", "compose", "config", "--format", "json"], timeout=120)
    if out.returncode != 0:
        raise RuntimeError(f"`docker compose config` failed: {out.stderr.strip()[:400]}")
    try:
        services = json.loads(out.stdout).get("services") or {}
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"`docker compose config` did not emit JSON: {exc}") from exc
    entry = services.get(service)
    if entry is None:
        raise RuntimeError(f"{service!r} is not a service in the compose file at {root}")
    image = entry.get("image")
    if not image:
        raise RuntimeError(f"{service!r} declares no image tag to probe")
    return str(image)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Watch a running container for outbound calls.")
    parser.add_argument("--service", action="append", default=[], help="a compose service to probe (repeatable)")
    parser.add_argument(
        "--probe-image",
        default=None,
        help=(
            "probe this image instead of resolving the service's tag from the compose file. "
            "This exists so the gate can be shown going red against an image that does dial "
            "out; CI names real services everywhere else."
        ),
    )
    parser.add_argument("--seconds", type=int, default=DEFAULT_WINDOW_SECONDS, help="startup window to observe")
    parser.add_argument(
        "--negative-control",
        action="store_true",
        help="run a canary wired like the probed containers and require the sinkhole to see its lookup",
    )
    parser.add_argument("--repo-root", type=Path, default=None)
    args = parser.parse_args(argv)

    root = args.repo_root.resolve() if args.repo_root else repo_root()
    if not (root / "docker-compose.yml").is_file():
        print(f"ERROR: no docker-compose.yml under {root} — nothing to probe", file=sys.stderr)
        return 2
    if not args.service:
        print("ERROR: name at least one --service. A probe that covers nothing must not report clean.", file=sys.stderr)
        return 2
    if shutil.which("docker") is None:
        print("ERROR: docker is not on PATH — this gate observes running containers and cannot be faked", file=sys.stderr)
        return 2

    os.chdir(root)
    problems: list[str] = []
    observed: list[str] = []

    try:
        with Probe(uuid.uuid4().hex[:8]) as probe:
            if args.negative_control:
                seen = probe.canary()
                public, _ = classify(seen)
                if NEGATIVE_CONTROL_HOST not in public:
                    problems.append(
                        f"a canary wired exactly like the probed containers asked for {NEGATIVE_CONTROL_HOST} "
                        f"and the sinkhole did not record it. The probe is blind, so a clean run proves nothing. "
                        f"Names seen: {', '.join(seen) or 'none'}"
                    )
                else:
                    observed.append(f"canary observed asking for {NEGATIVE_CONTROL_HOST} — the probe can see egress")
            else:
                for service in args.service:
                    image = args.probe_image or image_for(service, root)
                    queries, service_log = probe.observe(service, image, dict(MINIMAL_ENV), args.seconds)
                    public, internal = classify(queries)

                    if not service_log.strip() and not queries:
                        problems.append(
                            f"{service} ({image}) produced no log output and asked for no name in {args.seconds}s — "
                            "the probe observed nothing at all, which is not evidence that the image declines to "
                            "phone home. Check the image starts under `docker run` with no dependencies."
                        )
                    elif public:
                        problems.append(
                            f"{service} ({image}) asked for {len(public)} public name(s) within {args.seconds}s: {', '.join(public)}"
                        )
                        print(f"--- last lines of {service} ---", file=sys.stderr)
                        print("\n".join(service_log.splitlines()[-25:]), file=sys.stderr)
                    else:
                        observed.append(
                            f"{service}: 0 public, {len(internal)} internal "
                            f"({', '.join(internal) or 'none'}), {len(service_log.splitlines())} log line(s)"
                        )
    except subprocess.TimeoutExpired as exc:
        print(f"ERROR: a docker command timed out: {exc}", file=sys.stderr)
        return 2
    except (RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: the probe could not run: {exc}", file=sys.stderr)
        return 2

    mode = "negative control" if args.negative_control else "egress probe"
    if problems:
        print(f"container-egress: {len(problems)} finding(s) — {mode}, {args.seconds}s window", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1

    print(f"container-egress: OK — {mode}, {args.seconds}s window, {len(args.service)} service(s)")
    for line in observed:
        print(f"  {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
