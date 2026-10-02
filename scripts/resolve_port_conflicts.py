#!/usr/bin/env python3
"""Move AiSOC's host ports off anything already listening, automatically.

Why this exists
---------------
`make up` used to **refuse to start** when any one of sixteen host ports was
taken, and tell the operator to go edit `docker-compose.yml` by hand. That
is a hard stop at step one of the documented quick start, triggered by the
single most common condition in the target audience's environment: a
Postgres on 5432, or — worse, because this product's readers are exactly
the people who have one — an Ollama on 11434.

Refusing was a real improvement over the alternative at the time. Compose
reports `Bind for 127.0.0.1:NNNN failed` against whichever container lost
the race, half a stack later, which is a much worse diagnostic. But the
right answer to "that port is busy" is not to stop; it is to use a
different one and say so.

What it does
------------
Reads the port inventory `scripts/doctor.sh` already maintains (and which
`tests/test_doctor_port_coverage.py` keeps honest in both directions),
finds what is actually listening, picks the next free port for each
conflict, and writes `docker-compose.ports.yml`.

Three details that are not obvious
-----------------------------------
**`ports: !override` is mandatory.** A plain override *appends*, so the
conflicting binding stays published and compose fails anyway with the
file in place and apparently correct. This is written down in the repo
already, which is how it is known.

**A remapped console port has to reach `.env`.** If the console moves off
3000 then the address `make up` prints, and `AISOC_CONSOLE_URL`, must move
with it — otherwise the operator is handed a URL that answers nothing,
which is worse than the conflict.

**Only the host side moves.** Service-to-service traffic inside the compose
network uses container ports and service names, so remapping the published
port changes nothing about how the stack talks to itself.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import socket
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
COMPOSE = REPO / "docker-compose.yml"
OVERRIDE = REPO / "docker-compose.ports.yml"
DOCTOR = REPO / "scripts" / "doctor.sh"

#: Where to start looking for a replacement. High enough to be clear of the
#: well-known range and of anything the stack itself publishes.
SEARCH_BASE = 15000
SEARCH_LIMIT = 400

#: The published port a human is handed. Worth naming, because this is the
#: one whose remap has to propagate into `.env` and the printed address.
CONSOLE_SERVICE = "web"


def inventory() -> list[tuple[int, str, int]]:
    """`(host_port, service, container_port)` read from `doctor.sh`.

    Parsed from the shell rather than duplicated here on purpose. A second
    hand-maintained list is a second thing to forget: the Ollama port was
    missing from the original for exactly that reason, and the conflict
    this audience is most likely to hit was the one nothing checked.
    """
    text = DOCTOR.read_text()
    match = re.search(r'for spec in (".*?"); do', text, re.S)
    if not match:
        raise SystemExit(
            "resolve_port_conflicts: could not read the port inventory out of "
            "scripts/doctor.sh. It is the single source of truth for which host "
            "ports CORE publishes; refusing to guess."
        )
    specs = re.findall(r'"(\d+)\s+([a-z0-9-]+)\s+(\d+)"', match.group(1))
    if not specs:
        raise SystemExit("resolve_port_conflicts: the port inventory parsed to nothing")
    return [(int(h), s, int(c)) for h, s, c in specs]


def _listening(port: int) -> bool:
    """Whether anything holds this port.

    Binds rather than connects: a port can be held by a listener that
    refuses connections, and `connect` would call that free.

    Two details, both of which this got wrong first time and both of which
    would have missed the single most common conflict — a Docker container
    publishing Postgres on 5432:

    **No `SO_REUSEADDR`.** It makes the probe *more permissive than the
    real bind*. With it set, binding `127.0.0.1:5432` succeeds while
    another container holds `0.0.0.0:5432`; without it, the same bind
    correctly fails. A probe that is easier to satisfy than the thing it
    predicts is worse than no probe.

    **The wildcard address first.** Docker publishes to `0.0.0.0` by
    default, so that is the bind that actually has to succeed. Loopback is
    checked too, for a port held only there.
    """
    for family, addr in (
        (socket.AF_INET, "0.0.0.0"),  # noqa: S104 — probing, never serving
        (socket.AF_INET, "127.0.0.1"),
        (socket.AF_INET6, "::1"),
    ):
        try:
            with socket.socket(family, socket.SOCK_STREAM) as probe:
                probe.bind((addr, port))
        except OSError:
            return True
        except Exception:  # noqa: BLE001 — no IPv6 on this host, say
            continue
    return False


def _holder(port: int) -> str:
    """A human name for whatever holds the port, best effort."""
    try:
        out = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"],
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout
        for line in out.splitlines():
            name, _, ports = line.partition("\t")
            if re.search(rf"(^|[^0-9]){port}->", ports):
                return f"container {name}"
    except Exception:  # noqa: BLE001
        pass
    try:
        out = subprocess.run(
            ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"],
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.splitlines()
        if len(out) > 1:
            return out[1].split()[0]
    except Exception:  # noqa: BLE001
        pass
    return "another process"


def _free_port(start: int, taken: set[int]) -> int:
    for candidate in range(start, start + SEARCH_LIMIT):
        if candidate not in taken and not _listening(candidate):
            return candidate
    raise SystemExit(
        f"resolve_port_conflicts: no free port between {start} and {start + SEARCH_LIMIT}. Something is very wrong with this host."
    )


def plan() -> list[tuple[int, str, int, int]]:
    """`(old, service, container_port, new)` for each conflict."""
    ours = _our_containers()
    moves: list[tuple[int, str, int, int]] = []
    taken: set[int] = {h for h, _, _ in inventory()}
    for host, service, container in inventory():
        if not _listening(host):
            continue
        # Our own container already holding it is not a conflict; that is a
        # stack which is simply already up.
        if service in ours:
            continue
        replacement = _free_port(SEARCH_BASE + (host % 1000), taken)
        taken.add(replacement)
        moves.append((host, service, container, replacement))
    return moves


def _our_containers() -> set[str]:
    try:
        out = subprocess.run(
            ["docker", "compose", "ps", "--services", "--status", "running"],
            capture_output=True,
            text=True,
            cwd=REPO,
            timeout=20,
        )
        return {line.strip() for line in out.stdout.splitlines() if line.strip()}
    except Exception:  # noqa: BLE001
        return set()


def render(moves: list[tuple[int, str, int, int]]) -> str:
    lines = [
        "# Generated by scripts/resolve_port_conflicts.py — do not edit by hand.",
        "#",
        "# Host ports AiSOC publishes that were already in use when the stack",
        "# started, moved somewhere free. Only the published side moves:",
        "# service-to-service traffic inside the compose network uses container",
        "# ports and service names, so nothing about how the stack talks to",
        "# itself changes.",
        "#",
        "# `ports: !override` is required and not decorative. A plain override",
        "# *appends*, which would leave the conflicting binding published and",
        "# fail the bind anyway, with this file in place and looking correct.",
        "",
        "services:",
    ]
    for old, service, container, new in moves:
        lines.append(f"  # {service}: {old} was in use, published on {new} instead")
        lines.append(f"  {service}:")
        lines.append("    ports: !override")
        lines.append(f'      - "{new}:{container}"')
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="report conflicts and exit non-zero, changing nothing",
    )
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    moves = plan()

    if not moves:
        # A stale override from a previous run would silently keep the stack
        # on moved ports after the conflict is gone, so it is removed.
        if OVERRIDE.exists():
            OVERRIDE.unlink()
            if not args.quiet:
                print("  every port is free again; removed docker-compose.ports.yml")
        elif not args.quiet:
            print("  all 16 host ports are free")
        return 0

    if args.check:
        for old, service, _c, new in moves:
            print(f"  {service}: {old} held by {_holder(old)} — would use {new}")
        return 1

    OVERRIDE.write_text(render(moves))
    print()
    print(f"  {len(moves)} port(s) were already in use, so AiSOC moved:")
    for old, service, _c, new in moves:
        print(f"    {service:<14} {old} → {new}   ({old} is held by {_holder(old)})")
    print()
    print("  Written to docker-compose.ports.yml, which make up includes.")
    print("  Nothing inside the stack changed: only the ports published to this host.")
    print()

    console = next((new for _o, s, _c, new in moves if s == CONSOLE_SERVICE), None)
    if console:
        _rewrite_console_url(console)
    return 0


def _rewrite_console_url(port: int) -> None:
    """Point `AISOC_CONSOLE_URL` at the port the console actually answers on.

    Without this the operator is handed an address that answers nothing,
    which is a worse outcome than the conflict that caused the move.
    """
    env = REPO / ".env"
    url = f"http://localhost:{port}"
    if not env.exists():
        return
    text = env.read_text()
    if "AISOC_CONSOLE_URL=" in text:
        text = re.sub(r"^AISOC_CONSOLE_URL=.*$", f"AISOC_CONSOLE_URL={url}", text, flags=re.M)
    else:
        text = text.rstrip("\n") + f"\n\n# The console moved off 3000; see docker-compose.ports.yml\nAISOC_CONSOLE_URL={url}\n"
    env.write_text(text)
    print(f"  The console moved, so AISOC_CONSOLE_URL now reads {url}")
    print()


if __name__ == "__main__":
    sys.exit(main())
