#!/usr/bin/env python3
"""Gate: the published compose-profile service counts match the compose file.

Five documents publish how many services each profile starts, and until this
gate existed nothing compared any of them to ``docker-compose.yml``. That is
the shape this repository keeps paying for: a number copied into prose goes
stale silently, and a reader has no way to tell a current figure from one that
was true two releases ago. ADR-0006 found exactly this while editing the same
table for a different reason: the published ``full`` count was 30, which is
every profile at once rather than what ``make up-full`` starts.

Derived from the YAML rather than from ``docker compose config``, for two
reasons. CI has no Docker daemon in the jobs that would want to run this, and
``docker compose`` resolves ``.env``, so the answer would depend on the
caller's environment rather than on the tree.

What it checks, in both directions:

  1. Every documented count equals the count the compose file implies.
  2. Every profile a document names still exists in the compose file, so a
     renamed profile fails as a stale reference rather than passing because
     nothing matched it.
  3. ``actions`` is reachable from the ``chatops`` profile, because
     ``slack-bot`` declares a dependency on it and a compose file whose
     dependency is outside the profile fails to render at all. ADR-0007 moved
     ``actions`` out of every profile list to satisfy this, and "it is in no
     list" is precisely the state a future edit would undo by adding one back.

Run:  python3 scripts/check_profile_service_counts.py
      python3 scripts/check_profile_service_counts.py --inventory
      python3 scripts/check_profile_service_counts.py --self-test

Exit codes: 0 clean, 1 a published count is wrong, 2 the scan could not run.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

REPO_ROOT = repo_root()
COMPOSE = REPO_ROOT / "docker-compose.yml"

#: One-shot containers that run to completion and exit. Counted separately
#: because "long-running services" is the figure the documents publish, and
#: folding a container that exits into it would overstate what is resident.
ONE_SHOT: frozenset[str] = frozenset({"ollama-pull"})

#: Where a count is published, and how to find it. Each entry is
#: ``(path, profile, regex)`` where the regex has one group holding the
#: number. Deliberately a list of exact sites rather than a search for any
#: integer near the word "services": a gate that guesses which numbers are
#: claims would either miss the one that matters or flag prose forever.
CLAIM_SITES: tuple[tuple[str, str, str], ...] = (
    ("README.md", "core", r"\|\s*\*\*core\*\*\s*\|\s*`make up`\s*\|\s*(\d+)\s*\|"),
    ("README.md", "full", r"\|\s*\*\*full\*\*\s*\|\s*`make up-full`\s*\|\s*(\d+)\s*\|"),
    ("README.md", "core", r"\|\s*\*\*demo\*\*\s*\|\s*`make up && make demo`\s*\|\s*(\d+)\s*\|"),
    (
        "apps/docs/docs/architecture.md",
        "core",
        r"\|\s*\*\*core\*\*\s*\|\s*`make up`\s*\|\s*(\d+)\s*\|",
    ),
    (
        "apps/docs/docs/architecture.md",
        "full",
        r"\|\s*\*\*full\*\*\s*\|\s*`make up-full`\s*\|\s*(\d+)\s*\|",
    ),
    (
        "apps/docs/docs/architecture.md",
        "core",
        r"CORE is (\d+) long-running containers",
    ),
    (
        "apps/docs/docs/architecture.md",
        "full",
        r"`full` is (\d+) long-running containers",
    ),
    (
        "apps/docs/docs/quickstart.md",
        "core",
        r"CORE is (\d+) long-running services",
    ),
    (
        "apps/docs/docs/quickstart.md",
        "full",
        r"and `full` is (\d+)",
    ),
    (
        "docs/audit/REPOSITORY_REALITY.md",
        "core",
        r"CORE profile: (\d+) long-running services",
    ),
    # The five below went unchecked until ADR-0007 moved CORE to 16 and they
    # kept saying 14. Two of them are the landing page and the FAQ, so the
    # wrong number was the one a reader met first.
    ("ROADMAP.md", "core", r"CORE is (\d+) long-running services"),
    (
        "apps/web/public/screenshots/README.md",
        "core",
        r"CORE: (\d+) long-running services",
    ),
    ("apps/web/src/app/page.tsx", "core", r"core profile brings up (\d+) services"),
    (
        "apps/web/src/components/landing/sections/Faq.tsx",
        "core",
        r"core profile brings up (\d+) services",
    ),
    (
        "docs/testing/CLEAN_INSTALL.md",
        "core",
        r"CORE profile, (\d+) long-running services",
    ),
)


#: Where a service count may be *mentioned* without being a claim about a
#: profile. Each entry is a path, and every one is a deliberate decision that
#: the number there is not the CORE or `full` figure.
COUNT_MENTION_EXEMPT: frozenset[str] = frozenset(
    {
        # Records what each release changed, including counts that were correct
        # then and are not now. Rewriting them would be revisionism.
        "CHANGELOG.md",
        "RELEASES.md",
        # An ADR states the count at the moment it was decided, as its own
        # evidence. ADR-0006 says 11 and ADR-0007 says 14 to 16; both are true
        # of the day they were written.
        "docs/decisions",
        # Historical prototype subtree, not this product.
        "plans",
        # Counts source directories, not running containers.
        "docs/architecture/SYSTEM_DESIGN.md",
        # Counts what that deployment target runs, which is not a profile of
        # this compose file.
        "infra/railway/README.md",
    }
)

#: Finds a sentence that looks like it publishes a profile's service count.
#: Deliberately narrow: it wants the number adjacent to the word services, not
#: any integer in the vicinity.
COUNT_MENTION = re.compile(r"\b(\d+)\s+(?:long-running\s+)?(?:services|containers)\b")


class ScanError(RuntimeError):
    """The compose file could not be read or parsed."""


def unregistered_mentions() -> list[str]:
    """Files publishing a service count that no CLAIM_SITES entry validates.

    The list above is deliberately exact, and the reasoning is sound: a gate
    that guessed which integers were claims would flag prose forever. But it
    left the gate blind in the direction things actually move. Nothing noticed
    when five surfaces kept saying 14 after ADR-0007 took CORE to 16, including
    the landing page and the FAQ, because a figure added to a file this list
    does not name is a figure this gate never reads.

    So the exactness stays for *validating* a number, and this asks the
    complementary question: does anything publish a count we are not checking?
    A new surface must either join CLAIM_SITES or be exempted on purpose.
    """
    registered = {rel for rel, _profile, _pattern in CLAIM_SITES}
    findings: list[str] = []
    for path in sorted(REPO_ROOT.rglob("*")):
        if path.is_dir() or path.suffix not in {".md", ".mdx", ".tsx", ".ts"}:
            continue
        rel = path.relative_to(REPO_ROOT).as_posix()
        if rel in registered or any(rel == e or rel.startswith(f"{e}/") for e in COUNT_MENTION_EXEMPT):
            continue
        if any(part in {"node_modules", ".git", ".next", "dist"} for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            if "profile" not in line.lower() and "make up" not in line and "CORE" not in line:
                continue
            match = COUNT_MENTION.search(line)
            if match:
                findings.append(f"{rel}:{line_no} publishes '{match.group(0)}' and no CLAIM_SITES entry validates it")
    return findings


def _parse_services(text: str) -> dict[str, list[str] | None]:
    """Service name to its declared profile list, or ``None`` for no list.

    Hand-parsed rather than via PyYAML because several gates here run on a
    bare interpreter before any ``pip install``, and ``gate_toolkit`` exists
    to keep that true. The shape being read is narrow: two-space-indented
    service keys under a top-level ``services:``, and a ``profiles:`` key
    four spaces in, in either inline (``["a", "b"]``) or block (``- a``)
    form. Both forms appear in this file.
    """
    services: dict[str, list[str] | None] = {}
    in_services = False
    current: str | None = None
    collecting_block: bool = False

    for raw in text.splitlines():
        if re.match(r"^services:\s*$", raw):
            in_services = True
            continue
        if not in_services:
            continue
        # A new top-level key ends the services block.
        if raw and not raw.startswith((" ", "\t")) and not raw.startswith("#"):
            break

        service = re.match(r"^  ([A-Za-z0-9][A-Za-z0-9._-]*):\s*$", raw)
        if service:
            current = service.group(1)
            services.setdefault(current, None)
            collecting_block = False
            continue

        if current is None:
            continue

        inline = re.match(r"^    profiles:\s*\[(.*)\]\s*$", raw)
        if inline:
            services[current] = re.findall(r"[A-Za-z0-9._-]+", inline.group(1))
            collecting_block = False
            continue

        if re.match(r"^    profiles:\s*$", raw):
            services[current] = []
            collecting_block = True
            continue

        if collecting_block:
            item = re.match(r"^      -\s*([A-Za-z0-9._-]+)\s*$", raw)
            if item:
                bucket = services[current]
                if bucket is None:  # pragma: no cover - set to [] just above
                    bucket = services[current] = []
                bucket.append(item.group(1))
                continue
            collecting_block = False

    return services


def _profile_members(services: dict[str, list[str] | None], profile: str) -> set[str]:
    """Services a ``--profile <profile>`` run starts.

    A service with no ``profiles:`` key is started by every run, which is the
    compose semantic ADR-0007 relies on. ``core`` is spelled as a profile here
    for symmetry with the documents, and means "no named profile".
    """
    members = {name for name, profiles in services.items() if not profiles}
    if profile != "core":
        members |= {name for name, profiles in services.items() if profiles and profile in profiles}
    return members


def _long_running(members: set[str]) -> int:
    return len(members - ONE_SHOT)


def _declared_profiles(services: dict[str, list[str] | None]) -> set[str]:
    return {p for profiles in services.values() if profiles for p in profiles}


def scan() -> tuple[dict[str, int], dict[str, set[str]], list[str]]:
    """Returns (counts by profile, members by profile, errors)."""
    if not COMPOSE.is_file():
        raise ScanError(f"no compose file at {COMPOSE}")
    text = COMPOSE.read_text(encoding="utf-8")
    services = _parse_services(text)
    if not services:
        raise ScanError(f"parsed zero services out of {COMPOSE}; the format this gate reads has changed")

    errors: list[str] = []
    profiles = ("core", *sorted(_declared_profiles(services)))
    members = {p: _profile_members(services, p) for p in profiles}
    counts = {p: _long_running(members[p]) for p in profiles}

    for rel, profile, pattern in CLAIM_SITES:
        path = REPO_ROOT / rel
        if not path.is_file():
            errors.append(f"{rel}: published a profile count and the file is gone")
            continue
        if profile not in counts:
            errors.append(f"{rel}: names profile {profile!r}, which no service in docker-compose.yml declares")
            continue
        found = re.search(pattern, path.read_text(encoding="utf-8"))
        if found is None:
            errors.append(
                f"{rel}: the {profile!r} count this gate watches is no longer there "
                f"(pattern {pattern!r}). Either the figure moved, in which case update "
                f"CLAIM_SITES, or it was deleted and the entry is stale."
            )
            continue
        published = int(found.group(1))
        if published != counts[profile]:
            errors.append(
                f"{rel}: publishes {published} services for the {profile!r} profile; "
                f"docker-compose.yml has {counts[profile]} long-running "
                f"({', '.join(sorted(members[profile] - ONE_SHOT))})"
            )

    # slack-bot depends on actions, and compose refuses to render a file whose
    # dependency sits outside the profile being started. ADR-0007 satisfies
    # this by putting actions in no profile at all; a later edit adding it
    # back to a list would break `--profile chatops` for everyone.
    if "chatops" in members and "actions" in services and "actions" not in members["chatops"]:
        errors.append(
            "actions is not reachable from the chatops profile, and slack-bot depends on it; "
            "`docker compose --profile chatops` will refuse to render"
        )

    # Asks the tree about the list, having just asked the list about the tree.
    # Without this the gate can only be wrong about files it already knows.
    errors.extend(unregistered_mentions())

    return counts, members, errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", action="store_true", help="print the per-profile membership and exit 0")
    args = parser.parse_args(argv)

    try:
        counts, members, errors = scan()
    except ScanError as exc:
        print(f"profile-service-counts: {exc}", file=sys.stderr)
        return 2

    if args.inventory:
        for profile in sorted(counts):
            print(f"{profile:12s} {counts[profile]:3d}  {', '.join(sorted(members[profile]))}")
        return 0

    if errors:
        print("PROFILE SERVICE COUNT GATE FAILED:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print(
        f"profile-service-counts: OK, core {counts['core']}, full {counts.get('full', 0)}, "
        f"{len(CLAIM_SITES)} published figures agree with docker-compose.yml"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
