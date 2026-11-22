"""Shipped surfaces must not link to destinations that no longer exist.

A published link is a claim. The 2026-11-22 QA pass fetched every external
destination the web app ships and four of them were dead in ways a reader
would hit immediately:

* ``discord.gg/aisoc`` — Discord's own invite API answers
  ``{"message": "Unknown Invite", "code": 10006}``. The invite page still
  serves HTTP 200, which is exactly why a status-code check never caught it.
* ``twitter.com/tryaisoc`` / ``x.com/tryaisoc`` — the account does not exist
  (x.com answers 404).
* ``mailto:hello@tryaisoc.com`` — the domain publishes no MX record, so the
  contact address on the customers pages bounced.
* ``tryaisoc.com/cases/…`` — the host now 301s every path to the GitHub repo
  front page, so a deep link promising "a pre-seeded investigation with the
  ledger visible" landed on a repository README instead.

The footer had already removed its status-page row "rather than ship a link
to nowhere" (its comment says so); these were stragglers of the same sweep.
The replacements point at the project's real venues: GitHub Discussions
(named by SUPPORT.md and the README) and the published quickstart docs.

Scope is deliberate: this scans the *shipped* web sources plus the two mesh
claims corrected alongside them. Historical records (CHANGELOG, decision
records, marketing notes, the live-demo runbook) keep their text — rewriting
history to claim a different URL was always used is revisionism, and the
hosted-hostname gate already accounts for every remaining occurrence.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

REPO = Path(
    subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
)

WEB_SRC = REPO / "apps" / "web" / "src"

#: Destination substrings that must not appear in shipped web sources.
#: Each entry records why it is dead so a future re-add is a deliberate
#: decision against the evidence, not an accident.
DEAD_DESTINATIONS: dict[str, str] = {
    "discord.gg/aisoc": "Discord invite API: Unknown Invite (code 10006)",
    "twitter.com/tryaisoc": "x.com answers 404 — the account does not exist",
    "x.com/tryaisoc": "x.com answers 404 — the account does not exist",
    # Catches every address at the domain (hello@, press@, privacy@,
    # security@ all shipped): no MX record exists, so all of them bounce.
    # Plain prose mentions of the bare hostname are deliberately NOT
    # matched — the hosted-hostname gate accounts for those one by one.
    "@tryaisoc.com": "tryaisoc.com publishes no MX record — mail bounces",
    "tryaisoc.com/cases/": "the host 301s every path to the repo front page",
    "mesh.tryaisoc.com": "NXDOMAIN — the community hub does not run there",
}

#: Files whose remaining occurrences are prose *about* the dead hosts
#: (comments recording why a link was removed), never rendered links.
ALLOWED_PROSE: set[str] = set()


def _scan(root: Path) -> list[str]:
    hits: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix not in {".ts", ".tsx", ".js", ".jsx"}:
            continue
        rel = path.relative_to(REPO).as_posix()
        if ".test." in path.name or "/__tests__/" in rel:
            # Test fixtures may simulate hostile or historical inputs.
            continue
        if rel in ALLOWED_PROSE:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for needle, why in DEAD_DESTINATIONS.items():
            if needle in text:
                for lineno, line in enumerate(text.splitlines(), 1):
                    if needle in line:
                        hits.append(f"{rel}:{lineno}: {needle} ({why})")
    return hits


def test_web_sources_ship_no_dead_destinations() -> None:
    hits = _scan(WEB_SRC)
    assert not hits, (
        "Shipped web sources link to destinations verified dead on "
        "2026-11-22. Point the surface at a live venue (GitHub Discussions, "
        "the published docs) or delete the link and rewrite the sentence:\n"
        + "\n".join(hits)
    )


def test_mesh_claims_name_no_dead_hub() -> None:
    """The mesh doc and service docstring must not claim a hub that is down.

    ``docs/architecture/mesh.md`` and ``services/mesh/app/main.py`` both
    stated the community hub "runs at mesh.tryaisoc.com"; the host is
    NXDOMAIN. The corrected text describes the hub as self-hosted with no
    default endpoint.
    """
    for rel in ("docs/architecture/mesh.md", "services/mesh/app/main.py"):
        text = (REPO / rel).read_text(encoding="utf-8")
        assert "mesh.tryaisoc.com" not in text, (
            f"{rel} still names mesh.tryaisoc.com, which does not resolve; "
            "describe the hub as self-hosted instead of claiming a dead host"
        )


def test_scan_is_not_vacuous() -> None:
    """A scan that inspects nothing must fail, not pass.

    The detector walks real files: assert it saw a plausible number of
    sources, so a moved tree or broken glob reads as failure rather than
    as a clean bill.
    """
    count = sum(
        1
        for p in WEB_SRC.rglob("*")
        if p.is_file() and p.suffix in {".ts", ".tsx"}
    )
    assert count > 200, f"only {count} web sources seen — scan is broken"
