#!/usr/bin/env python3
"""Collect a dated adoption snapshot from data GitHub and the registries publish.

The project has no usage telemetry it can actually read: the CLI's opt-in
endpoint (`telemetry.tryaisoc.com`) does not resolve, and the packages that
would report were never published. That left nobody able to answer the only
question that matters for adoption — of the people who arrive, how many end up
using the thing.

This closes the gap without asking users for anything and without standing up a
collector, by reading what is already public:

  * GitHub traffic (views / clones), stars, forks, contributors, discussions
  * release asset download counts
  * npm per-package download counts
  * PyPI per-package download counts

Honesty rule: a source that cannot be read is recorded as ``null`` with a note
saying why. It is never recorded as zero, because "nobody downloaded it" and
"we could not ask" are different facts and conflating them is how a dashboard
starts lying.

Usage:
    python3 scripts/adoption_snapshot.py --write     # update the committed snapshot
    python3 scripts/adoption_snapshot.py             # print JSON, change nothing
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import urllib.error
import urllib.request

REPO = os.environ.get("AISOC_SNAPSHOT_REPO", "beenuar/AiSOC")
REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT_JSON = REPO_ROOT / "docs" / "adoption" / "snapshot.json"
OUT_MD = REPO_ROOT / "docs" / "adoption" / "README.md"

NPM_PACKAGES = ["aisoc", "@aisoc/mcp", "@aisoc/sdk"]
PYPI_PACKAGES = [
    "aisoc-sandbox",
    "aisoc-cli",
    "aisoc-sdk",
    "aisoc-plugin-sdk",
    "aisoc-detections",
]

UA = "aisoc-adoption-snapshot"


def _get(url: str, token: str | None = None, timeout: int = 25):
    """Return parsed JSON, or a (None, reason) pair on any failure."""
    headers = {"User-Agent": UA, "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode()), None
    except urllib.error.HTTPError as exc:
        return None, f"HTTP {exc.code}"
    except Exception as exc:  # noqa: BLE001 - the reason is the payload
        return None, f"{type(exc).__name__}"


def collect() -> dict:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    notes: list[str] = []
    snap: dict = {
        "date": dt.date.today().isoformat(),
        "repo": REPO,
        "github": {},
        "npm": {},
        "pypi": {},
        "notes": notes,
    }

    repo, err = _get(f"https://api.github.com/repos/{REPO}", token)
    if repo:
        snap["github"].update(
            stars=repo.get("stargazers_count"),
            forks=repo.get("forks_count"),
            watchers=repo.get("subscribers_count"),
            open_issues=repo.get("open_issues_count"),
        )
    else:
        notes.append(f"repo metadata unavailable ({err})")

    # Traffic needs push access. On a fork or with a read-only token this 403s,
    # which is a legitimate "could not ask" rather than zero traffic.
    for kind in ("views", "clones"):
        data, err = _get(f"https://api.github.com/repos/{REPO}/traffic/{kind}", token)
        if data:
            snap["github"][f"{kind}_14d"] = data.get("count")
            snap["github"][f"unique_{kind}_14d"] = data.get("uniques")
        else:
            snap["github"][f"{kind}_14d"] = None
            snap["github"][f"unique_{kind}_14d"] = None
            notes.append(f"traffic/{kind} unavailable ({err}; needs push access)")

    contributors, err = _get(
        f"https://api.github.com/repos/{REPO}/contributors?per_page=100", token
    )
    snap["github"]["contributors"] = len(contributors) if contributors else None
    if contributors is None:
        notes.append(f"contributors unavailable ({err})")

    releases, err = _get(f"https://api.github.com/repos/{REPO}/releases?per_page=100", token)
    if releases is not None:
        snap["github"]["releases"] = len(releases)
        snap["github"]["release_asset_downloads"] = sum(
            a.get("download_count", 0) for r in releases for a in r.get("assets", [])
        )
    else:
        snap["github"]["releases"] = None
        snap["github"]["release_asset_downloads"] = None
        notes.append(f"releases unavailable ({err})")

    # A 404 means the package does not exist yet, which is a fact about the
    # project. Anything else means the registry would not answer, which is a
    # fact about this run. Reporting both as "unavailable" would hide the
    # difference.
    def _why(err: str | None) -> str:
        if err == "HTTP 404":
            return "not published yet"
        return f"registry did not answer ({err or 'no data'})"

    for pkg in NPM_PACKAGES:
        quoted = pkg.replace("/", "%2F")
        data, err = _get(f"https://api.npmjs.org/downloads/point/last-month/{quoted}")
        if data and isinstance(data.get("downloads"), int):
            snap["npm"][pkg] = data["downloads"]
        else:
            snap["npm"][pkg] = None
            notes.append(f"npm {pkg}: {_why(err)}")

    for pkg in PYPI_PACKAGES:
        data, err = _get(f"https://pypistats.org/api/packages/{pkg}/recent")
        if data and isinstance(data.get("data"), dict):
            snap["pypi"][pkg] = data["data"].get("last_month")
        else:
            snap["pypi"][pkg] = None
            notes.append(f"pypi {pkg}: {_why(err)}")

    return snap


def render_markdown(history: list[dict]) -> str:
    latest = history[-1]
    g = latest["github"]

    def fmt(value) -> str:
        return "not measured" if value is None else f"{value:,}"

    lines = [
        "# Adoption snapshot",
        "",
        "Collected by `scripts/adoption_snapshot.py`, refreshed monthly by",
        "`.github/workflows/adoption-snapshot.yml`. Everything here comes from",
        "public GitHub and registry APIs — the project ships no usage telemetry",
        "that phones home.",
        "",
        "A value of **not measured** means the source could not be read on that",
        "run. It does not mean zero. The two get conflated constantly and the",
        "difference matters: one is a fact about users, the other is a fact",
        "about our tooling.",
        "",
        f"## Latest — {latest['date']}",
        "",
        "### Reach",
        "",
        f"- Stars: {fmt(g.get('stars'))}",
        f"- Forks: {fmt(g.get('forks'))}",
        f"- Unique visitors (14d): {fmt(g.get('unique_views_14d'))}",
        f"- Unique cloners (14d): {fmt(g.get('unique_clones_14d'))}",
        "",
        "### Conversion",
        "",
        f"- Contributors: {fmt(g.get('contributors'))}",
        f"- Release asset downloads (all time): {fmt(g.get('release_asset_downloads'))}",
        "",
        "### Package downloads (last month)",
        "",
    ]

    for pkg, count in latest["npm"].items():
        lines.append(f"- npm `{pkg}`: {fmt(count)}")
    for pkg, count in latest["pypi"].items():
        lines.append(f"- PyPI `{pkg}`: {fmt(count)}")

    if latest.get("notes"):
        lines += ["", "### Why some values are missing", ""]
        lines += [f"- {n}" for n in latest["notes"]]

    if len(history) > 1:
        lines += [
            "",
            "## History",
            "",
            "| Date | Stars | Unique cloners (14d) | Contributors | npm `aisoc` |",
            "| --- | --- | --- | --- | --- |",
        ]
        for row in history[-12:]:
            rg = row["github"]
            lines.append(
                f"| {row['date']} | {fmt(rg.get('stars'))} | "
                f"{fmt(rg.get('unique_clones_14d'))} | {fmt(rg.get('contributors'))} | "
                f"{fmt(row.get('npm', {}).get('aisoc'))} |"
            )

    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write", action="store_true", help="update the committed snapshot files"
    )
    args = parser.parse_args()

    snapshot = collect()

    if not args.write:
        print(json.dumps(snapshot, indent=2))
        return 0

    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    history: list[dict] = []
    if OUT_JSON.exists():
        try:
            history = json.loads(OUT_JSON.read_text()).get("history", [])
        except json.JSONDecodeError:
            history = []

    # One row per day; re-running the same day replaces rather than duplicates.
    history = [row for row in history if row.get("date") != snapshot["date"]]
    history.append(snapshot)
    history.sort(key=lambda row: row["date"])

    OUT_JSON.write_text(json.dumps({"history": history}, indent=2) + "\n")
    OUT_MD.write_text(render_markdown(history))
    print(f"wrote {OUT_JSON} ({len(history)} rows) and {OUT_MD}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
