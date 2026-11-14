"""The published profile table must be what `docker-compose.yml` actually says.

The quick start tells a reader which services each compose profile starts.
That table had drifted: it put `kafka-ui` on 8080 (it is 8090) and
`connectors` on 8003 (that is `fusion`; connectors is 8088), it filed
`actions` under `full` alone when it is in `full` and `chatops`, and it
omitted the `monitoring` and `chatops` profiles entirely. None of that is
visible to a reader, and all of it sends someone to the wrong port.

A prose table cannot be kept in step with a 1,100-line compose file by
attention, and this one is moving: services get promoted into the default
profile when the default install turns out not to be able to do something
(the LLM gateway was a `full` service until 2026-09, which meant the default
install could not do AI triage even with a provider key set). So the check is
mechanical, and it runs in the direction drift actually happens — from the
compose file to the documentation.

If this fails because you moved a service between profiles, the fix is to
update the table in `apps/docs/docs/quickstart.md`. The failure message names
the rows.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
COMPOSE = REPO / "docker-compose.yml"
QUICKSTART = REPO / "apps/docs/docs/quickstart.md"

#: The table's row label for services that declare no `profiles:` key.
DEFAULT_LABEL = "default"


def _compose_profiles() -> dict[str, set[str]]:
    """profile name -> the services compose starts under it."""
    services = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"]
    out: dict[str, set[str]] = {}
    for name, cfg in services.items():
        for profile in (cfg or {}).get("profiles") or [DEFAULT_LABEL]:
            out.setdefault(profile, set()).add(name)
    return out


def _table_rows() -> list[list[str]]:
    """The `| Profile | Services |` table's data rows, as stripped cells."""
    text = QUICKSTART.read_text(encoding="utf-8")
    header = re.search(r"^\|\s*Profile\s*\|\s*Services\s*\|\s*$", text, re.MULTILINE)
    assert header, "quickstart.md no longer has a `| Profile | Services |` table"

    rows: list[list[str]] = []
    for line in text[header.end() :].lstrip("\n").splitlines():
        if not line.startswith("|"):
            break
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 2 or set(cells[0]) <= set("-: "):
            continue  # the |---|---| separator
        rows.append(cells)
    assert rows, "the `| Profile | Services |` table has no rows"
    return rows


def _documented_profiles() -> dict[str, set[str]]:
    """profile name -> the services the quick-start table lists under it.

    Service names are the **bolded** entries in the Services column, which is
    the convention the table already used. A profile's own name is whatever
    the row's first cell contains, stripped of backticks and the
    `*(default — CORE)*` decoration.
    """
    out: dict[str, set[str]] = {}
    for cells in _table_rows():
        label = cells[0].strip("*`_ ()")
        if label.lower().startswith(DEFAULT_LABEL):
            label = DEFAULT_LABEL
        out[label] = set(re.findall(r"\*\*([a-z0-9][a-z0-9._-]*)\*\*", cells[1]))
    return out


def test_every_compose_profile_is_documented() -> None:
    compose = _compose_profiles()
    documented = _documented_profiles()
    missing = sorted(set(compose) - set(documented))
    assert not missing, (
        f"docker-compose.yml defines profiles the quick-start table never mentions: {missing}. "
        f"Add a row for each in {QUICKSTART.relative_to(REPO)}."
    )


def test_no_documented_profile_is_invented() -> None:
    compose = _compose_profiles()
    documented = _documented_profiles()
    invented = sorted(set(documented) - set(compose))
    assert not invented, f"the quick-start table lists profiles docker-compose.yml does not define: {invented}"


@pytest.mark.parametrize("profile", sorted(_compose_profiles()))
def test_profile_membership_matches_compose(profile: str) -> None:
    actual = _compose_profiles()[profile]
    documented = _documented_profiles().get(profile, set())
    undocumented = sorted(actual - documented)
    phantom = sorted(documented - actual)
    assert not undocumented and not phantom, (
        f"profile {profile!r} has drifted from the quick-start table.\n"
        f"  started by compose but not documented: {undocumented or 'none'}\n"
        f"  documented but not started by compose: {phantom or 'none'}\n"
        f"Update the {profile!r} row in {QUICKSTART.relative_to(REPO)}."
    )


def test_documented_host_ports_match_compose() -> None:
    """A port in the table is a reader's next command; a wrong one is a dead end."""
    services = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"]
    actual: dict[str, set[str]] = {}
    for name, cfg in services.items():
        published = set()
        for mapping in (cfg or {}).get("ports") or []:
            # `[bind:]host:container[/proto]`. Read positionally from the right
            # rather than matching the bind address, which is now a Compose
            # interpolation with a nested default —
            # `${AISOC_CONSOLE_BIND_ADDR:-${AISOC_BIND_ADDR:-127.0.0.1}}` —
            # and carries colons of its own. A pattern anchored on a literal
            # IP silently matched nothing and reported every service as
            # publishing no host port at all.
            fields = str(mapping).split("/")[0].split(":")
            if len(fields) >= 2 and fields[-2].isdigit():
                published.add(fields[-2])
        actual[name] = published

    wrong: list[str] = []
    # `**web** (3000)` / `**clickhouse** (8123/9000)` / `**web** (3000, Next)`
    entry = re.compile(r"\*\*([a-z0-9][a-z0-9._-]*)\*\*\s*\(([\d/]+)(?:,[^)]*)?\)")
    for cells in _table_rows():
        for name, ports in entry.findall(cells[1]):
            claimed = set(ports.split("/"))
            if name in actual and claimed - actual[name]:
                wrong.append(f"{name}: table says {sorted(claimed)}, compose publishes {sorted(actual[name]) or 'no host port'}")
    assert not wrong, "quick-start table publishes host ports the compose file does not:\n  " + "\n  ".join(wrong)
