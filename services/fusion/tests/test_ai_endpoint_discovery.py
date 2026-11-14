"""Endpoint discovery of AI assets, from sources that already exist.

Depth plan 6.2: *known coding-agent processes, MCP server processes and the
configuration files that popular MCP clients read*, from EDR process telemetry
and osquery, **with no new agent**.

Every payload below is the shape the connector in question actually emits,
read out of its `normalize()` rather than invented:

* `windows_event` puts `process_name` at the top level and lifts `Image` and
  `CommandLine` out of `EventData` into `raw_event`.
* `auditd` emits a flat `syscall` / `exe` / `argv` / `path` record.
* `fleetdm` and `osctrl` flatten the osquery row's columns to the top level.

That distinction is the whole item. The OCSF canonical field map carries
`title`, `external_id` and the identity aliases and **nothing else**, so a
reader that looks for `process.name` on the OCSF event finds `None` for every
one of these sources — which is what 6.1's endpoint branch did, and what the
first test here reproduced before it was fixed.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from app.services.ai_asset_recorder import classify

TENANT = "11111111-1111-1111-1111-111111111111"


def ingest_event(connector_type: str, payload: dict[str, Any], class_uid: int = 1007) -> dict[str, Any]:
    """Wrap a connector payload the way `services/ingest` publishes it.

    `normalizer.go` runs `json.Marshal(raw.Payload)` into `ocsf["raw_data"]`
    as a **string**, and the canonical profile maps almost nothing else. An
    event built any other way would be testing a pipeline this product does
    not have.
    """
    ocsf: dict[str, Any] = {
        "class_uid": class_uid,
        "class_name": "Process Activity",
        "source_type": connector_type,
        "metadata": {"product": {"name": connector_type, "vendor_name": connector_type}},
        "raw_data": json.dumps(payload),
    }
    if payload.get("hostname"):
        ocsf["device"] = {"name": payload["hostname"]}
    if payload.get("username") or payload.get("actor"):
        ocsf["actor"] = {"user": {"name": payload.get("username") or payload.get("actor")}}
    return {"tenant_id": TENANT, "ocsf_event": ocsf}


# ---------------------------------------------------------------------------
# EDR and syscall process telemetry
# ---------------------------------------------------------------------------


def test_windows_event_process_creation_finds_a_coding_agent():
    """Sysmon event 1 / Security 4688, as `windows_event.normalize()` emits it."""
    event = ingest_event(
        "windows_event",
        {
            "source": "windows_event",
            "event_type": "windows.microsoft-windows-sysmon/operational.1",
            "hostname": "WIN-DEV-02",
            "username": "CONTOSO\\ada",
            "process_name": "C:\\Users\\ada\\AppData\\Local\\Programs\\claude\\claude.exe",
            "raw_event": {
                "EventID": "1",
                "Image": "C:\\Users\\ada\\AppData\\Local\\Programs\\claude\\claude.exe",
                "CommandLine": "claude.exe --dangerously-skip-permissions -p refactor",
                "Computer": "WIN-DEV-02",
            },
        },
    )
    sightings = classify(event)
    assert [s.kind for s in sightings] == ["coding_agent"]
    assert sightings[0].device == "WIN-DEV-02"
    assert sightings[0].discovery_source == "endpoint"
    # The flag is only ever on the command line, and it is the single
    # highest-signal attribute an endpoint source can supply: an agent
    # started this way takes no human confirmation before acting.
    assert sightings[0].attributes["permission_prompts_disabled"] is True


def test_auditd_execve_finds_a_coding_agent():
    """A flat auditd record: `syscall`, `exe`, `argv`."""
    event = ingest_event(
        "auditd",
        {
            "source": "auditd",
            "syscall": "execve",
            "exe": "/usr/local/bin/aider",
            "argv": ["aider", "--yes-always", "main.py"],
            "hostname": "build-07",
            "actor": "ada",
        },
    )
    sightings = classify(event)
    assert [s.kind for s in sightings] == ["coding_agent"]
    assert sightings[0].vendor == "Aider"
    assert sightings[0].device == "build-07"


def test_osquery_process_row_finds_a_coding_agent():
    """A FleetDM scheduled-query row; columns are flattened to the top level."""
    event = ingest_event(
        "fleetdm",
        {
            "source": "fleetdm",
            "event_type": "osquery_query_row",
            "hostname": "ada-mbp",
            "name": "codex",
            "path": "/opt/homebrew/bin/codex",
            "cmdline": "codex --auto-approve",
            "uid": "501",
        },
    )
    sightings = classify(event)
    assert [s.kind for s in sightings] == ["coding_agent"]
    assert sightings[0].vendor == "OpenAI"
    assert sightings[0].attributes["permission_prompts_disabled"] is True


def test_an_mcp_server_process_is_found_on_the_endpoint():
    event = ingest_event(
        "osctrl",
        {
            "source": "osctrl",
            "hostname": "ada-mbp",
            "name": "mcp-server-filesystem",
            "path": "/usr/local/bin/mcp-server-filesystem",
            "cmdline": "mcp-server-filesystem /Users/ada",
        },
    )
    sightings = classify(event)
    assert [s.kind for s in sightings] == ["mcp_server"]
    assert sightings[0].device == "ada-mbp"


def test_an_ordinary_process_row_is_not_an_ai_asset():
    """The negative control.

    A substring heuristic on "agent" or "server" would put every EDR sensor
    and every web daemon on an AI inventory, and a false positive here is a
    name on a governance review that somebody acts on.
    """
    for name in ("falcon-sensor", "osqueryd", "nginx", "chrome", "MsMpEng.exe", "node"):
        event = ingest_event("fleetdm", {"source": "fleetdm", "hostname": "h", "name": name, "path": f"/usr/bin/{name}"})
        assert classify(event) == [], name


# ---------------------------------------------------------------------------
# Configuration files the MCP clients read
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "client"),
    [
        ("/Users/ada/Library/Application Support/Claude/claude_desktop_config.json", "Claude Desktop"),
        ("/Users/ada/.cursor/mcp.json", "Cursor"),
        ("/home/ada/.codeium/windsurf/mcp_config.json", "Windsurf"),
        ("/home/ada/.config/Code/User/mcp.json", "VS Code"),
        ("/home/ada/.continue/config.json", "Continue"),
        ("/Users/ada/.aws/amazonq/mcp.json", "Amazon Q"),
    ],
)
def test_an_mcp_client_configuration_file_is_an_mcp_server_asset(path: str, client: str):
    """The file is the evidence that a server is configured, and where.

    A configuration file is a different kind of evidence from a running
    process: it says a server is *wired in*, which survives a reboot and a
    `ps` that happened to miss the window.
    """
    event = ingest_event(
        "fleetdm",
        {"source": "fleetdm", "hostname": "ada-mbp", "path": path, "directory": path.rsplit("/", 1)[0], "uid": "501"},
    )
    sightings = classify(event)
    assert [s.kind for s in sightings] == ["mcp_server"], path
    assert sightings[0].attributes["mcp_client"] == client
    assert sightings[0].attributes["config_path"] == path


def test_an_ide_extension_directory_is_an_extension_asset():
    event = ingest_event(
        "fleetdm",
        {
            "source": "fleetdm",
            "hostname": "ada-mbp",
            "path": "/Users/ada/.vscode/extensions/github.copilot-1.250.0/package.json",
            "directory": "/Users/ada/.vscode/extensions/github.copilot-1.250.0",
        },
    )
    sightings = classify(event)
    assert [s.kind for s in sightings] == ["ide_extension"]
    assert sightings[0].external_id == "github.copilot"
    assert sightings[0].attributes["version"] == "1.250.0"


def test_an_unrelated_ide_extension_is_not_an_ai_asset():
    """An editor has hundreds of extensions and six of them are AI.

    Listing all of them would make the AI inventory a package manifest, and
    the column that matters — "what AI is running here" — unreadable.
    """
    event = ingest_event(
        "fleetdm",
        {
            "source": "fleetdm",
            "hostname": "ada-mbp",
            "path": "/Users/ada/.vscode/extensions/esbenp.prettier-vscode-11.0.0/package.json",
            "directory": "/Users/ada/.vscode/extensions/esbenp.prettier-vscode-11.0.0",
        },
    )
    assert classify(event) == []


def test_an_unrelated_json_file_is_not_an_mcp_configuration():
    event = ingest_event(
        "fleetdm",
        {"source": "fleetdm", "hostname": "ada-mbp", "path": "/Users/ada/project/package.json"},
    )
    assert classify(event) == []


# ---------------------------------------------------------------------------
# What each source can and cannot see
# ---------------------------------------------------------------------------


def test_every_discovery_source_declares_what_it_cannot_see():
    """The plan asks for this in words: *record what each source can and cannot see.*

    Both directions, because a one-directional check is this repository's
    dominant gate failure: every source the recorder can emit must appear in
    the table, and every source in the table must be one the recorder can
    emit.
    """
    from app.services.ai_asset_recorder import DISCOVERY_SOURCES, SOURCE_CAPABILITIES

    assert set(SOURCE_CAPABILITIES) == set(DISCOVERY_SOURCES)
    for source, capability in SOURCE_CAPABILITIES.items():
        assert capability.sees, source
        # The half that matters. A table listing only what a source provides
        # reads as complete coverage; the blind spots are what an analyst
        # needs when a column is empty.
        assert capability.cannot_see, f"{source} declares no blind spot, which no real source has"
        assert capability.connectors, source


def test_an_endpoint_asset_never_claims_a_model():
    """Endpoint telemetry cannot see which model an agent called.

    Asserting the absence rather than trusting the table: a recorder that
    filled this in from a default would make the inventory assert something
    no source observed.
    """
    event = ingest_event(
        "auditd",
        {"source": "auditd", "syscall": "execve", "exe": "/usr/local/bin/aider", "argv": ["aider"], "hostname": "h"},
    )
    sighting = classify(event)[0]
    assert "models" not in sighting.attributes
    assert "provider" not in sighting.attributes
