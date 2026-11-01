"""Build the observed AI estate out of the event stream.

Depth plan 6.1. This is the writer behind ``aisoc_ai_assets``, and it sits on
the fusion consumer's raw-events branch because that is the one path every
normalized event already travels on the default profile. A recorder behind a
flag, or in a service CORE does not start, is a table nothing writes and a
console page that renders "no AI estate" to a tenant that has one.

What it reads
-------------
Three shapes, each identified by what the ingest normalizer stamped on it
rather than by guessing from field presence:

* ``ai-runtime`` and ``ai-finding`` — the SDK and gateway telemetry. These
  name the agent, the model, the MCP server and the human it acted for.
  ``agentmetry`` rides the same branch: its inbox template maps the coding
  agent onto the identical slots (``agent.name`` → ``actor.process.name``,
  ``actor.id`` → ``actor.user.name``, ``host_id`` →
  ``src_endpoint.hostname``) precisely so this recorder and the graph
  projection read one shape.
* ``llm_usage`` provider audit events — these name a provider key and the
  account that minted it, and nothing about any device.
* OCSF Process Activity (class 1007) carrying a known coding-agent or MCP
  server binary — these name the device and the binary, and nothing about
  the model. Depth 6.2 widens this set; the hook is here so the two items do
  not have to touch the same file twice.

Each row records which of the three saw it, because an analyst reading an
asset with no device needs to know whether the link is missing or whether
that source could never have supplied it.

Why it buffers
--------------
A busy agent emits a span per tool call. Upserting per span would put a
write on the hot path of every AI event in the deployment to update a
``last_seen_at`` that nobody reads at that resolution. Sightings coalesce in
memory by identity and flush on size or age, the same shape the lake writer
uses, so one row is written per asset per flush interval however chatty the
agent is.

Fail-soft, in one direction
---------------------------
A Postgres outage drops the buffered sightings and logs it. It must never
wedge the consumer: an inventory is a governance surface, and losing an hour
of it is survivable in a way that stalling alert promotion is not. The drop
is counted and logged at ``warning`` so a quiet inventory is diagnosable
rather than mysterious.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog

logger = structlog.get_logger()

#: Flush when either is reached. Sized so a tenant with one agent still sees
#: its first asset inside a minute of the first span.
_MAX_PENDING = 200
_MAX_AGE_SECONDS = 30.0

#: Process names that mean a coding agent is running on a device. Matched on
#: the executable's base name, lowercased. Deliberately a small, named list
#: rather than a substring heuristic: "agent" matches half the EDR estate,
#: and a false positive here puts somebody's antivirus on an AI inventory.
CODING_AGENT_PROCESSES: dict[str, str] = {
    "claude": "Anthropic",
    "codex": "OpenAI",
    "aider": "Aider",
    "goose": "Block",
    "continue": "Continue",
    "opencode": "OpenCode",
    "gemini": "Google",
    "copilot": "GitHub",
    "copilot-language-server": "GitHub",
    "amazonq": "Amazon",
    "cline": "Cline",
}

#: Process names that mean an MCP server is running locally. Matched as a
#: prefix on the executable's base name, never as a substring anywhere: `uvx`
#: as a substring matches nothing useful and `mcp` as one matches `mcpelauncher`.
MCP_SERVER_PROCESSES: tuple[str, ...] = (
    "mcp-server",
    "mcp_server",
    "mcp-proxy",
)

#: Configuration files the popular MCP clients read, and the client each
#: belongs to. Depth plan 6.2 names these explicitly, and they are a
#: different kind of evidence from a running process: a config file says a
#: server is *wired in*, which survives a reboot and survives a `ps` that
#: happened to miss the window.
#:
#: Matched on a path suffix rather than an absolute path, because every one
#: of them sits under a per-user home directory whose shape differs across
#: macOS, Linux and Windows. Each entry was taken from the client's own
#: published configuration documentation.
MCP_CLIENT_CONFIGS: tuple[tuple[str, str], ...] = (
    ("/claude/claude_desktop_config.json", "Claude Desktop"),
    ("/.claude.json", "Claude Code"),
    ("/.cursor/mcp.json", "Cursor"),
    ("/.codeium/windsurf/mcp_config.json", "Windsurf"),
    ("/code/user/mcp.json", "VS Code"),
    ("/.vscode/mcp.json", "VS Code"),
    ("/.continue/config.json", "Continue"),
    ("/.aws/amazonq/mcp.json", "Amazon Q"),
    ("/.gemini/settings.json", "Gemini CLI"),
    ("/.codex/config.toml", "Codex CLI"),
    ("/.config/zed/settings.json", "Zed"),
)

#: Directories an editor keeps its extensions in. The path under one of these
#: carries `<publisher>.<name>-<version>`, which is where the extension's
#: identity comes from.
IDE_EXTENSION_DIRS: tuple[str, ...] = (
    "/.vscode/extensions/",
    "/.vscode-insiders/extensions/",
    "/.vscode-server/extensions/",
    "/.cursor/extensions/",
    "/.windsurf/extensions/",
)

#: Extension publishers and names that are AI assistants. Deliberately a
#: named list: an editor has hundreds of extensions and six of them are AI,
#: so listing all of them would turn the AI inventory into a package manifest
#: and make the column that matters unreadable.
AI_IDE_EXTENSIONS: dict[str, str] = {
    "github.copilot": "GitHub",
    "github.copilot-chat": "GitHub",
    "continue.continue": "Continue",
    "codeium.codeium": "Codeium",
    "amazonwebservices.amazon-q-vscode": "Amazon",
    "tabnine.tabnine-vscode": "Tabnine",
    "sourcegraph.cody-ai": "Sourcegraph",
    "google.geminicodeassist": "Google",
    "anthropic.claude-code": "Anthropic",
}

#: Command-line flags that disable an agent's permission prompts. The single
#: highest-signal attribute an endpoint source can supply, and the only place
#: it appears: an agent started this way takes no human confirmation before
#: acting.
NO_PROMPT_FLAGS: tuple[str, ...] = (
    "--dangerously-skip-permissions",
    "--yolo",
    "--auto-approve",
    "--no-confirm",
    "--yes-always",
    "--full-auto",
)

#: Connector fields that carry an executable's name or path, in the order
#: they are consulted. Read from each connector's own `normalize()` rather
#: than assumed: `windows_event` sets `process_name` and lifts `Image` out of
#: `EventData`; `auditd` emits `exe`; an osquery row's columns arrive under
#: whatever the query selected, which for `processes` is `name` and `path`.
#:
#: This list is the item. The OCSF canonical field map carries `title`,
#: `external_id` and the identity aliases and nothing else, so a reader
#: looking for `process.name` on the OCSF event finds `None` for every
#: endpoint source this product has.
PROCESS_FIELDS: tuple[str, ...] = ("process_name", "Image", "exe", "name", "path", "process")

#: Connector fields carrying a command line, same reasoning.
COMMAND_LINE_FIELDS: tuple[str, ...] = ("CommandLine", "cmdline", "cmd_line", "command_line", "argv")

#: Connector fields carrying a file path, for the config-file and extension
#: evidence. `path` doubles as a process path, which is why the file rules
#: run only when the process rules have already declined.
FILE_PATH_FIELDS: tuple[str, ...] = ("path", "file_path", "target_path", "filename")

#: Connector fields carrying the device, in order.
DEVICE_FIELDS: tuple[str, ...] = ("hostname", "host_hostname", "computer", "Computer", "device_name", "host")

#: Connector fields carrying the acting user, in order.
PRINCIPAL_FIELDS: tuple[str, ...] = ("username", "user", "actor", "TargetUserName", "SubjectUserName", "user_name")

#: The six kinds. Mirrors `app.models.ai_asset.AI_ASSET_KINDS` in the API
#: service; the two cannot import each other because both package their code
#: as a top-level ``app``, which is the same reason the capability vocabulary
#: is mirrored rather than shared.
KIND_AI_APP = "ai_app"
KIND_CODING_AGENT = "coding_agent"
KIND_MCP_SERVER = "mcp_server"
KIND_IDE_EXTENSION = "ide_extension"
KIND_PROVIDER_KEY = "provider_key"
KIND_OAUTH_GRANT = "oauth_grant"

ALL_KINDS = (
    KIND_AI_APP,
    KIND_CODING_AGENT,
    KIND_MCP_SERVER,
    KIND_IDE_EXTENSION,
    KIND_PROVIDER_KEY,
    KIND_OAUTH_GRANT,
)

#: Every discovery source a row may carry. Mirrors the CHECK constraint in
#: `105_ai_assets.sql` and `AI_ASSET_SOURCES` in the API model.
DISCOVERY_SOURCES: tuple[str, ...] = ("ai_runtime", "endpoint", "provider_audit", "oauth_audit", "declared")


@dataclass(frozen=True)
class SourceCapability:
    """What one discovery source can and cannot see.

    Depth plan 6.2 asks for this in words — *record what each source can and
    cannot see* — and the second half is the half that matters. A table
    listing only what a source provides reads as complete coverage; the blind
    spots are what an analyst needs when a column on the inventory page is
    empty, because "no device" and "this source has never carried a device"
    are different facts and only one of them is a finding.
    """

    sees: tuple[str, ...]
    cannot_see: tuple[str, ...]
    connectors: tuple[str, ...]


SOURCE_CAPABILITIES: dict[str, SourceCapability] = {
    "ai_runtime": SourceCapability(
        sees=("agent identity", "model", "provider", "tool names", "the human it acted for", "prompt secret shapes"),
        cannot_see=(
            "the device, unless the app reports a hostname",
            "anything about an agent that is not instrumented",
            "a process that never called a model",
        ),
        connectors=("ai_gateway", "inbox ai-runtime template", "inbox ai-finding template"),
    ),
    "endpoint": SourceCapability(
        sees=(
            "the device",
            "the binary and its command line",
            "whether permission prompts were disabled",
            "MCP client configuration files",
            "IDE extension directories",
        ),
        cannot_see=(
            "which model was called",
            "which tools were invoked",
            "what the prompt contained",
            "an agent running somewhere with no endpoint agent",
        ),
        connectors=("fleetdm", "osctrl", "auditd", "windows_event"),
    ),
    "provider_audit": SourceCapability(
        sees=("the provider account", "who minted or used a key", "role and logging changes"),
        cannot_see=(
            "any device",
            "which application used the key",
            "anything about a key minted outside the audited organisation",
        ),
        connectors=("llm_usage",),
    ),
    "oauth_audit": SourceCapability(
        sees=("the application that was granted access", "the scopes granted", "who consented"),
        cannot_see=("any device", "what the application did with the grant", "a grant made in an unaudited directory"),
        connectors=("llm_usage", "google_workspace", "azure_entra"),
    ),
    "declared": SourceCapability(
        sees=("whatever an operator wrote down",),
        cannot_see=("anything nobody declared, which is the population this inventory exists to find",),
        connectors=("console",),
    ),
}

_UPSERT_SQL = """
INSERT INTO aisoc_ai_assets (
    tenant_id, kind, external_id, display_name, vendor, discovery_source,
    principal, device, attributes, risk_score, risk_reasons,
    first_seen_at, last_seen_at, observation_count
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11::jsonb, $12, $13, $14)
ON CONFLICT ON CONSTRAINT aisoc_ai_assets_identity DO UPDATE SET
    -- LEAST/GREATEST rather than assignment: a replayed Kafka batch or a
    -- late-arriving span must not be able to move first_seen_at forward,
    -- which would erase the one fact an inventory exists to keep.
    first_seen_at     = LEAST(aisoc_ai_assets.first_seen_at, EXCLUDED.first_seen_at),
    last_seen_at      = GREATEST(aisoc_ai_assets.last_seen_at, EXCLUDED.last_seen_at),
    observation_count = aisoc_ai_assets.observation_count + EXCLUDED.observation_count,
    display_name      = COALESCE(EXCLUDED.display_name, aisoc_ai_assets.display_name),
    vendor            = COALESCE(EXCLUDED.vendor, aisoc_ai_assets.vendor),
    -- A later sighting that did not learn the person must not erase one an
    -- earlier sighting did. COALESCE in this order keeps the newer value
    -- when there is one and the older value when there is not.
    principal         = COALESCE(EXCLUDED.principal, aisoc_ai_assets.principal),
    attributes        = aisoc_ai_assets.attributes || EXCLUDED.attributes,
    risk_score        = EXCLUDED.risk_score,
    risk_reasons      = EXCLUDED.risk_reasons,
    updated_at        = NOW()
"""


@dataclass
class _Sighting:
    """One asset as last seen, with everything merged in."""

    tenant_id: str
    kind: str
    external_id: str
    device: str | None
    display_name: str | None = None
    vendor: str | None = None
    discovery_source: str = "ai_runtime"
    principal: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    count: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0

    @property
    def identity(self) -> tuple[str, str, str, str]:
        # The device participates in identity, and the empty string stands in
        # for "no device" so two unlinked sightings of one provider key
        # coalesce rather than accumulating. The database agrees through
        # NULLS NOT DISTINCT on the same tuple.
        return (self.tenant_id, self.kind, self.external_id, self.device or "")

    def merge(self, other: _Sighting) -> None:
        self.count += other.count
        self.first_seen = min(self.first_seen, other.first_seen) if self.first_seen else other.first_seen
        self.last_seen = max(self.last_seen, other.last_seen)
        self.display_name = other.display_name or self.display_name
        self.vendor = other.vendor or self.vendor
        self.principal = other.principal or self.principal
        for key, value in other.attributes.items():
            if key in ("tools", "models", "prompt_secret_kinds"):
                merged = set(self.attributes.get(key, [])) | set(value or [])
                self.attributes[key] = sorted(merged)
            else:
                self.attributes[key] = value


def _nested(obj: Any, *path: str) -> Any:
    cur: Any = obj
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _text(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()[:255]
    return None


def _basename(path: str) -> str:
    stem = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return stem[:-4] if stem.endswith(".exe") else stem


def classify(message: dict[str, Any]) -> list[_Sighting]:
    """Turn one normalized event into zero or more AI-asset sightings.

    Pure, so the classification can be tested against vendor-shaped payloads
    without a database — and so the database half can be tested without
    reconstructing an event.
    """
    ocsf = message.get("ocsf_event")
    if not isinstance(ocsf, dict):
        return []
    tenant_id = _text(message.get("tenant_id") or ocsf.get("tenant_uid"))
    if not tenant_id:
        return []

    now = time.time()
    source_type = _text(ocsf.get("source_type")) or _text(_nested(ocsf, "metadata", "product", "name")) or ""
    out: list[_Sighting] = []

    if source_type in ("ai-runtime", "ai-finding", "agentmetry", "AI Runtime", "AI Guardrail"):
        out.extend(_from_ai_telemetry(tenant_id, ocsf, now))
    elif source_type in ("llm_usage", "AI / LLM Usage Audit"):
        out.extend(_from_provider_audit(tenant_id, ocsf, now))
    elif ocsf.get("class_uid") == 1007:
        out.extend(_from_endpoint(tenant_id, ocsf, now))

    return out


def _connector_fields(ocsf: dict[str, Any]) -> dict[str, Any]:
    """The flat namespace the connector actually produced.

    `services/ingest` stores the connector's own normalized dict as a JSON
    **string** under `ocsf["raw_data"]`, and the canonical OCSF field map
    carries `title`, `external_id` and the identity aliases and nothing else.
    So every endpoint field this module needs — `exe`, `process_name`,
    `Image`, `CommandLine`, an osquery row's columns — exists only here.

    This is the same reconstruction `DetectionEngine._raw_fields` performs,
    and for the same reason: 663 of 825 loaded rules once matched on fields
    that were not visible because nothing merged this namespace back. It is
    reimplemented rather than imported only because the detection engine
    loads the whole compiled ruleset at import time, which this module has no
    business doing; `test_ai_endpoint_discovery.py` asserts the two agree.
    """
    raw = ocsf.get("raw_data")
    decoded: dict[str, Any] | None = None
    if isinstance(raw, dict):
        decoded = raw
    elif isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
        except (ValueError, TypeError):
            # One malformed payload must not raise out of the consumer's hot
            # path. An event we cannot read evidences no AI asset, which is
            # the safe direction for an inventory.
            return {}
        if isinstance(parsed, dict):
            decoded = parsed
    if decoded is None:
        return ocsf

    nested = decoded.get("raw_event")
    if isinstance(nested, dict):
        merged = {k: v for k, v in nested.items() if isinstance(k, str)}
        # Connector-normalized keys win on collision: the connector has
        # already made a deliberate decision about `severity` or `hostname`
        # and a vendor field of the same name must not override it.
        merged.update(decoded)
        return merged
    return decoded


def _first(fields: dict[str, Any], names: tuple[str, ...]) -> str | None:
    """First non-empty value among `names`, flattened if it is a list.

    `auditd` emits `argv` as a list, so a caller asking for a command line
    gets the joined vector rather than a repr.
    """
    for name in names:
        value = fields.get(name)
        if isinstance(value, list):
            joined = " ".join(str(v) for v in value if v)
            if joined.strip():
                return joined.strip()[:1000]
        text = _text(value)
        if text:
            return text
    return None


def _from_ai_telemetry(tenant_id: str, ocsf: dict[str, Any], now: float) -> list[_Sighting]:
    """SDK and gateway spans: the agent, its model, and any MCP server."""
    agent_id = _text(_nested(ocsf, "actor", "process", "name"))
    agent_name = _text(_nested(ocsf, "actor", "process", "path"))
    principal = _text(_nested(ocsf, "actor", "user", "name"))
    device = _text(_nested(ocsf, "src_endpoint", "hostname"))
    model = _text(_nested(ocsf, "metadata", "product", "feature", "name"))
    provider = _text(ocsf.get("cloud", {}).get("provider")) if isinstance(ocsf.get("cloud"), dict) else None
    tool = _text(ocsf.get("activity_name"))
    secret_kinds = _nested(ocsf, "finding", "evidence", "prompt_secret_kinds") or []
    server = _text(ocsf.get("resource", {}).get("name")) if isinstance(ocsf.get("resource"), dict) else None

    out: list[_Sighting] = []
    if agent_id:
        attributes: dict[str, Any] = {}
        if model:
            attributes["models"] = [model]
        if provider:
            attributes["provider"] = provider
        if tool:
            attributes["tools"] = [tool]
        if isinstance(secret_kinds, list) and secret_kinds:
            attributes["prompt_secret_kinds"] = sorted({str(k) for k in secret_kinds})
        # A coding agent is distinguished by its binary, not by the fact that
        # it is an agent. An agent we cannot place is an `ai_app`, which is
        # the honest answer rather than the flattering one.
        base = _basename(agent_name or agent_id)
        is_coding = base in CODING_AGENT_PROCESSES
        out.append(
            _Sighting(
                tenant_id=tenant_id,
                kind=KIND_CODING_AGENT if is_coding else KIND_AI_APP,
                external_id=agent_id,
                device=device,
                display_name=agent_name or agent_id,
                vendor=CODING_AGENT_PROCESSES.get(base) or provider,
                discovery_source="ai_runtime",
                principal=principal,
                attributes=attributes,
                count=1,
                first_seen=now,
                last_seen=now,
            )
        )
    if server:
        out.append(
            _Sighting(
                tenant_id=tenant_id,
                kind=KIND_MCP_SERVER,
                external_id=server,
                device=device,
                display_name=server,
                discovery_source="ai_runtime",
                principal=principal,
                attributes={"tools": [tool]} if tool else {},
                count=1,
                first_seen=now,
                last_seen=now,
            )
        )
    return out


def _from_endpoint(tenant_id: str, ocsf: dict[str, Any], now: float) -> list[_Sighting]:
    """EDR, syscall and osquery telemetry: the device, the binary, the files.

    Depth plan 6.2, and the rule the whole branch rests on: every field here
    is read out of the **connector's** namespace through `_connector_fields`,
    not off the OCSF event. The canonical profile maps `title`, `external_id`
    and the identity aliases and nothing else, so an earlier version of this
    function reading `process.name` found `None` for `fleetdm`, `osctrl`,
    `auditd` and `windows_event` alike — every endpoint source this product
    has — and endpoint discovery could never have produced a single row.

    Three kinds of evidence, in order, because the first match wins and a
    process path is also a file path:

    1. A known coding-agent binary.
    2. A local MCP server process.
    3. A file: an MCP client's configuration, or an AI IDE extension.

    One deliberate restraint: nothing here sets a model or a provider.
    Endpoint telemetry cannot see either, and filling them in from a default
    would make the inventory assert something no source observed.
    """
    fields = _connector_fields(ocsf)
    device = _first(fields, DEVICE_FIELDS) or _text(_nested(ocsf, "device", "name")) or _text(_nested(ocsf, "src_endpoint", "hostname"))
    principal = _first(fields, PRINCIPAL_FIELDS) or _text(_nested(ocsf, "actor", "user", "name"))
    cmdline = _first(fields, COMMAND_LINE_FIELDS) or ""

    # The connector namespace first, then OCSF's own nested slots. Both
    # exist: the four endpoint connectors populate only the former, while a
    # producer posting OCSF directly through `/alerts/submit` populates only
    # the latter, and reading one of the two is how this branch came to find
    # nothing on every real source.
    process = _first(fields, PROCESS_FIELDS) or _text(_nested(ocsf, "process", "name")) or _text(_nested(ocsf, "actor", "process", "name"))
    cmdline = cmdline or _text(_nested(ocsf, "process", "cmd_line")) or ""
    if process:
        sighting = _process_sighting(tenant_id, process, cmdline, device, principal, now)
        if sighting is not None:
            return [sighting]

    for candidate in (_first(fields, FILE_PATH_FIELDS), _text(fields.get("directory"))):
        if not candidate:
            continue
        sighting = _file_sighting(tenant_id, candidate, device, principal, now)
        if sighting is not None:
            return [sighting]
    return []


def _process_sighting(tenant_id: str, name: str, cmdline: str, device: str | None, principal: str | None, now: float) -> _Sighting | None:
    base = _basename(name)
    lowered = cmdline.lower()

    if base in CODING_AGENT_PROCESSES:
        attributes: dict[str, Any] = {"process": base}
        # The flag an agent is started with to stop asking. Read from the
        # command line because that is the only place it ever appears.
        if any(flag in lowered for flag in NO_PROMPT_FLAGS):
            attributes["permission_prompts_disabled"] = True
        if cmdline:
            attributes["cmd_line"] = cmdline[:255]
        return _Sighting(
            tenant_id=tenant_id,
            kind=KIND_CODING_AGENT,
            external_id=base,
            device=device,
            display_name=name,
            vendor=CODING_AGENT_PROCESSES[base],
            discovery_source="endpoint",
            principal=principal,
            attributes=attributes,
            count=1,
            first_seen=now,
            last_seen=now,
        )

    # Prefix, not substring. `mcp` as a substring matches `mcpelauncher`, and
    # a false positive here puts a game launcher on a security review.
    if any(base.startswith(token) for token in MCP_SERVER_PROCESSES):
        attributes = {"process": base}
        if cmdline:
            attributes["cmd_line"] = cmdline[:255]
        return _Sighting(
            tenant_id=tenant_id,
            kind=KIND_MCP_SERVER,
            external_id=base,
            device=device,
            display_name=name,
            discovery_source="endpoint",
            principal=principal,
            attributes=attributes,
            count=1,
            first_seen=now,
            last_seen=now,
        )
    return None


def _file_sighting(tenant_id: str, path: str, device: str | None, principal: str | None, now: float) -> _Sighting | None:
    """An MCP client configuration file, or an AI IDE extension directory.

    A file is a different kind of evidence from a process: it says a server
    or an extension is *wired in*, which survives a reboot and survives a
    process listing that happened to miss the window.
    """
    lowered = path.replace("\\", "/").lower()

    for suffix, client in MCP_CLIENT_CONFIGS:
        if lowered.endswith(suffix):
            return _Sighting(
                tenant_id=tenant_id,
                kind=KIND_MCP_SERVER,
                # Keyed on the client, not the file: two laptops with Cursor
                # configured are two assets, and the same laptop's file moving
                # between releases is still one.
                external_id=f"{client} MCP configuration",
                device=device,
                display_name=f"{client} MCP configuration",
                discovery_source="endpoint",
                principal=principal,
                attributes={"mcp_client": client, "config_path": path[:255]},
                count=1,
                first_seen=now,
                last_seen=now,
            )

    for directory in IDE_EXTENSION_DIRS:
        if directory not in lowered:
            continue
        remainder = lowered.split(directory, 1)[1]
        folder = remainder.split("/", 1)[0]
        identifier, version = _split_extension_folder(folder)
        vendor = AI_IDE_EXTENSIONS.get(identifier)
        # An editor has hundreds of extensions and a handful are AI. Listing
        # all of them would turn this into a package manifest and make the
        # column that matters unreadable.
        if vendor is None:
            return None
        attributes = {"extension": identifier}
        if version:
            attributes["version"] = version
        return _Sighting(
            tenant_id=tenant_id,
            kind=KIND_IDE_EXTENSION,
            external_id=identifier,
            device=device,
            display_name=identifier,
            vendor=vendor,
            discovery_source="endpoint",
            principal=principal,
            attributes=attributes,
            count=1,
            first_seen=now,
            last_seen=now,
        )
    return None


def _split_extension_folder(folder: str) -> tuple[str, str | None]:
    """`publisher.name-1.2.3` -> `("publisher.name", "1.2.3")`.

    Split on the last hyphen followed by a digit, because a publisher or an
    extension name may itself contain hyphens (`sourcegraph.cody-ai`) and
    splitting on the first would truncate the identifier.
    """
    match = re.search(r"^(.*?)-(\d[\w.+-]*)$", folder)
    if match:
        return match.group(1), match.group(2)
    return folder, None


def _from_provider_audit(tenant_id: str, ocsf: dict[str, Any], now: float) -> list[_Sighting]:
    """Provider control-plane audit: keys minted, grants consented to.

    No device is available from any provider's audit log, and that is the
    reason `discovery_source` exists: an analyst must be able to tell an
    unlinked device from an unlinkable one.
    """
    event_type = _text(ocsf.get("activity_name")) or ""
    principal = _text(_nested(ocsf, "actor", "user", "name"))
    provider = _text(_nested(ocsf, "metadata", "product", "vendor_name"))
    subject = _text(_nested(ocsf, "finding", "uid")) or _text(ocsf.get("message"))
    if not subject:
        return []

    lowered = event_type.lower()
    if "api_key" in lowered or "service_account" in lowered:
        kind, source = KIND_PROVIDER_KEY, "provider_audit"
    elif "oauth" in lowered or "consent" in lowered or "token" in lowered:
        kind, source = KIND_OAUTH_GRANT, "oauth_audit"
    else:
        return []

    attributes: dict[str, Any] = {"event_type": event_type}
    scopes = _nested(ocsf, "finding", "evidence", "scopes")
    if isinstance(scopes, list) and scopes:
        attributes["scopes"] = sorted({str(s) for s in scopes})

    return [
        _Sighting(
            tenant_id=tenant_id,
            kind=kind,
            external_id=subject,
            device=None,
            display_name=subject,
            vendor=provider,
            discovery_source=source,
            principal=principal,
            attributes=attributes,
            count=1,
            first_seen=now,
            last_seen=now,
        )
    ]


class AiAssetRecorder:
    """Coalesce AI-asset sightings and upsert them into Postgres."""

    def __init__(
        self,
        pool_provider: Callable[[], Any],
        *,
        max_pending: int = _MAX_PENDING,
        max_age_seconds: float = _MAX_AGE_SECONDS,
    ) -> None:
        self._pool_provider = pool_provider
        self._max_pending = max_pending
        self._max_age = max_age_seconds
        self._pending: dict[tuple[str, str, str, str], _Sighting] = {}
        self._last_flush = time.monotonic()
        self._metrics = {"observed": 0, "written": 0, "dropped": 0}

    @property
    def metrics(self) -> dict[str, int]:
        return dict(self._metrics)

    async def observe(self, message: dict[str, Any]) -> int:
        """Buffer any AI assets this event evidences. Returns how many."""
        sightings = classify(message)
        for sighting in sightings:
            existing = self._pending.get(sighting.identity)
            if existing is None:
                self._pending[sighting.identity] = sighting
            else:
                existing.merge(sighting)
        self._metrics["observed"] += len(sightings)
        if len(self._pending) >= self._max_pending:
            await self.flush()
        return len(sightings)

    async def flush_if_stale(self) -> None:
        if self._pending and (time.monotonic() - self._last_flush) >= self._max_age:
            await self.flush()

    async def flush(self) -> int:
        """Write everything buffered. Never raises into the consumer."""
        if not self._pending:
            self._last_flush = time.monotonic()
            return 0
        batch = list(self._pending.values())
        self._pending.clear()
        self._last_flush = time.monotonic()

        pool = self._pool_provider() if callable(self._pool_provider) else self._pool_provider
        if pool is None:
            self._metrics["dropped"] += len(batch)
            logger.warning(
                "ai_asset_recorder.no_pool",
                dropped=len(batch),
                detail="no database pool; AI inventory sightings were discarded",
            )
            return 0

        written = 0
        try:
            async with pool.acquire() as conn:
                for sighting in batch:
                    score, reasons = _score(sighting)
                    await conn.execute(
                        _UPSERT_SQL,
                        sighting.tenant_id,
                        sighting.kind,
                        sighting.external_id,
                        sighting.display_name,
                        sighting.vendor,
                        sighting.discovery_source,
                        sighting.principal,
                        sighting.device,
                        _json(sighting.attributes),
                        score,
                        _json(reasons),
                        _utc(sighting.first_seen),
                        _utc(sighting.last_seen),
                        sighting.count,
                    )
                    written += 1
        except Exception as exc:  # noqa: BLE001 — an inventory must never wedge promotion
            self._metrics["dropped"] += len(batch) - written
            logger.warning("ai_asset_recorder.flush_failed", error=str(exc)[:300], dropped=len(batch) - written)
        self._metrics["written"] += written
        return written


def _json(value: Any) -> str:
    return json.dumps(value, default=str)


def _utc(epoch: float) -> datetime:
    return datetime.fromtimestamp(epoch or time.time(), tz=UTC)


def _score(sighting: _Sighting) -> tuple[int, list[str]]:
    """Risk for a freshly observed asset.

    Mirrors ``services/api/app/services/ai_inventory.py::score_risk`` for the
    inputs a sighting carries. The two services cannot import each other, so
    ``scripts/check_ai_asset_inventory.py`` is not the thing holding them
    together — ``services/fusion/tests/test_ai_asset_recorder.py`` asserts
    the two agree on a shared table of cases, which is the only way a mirror
    stays a mirror.

    `sanctioned` is always None here: a newly observed asset is by definition
    one nobody has judged yet, and the sanction route recomputes the score
    when somebody does.
    """
    points = 0
    reasons: list[str] = []
    if not sighting.principal:
        points += 15
        reasons.append("No person is linked: nobody is accountable for what it does.")
    if not sighting.device and sighting.kind in {KIND_CODING_AGENT, KIND_IDE_EXTENSION, KIND_MCP_SERVER}:
        points += 10
        reasons.append("No device is linked, so containment has nowhere to act.")
    points += 20
    reasons.append("Not declared in the inventory: nobody has reviewed it.")
    if sighting.attributes.get("permission_prompts_disabled"):
        points += 25
        reasons.append("Started with its permission prompts disabled, so a human confirms nothing.")
    source = str(sighting.attributes.get("install_source") or "")
    if source and source not in {"official", "vendor", "internal"}:
        points += 20
        reasons.append(f"Installed from an unvetted source ({source}).")
    secret_kinds = sighting.attributes.get("prompt_secret_kinds") or []
    if secret_kinds:
        points += 20
        reasons.append(f"Credential material has appeared in its prompts ({', '.join(sorted(secret_kinds)[:3])}).")
    tools = {str(t) for t in (sighting.attributes.get("tools") or [])}
    risky = sorted(tools & _HIGH_RISK_TOOLS)
    if risky:
        points += 15
        reasons.append(f"Calls tools that change an estate ({', '.join(risky[:3])}).")
    scopes = {str(s) for s in (sighting.attributes.get("scopes") or [])}
    broad = sorted(scopes & _BROAD_OAUTH_SCOPES)
    if broad:
        points += 25
        reasons.append(f"Holds an OAuth scope covering a whole mailbox, drive or org ({broad[0]}).")
    return min(points, 100), reasons


#: Mirrors of the two tables in `app/services/ai_inventory.py`, kept here for
#: the same reason the capability vocabulary is mirrored: two independently
#: deployable services, one shared meaning, and a test that compares them.
_HIGH_RISK_TOOLS: frozenset[str] = frozenset(
    {
        "execute_command",
        "run_shell",
        "write_file",
        "delete_file",
        "send_email",
        "create_user",
        "grant_permission",
        "deploy",
        "terraform_apply",
        "database_write",
    }
)

_BROAD_OAUTH_SCOPES: frozenset[str] = frozenset(
    {
        "https://mail.google.com/",
        "https://www.googleapis.com/auth/drive",
        "https://www.googleapis.com/auth/gmail.modify",
        "https://www.googleapis.com/auth/admin.directory.user",
        "Mail.ReadWrite",
        "Mail.Read",
        "Files.ReadWrite.All",
        "Sites.ReadWrite.All",
        "Directory.ReadWrite.All",
        "repo",
        "admin:org",
    }
)
