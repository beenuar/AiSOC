"""Find the AI configuration a repository carries, and distrust all of it.

Depth plan wave 2, Phase 7.2.

What this reads
---------------
Three families of file, all of which tell an agent what it may do:

* **agent instruction files** — ``AGENTS.md``, ``.github/copilot-instructions.md``,
  ``.cursor/rules/*.mdc`` and the other conventional names;
* **skill directories** — a ``SKILL.md`` under a ``skills/`` tree, which is a
  unit of instruction an agent loads on demand;
* **MCP configuration** — ``.mcp.json``, ``.vscode/mcp.json``,
  ``.cursor/mcp.json`` and the equivalents, which name the servers an agent
  may call and the command used to start each one.

For each it records which tools and which servers are referenced, as an
asset linked to the repository. "Which repositories point an agent at this
MCP server" is the question the estate could not answer before.

Why every byte of this is untrusted
-----------------------------------
These files are checked into source control. Anyone with write access can
edit them, and on most repositories a merged pull request is enough. They
are then read by an agent **verbatim**, as instructions, with whatever tools
that agent holds. That is the definition of an attacker-controlled channel,
and it is the same trust class as a retrieved runbook or a prior analyst
note — both of which this platform already treats as hostile input
(``_scannable_fields`` in ``services/agents/app/agents/auto_triage_agent.py``).

So three things happen here and none of them is optional:

1. **Nothing is stored raw.** Every excerpt is sanitised and capped before
   it reaches a column. The point is not storage cost; it is that an
   unbounded verbatim copy of an instruction file inside an asset record is
   a second place the payload lives, one that a console renders.
2. **The content is scanned at capture.** Matched signal names go into
   ``attributes["injection_signals"]``, which ``score_risk`` reads — so a
   skill file carrying an override attempt raises the asset's exposure
   score and says why, through the one scorer.
3. **What is kept is a list of names, not prose.** Tool names, server
   names, commands. A reviewer needs "this repository points an agent at
   `npx some-unknown-package`"; they do not need the paragraph around it.

The guard itself lives in ``services/agents`` and cannot be imported here
(separate deployable, separate build context), so the patterns are a
deliberately small, auditable subset carried in
``app/_vendor/ai_instruction_rules.py`` and kept in lockstep by
``scripts/sync_vendored_ai_instruction_rules.py``. A subset is honest: this
is a *capture-time signal* on a file, not the authorization control, which
remains claim-support at triage time.
"""

from __future__ import annotations

import json
import posixpath
import re
from dataclasses import dataclass, field
from typing import Any

from app._vendor.ai_instruction_rules import scan_instruction_text

#: Longest excerpt stored from any instruction file. A reviewer needs
#: enough to recognise the file; the file itself lives in the repository,
#: which is where they should read it.
EXCERPT_MAX = 400

#: Conventional agent-instruction filenames. Matched on the basename except
#: where the directory is what makes it one.
_INSTRUCTION_BASENAMES = frozenset(
    {
        "agents.md",
        "claude.md",
        "copilot-instructions.md",
        "gemini.md",
        "cursorrules",
        ".cursorrules",
        "conventions.md",
    }
)
_INSTRUCTION_DIR_PATTERNS = (
    re.compile(r"(^|/)\.cursor/rules/[^/]+\.mdc$"),
    re.compile(r"(^|/)\.github/(copilot-instructions|instructions/[^/]+)\.md$"),
    re.compile(r"(^|/)\.github/agents/[^/]+\.md$"),
)

#: A skill is a directory with a `SKILL.md` in it; the directory name is the
#: skill's name. Matched on the whole path because `SKILL.md` alone, outside
#: a skills tree, is documentation.
_SKILL_PATTERN = re.compile(r"(^|/)(?:\.claude/skills|\.agent/skills|skills)/([^/]+)/SKILL\.md$", re.I)

#: MCP configuration files. The vendor-specific paths matter: an MCP config
#: under `.vscode/` applies to everyone who opens the repository in that
#: editor, which is a wider blast radius than a user-level config.
_MCP_PATTERNS = (
    re.compile(r"(^|/)\.mcp\.json$"),
    re.compile(r"(^|/)\.vscode/mcp\.json$"),
    re.compile(r"(^|/)\.cursor/mcp\.json$"),
    re.compile(r"(^|/)\.github/workflows/copilot-setup-steps\.ya?ml$"),
    re.compile(r"(^|/)mcp\.json$"),
)

#: Hosts a server package may come from and still be called vetted. Anything
#: else — including a bare command with no origin, which is the common case
#: in a checked-in config — is unvetted, and deliberately so: a bare command
#: is less reviewable than a named registry, not more.
_VETTED_HOSTS = frozenset({"github.com", "npmjs.com", "registry.npmjs.org", "pypi.org"})


@dataclass(frozen=True)
class RepoAiArtifact:
    """One AI artefact found in a repository, ready to become an asset."""

    kind: str
    repository: str
    path: str
    name: str
    tools: tuple[str, ...] = ()
    mcp_servers: tuple[dict[str, Any], ...] = ()
    skills: tuple[dict[str, Any], ...] = ()
    #: Sanitised and capped. Never the file.
    excerpt: str | None = None
    #: Names of the injection patterns the content matched, never the text
    #: that matched them. Read by `score_risk`.
    injection_signals: tuple[str, ...] = ()
    parse_error: str | None = None

    def attributes(self) -> dict[str, Any]:
        """The `attributes` blob for `aisoc_ai_assets`.

        Keys chosen to match what `score_risk` already reads — `tools`,
        `mcp_servers`, `skills`, `injection_signals` — so the one scorer
        needs no special case for this producer.
        """
        out: dict[str, Any] = {
            "repository": self.repository,
            "path": self.path,
            "artifact_kind": self.kind,
        }
        if self.tools:
            out["tools"] = list(self.tools)
        if self.mcp_servers:
            out["mcp_servers"] = [dict(s) for s in self.mcp_servers]
        if self.skills:
            out["skills"] = [dict(s) for s in self.skills]
        if self.excerpt:
            out["instruction_excerpt"] = self.excerpt
        if self.injection_signals:
            out["injection_signals"] = list(self.injection_signals)
        if self.parse_error:
            # Recorded rather than swallowed. A config nothing can parse is
            # a finding — it is also what an agent will fail on — and an
            # artefact that silently disappeared would read as "this
            # repository has no MCP config", which is the wrong answer.
            out["parse_error"] = self.parse_error
        return out


@dataclass
class _Found:
    artifacts: list[RepoAiArtifact] = field(default_factory=list)


def _normalise(path: str) -> str:
    """Drop a leading `./` without eating the dot of a dotfolder.

    `lstrip("./")` strips any leading `.` or `/`, so `.cursor/rules/x.mdc`
    becomes `cursor/rules/x.mdc` and stops matching — silently, as a path
    that is simply not an AI artefact. Every convention in this file lives
    in a dotfolder, so that one call would have turned most of the scan off.
    """
    while path.startswith("./"):
        path = path[2:]
    return path.lstrip("/")


def classify_path(path: str) -> str | None:
    """Which artefact family a repository path belongs to, if any."""
    normalised = _normalise(path)
    base = posixpath.basename(normalised).lower()
    if _SKILL_PATTERN.search(normalised):
        return "skill"
    for pattern in _MCP_PATTERNS:
        if pattern.search(normalised):
            return "mcp_config"
    if base in _INSTRUCTION_BASENAMES:
        return "instruction"
    for pattern in _INSTRUCTION_DIR_PATTERNS:
        if pattern.search(normalised):
            return "instruction"
    return None


def _sanitise(text: str) -> str:
    """Flatten an excerpt so it cannot carry structure into a renderer.

    Control characters, zero-width characters and the bidirectional
    overrides go, because an instruction file is a place somebody hides a
    payload that looks like nothing in a diff. Newlines collapse so the
    excerpt is one line in a table and cannot fake a document boundary.
    """
    cleaned = re.sub(r"[\u0000-\u0008\u000b-\u001f\u007f\u200b-\u200f\u2028-\u202e\ufeff]", "", text)
    return re.sub(r"\s+", " ", cleaned).strip()


def _excerpt(text: str) -> str:
    sanitised = _sanitise(text)
    return sanitised[:EXCERPT_MAX]


def _server_source(entry: dict[str, Any]) -> str:
    """Where an MCP server comes from, from the config alone.

    Returns a value `score_risk` compares against `VETTED_MCP_SOURCES`. A
    config that names no origin returns `"unknown"`, which is unvetted —
    the honest answer, since nobody can review an origin that was never
    stated.
    """
    url = str(entry.get("url") or "")
    if url:
        host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0].lower()
        if host in _VETTED_HOSTS:
            return "vendor"
        return "remote"
    args = entry.get("args")
    joined = " ".join(str(a) for a in args) if isinstance(args, list) else str(entry.get("command") or "")
    if "@modelcontextprotocol/" in joined:
        return "official"
    return "unknown"


def _parse_mcp_config(repository: str, path: str, content: str) -> RepoAiArtifact:
    try:
        blob = json.loads(content)
    except (ValueError, TypeError) as exc:
        return RepoAiArtifact(
            kind="mcp_config",
            repository=repository,
            path=path,
            name=posixpath.basename(path),
            parse_error=f"not valid JSON: {exc}"[:200],
        )

    # Both spellings are in the wild; a reader that knew only one would
    # report "no servers" for half of them.
    servers = {}
    for key in ("mcpServers", "servers", "mcp_servers"):
        candidate = blob.get(key) if isinstance(blob, dict) else None
        if isinstance(candidate, dict):
            servers = candidate
            break

    parsed: list[dict[str, Any]] = []
    for name, entry in servers.items():
        if not isinstance(entry, dict):
            continue
        command = str(entry.get("command") or "")
        args = entry.get("args")
        if isinstance(args, list) and args:
            command = (command + " " + " ".join(str(a) for a in args)).strip()
        parsed.append(
            {
                "name": _sanitise(str(name))[:120],
                "source": _server_source(entry),
                # Capped: a command line in a checked-in config is itself
                # attacker-controlled text that a console will render.
                "command": _sanitise(command)[:200] or None,
                "url": _sanitise(str(entry.get("url") or ""))[:300] or None,
            }
        )

    return RepoAiArtifact(
        kind="mcp_config",
        repository=repository,
        path=path,
        name=posixpath.basename(path),
        mcp_servers=tuple(parsed),
    )


def _parse_instruction(kind: str, repository: str, path: str, content: str) -> RepoAiArtifact:
    signals = scan_instruction_text(content)
    name = posixpath.basename(path)
    skills: tuple[dict[str, Any], ...] = ()
    if kind == "skill":
        match = _SKILL_PATTERN.search(_normalise(path))
        skill_name = match.group(2) if match else name
        skills = ({"name": _sanitise(skill_name)[:120], "pinned_revision": None, "path": path},)
        name = skill_name

    return RepoAiArtifact(
        kind=kind,
        repository=repository,
        path=path,
        name=_sanitise(name)[:120],
        tools=_referenced_tools(content),
        skills=skills,
        excerpt=_excerpt(content) or None,
        injection_signals=signals,
    )


#: Tool names an instruction file can grant or forbid. Matched inside the
#: conventional allow/deny syntaxes rather than anywhere in prose, because
#: "do not use `write_file`" in a paragraph is not a grant and counting it
#: as one would make every careful instruction file look dangerous.
_TOOL_GRANT = re.compile(
    r"(?:allowed[_-]?tools|allow|tools)\s*[:=]\s*\[?([A-Za-z0-9_,\s\"'-]{2,400})\]?",
    re.I,
)
_TOOL_TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9_]{2,40}")


def _referenced_tools(content: str) -> tuple[str, ...]:
    found: set[str] = set()
    for match in _TOOL_GRANT.finditer(content):
        for token in _TOOL_TOKEN.findall(match.group(1)):
            found.add(token)
    return tuple(sorted(found)[:40])


def scan_repository(repository: str, files: dict[str, str]) -> list[RepoAiArtifact]:
    """Every AI artefact in one repository.

    `files` is ``path -> content``, as a code-platform connector returns it.
    Paths that are not AI artefacts are ignored rather than listed, because
    an inventory of a repository's whole file tree is not what this is for.
    """
    out: list[RepoAiArtifact] = []
    for path, content in sorted(files.items()):
        kind = classify_path(path)
        if kind is None:
            continue
        if kind == "mcp_config":
            out.append(_parse_mcp_config(repository, path, content))
        else:
            out.append(_parse_instruction(kind, repository, path, content))
    return out
