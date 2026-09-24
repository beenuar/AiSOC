#!/usr/bin/env python3
"""A model name must have somewhere to go, and the variable that sends it there must be read.

Why this exists
---------------
AI triage is this product's headline capability and it could not reach a model
in the default deployment. Not for want of a key — for two wiring defects that
each looked fine in isolation:

``docker-compose.yml`` set ``LLM_GATEWAY_URL`` on the api and agents services.
Both resolvers deliberately ignored it, honouring only ``OPENAI_BASE_URL``,
which compose never set. So the one variable the deployment supplied was read by
nothing, every ``aisoc-<role>`` alias went to ``api.openai.com``, and the 404
came back through a caller's ``except`` as "no LLM available". The service even
logged the diagnosis at boot; the diagnosis existed and the wiring did not.

And ``.env.example`` shipped ``OPENAI_MODEL=gpt-4-turbo-preview`` — a model no
gateway config in this tree has ever defined — which the auto-triage worker
picked up as a per-tenant BYOK override and sent in place of ``aisoc-triage``.
The commercial deployment hit the same shape from the other end: the model names
its LiteLLM did not know produced "Invalid model name" on every call and the
whole thing degraded to empty output across the copilot and every triage agent.

Both are unreachability, and both are structural: a name that resolves nowhere,
or a variable nothing reads. Neither is visible in a diff.

What it checks, in both directions
----------------------------------
The dominant bug shape in this repository is the one-directional check: it
compares A against B and never B against A, so drift in the direction things
actually change slips through while the check prints OK. Every rule below is a
resolution requirement on a specific name, and both name spaces are enumerated.

  PIN   -> GW    every role pin's shipped alias is defined by the gateway
  GW    -> PIN   every gateway alias is claimed by a role pin; an orphan is a
                 model the operator maintains and nothing requests
  AGENTS<->API   the role set and the routing surface agree across the two
                 packages, which cannot import one another and so drift
  CONFIG-> GW    every router fallback names a defined alias, in both the key
                 and the value position
  ENV   -> GW    every model an env/compose file names, in a file that wires
                 the bundled gateway, is one the gateway defines
  CMP   -> CODE  every variable compose points at the bundled gateway is read
                 by both resolvers. This is the defect above, stated as a rule
  CODE  -> CMP   every gateway variable the resolvers read is set by compose on
                 the services that call models. The same defect, mirrored: a
                 read with nothing to read is as dead as a write nobody reads
  PAIRING        a service handed the gateway URL is handed the gateway's key.
                 Resolving the two independently is what made adopting the URL
                 look ambiguous; a provider key sent to LiteLLM is rejected
  SCOPE          embeddings are recorded as outside the gateway (its model list
                 is seven chat aliases), and the exclusion is checked in both
                 directions rather than asserted in a comment

Usage
-----
    python3 scripts/check_llm_model_routing.py              # gate
    python3 scripts/check_llm_model_routing.py --json
    python3 scripts/check_llm_model_routing.py --self-test  # prove it bites

``--repo-root`` overrides the tree under inspection. The resolved root comes
from ``git rev-parse``, every file read and every count is printed before the
verdict, and a missing or empty input is a hard error rather than a quiet zero:
a gate that reports OK about a tree it never opened is worse than no gate.

Stdlib only. The lint job that runs this installs ruff and mypy and nothing
else, and a gate that needs a ``pip install`` to render a verdict is a gate that
can be skipped.

Exit codes: 0 clean, 1 findings, 2 the scan itself could not run.
"""

from __future__ import annotations

import argparse
import ast
import copy
import json
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_main  # noqa: E402

CONFIG_REL = "infra/litellm/config.yaml"
PINS_REL = "services/agents/app/llm/model_pins.py"
AGENTS_ROUTING_REL = "services/agents/app/llm/routing.py"
API_ROUTING_REL = "services/api/app/services/model_aliases.py"
ENV_EXAMPLE_REL = ".env.example"
COMPOSE_REL = "docker-compose.yml"
EMBEDDING_REL = "services/agents/app/tools/mitre_full.py"

#: Env vars whose value is a model name. Read from the tree where possible;
#: this is the shape that identifies one in a compose or dotenv file, where
#: there is no code to parse.
MODEL_VAR_RE = re.compile(r"^(OPENAI_MODEL|LLM_MODEL|AISOC_LLM_MODEL|AISOC_MODEL_PIN_[A-Z0-9_]+)$")

#: How the bundled gateway is recognised in a compose or dotenv value. Matched
#: on the service name compose gives it, so a port change does not blind this.
BUNDLED_GATEWAY_RE = re.compile(r"https?://litellm(:\d+)?(/|$)")

#: Compose services that make LLM calls, and so need both halves of the pair.
#: Derived below from the services that set a gateway variable *or* a model
#: variable, so adding a third LLM service does not require editing this file.
GATEWAY_KEY_VAR = "LITELLM_MASTER_KEY"

#: Embeddings are out of the gateway's scope: ``infra/litellm/config.yaml``
#: declares chat aliases only, so routing an embedding call there 400s on every
#: batch. Recorded here so the exclusion is a checked property rather than a
#: comment, and enforced in both directions below.
EMBEDDING_MODEL_SHAPES = ("embedding", "embed-")


class GateError(RuntimeError):
    """The scan could not be performed — distinct from the scan finding nothing."""


@dataclass
class RoutingModule:
    """What one routing module defines, declares as the rule, and reads."""

    defined: set[str] = field(default_factory=set)
    declared: set[str] = field(default_factory=set)
    reads: dict[str, set[str]] = field(default_factory=dict)

    @property
    def all_reads(self) -> set[str]:
        return set().union(*self.reads.values()) if self.reads else set()


@dataclass
class Corpus:
    """Everything the gate read, named, so a caller cannot lose track of which tree."""

    gateway_aliases: set[str] = field(default_factory=set)
    fallbacks: dict[str, list[str]] = field(default_factory=dict)
    role_pins: dict[str, str] = field(default_factory=dict)
    api_roles: set[str] = field(default_factory=set)
    agents_routing: RoutingModule = field(default_factory=RoutingModule)
    api_routing: RoutingModule = field(default_factory=RoutingModule)
    env_example: dict[str, str] = field(default_factory=dict)
    compose: dict[str, dict[str, str]] = field(default_factory=dict)
    embedding_default: str = ""


# --------------------------------------------------------------------------
# Parsing. Every parser below is comment-aware or AST-based, never a bare
# regex over raw source, because both of this gate's corpora contain text that
# looks exactly like the thing it is looking for:
#
#   * ``infra/litellm/config.yaml`` ends with commented Ollama / vLLM /
#     Anthropic examples that repeat ``model_name: aisoc-triage`` verbatim. A
#     line regex credits three aliases the gateway does not serve.
#   * ``.env.example`` documents the direct-to-provider escape hatch as
#     ``#        AISOC_MODEL_PIN_TRIAGE=gpt-4o-mini``. A line regex reads that
#     as a live assignment and fails the build over documentation.
#   * ``docker-compose.yml`` explains the gateway in prose containing
#     ``OPENAI_BASE_URL=http://litellm:4000/v1`` two lines above the key it is
#     describing.
#
# The self-test injects each of those three shapes and requires the parser to
# decline to credit it.
# --------------------------------------------------------------------------


def strip_comment(line: str) -> str:
    """Drop a trailing ``#`` comment, respecting quotes."""
    out: list[str] = []
    quote: str | None = None
    for ch in line:
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            out.append(ch)
            continue
        if ch == "#":
            break
        out.append(ch)
    return "".join(out).rstrip()


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def parse_gateway_aliases(text: str) -> set[str]:
    """Every ``model_name`` the gateway actually serves."""
    aliases: set[str] = set()
    for raw in text.splitlines():
        line = strip_comment(raw)
        m = re.match(r"^\s*-?\s*model_name:\s*(\S+)\s*$", line)
        if m:
            aliases.add(_unquote(m.group(1)))
    return aliases


def parse_gateway_fallbacks(text: str) -> dict[str, list[str]]:
    """``router_settings.fallbacks`` as ``{alias: [alias, ...]}``."""
    fallbacks: dict[str, list[str]] = {}
    in_block = False
    for raw in text.splitlines():
        line = strip_comment(raw)
        if not line.strip():
            continue
        if re.match(r"^\s*fallbacks:\s*$", line):
            in_block = True
            continue
        if in_block:
            m = re.match(r"^\s*-\s*([A-Za-z0-9_.\-]+):\s*\[(.*)\]\s*$", line)
            if not m:
                # Any non-item line ends the block; a `fallbacks:` entry is a
                # flat list of one-key maps in this file.
                if not re.match(r"^\s*-\s", line):
                    in_block = False
                continue
            targets = [_unquote(t) for t in m.group(2).split(",") if t.strip()]
            fallbacks[m.group(1)] = targets
    return fallbacks


def parse_role_pins(source: str) -> dict[str, str]:
    """``_DEFAULT_PINS`` as ``{role: shipped primary model}``, read as code.

    AST rather than regex: ``model_pins.py`` names ``aisoc-triage`` in its
    module docstring and in an inline comment explaining the escape hatch, and
    a gate that credits a variable mentioned in prose is a gate that credits
    documentation for the behaviour it describes.
    """
    tree = ast.parse(source)
    pins: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.AnnAssign | ast.Assign):
            continue
        targets = [node.target] if isinstance(node, ast.AnnAssign) else node.targets
        if not any(isinstance(t, ast.Name) and t.id == "_DEFAULT_PINS" for t in targets):
            continue
        if not isinstance(node.value, ast.Dict):
            continue
        for key, value in zip(node.value.keys, node.value.values, strict=False):
            if not (isinstance(key, ast.Constant) and isinstance(key.value, str)):
                continue
            if not isinstance(value, ast.Call) or len(value.args) < 2:
                continue
            primary = value.args[1]
            if isinstance(primary, ast.Constant) and isinstance(primary.value, str):
                pins[key.value] = primary.value
    return pins


def parse_api_roles(source: str) -> set[str]:
    """``ROLES`` from the API-side mirror, read as code."""
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(t, ast.Name) and t.id == "ROLES" for t in node.targets):
            continue
        for sub in ast.walk(node.value):
            if isinstance(sub, ast.Set):
                return {e.value for e in sub.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)}
    return set()


def _env_reads(node: ast.AST) -> set[str]:
    """Env var names read by an actual call under ``node``, not mentioned in prose."""
    names: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            func = sub.func
            target = None
            if isinstance(func, ast.Attribute) and func.attr in ("getenv", "get"):
                owner = func.value
                if isinstance(owner, ast.Name) and owner.id == "os":
                    target = sub.args[0] if sub.args else None
                elif isinstance(owner, ast.Attribute) and owner.attr == "environ":
                    target = sub.args[0] if sub.args else None
            if isinstance(target, ast.Constant) and isinstance(target.value, str):
                names.add(target.value)
        elif isinstance(sub, ast.Subscript):
            owner = sub.value
            if isinstance(owner, ast.Attribute) and owner.attr == "environ" and isinstance(sub.slice, ast.Constant):
                if isinstance(sub.slice.value, str):
                    names.add(sub.slice.value)
    return names


def parse_routing_module(source: str) -> RoutingModule:
    """Names defined, names declared in ``__all__``, and the env vars each function reads."""
    tree = ast.parse(source)
    functions: dict[str, set[str]] = {}
    defined: set[str] = set()
    declared: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            functions[node.name] = _env_reads(node)
            defined.add(node.name)
        elif isinstance(node, ast.ClassDef):
            defined.add(node.name)
        elif isinstance(node, ast.Assign):
            names = {t.id for t in node.targets if isinstance(t, ast.Name)}
            defined |= names
            if "__all__" in names and isinstance(node.value, ast.List | ast.Tuple):
                declared = {e.value for e in node.value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)}
    return RoutingModule(defined=defined, declared=declared, reads=functions)


def parse_env_file(text: str) -> dict[str, str]:
    """Live ``KEY=VALUE`` assignments. A commented example is documentation."""
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line)
        if m:
            out[m.group(1)] = _unquote(strip_comment(m.group(2)))
    return out


def parse_compose_env(text: str) -> dict[str, dict[str, str]]:
    """``{service: {VAR: value}}`` from a compose file's ``environment:`` blocks."""
    services: dict[str, dict[str, str]] = {}
    in_services = False
    service: str | None = None
    in_env = False
    for raw in text.splitlines():
        line = strip_comment(raw)
        if not line.strip():
            continue
        if re.match(r"^services:\s*$", line):
            in_services, service, in_env = True, None, False
            continue
        if re.match(r"^[A-Za-z_]", line):  # another top-level key
            in_services, service, in_env = False, None, False
            continue
        if not in_services:
            continue
        m = re.match(r"^  ([A-Za-z0-9_.\-]+):\s*$", line)
        if m:
            service, in_env = m.group(1), False
            services.setdefault(service, {})
            continue
        if service is None:
            continue
        if re.match(r"^    environment:\s*$", line):
            in_env = True
            continue
        if re.match(r"^    [A-Za-z0-9_.\-]+:", line):  # sibling of environment:
            in_env = False
            continue
        if not in_env:
            continue
        m = re.match(r"^      ([A-Z_][A-Z0-9_]*):\s*(.*)$", line)
        if m:
            services[service][m.group(1)] = _unquote(m.group(2))
            continue
        m = re.match(r"^      -\s*([A-Z_][A-Z0-9_]*)=(.*)$", line)
        if m:
            services[service][m.group(1)] = _unquote(m.group(2))
    return services


def parse_embedding_default(source: str) -> str:
    """The model the RAG embedding path sends when nothing overrides it."""
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "_DEFAULT_EMBEDDING_MODEL" for t in node.targets):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                return node.value.value
    return ""


# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------


def _resolve_value(value: str, env: dict[str, str]) -> str:
    """Resolve ``${VAR:-default}`` / ``${VAR}`` against a dotenv baseline."""

    def sub(m: re.Match[str]) -> str:
        name, default = m.group(1), m.group(3) or ""
        return env.get(name) or default

    return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(:-([^}]*))?\}", sub, value).strip()


def evaluate(c: Corpus) -> list[tuple[str, str]]:
    """Return ``(code, detail)`` for every unresolvable name. Empty means clean."""
    out: list[tuple[str, str]] = []
    gateway_aliases = c.gateway_aliases
    fallbacks = c.fallbacks
    role_pins = c.role_pins
    api_roles = c.api_roles
    agents_routing = c.agents_routing
    api_routing = c.api_routing
    env_example = c.env_example
    compose = c.compose
    embedding_default = c.embedding_default

    # PIN -> GW / GW -> PIN.
    claimed = set(role_pins.values())
    for role, primary in sorted(role_pins.items()):
        if primary not in gateway_aliases:
            out.append(("pin-alias-undefined", f"role '{role}' ships primary '{primary}', which {CONFIG_REL} does not define"))
    for alias in sorted(gateway_aliases - claimed):
        out.append(("gateway-alias-unclaimed", f"{CONFIG_REL} defines '{alias}', which no role pin in {PINS_REL} requests"))

    # AGENTS <-> API.
    for role in sorted(set(role_pins) - api_roles):
        out.append(("role-set-drift", f"'{role}' is pinned in {PINS_REL} but absent from ROLES in {API_ROUTING_REL}"))
    for role in sorted(api_roles - set(role_pins)):
        out.append(("role-set-drift", f"'{role}' is in ROLES in {API_ROUTING_REL} but has no pin in {PINS_REL}"))

    # The mirror compared against the rule the agents module declares, in both
    # directions. Equality of *every* name would be wrong — the API module also
    # carries alias resolution, which the agents side gets from model_pins — so
    # the contract is ``__all__``: the mirror may not lose a rule, and may not
    # grow a routing rule the agents side does not have. Growth is detected by
    # the reads, not by the name, because a new rule is one that consults the
    # environment.
    declared = agents_routing.declared
    routing_vars = agents_routing.all_reads
    api_defined = api_routing.defined
    agents_defined = agents_routing.defined
    for name in sorted(declared - agents_defined):
        out.append(("routing-surface-drift", f"{AGENTS_ROUTING_REL} declares '{name}' in __all__ and does not define it"))
    for name in sorted(declared - api_defined):
        out.append(
            ("routing-surface-drift", f"{AGENTS_ROUTING_REL} declares '{name}' as a routing rule and the {API_ROUTING_REL} mirror lacks it")
        )
    for name, reads in sorted(api_routing.reads.items()):
        if reads & routing_vars and name.lstrip("_") not in declared:
            out.append(
                (
                    "routing-surface-drift",
                    f"{API_ROUTING_REL} defines '{name}', which reads {', '.join(sorted(reads & routing_vars))}, "
                    f"and {AGENTS_ROUTING_REL} does not declare it — the two services would route differently",
                )
            )

    agents_reads = agents_routing.all_reads
    api_reads = api_routing.all_reads
    for name in sorted(agents_reads ^ api_reads):
        side = AGENTS_ROUTING_REL if name in agents_reads else API_ROUTING_REL
        other = API_ROUTING_REL if name in agents_reads else AGENTS_ROUTING_REL
        out.append(("routing-read-drift", f"'{name}' is read by {side} and not by {other}; the two services would route differently"))

    # CONFIG -> GW.
    for key, targets in sorted(fallbacks.items()):
        if key not in gateway_aliases:
            out.append(("fallback-undefined", f"router fallback is keyed on '{key}', which {CONFIG_REL} does not define"))
        for target in targets:
            if target not in gateway_aliases:
                out.append(("fallback-undefined", f"router fallback '{key}' falls back to '{target}', which {CONFIG_REL} does not define"))

    # ENV -> GW. Only in a file that wires the bundled gateway: an operator
    # pointing at their own vLLM with concrete model names is correct, and only
    # this gateway's contents are knowable from here.
    env_wires_gateway = any(BUNDLED_GATEWAY_RE.search(v) for v in env_example.values())
    if env_wires_gateway:
        for name, value in sorted(env_example.items()):
            if MODEL_VAR_RE.match(name) and value and value not in gateway_aliases:
                out.append(
                    (
                        "env-model-undefined",
                        f"{ENV_EXAMPLE_REL} sets {name}={value} while wiring the bundled gateway, which does not define it",
                    )
                )
    for service, env in sorted(compose.items()):
        if not any(BUNDLED_GATEWAY_RE.search(v) for v in env.values()):
            continue
        for name, value in sorted(env.items()):
            if not MODEL_VAR_RE.match(name):
                continue
            resolved = _resolve_value(value, env_example)
            if resolved and resolved not in gateway_aliases:
                out.append(
                    (
                        "env-model-undefined",
                        f"{COMPOSE_REL} service '{service}' sets {name}={value} (resolves to '{resolved}') "
                        f"while wiring the bundled gateway, which does not define it",
                    )
                )

    # CMP -> CODE and CODE -> CMP. The variable compose points at the gateway
    # and the variable the resolvers read have to be the same variable.
    read_everywhere = agents_reads & api_reads
    gateway_services = {s for s, env in compose.items() if any(BUNDLED_GATEWAY_RE.search(v) for v in env.values())}
    compose_gateway_vars: set[str] = set()
    for service in gateway_services:
        for name, value in compose[service].items():
            if BUNDLED_GATEWAY_RE.search(value):
                compose_gateway_vars.add(name)
    for name in sorted(compose_gateway_vars - read_everywhere):
        out.append(
            (
                "compose-var-unread",
                f"{COMPOSE_REL} points {name} at the bundled gateway and neither resolver reads it; "
                "the deployment supplies a route nothing can follow",
            )
        )
    # The mirror. Every gateway variable the resolvers read has to be supplied,
    # or the read is as dead as the write was.
    code_gateway_vars = {n for n in read_everywhere if n.endswith("GATEWAY_URL")}
    if not code_gateway_vars:
        out.append(("code-var-unset", f"no *_GATEWAY_URL variable is read by both {AGENTS_ROUTING_REL} and {API_ROUTING_REL}"))
    for name in sorted(code_gateway_vars):
        if not any(name in compose[s] for s in compose):
            out.append(("code-var-unset", f"both resolvers read {name} and no {COMPOSE_REL} service sets it"))

    # PAIRING. The route decides the bearer; a provider key sent to LiteLLM is
    # rejected as an invalid proxy token.
    for service in sorted(gateway_services):
        if GATEWAY_KEY_VAR not in compose[service]:
            out.append(
                (
                    "gateway-without-key",
                    f"{COMPOSE_REL} service '{service}' is pointed at the bundled gateway without {GATEWAY_KEY_VAR}; "
                    "it would authenticate with a provider key the gateway rejects",
                )
            )

    # SCOPE. Embeddings are excluded from the gateway, in both directions.
    if not embedding_default:
        out.append(("embedding-scope", f"{EMBEDDING_REL} declares no default embedding model to classify"))
    elif embedding_default.startswith("aisoc-"):
        out.append(
            (
                "embedding-scope",
                f"{EMBEDDING_REL} defaults to '{embedding_default}', a gateway alias — but {CONFIG_REL} "
                "declares chat models only, so every embedding batch would 400",
            )
        )
    for alias in sorted(gateway_aliases):
        if any(shape in alias for shape in EMBEDDING_MODEL_SHAPES):
            out.append(
                (
                    "embedding-scope",
                    f"{CONFIG_REL} defines '{alias}', which looks like an embedding model; the exclusion "
                    f"recorded in {EMBEDDING_REL} says the gateway carries chat aliases only",
                )
            )
    return out


# --------------------------------------------------------------------------
# I/O
# --------------------------------------------------------------------------


def load(root: Path) -> Corpus:
    paths = {
        "config": root / CONFIG_REL,
        "pins": root / PINS_REL,
        "agents_routing": root / AGENTS_ROUTING_REL,
        "api_routing": root / API_ROUTING_REL,
        "env_example": root / ENV_EXAMPLE_REL,
        "compose": root / COMPOSE_REL,
        "embedding": root / EMBEDDING_REL,
    }
    for name, path in paths.items():
        if not path.is_file():
            raise GateError(f"expected input does not exist: {path} ({name})")

    config_text = paths["config"].read_text(encoding="utf-8")
    corpus = Corpus(
        gateway_aliases=parse_gateway_aliases(config_text),
        fallbacks=parse_gateway_fallbacks(config_text),
        role_pins=parse_role_pins(paths["pins"].read_text(encoding="utf-8")),
        api_roles=parse_api_roles(paths["api_routing"].read_text(encoding="utf-8")),
        agents_routing=parse_routing_module(paths["agents_routing"].read_text(encoding="utf-8")),
        api_routing=parse_routing_module(paths["api_routing"].read_text(encoding="utf-8")),
        env_example=parse_env_file(paths["env_example"].read_text(encoding="utf-8")),
        compose=parse_compose_env(paths["compose"].read_text(encoding="utf-8")),
        embedding_default=parse_embedding_default(paths["embedding"].read_text(encoding="utf-8")),
    )
    # An empty parse means the format moved, not that the tree is clean. Found
    # nothing and scanned nothing print the same word unless one of them refuses.
    empty = [
        name for name in ("gateway_aliases", "fallbacks", "role_pins", "api_roles", "env_example", "compose") if not getattr(corpus, name)
    ]
    if empty:
        raise GateError(f"parsed zero {empty[0]} — refusing to report a clean tree from an empty read")
    for side in ("agents_routing", "api_routing"):
        module: RoutingModule = getattr(corpus, side)
        if not module.defined:
            raise GateError(f"parsed zero definitions from {side} — refusing to report a clean tree from an empty read")
    if not corpus.agents_routing.declared:
        raise GateError(f"{AGENTS_ROUTING_REL} declares no __all__ — the routing contract the mirror is checked against is missing")
    return corpus


def _summary(c: Corpus, root: Path) -> list[str]:
    gateway_services = sorted(s for s, env in c.compose.items() if any(BUNDLED_GATEWAY_RE.search(v) for v in env.values()))
    reads = ", ".join(sorted(c.agents_routing.all_reads))
    wired = ", ".join(gateway_services)
    return [
        f"repo root        {root}",
        f"gateway config   {CONFIG_REL}  ({len(c.gateway_aliases)} aliases, {len(c.fallbacks)} router fallbacks)",
        f"role pins        {PINS_REL}  ({len(c.role_pins)} roles)",
        f"agents routing   {AGENTS_ROUTING_REL}  ({len(c.agents_routing.declared)} declared rules, reads {reads})",
        f"api routing      {API_ROUTING_REL}  ({len(c.api_routing.defined)} definitions, {len(c.api_roles)} roles)",
        f"env example      {ENV_EXAMPLE_REL}  ({len(c.env_example)} live assignments)",
        f"compose          {COMPOSE_REL}  ({len(c.compose)} services, {len(gateway_services)} on the bundled gateway: {wired})",
        f"embedding scope  {EMBEDDING_REL}  (default '{c.embedding_default}', excluded from the gateway)",
    ]


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------


def self_test(root: Path) -> int:
    """Prove the gate still catches what it claims, and still declines prose.

    Two kinds of case. The first injects a defect into the parsed data and
    requires the matching code. The second feeds the *parsers* text shaped like
    the thing they look for but commented out, and requires them not to credit
    it — because every blind spot found in this tree so far was something a
    gate credited, not something it failed to flag.
    """
    try:
        base = load(root)
    except GateError as exc:
        print(f"self-test cannot run: {exc}", file=sys.stderr)
        return 2

    baseline = evaluate(base)
    if baseline:
        print("self-test cannot run: the clean tree already has findings:", file=sys.stderr)
        for code, detail in baseline:
            print(f"  [{code}] {detail}", file=sys.stderr)
        return 2

    def drop_gateway_read(c: Corpus) -> None:
        for reads in c.api_routing.reads.values():
            reads.discard("LLM_GATEWAY_URL")

    def add_unset_gateway_var(c: Corpus) -> None:
        for module in (c.agents_routing, c.api_routing):
            module.reads.setdefault("gateway_url", set()).add("AISOC_GATEWAY_URL")

    def drop_gateway_key(c: Corpus) -> None:
        c.compose["agents"].pop(GATEWAY_KEY_VAR, None)

    def use_embedding_alias(c: Corpus) -> None:
        c.embedding_default = "aisoc-summary"

    # Each case is a defect injected into a deep copy of the real corpus, and
    # the code it must produce. deepcopy, not a shallow one: the corpora are
    # nested (compose is service -> var -> value), and the first draft let one
    # case mutate the baseline every later case was measured against, so every
    # case "caught" three codes it had inherited. A self-test that passes for
    # the wrong reason is the defect this gate exists to find, one level up.
    cases: list[tuple[str, str, Callable[[Corpus], None]]] = [
        (
            "PIN -> GW: a role pinned to an alias the gateway does not define",
            "pin-alias-undefined",
            lambda c: c.role_pins.update({"triage": "aisoc-triage-v2"}),
        ),
        (
            "GW -> PIN: an alias the gateway serves that no role requests",
            "gateway-alias-unclaimed",
            lambda c: c.gateway_aliases.add("aisoc-orphan"),
        ),
        (
            "AGENTS <-> API: a role pinned on one side only",
            "role-set-drift",
            lambda c: c.api_roles.discard("triage"),
        ),
        (
            "AGENTS <-> API: the mirror loses a routing function",
            "routing-surface-drift",
            lambda c: c.api_routing.defined.discard("resolve_api_key"),
        ),
        (
            "AGENTS <-> API: the mirror stops reading a variable the other reads",
            "routing-read-drift",
            drop_gateway_read,
        ),
        (
            "CONFIG -> GW: a router fallback naming an undefined alias",
            "fallback-undefined",
            lambda c: c.fallbacks.update({"aisoc-report": ["aisoc-nonexistent"]}),
        ),
        (
            "ENV -> GW: .env.example ships a model the gateway does not define",
            "env-model-undefined",
            lambda c: c.env_example.update({"OPENAI_MODEL": "gpt-4-turbo-preview"}),
        ),
        (
            "ENV -> GW: a compose service pins a role to a model the gateway lacks",
            "env-model-undefined",
            lambda c: c.compose["agents"].update({"AISOC_MODEL_PIN_TRIAGE": "gpt-4o-mini"}),
        ),
        (
            "CMP -> CODE: compose supplies a gateway route no resolver reads",
            "compose-var-unread",
            lambda c: c.compose["agents"].update({"LLM_PROXY_URL": "http://litellm:4000/v1"}),
        ),
        (
            "CODE -> CMP: both resolvers read a gateway variable compose never sets",
            "code-var-unset",
            add_unset_gateway_var,
        ),
        (
            "PAIRING: a service given the gateway URL but not the gateway key",
            "gateway-without-key",
            drop_gateway_key,
        ),
        (
            "SCOPE: the gateway grows an embedding alias it cannot serve as chat",
            "embedding-scope",
            lambda c: c.gateway_aliases.add("aisoc-embedding"),
        ),
        (
            "SCOPE: the RAG path defaults to a gateway alias for an embedding call",
            "embedding-scope",
            use_embedding_alias,
        ),
    ]

    print(f"self-test against {root}")
    print("clean tree: 0 findings (the baseline every case below perturbs)\n")
    results: list[tuple[str, bool]] = []
    for description, expected, mutate in cases:
        perturbed = copy.deepcopy(base)
        mutate(perturbed)
        codes = {code for code, _ in evaluate(perturbed)}
        caught = expected in codes
        results.append((f"{description}\n        expected [{expected}]  got {sorted(codes) or 'nothing'}", caught))

    # Parser blind spots: text that looks like the thing, and is not it.
    blind: list[tuple[str, bool]] = [
        (
            "PARSER: a commented-out model_name in the Ollama example is not a served alias",
            "aisoc-never-served"
            not in parse_gateway_aliases("model_list:\n  - model_name: aisoc-triage\n  # - model_name: aisoc-never-served\n"),
        ),
        (
            "PARSER: a model_name inside a quoted value is not mistaken for a comment boundary",
            parse_gateway_aliases('model_list:\n  - model_name: "aisoc-triage"  # the high-volume path\n') == {"aisoc-triage"},
        ),
        (
            "PARSER: a commented-out .env assignment is documentation, not configuration",
            parse_env_file("#        AISOC_MODEL_PIN_TRIAGE=gpt-4o-mini\nOPENAI_MODEL=aisoc-summary\n")
            == {"OPENAI_MODEL": "aisoc-summary"},
        ),
        (
            "PARSER: a compose comment naming a variable two lines above is not an assignment",
            parse_compose_env(
                "services:\n  agents:\n    environment:\n"
                "      # set OPENAI_BASE_URL=http://litellm:4000/v1 to route here\n"
                "      LLM_GATEWAY_URL: http://litellm:4000/v1\n"
            )
            == {"agents": {"LLM_GATEWAY_URL": "http://litellm:4000/v1"}},
        ),
        (
            "PARSER: a role pin named only in a docstring is not a shipped pin",
            parse_role_pins('"""_DEFAULT_PINS maps triage to aisoc-triage."""\n_DEFAULT_PINS = {}\n') == {},
        ),
        (
            "PARSER: an env var named only in a docstring is not read",
            "LLM_GATEWAY_URL"
            not in parse_routing_module('def gateway_url():\n    """Reads LLM_GATEWAY_URL."""\n    return None\n').all_reads,
        ),
        (
            "PARSER: an env var read through os.environ[...] counts as read",
            parse_routing_module('import os\ndef f():\n    return os.environ["LLM_GATEWAY_URL"]\n').all_reads == {"LLM_GATEWAY_URL"},
        ),
    ]
    results.extend(blind)
    results.append(
        (
            f"{len(cases)} injected defects and {len(blind)} parser blind spots, each caught by its own code",
            all(passed for _, passed in results),
        )
    )
    # Delegated so the empty-tree probe is the shared one every gate answers,
    # run here rather than restated: a gate that refuses nothing is the failure
    # scripts/check_gate_contract.py exists to make impossible.
    return self_test_main(Path(__file__).name, [], extra=results)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo-root", type=Path, default=None)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true", help="prove the gate detects injected drift in each direction")
    args = parser.parse_args(argv)

    root = (args.repo_root or repo_root()).resolve()
    if args.self_test:
        return self_test(root)

    try:
        corpus = load(root)
    except GateError as exc:
        print(f"check_llm_model_routing: FAILED to read the tree: {exc}", file=sys.stderr)
        return 2
    except SyntaxError as exc:
        print(f"check_llm_model_routing: FAILED to parse the tree: {exc}", file=sys.stderr)
        return 2

    findings = evaluate(corpus)

    if args.json:
        print(
            json.dumps(
                {
                    "repo_root": str(root),
                    "gateway_aliases": sorted(corpus.gateway_aliases),
                    "role_pins": corpus.role_pins,
                    "api_roles": sorted(corpus.api_roles),
                    "agents_reads": sorted(corpus.agents_routing.all_reads),
                    "api_reads": sorted(corpus.api_routing.all_reads),
                    "embedding_default": corpus.embedding_default,
                    "findings": [{"code": c, "detail": d} for c, d in findings],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1 if findings else 0

    for line in _summary(corpus, root):
        print(line)
    print()
    if findings:
        print(f"FAIL: {len(findings)} model name(s) or routing variable(s) that resolve nowhere\n", file=sys.stderr)
        for code, detail in findings:
            print(f"  [{code}] {detail}", file=sys.stderr)
        return 1
    print(
        f"OK: {len(corpus.role_pins)} role pins, {len(corpus.gateway_aliases)} gateway aliases and "
        f"every model named in {ENV_EXAMPLE_REL} / {COMPOSE_REL} resolve at the gateway, "
        "and the variable compose supplies is the variable both resolvers read"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
