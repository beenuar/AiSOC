#!/usr/bin/env python3
"""No service may name a public host in its default configuration.

Why this exists
---------------
The front page says AiSOC "runs entirely on your infrastructure" with no data
exfiltration. Three things already hold parts of that line: the CLI makes zero
network calls when telemetry is unconfigured, the Helm chart denies egress by
default, and the agents' redactor keeps raw PII out of anything that leaves a
process. What none of them answer is the platform-wide question — **boot every
service with an empty environment and is anything pointed at the internet?**

That question is settled in two places at once, because either half alone is
satisfied by the other's blind spot:

* this gate, which reads the *declared defaults* and is exhaustive over them
  but cannot see a URL built at runtime;
* ``tests/test_no_default_egress.py``, which imports each service under a
  socket guard and is blind to code paths startup does not reach, but sees
  every host actually dialled on the paths it does.

The defect that motivated it
----------------------------
``services/purple-team`` declared::

    attack_stix_url: str = "https://raw.githubusercontent.com/mitre/cti/..."

and nothing in the service read it. A dead setting still publishes an external
default: it is documented, it is settable, and the next person to need an ATT&CK
bundle wires the existing field rather than asking whether the service should be
reaching a CDN at all. It was deleted rather than exempted.

What counts as a settings module
--------------------------------
Structurally, never by filename alone — ``services/threatintel`` keeps its
settings in ``app/config.py`` while ``services/api`` uses ``app/core/config.py``,
and a gate keyed on one path would silently stop covering a service that moved
its file. A module qualifies when it declares a ``BaseSettings`` subclass, or
when it is named ``config.py`` / ``settings.py`` under ``services/<svc>/app/``.
The second clause is deliberately wider than the first: it means a config module
that stops using pydantic keeps its coverage.

Vendor API clients are out of scope, and that is a real limit rather than an
oversight. ``services/actions/app/clients/crowdstrike_rtr.py`` names
``api.crowdstrike.com`` because that *is* CrowdStrike; the host is reached only
once an operator has configured that integration with credentials, so it is a
configured destination, not a default. The claim under test is about what an
unconfigured install does.

Reusing the shipped predicate instead of writing a third copy
-------------------------------------------------------------
"Is this host private?" is already answered twice in this tree, by
``services/api/app/core/airgap.py`` and its mirror in
``services/threatintel/app/airgap.py``. A third copy here would be the fastest
possible way to make the gate disagree with the enforcement it reports on.

Neither module imports cleanly from ``scripts/``: both bind a pydantic
``settings`` object and one pulls in ``structlog``, and this gate runs on the
bare interpreter in the lint job. Stubbing those imports would work until the
module grew another one. So the predicate is read *structurally*: its function
and the suffix tuple it closes over are lifted out of the shipped source by
``ast``, checked to reference nothing but ``ipaddress``, and compiled on their
own. The gate therefore executes the same code the service executes, and a
rename or deletion in either module fails the gate loudly rather than silently
forking its behaviour.

The two copies are then compared *by behaviour* over a probe set rather than
byte-for-byte, because they are legitimately worded differently. If they ever
disagree about a host, this gate's verdict would be correct for one service and
wrong for the other, so a disagreement is a finding.

Bidirectional by construction
-----------------------------
The failure shape this repository keeps rediscovering is the one-directional
check: it compares A against B, never B against A, and drift in the direction
things actually move slips past while the check prints OK. An allow-list keyed
only on "may this setting name a public host?" has exactly that shape — delete
the guard that made the exemption defensible and the exemption outlives it.

So every entry names the enforcement that justifies it, and all three
directions are errors:

  * tree -> allow-list : a public default with no entry.
  * allow-list -> tree : an entry whose setting, module or host is gone.
  * entry -> enforcement : a named guard that is not defined where the entry
    says, or that is defined and called by nothing. Deleting the guard must
    revoke the exemption, or the guard was never what made it safe.

Non-vacuity
-----------
A gate that passes while inspecting nothing launders the claim it stands for.
The repository root comes from git rather than ``__file__``; the scan must reach
a plausible number of settings modules and URL defaults; and it must classify at
least one host as private, because a classifier stuck on "public" and one stuck
on "private" both report a clean tree when the corpus is empty. ``--self-test``
proves the detector separates known-bad from known-good, that all three
directions fire, that the happy path is still reachable, and that the gate
refuses a tree with no content.

Usage:
    python3 scripts/check_default_egress.py --self-test
    python3 scripts/check_default_egress.py
    python3 scripts/check_default_egress.py --list

Exit codes: 0 clean, 1 findings, 2 the scan itself could not run.
"""

from __future__ import annotations

import argparse
import ast
import builtins
import ipaddress
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_main  # noqa: E402

# --------------------------------------------------------------------------
# The shipped predicate, and its mirror.
# --------------------------------------------------------------------------

#: The module whose private-address logic this gate executes verbatim.
PREDICATE_MODULE = "services/api/app/core/airgap.py"

#: The mirror that must keep agreeing with it. Two copies of a security
#: predicate are a fork waiting to happen; this is what notices.
PREDICATE_MIRROR = "services/threatintel/app/airgap.py"

#: The names lifted out of the shipped module, in the order they must be bound.
PREDICATE_SUFFIXES = "_PRIVATE_SUFFIXES"
PREDICATE_FUNCTION = "_is_private_address"

#: Everything the lifted function is allowed to reach for beyond its own
#: arguments, locals and the builtins. If it grows a dependency on the service's
#: settings object the lift stops being safe, and this is what refuses it.
PREDICATE_FREE_NAMES = frozenset({"ipaddress", PREDICATE_SUFFIXES})

#: Hosts the two copies are compared over. Covers each branch either one takes:
#: literal IPs across the private ranges, loopback, link-local, unspecified, the
#: internal suffixes, a single-label container name, and public hosts of the
#: exact shapes that appear in this tree's defaults.
PARITY_PROBES = (
    "127.0.0.1",
    "10.0.0.5",
    "192.168.1.10",
    "172.16.0.1",
    "169.254.169.254",
    "0.0.0.0",
    "::1",
    "fd00::1",
    "localhost",
    "ollama.local",
    "vllm.internal",
    "gateway.lan",
    "host.intranet",
    "db.corp",
    "nas.home",
    "box.localdomain",
    "connectors",
    "aisoc-api",
    "raw.githubusercontent.com",
    "otx.alienvault.com",
    "www.cisa.gov",
    "api.openai.com",
    "8.8.8.8",
)

# --------------------------------------------------------------------------
# Scope.
# --------------------------------------------------------------------------

#: Filenames that hold settings regardless of whether they use pydantic.
SETTINGS_FILENAMES = frozenset({"config.py", "settings.py"})

#: URL schemes worth classifying. A scheme that never leaves the host (``file``)
#: or that carries no host at all says nothing about egress.
NETWORK_SCHEMES = frozenset(
    {
        "http",
        "https",
        "ws",
        "wss",
        "grpc",
        "grpcs",
        "redis",
        "rediss",
        "amqp",
        "amqps",
        "mongodb",
        "kafka",
        "postgres",
        "postgresql",
        "mysql",
        "clickhouse",
        "bolt",
        "neo4j",
    }
)

#: Calls whose fallback argument is a default. ``os.getenv("X", "https://…")``
#: declares an egress default exactly as surely as a class attribute does.
ENV_LOOKUPS = (("os", "getenv"), ("os", "environ", "get"), ("environ", "get"), ("getenv",))

#: Floors for the scan itself. Set well under today's counts: they exist to
#: catch a walk that broke, not to pin a number that moves with the tree.
MIN_SETTINGS_MODULES = 8
MIN_URL_DEFAULTS = 15

#: Files that must exist for a directory to be this repository.
SENTINELS = (PREDICATE_MODULE, PREDICATE_MIRROR, "services/purple-team/app/core/config.py")


# --------------------------------------------------------------------------
# The allow-list. Shrink-only, and every entry names what enforces it.
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Exemption:
    """A public default somebody signed off on, and the guard that justifies it."""

    module: str
    setting: str
    host: str
    reason: str
    #: (file, symbol) pairs. Each symbol must be defined in that file *and*
    #: called from somewhere in the owning service. An exemption whose guard is
    #: deleted, renamed or orphaned stops applying.
    enforced_by: tuple[tuple[str, str], ...]


_THREATINTEL_GUARD = (
    (PREDICATE_MIRROR, "is_host_allowed_for_airgap"),
    ("services/threatintel/app/main.py", "_airgap_check_feed_url"),
)

ALLOWED: tuple[Exemption, ...] = (
    Exemption(
        module="services/threatintel/app/config.py",
        setting="OTX_BASE_URL",
        host="otx.alienvault.com",
        reason=(
            "AlienVault OTX is a public feed with no internal mirror to point at, so the default has to name it. "
            "Under AISOC_AIRGAPPED the feed is refused at registration time rather than at request time, because a "
            "failed poll every 30 minutes is itself a signal that an instance exists."
        ),
        enforced_by=_THREATINTEL_GUARD,
    ),
    Exemption(
        module="services/threatintel/app/config.py",
        setting="CISA_KEV_URL",
        host="www.cisa.gov",
        reason=(
            "The CISA Known Exploited Vulnerabilities catalog is the authoritative public source and needs no API key, "
            "which is why it is what CORE ships so a first run shows real data. An air-gapped deployment mirrors the "
            "JSON internally and allow-lists the mirror; the feed is otherwise refused at registration time."
        ),
        enforced_by=_THREATINTEL_GUARD,
    ),
)


# --------------------------------------------------------------------------
# Findings.
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class UrlDefault:
    """A URL-valued default found in a settings module."""

    module: str
    setting: str
    lineno: int
    url: str
    host: str

    @property
    def service(self) -> str:
        parts = Path(self.module).parts
        return parts[1] if len(parts) > 1 else "?"


class GateError(RuntimeError):
    """Raised when the gate cannot trust its own inputs."""


# --------------------------------------------------------------------------
# Lifting the shipped predicate.
# --------------------------------------------------------------------------


def _free_names(fn: ast.FunctionDef) -> set[str]:
    """Names ``fn`` loads that it neither binds nor inherits from the builtins."""
    bound = {a.arg for a in (*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs)}
    if fn.args.vararg:
        bound.add(fn.args.vararg.arg)
    if fn.args.kwarg:
        bound.add(fn.args.kwarg.arg)
    loaded: set[str] = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Name):
            (loaded if isinstance(node.ctx, ast.Load) else bound).add(node.id)
        elif isinstance(node, (ast.comprehension,)):
            for target in ast.walk(node.target):
                if isinstance(target, ast.Name):
                    bound.add(target.id)
    return loaded - bound - set(dir(builtins))


def load_shipped_predicate(root: Path, module: str):
    """Compile ``_is_private_address`` out of ``module`` and return it.

    Read rather than imported, and read rather than copied: the gate runs the
    service's own classification without needing the service's dependencies,
    and cannot drift from it.
    """
    path = root / module
    try:
        source = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise GateError(f"cannot read the shipped air-gap predicate at {module}: {exc}") from exc

    tree = ast.parse(source, filename=module)
    fn = next((n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == PREDICATE_FUNCTION), None)
    suffixes = next(
        (n for n in tree.body if isinstance(n, (ast.Assign, ast.AnnAssign)) and PREDICATE_SUFFIXES in ast.dump(n)),
        None,
    )
    if fn is None:
        raise GateError(
            f"{module} no longer defines {PREDICATE_FUNCTION}() — this gate classifies hosts with that function, so it cannot run"
        )
    if suffixes is None:
        raise GateError(
            f"{module} no longer defines {PREDICATE_SUFFIXES} — {PREDICATE_FUNCTION}() closes over it, so the lift is incomplete"
        )

    stray = _free_names(fn) - PREDICATE_FREE_NAMES
    if stray:
        raise GateError(
            f"{module}::{PREDICATE_FUNCTION}() now reads {', '.join(sorted(stray))}, which this gate cannot supply. "
            "Lifting it would run different code than the service does; re-read the function and widen "
            "PREDICATE_FREE_NAMES deliberately, or give the gate a supported way to import it."
        )

    namespace: dict[str, object] = {"ipaddress": ipaddress}
    lifted = ast.Module(body=[suffixes, fn], type_ignores=[])
    exec(compile(lifted, filename=f"{module} (lifted)", mode="exec"), namespace)  # noqa: S102 - repo's own tracked source, vetted above
    return namespace[PREDICATE_FUNCTION]


def predicate_parity(root: Path) -> list[str]:
    """Both shipped copies must answer every probe host the same way."""
    primary = load_shipped_predicate(root, PREDICATE_MODULE)
    mirror = load_shipped_predicate(root, PREDICATE_MIRROR)
    disagreements = [host for host in PARITY_PROBES if bool(primary(host)) != bool(mirror(host))]
    if not disagreements:
        return []
    return [
        f"PREDICATE FORK    {PREDICATE_MODULE} and {PREDICATE_MIRROR} disagree about: {', '.join(disagreements)}",
        "                  Two copies of the private-address rule means this gate's verdict is right for one service",
        "                  and wrong for the other. Reconcile them before trusting either.",
    ]


# --------------------------------------------------------------------------
# Finding the settings modules and their URL defaults.
# --------------------------------------------------------------------------


def _is_settings_class(node: ast.ClassDef) -> bool:
    return any("BaseSettings" in ast.unparse(base) for base in node.bases)


def is_settings_module(rel: str, tree: ast.Module) -> bool:
    """Whether ``rel`` declares service settings, by structure then by name."""
    parts = Path(rel).parts
    if len(parts) < 3 or parts[0] != "services" or parts[2] != "app":
        return False
    if any(isinstance(n, ast.ClassDef) and _is_settings_class(n) for n in ast.walk(tree)):
        return True
    return Path(rel).name in SETTINGS_FILENAMES


def _call_path(node: ast.expr) -> tuple[str, ...]:
    """Dotted name of a call target, e.g. ``os.environ.get`` -> ('os','environ','get')."""
    parts: list[str] = []
    cur: ast.expr | None = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return tuple(reversed(parts))


def _string_defaults(value: ast.expr) -> list[tuple[str, int]]:
    """Every ``(string, line)`` that ``value`` supplies as a default.

    Returns the unwrapped string rather than the ``ast.Constant`` so the
    ``isinstance`` narrowing done here survives into the caller; handing back
    the node leaves every reader to re-prove that ``.value`` is a ``str``.

    Covers the four shapes settings take in this tree: a bare literal, the
    first positional or ``default=`` of a ``Field(...)``, and the fallback
    argument of an environment lookup.
    """
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return [(value.value, value.lineno)]
    if not isinstance(value, ast.Call):
        return []

    path = _call_path(value.func)
    candidates: list[ast.expr] = []

    if path and path[-1] == "Field":
        candidates.extend(value.args[:1])
        candidates.extend(kw.value for kw in value.keywords if kw.arg == "default")
    elif path in ENV_LOOKUPS and len(value.args) >= 2:
        candidates.append(value.args[1])

    return [(node.value, node.lineno) for node in candidates if isinstance(node, ast.Constant) and isinstance(node.value, str)]


def _target_name(node: ast.stmt) -> str | None:
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return node.target.id
    if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
        return node.targets[0].id
    return None


def url_defaults(rel: str, tree: ast.Module) -> list[UrlDefault]:
    """Every URL-valued default declared at module scope or in a settings class."""
    statements: list[ast.stmt] = []
    for node in tree.body:
        statements.append(node)
        if isinstance(node, ast.ClassDef):
            statements.extend(node.body)

    found: list[UrlDefault] = []
    for stmt in statements:
        name = _target_name(stmt)
        value = getattr(stmt, "value", None)
        if name is None or value is None:
            continue
        for raw, lineno in _string_defaults(value):
            parsed = _parse_url(raw)
            if parsed is None:
                continue
            found.append(UrlDefault(module=rel, setting=name, lineno=lineno, url=raw, host=parsed))
    return found


def _parse_url(raw: str) -> str | None:
    """The hostname of ``raw`` if it is a network URL, else None."""
    if "://" not in raw:
        return None
    try:
        parsed = urlparse(raw.strip())
    except ValueError:
        return None
    if parsed.scheme.lower() not in NETWORK_SCHEMES:
        return None
    try:
        host = parsed.hostname
    except ValueError:
        return None
    return host.lower() if host else None


def scan(root: Path, paths: list[str]) -> tuple[list[UrlDefault], list[str]]:
    """Every URL default across every settings module. Returns (defaults, modules)."""
    defaults: list[UrlDefault] = []
    modules: list[str] = []
    for rel in sorted(paths):
        if not rel.endswith(".py") or not rel.startswith("services/"):
            continue
        try:
            tree = ast.parse((root / rel).read_text(encoding="utf-8", errors="replace"), filename=rel)
        except (OSError, SyntaxError, ValueError):
            continue
        if not is_settings_module(rel, tree):
            continue
        modules.append(rel)
        defaults.extend(url_defaults(rel, tree))
    return defaults, modules


# --------------------------------------------------------------------------
# Enforcement: the direction that makes an exemption revocable.
# --------------------------------------------------------------------------


def _defines(tree: ast.Module, symbol: str) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == symbol:
            return True
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and _target_name(node) == symbol:
            return True
    return False


def _calls(tree: ast.Module, symbol: str) -> bool:
    return any(isinstance(n, ast.Call) and _call_path(n.func)[-1:] == (symbol,) for n in ast.walk(tree))


def enforcement_problems(root: Path, paths: list[str], exemption: Exemption) -> list[str]:
    """Whether the guard an exemption names is defined and actually called."""
    problems: list[str] = []
    service = Path(exemption.module).parts[1]
    label = f"{exemption.module}::{exemption.setting}"

    for guard_module, symbol in exemption.enforced_by:
        path = root / guard_module
        if not path.exists():
            problems.append(f"EXEMPTION UNENFORCED  {label}: names {guard_module}::{symbol}, and that file is gone")
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=guard_module)
        except (OSError, SyntaxError, ValueError) as exc:
            problems.append(f"EXEMPTION UNENFORCED  {label}: cannot parse {guard_module} ({exc})")
            continue
        if not _defines(tree, symbol):
            problems.append(f"EXEMPTION UNENFORCED  {label}: {guard_module} no longer defines {symbol}")
            continue

        callers = [
            rel
            for rel in paths
            if rel.startswith(f"services/{service}/app/")
            and rel.endswith(".py")
            and _calls_in(root, rel, symbol, skip_definition_of=symbol if rel == guard_module else None)
        ]
        if not callers:
            problems.append(
                f"EXEMPTION UNENFORCED  {label}: {guard_module}::{symbol} is defined but called from nowhere in "
                f"services/{service}/app/ — a guard nothing invokes did not make this default safe"
            )
    return problems


def _calls_in(root: Path, rel: str, symbol: str, skip_definition_of: str | None = None) -> bool:
    """Whether ``rel`` calls ``symbol`` outside that symbol's own definition."""
    try:
        tree = ast.parse((root / rel).read_text(encoding="utf-8", errors="replace"), filename=rel)
    except (OSError, SyntaxError, ValueError):
        return False
    if skip_definition_of:
        tree.body = [n for n in tree.body if not (isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == skip_definition_of)]
    return _calls(tree, symbol)


# --------------------------------------------------------------------------
# The comparison, in all three directions.
# --------------------------------------------------------------------------


def compare(
    defaults: list[UrlDefault],
    allowed: tuple[Exemption, ...],
    is_private,
    *,
    root: Path | None = None,
    paths: list[str] | None = None,
) -> list[str]:
    """Returns a list of failure lines; empty means clean.

    ``root``/``paths`` are optional so the self-test can exercise the two
    list-comparison directions without a tree. When they are supplied the third
    direction — does the named guard still exist and run — is checked too.
    """
    problems: list[str] = []
    index = {(e.module, e.setting): e for e in allowed}

    # Direction 1: tree -> allow-list. A public default nobody signed off on.
    matched: set[tuple[str, str]] = set()
    for default in sorted(defaults, key=lambda d: (d.module, d.lineno)):
        if is_private(default.host):
            continue
        entry = index.get((default.module, default.setting))
        if entry is None:
            problems.append(
                f"EGRESS DEFAULT    {default.module}:{default.lineno} {default.setting} = {default.url!r} "
                f"-> public host {default.host!r}, no allow-list entry"
            )
            continue
        if entry.host != default.host:
            problems.append(
                f"HOST CHANGED      {default.module}:{default.lineno} {default.setting} now names {default.host!r}, "
                f"allow-list records {entry.host!r} — re-read the default before moving the entry"
            )
            continue
        matched.add((default.module, default.setting))

    # Direction 2: allow-list -> tree. An exemption outliving what it excused.
    for entry in allowed:
        if (entry.module, entry.setting) in matched:
            continue
        problems.append(
            f"STALE EXEMPTION   {entry.module}::{entry.setting} is allow-listed for {entry.host!r}, and no such "
            "public default is there any more — drop the entry"
        )

    # Direction 3: exemption -> enforcement. Deleting the guard revokes the pass.
    if root is not None and paths is not None:
        for entry in allowed:
            if (entry.module, entry.setting) in matched:
                problems.extend(enforcement_problems(root, paths, entry))

    return problems


# --------------------------------------------------------------------------
# Self-test.
# --------------------------------------------------------------------------


def _fake_private(host: str) -> bool:
    """A stand-in classifier for the list-direction checks, which are about the
    allow-list bookkeeping rather than about host classification."""
    return host.endswith(".internal") or host == "localhost"


def self_test() -> int:
    checks: list[tuple[str, bool]] = []

    root = repo_root()

    # The lifted predicate must be the shipped one, and must separate the two
    # classes of host this gate turns on.
    try:
        is_private = load_shipped_predicate(root, PREDICATE_MODULE)
        lifted_ok = True
        detail = ""
    except GateError as exc:
        is_private = _fake_private
        lifted_ok = False
        detail = f" ({exc})"
    checks.append((f"lifts {PREDICATE_FUNCTION}() out of {PREDICATE_MODULE}{detail}", lifted_ok))

    if lifted_ok:
        private_hosts = ("127.0.0.1", "10.0.0.5", "localhost", "ollama.local", "connectors", "::1")
        public_hosts = ("raw.githubusercontent.com", "otx.alienvault.com", "www.cisa.gov", "api.openai.com", "8.8.8.8")
        checks.append(("shipped predicate calls every known-private host private", all(is_private(h) for h in private_hosts)))
        checks.append(("shipped predicate calls every known-public host public", not any(is_private(h) for h in public_hosts)))
        checks.append((f"{PREDICATE_MODULE} and {PREDICATE_MIRROR} agree on every probe host", not predicate_parity(root)))

    # The URL extractor must see each of the four default shapes, and must not
    # invent findings from strings that are not network URLs.
    sample = (
        "import os\n"
        "from pydantic import Field\n"
        "from pydantic_settings import BaseSettings\n"
        "class S(BaseSettings):\n"
        "    plain: str = 'https://plain.example.com'\n"
        "    positional: str = Field('https://positional.example.com')\n"
        "    keyword: str = Field(default='https://keyword.example.com')\n"
        "    private: str = 'http://localhost:8000'\n"
        "    not_a_url: str = 'plain text, no scheme'\n"
        "    local_file: str = 'file:///etc/aisoc.yaml'\n"
        "ENV = os.getenv('X', 'https://env.example.com')\n"
    )
    tree = ast.parse(sample)
    rel = "services/sample/app/core/config.py"
    checks.append(("a BaseSettings module is in scope whatever it is called", is_settings_module(rel, tree)))
    checks.append(("a module outside services/<svc>/app/ is not", not is_settings_module("scripts/thing/config.py", ast.parse(sample))))

    found = {d.setting: d.host for d in url_defaults(rel, tree)}
    for shape, setting, host in (
        ("a bare literal default", "plain", "plain.example.com"),
        ("Field(...) positional", "positional", "positional.example.com"),
        ("Field(default=...)", "keyword", "keyword.example.com"),
        ("os.getenv fallback", "ENV", "env.example.com"),
        ("a private default", "private", "localhost"),
    ):
        checks.append((f"extractor reads {shape}", found.get(setting) == host))
    checks.append(("extractor ignores a string that is not a URL", "not_a_url" not in found))
    checks.append(("extractor ignores a non-network scheme", "local_file" not in found))

    # Direction 1.
    leak = UrlDefault(rel, "leak", 1, "https://evil.example.com", "evil.example.com")
    checks.append(("a public default with no entry is a finding", bool(compare([leak], (), _fake_private))))

    # Direction 2 — the one a one-directional gate misses.
    ghost = Exemption(rel, "gone", "gone.example.com", "r", ())
    checks.append(("an allow-list entry with no matching default is a finding", bool(compare([], (ghost,), _fake_private))))

    # A moved host must not inherit the old entry's sign-off.
    entry = Exemption(rel, "leak", "known.example.com", "r", ())
    checks.append(("an entry whose default changed host is a finding", bool(compare([leak], (entry,), _fake_private))))

    # The happy path has to stay reachable, or every check above is satisfied
    # by a comparison that always fails.
    ok_entry = Exemption(rel, "leak", "evil.example.com", "r", ())
    checks.append(("an exactly-matching entry passes", not compare([leak], (ok_entry,), _fake_private)))
    checks.append(
        ("a private default needs no entry", not compare([UrlDefault(rel, "p", 1, "http://localhost", "localhost")], (), _fake_private))
    )

    # Direction 3, proven against the real tree: an entry naming a guard that
    # is not there must stop exempting, which is what makes deleting the guard
    # unable to keep the pass.
    paths = tracked_files(root)
    real = ALLOWED[0]
    missing_guard = Exemption(real.module, real.setting, real.host, real.reason, (("services/threatintel/app/airgap.py", "no_such_guard"),))
    orphan_guard = Exemption(real.module, real.setting, real.host, real.reason, (("services/threatintel/app/airgap.py", "airgap_status"),))
    real_defaults, _ = scan(root, paths)
    checks.append(
        (
            "an exemption naming a guard that is not defined stops applying",
            bool(compare(real_defaults, (missing_guard,), is_private, root=root, paths=paths)),
        )
    )
    checks.append(
        (
            "an exemption naming a guard nothing calls stops applying",
            bool(compare(real_defaults, (orphan_guard,), is_private, root=root, paths=paths)),
        )
    )

    return self_test_main(Path(__file__).name, extra=checks)


# --------------------------------------------------------------------------
# Entry point.
# --------------------------------------------------------------------------


def tracked_files(root: Path) -> list[str]:
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", "-C", str(root), "ls-files", "-z"],
        capture_output=True,
        text=True,
        check=False,
    )
    return [p for p in out.stdout.split("\0") if p]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--self-test", action="store_true", help="prove the gate still detects what it claims, then exit")
    parser.add_argument("--list", action="store_true", help="print every URL default found, with its classification")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    root = repo_root()
    missing = [s for s in SENTINELS if not (root / s).exists()]
    if missing:
        print(f"FAIL: {root} does not look like the AiSOC repository (missing: {', '.join(missing)})")
        return 2

    paths = tracked_files(root)
    if not paths:
        print(f"FAIL: git listed no tracked files under {root}; the scan is broken, not the tree clean")
        return 2

    try:
        is_private = load_shipped_predicate(root, PREDICATE_MODULE)
    except GateError as exc:
        print(f"FAIL: {exc}")
        return 2

    defaults, modules = scan(root, paths)
    print(f"scanning {len(paths)} tracked files under {root}")
    print(f"settings modules  {len(modules)} across {len({Path(m).parts[1] for m in modules})} service(s)")
    print(f"url defaults      {len(defaults)}")

    if len(modules) < MIN_SETTINGS_MODULES:
        print(f"FAIL: found {len(modules)} settings module(s), expected >= {MIN_SETTINGS_MODULES}; the walk is broken, not the tree clean")
        return 2
    if len(defaults) < MIN_URL_DEFAULTS:
        print(f"FAIL: found {len(defaults)} URL default(s), expected >= {MIN_URL_DEFAULTS}; the extractor is broken, not the tree clean")
        return 2

    private = [d for d in defaults if is_private(d.host)]
    if not private:
        print("FAIL: not one default classified as private. Every service points somewhere internal by default, so a")
        print("      result with none means the classifier is stuck, not that the tree changed.")
        return 2
    print(f"classification    {len(private)} private, {len(defaults) - len(private)} public")

    if args.list:
        print()
        for default in sorted(defaults, key=lambda d: (d.module, d.lineno)):
            verdict = "private" if is_private(default.host) else "PUBLIC "
            print(f"  {verdict}  {default.module}:{default.lineno}  {default.setting} -> {default.host}")
        print()

    problems = predicate_parity(root) + compare(defaults, ALLOWED, is_private, root=root, paths=paths)

    if problems:
        print(f"\nFAIL: {len(problems)} problem(s).\n")
        for line in problems:
            print(f"  {line}")
        print(
            "\nA service must not reach the public internet on a default nobody chose. Either give the\n"
            "setting an internal default, delete it if nothing reads it, or add an Exemption naming the\n"
            "module that enforces air-gap policy on it. Never allow-list a default you could remove."
        )
        return 1

    print(f"OK — {len(defaults)} URL default(s) across {len(modules)} settings module(s); every public host is")
    print(f"     one of {len(ALLOWED)} allow-listed default(s), each with a reason and a guard that is called")
    return 0


if __name__ == "__main__":
    sys.exit(main())
