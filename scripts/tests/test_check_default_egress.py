"""The default-egress gate detects what it claims, in all three directions.

The cases below are the ones that decide whether this gate is worth its run
time. Direction 1 is the obvious one and the easiest to get right. Directions 2
and 3 are what stop the allow-list becoming a place to retire findings: an
entry that outlives its default, and an entry whose named guard has been
deleted or left calling nothing.

The extractor cases pin the four shapes a default takes in this tree, because a
gate that reads only bare literals would have missed
``services/fusion``'s ``Field(default=...)`` settings entirely and reported a
clean scan over them.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GATE = REPO_ROOT / "scripts" / "check_default_egress.py"

MODULE = "services/sample/app/core/config.py"


def _load():
    spec = importlib.util.spec_from_file_location("check_default_egress", GATE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gate = _load()


def _private(host: str) -> bool:
    """A stand-in classifier, so the comparison cases are about bookkeeping."""
    return host in {"localhost", "redis"} or host.endswith((".internal", ".local"))


def _default(setting: str, url: str, host: str, module: str = MODULE):
    return gate.UrlDefault(module=module, setting=setting, lineno=1, url=url, host=host)


# --------------------------------------------------------------------------
# Scope.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("rel", "source", "expected"),
    [
        (MODULE, "from pydantic_settings import BaseSettings\nclass S(BaseSettings):\n    x: int = 1\n", True),
        # Filename alone is enough: a config module that stops using pydantic
        # keeps its coverage rather than silently falling out of scope.
        ("services/sample/app/config.py", "URL = 'http://x'\n", True),
        ("services/sample/app/settings.py", "URL = 'http://x'\n", True),
        # A BaseSettings subclass is in scope wherever it lives, because
        # services do not agree on where to put it.
        ("services/sample/app/core/tuning.py", "from pydantic_settings import BaseSettings\nclass S(BaseSettings):\n    pass\n", True),
        # Out of scope: not a service, not under app/, and an ordinary module.
        ("scripts/config.py", "URL = 'http://x'\n", False),
        ("services/sample/tests/config.py", "URL = 'http://x'\n", False),
        ("services/sample/app/clients/crowdstrike.py", "BASE = 'https://api.crowdstrike.com'\n", False),
    ],
)
def test_scope_is_structural_then_by_name(rel: str, source: str, expected: bool) -> None:
    assert gate.is_settings_module(rel, ast.parse(source)) is expected


# --------------------------------------------------------------------------
# Extraction.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("declaration", "setting", "host"),
    [
        ("    plain: str = 'https://a.example.com'", "plain", "a.example.com"),
        ("    positional: str = Field('https://b.example.com')", "positional", "b.example.com"),
        ("    keyword: str = Field(default='https://c.example.com')", "keyword", "c.example.com"),
        ("    aliased: str = Field(default='https://d.example.com', alias='D')", "aliased", "d.example.com"),
        ("    private: str = 'http://localhost:8000'", "private", "localhost"),
        ("    container: str = 'http://redis:6379/0'", "container", "redis"),
        ("    scheme: str = 'redis://cache.internal:6379/2'", "scheme", "cache.internal"),
        ("    ported: str = 'https://e.example.com:8443/path?q=1'", "ported", "e.example.com"),
        ("    upper: str = 'https://F.EXAMPLE.COM/x'", "upper", "f.example.com"),
    ],
)
def test_extractor_reads_every_default_shape(declaration: str, setting: str, host: str) -> None:
    source = f"from pydantic import Field\nfrom pydantic_settings import BaseSettings\nclass S(BaseSettings):\n{declaration}\n"
    found = {d.setting: d.host for d in gate.url_defaults(MODULE, ast.parse(source))}
    assert found.get(setting) == host


@pytest.mark.parametrize(
    "declaration",
    [
        "    prose: str = 'not a url at all'",
        "    path: str = '/var/lib/aisoc'",
        "    local: str = 'file:///etc/aisoc.yaml'",
        "    empty: str = ''",
        "    template: str = '{scheme}://{host}'",
    ],
)
def test_extractor_invents_nothing_from_a_non_url(declaration: str) -> None:
    source = f"from pydantic_settings import BaseSettings\nclass S(BaseSettings):\n{declaration}\n"
    assert gate.url_defaults(MODULE, ast.parse(source)) == []


def test_extractor_reads_environment_fallbacks() -> None:
    """``os.getenv('X', 'https://…')`` declares a default as surely as a class attribute."""
    source = (
        "import os\n"
        "from os import environ, getenv\n"
        "A = os.getenv('A', 'https://a.example.com')\n"
        "B = os.environ.get('B', 'https://b.example.com')\n"
        "C = environ.get('C', 'https://c.example.com')\n"
        "D = getenv('D', 'https://d.example.com')\n"
        "E = os.getenv('E')\n"
    )
    found = {d.setting: d.host for d in gate.url_defaults("services/sample/app/config.py", ast.parse(source))}
    assert found == {
        "A": "a.example.com",
        "B": "b.example.com",
        "C": "c.example.com",
        "D": "d.example.com",
    }


# --------------------------------------------------------------------------
# Direction 1: a public default nobody signed off on.
# --------------------------------------------------------------------------


def test_a_public_default_with_no_entry_is_a_finding() -> None:
    # The finding is matched against the input rather than against a repeated
    # host literal: an assertion that restates the expected string can drift
    # from the value under test, and a bare `"host.example" in text` reads as
    # URL sanitization to a static analyser looking for exactly that mistake.
    leak = _default("leak", "https://cdn.example.com/x", "cdn.example.com")
    problems = gate.compare([leak], (), _private)
    assert len(problems) == 1
    assert "EGRESS DEFAULT" in problems[0]
    assert leak.host in problems[0]
    assert leak.setting in problems[0]


@pytest.mark.parametrize("host", ["localhost", "redis", "cache.internal", "box.local"])
def test_a_private_default_needs_no_entry(host: str) -> None:
    assert gate.compare([_default("p", f"http://{host}:1", host)], (), _private) == []


def test_the_shipped_defect_is_what_this_gate_was_built_for() -> None:
    """The purple-team setting that motivated the gate, replayed."""
    dead = _default(
        "attack_stix_url",
        "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
        "raw.githubusercontent.com",
        module="services/purple-team/app/core/config.py",
    )
    problems = gate.compare([dead], gate.ALLOWED, _private)
    assert any("attack_stix_url" in p and "EGRESS DEFAULT" in p for p in problems)


# --------------------------------------------------------------------------
# Direction 2: an exemption that outlived its default.
# --------------------------------------------------------------------------


def test_an_entry_with_no_matching_default_is_a_finding() -> None:
    stale = gate.Exemption(MODULE, "gone", "gone.example.com", "reason", ())
    problems = gate.compare([], (stale,), _private)
    assert len(problems) == 1
    assert "STALE EXEMPTION" in problems[0]


def test_an_entry_does_not_cover_a_default_that_changed_host() -> None:
    """A signed-off host is not a signed-off setting.

    Repointing a setting at a different public host must not inherit the old
    entry's approval — that is how an allow-list launders a real leak.
    """
    entry = gate.Exemption(MODULE, "feed", "known.example.com", "reason", ())
    moved = _default("feed", "https://elsewhere.example.com/x", "elsewhere.example.com")
    problems = gate.compare([moved], (entry,), _private)
    assert any("HOST CHANGED" in p for p in problems)


def test_an_exactly_matching_entry_passes() -> None:
    """The happy path must stay reachable, or every case above is satisfied by
    a comparison that always fails."""
    entry = gate.Exemption(MODULE, "feed", "known.example.com", "reason", ())
    assert gate.compare([_default("feed", "https://known.example.com/x", "known.example.com")], (entry,), _private) == []


# --------------------------------------------------------------------------
# Direction 3: the exemption must be revocable by deleting the guard.
# --------------------------------------------------------------------------


def _tree(tmp_path: Path, files: dict[str, str]) -> tuple[Path, list[str]]:
    root = tmp_path / "tree"
    for rel, body in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return root, sorted(files)


GUARD_MODULE = "services/sample/app/guard.py"
CALLER_MODULE = "services/sample/app/main.py"


def test_a_guard_that_is_defined_and_called_sustains_the_exemption(tmp_path: Path) -> None:
    root, paths = _tree(
        tmp_path,
        {
            GUARD_MODULE: "def block(host):\n    return False\n",
            CALLER_MODULE: "from app.guard import block\n\nif block('x'):\n    pass\n",
        },
    )
    entry = gate.Exemption(MODULE, "feed", "known.example.com", "r", ((GUARD_MODULE, "block"),))
    assert gate.enforcement_problems(root, paths, entry) == []


def test_deleting_the_guard_revokes_the_exemption(tmp_path: Path) -> None:
    """The bidirectional property. Without it, removing the enforcement leaves
    the exemption in place and the gate keeps printing OK over a real leak."""
    root, paths = _tree(tmp_path, {GUARD_MODULE: "def something_else():\n    return 1\n"})
    entry = gate.Exemption(MODULE, "feed", "known.example.com", "r", ((GUARD_MODULE, "block"),))
    problems = gate.enforcement_problems(root, paths, entry)
    assert len(problems) == 1
    assert "no longer defines block" in problems[0]


def test_an_orphaned_guard_revokes_the_exemption(tmp_path: Path) -> None:
    """A passing test on an uncalled function is indistinguishable from a
    working feature — the shape this repository found a dozen times in one
    audit. A guard nothing invokes did not make the default safe."""
    root, paths = _tree(
        tmp_path,
        {
            GUARD_MODULE: "def block(host):\n    return False\n",
            CALLER_MODULE: "from app.guard import block  # imported and never called\n",
        },
    )
    entry = gate.Exemption(MODULE, "feed", "known.example.com", "r", ((GUARD_MODULE, "block"),))
    problems = gate.enforcement_problems(root, paths, entry)
    assert len(problems) == 1
    assert "called from nowhere" in problems[0]


def test_a_guard_calling_only_itself_does_not_count(tmp_path: Path) -> None:
    """Recursion is not enforcement."""
    root, paths = _tree(tmp_path, {GUARD_MODULE: "def block(host):\n    return block(host)\n"})
    entry = gate.Exemption(MODULE, "feed", "known.example.com", "r", ((GUARD_MODULE, "block"),))
    assert "called from nowhere" in gate.enforcement_problems(root, paths, entry)[0]


def test_a_guard_in_a_file_that_is_gone_revokes_the_exemption(tmp_path: Path) -> None:
    root, paths = _tree(tmp_path, {CALLER_MODULE: "pass\n"})
    entry = gate.Exemption(MODULE, "feed", "known.example.com", "r", (("services/sample/app/vanished.py", "block"),))
    assert "that file is gone" in gate.enforcement_problems(root, paths, entry)[0]


# --------------------------------------------------------------------------
# The lifted predicate: the gate must run the code the services run.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "host", ["127.0.0.1", "10.0.0.5", "192.168.1.10", "172.16.0.1", "::1", "localhost", "ollama.local", "vllm.internal", "redis"]
)
def test_the_shipped_predicate_calls_internal_hosts_private(host: str) -> None:
    assert gate.load_shipped_predicate(REPO_ROOT, gate.PREDICATE_MODULE)(host)


@pytest.mark.parametrize("host", ["raw.githubusercontent.com", "otx.alienvault.com", "www.cisa.gov", "api.openai.com", "8.8.8.8"])
def test_the_shipped_predicate_calls_public_hosts_public(host: str) -> None:
    assert not gate.load_shipped_predicate(REPO_ROOT, gate.PREDICATE_MODULE)(host)


def test_both_shipped_copies_of_the_predicate_agree() -> None:
    """Two copies of a security predicate are a fork waiting to happen. If they
    diverge, this gate's verdict is right for one service and wrong for the
    other, so the divergence is the finding."""
    assert gate.predicate_parity(REPO_ROOT) == []


def test_the_lift_refuses_a_predicate_that_grew_a_dependency(tmp_path: Path) -> None:
    """Lifting a function that now reads the service's settings object would
    run different code than the service does. The gate must say so rather than
    quietly bind a stub."""
    rel = "airgap.py"
    (tmp_path / rel).write_text(
        "_PRIVATE_SUFFIXES = ('.local',)\n"
        "def _is_private_address(host):\n"
        "    return host.endswith(_PRIVATE_SUFFIXES) or host in settings.EXTRA\n",
        encoding="utf-8",
    )
    with pytest.raises(gate.GateError, match="settings"):
        gate.load_shipped_predicate(tmp_path, rel)


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("def _other(host):\n    return True\n", "no longer defines _is_private_address"),
        ("def _is_private_address(host):\n    return True\n", "no longer defines _PRIVATE_SUFFIXES"),
    ],
)
def test_the_lift_fails_loudly_when_the_shipped_names_move(tmp_path: Path, body: str, expected: str) -> None:
    """A rename in the service must break this gate rather than fork it."""
    (tmp_path / "airgap.py").write_text(body, encoding="utf-8")
    with pytest.raises(gate.GateError, match=expected):
        gate.load_shipped_predicate(tmp_path, "airgap.py")


# --------------------------------------------------------------------------
# Non-vacuity, over the real tree.
# --------------------------------------------------------------------------


def test_the_real_scan_reaches_a_plausible_corpus() -> None:
    """Found-nothing and scanned-nothing print the same word unless something
    counts what was opened."""
    paths = gate.tracked_files(REPO_ROOT)
    defaults, modules = gate.scan(REPO_ROOT, paths)
    assert len(modules) >= gate.MIN_SETTINGS_MODULES
    assert len(defaults) >= gate.MIN_URL_DEFAULTS
    is_private = gate.load_shipped_predicate(REPO_ROOT, gate.PREDICATE_MODULE)
    assert any(is_private(d.host) for d in defaults), "no default classified private — the classifier is stuck"


def test_every_allow_list_entry_names_at_least_one_guard() -> None:
    """An exemption with no enforcement is a permanent pass with a comment on it."""
    for entry in gate.ALLOWED:
        assert entry.enforced_by, f"{entry.module}::{entry.setting} is exempt with no guard named"
        assert entry.reason.strip(), f"{entry.module}::{entry.setting} is exempt with no reason given"


def test_the_real_tree_is_clean_and_every_exemption_is_still_enforced() -> None:
    paths = gate.tracked_files(REPO_ROOT)
    defaults, _ = gate.scan(REPO_ROOT, paths)
    is_private = gate.load_shipped_predicate(REPO_ROOT, gate.PREDICATE_MODULE)
    assert gate.compare(defaults, gate.ALLOWED, is_private, root=REPO_ROOT, paths=paths) == []
