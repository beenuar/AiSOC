"""Tests for the hosted-hostname gate, `scripts/check_hosted_hostname.py`.

The gate exists so a self-hoster never meets another deployment's hostname
presented as their own product's URL. What these tests assert is mostly not
"does it spot the string" — that part is trivial — but the two properties that
made the previous generation of gates in this repo untrustworthy:

  * It must fail in **both** directions. A one-directional allow-list catches a
    new leak but silently keeps an exemption alive after the occurrence it
    covered is gone, and a stale exemption is a standing permit for a future
    leak in a file nobody will look at again.
  * It must be unable to pass **vacuously**. A gate that resolves its repo root
    from its own file location will happily describe the checkout it lives in
    rather than the one under test, and a scan that matches nothing must be
    read as a broken scan, not a clean tree.

The regression cases at the bottom pin the specific defaults that leaked, so
the fix cannot be quietly reverted by an unrelated change.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_SCRIPT = _REPO / "scripts" / "check_hosted_hostname.py"


def _load_gate():
    spec = importlib.util.spec_from_file_location("check_hosted_hostname", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = _load_gate()
HOST = gate.HOSTED_HOSTNAME


# ── the detector separates bad from good ────────────────────────────────────


@pytest.mark.parametrize(
    "sample",
    [
        f'const BASE = "https://{HOST}";',
        f"_PUBLIC_BASE = 'https://{HOST}/r'",
        f'"https://www.{HOST}",',
        f"demo@{HOST}",
    ],
)
def test_detects_known_bad(sample: str) -> None:
    assert gate.count_in_text(sample) >= 1, f"detector missed: {sample!r}"


@pytest.mark.parametrize(
    "sample",
    [
        'const BASE = "http://localhost:3000";',
        "_PUBLIC_BASE = 'http://localhost:3000/r'",
        '"https://soc.example.com",',
        "demo@example.com",
    ],
)
def test_ignores_known_good(sample: str) -> None:
    assert gate.count_in_text(sample) == 0, f"detector false-positived: {sample!r}"


# ── compare() is bidirectional ──────────────────────────────────────────────


def test_flags_occurrence_with_no_allowlist_entry() -> None:
    """Forward direction: a new leak."""
    assert gate.compare({"new/file.ts": 1}, {})


def test_flags_allowlist_entry_with_no_occurrence() -> None:
    """Reverse direction — the one a one-directional gate misses.

    The exemption outlives the occurrence that justified it and becomes a
    standing permit for a future leak in that file.
    """
    assert gate.compare({}, {"deleted/file.ts": (1, "reason")})


def test_flags_count_growth() -> None:
    assert gate.compare({"f.ts": 3}, {"f.ts": (1, "reason")})


def test_flags_count_shrink() -> None:
    """A ceiling-only check would pass this and let the entry go stale."""
    assert gate.compare({"f.ts": 1}, {"f.ts": (3, "reason")})


def test_exact_match_passes() -> None:
    """The happy path must be reachable, or every assertion above is satisfied
    by a compare() that simply always fails."""
    assert gate.compare({"f.ts": 2}, {"f.ts": (2, "reason")}) == []


# ── it cannot pass vacuously ────────────────────────────────────────────────


def test_self_test_passes() -> None:
    assert gate.self_test() == 0


def test_rejects_a_tree_that_is_not_this_repo(tmp_path: Path) -> None:
    """A gate pointed at the wrong tree must refuse, not report clean."""
    with pytest.raises(gate.GateError):
        gate.resolve_repo_root(str(tmp_path))


def test_root_is_not_derived_from_the_scripts_own_location(tmp_path: Path) -> None:
    """Running from elsewhere must not silently inspect the gate's own checkout.

    A sibling gate resolved its root from ``__file__``, so a run launched from
    another worktree printed a confident OK about a tree it never opened.
    """
    proc = subprocess.run(
        [sys.executable, str(_SCRIPT)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert proc.returncode != 0, "gate reported success while run outside any repository"
    assert str(_REPO) not in proc.stdout, "gate fell back to its own checkout instead of failing"


def test_repo_scan_is_clean() -> None:
    """The real tree passes — and reports a non-empty, plausible scan."""
    proc = subprocess.run(
        [sys.executable, str(_SCRIPT)],
        cwd=str(_REPO),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "scanning" in proc.stdout
    assert "byte-identical" in proc.stdout


# ── the vendored CORS helper stays in lockstep ──────────────────────────────


def test_cors_copies_are_byte_identical() -> None:
    digests = {rel: (_REPO / rel).read_bytes() for rel in gate.CORS_COPIES}
    assert len(set(digests.values())) == 1, "vendored cors.py copies have drifted apart"


_CORS_DEFAULT_DECL = "DEFAULT_CORS_ORIGINS: tuple[str, ...] = ("


def _cors_default_tuple(text: str) -> str:
    """The literal tuple body, not the docstring that happens to name it.

    An earlier version of this helper split on the bare identifier, which
    matches the prose reference in the module docstring first and so inspected
    a sentence instead of the allow-list. It passed against a tree that did
    ship the hosted origin — a vacuous assertion, caught only by running it
    against the pre-change tree.
    """
    assert _CORS_DEFAULT_DECL in text, "cors.py no longer declares DEFAULT_CORS_ORIGINS as expected"
    return text.split(_CORS_DEFAULT_DECL, 1)[1].split(")", 1)[0]


def test_cors_default_tuple_extraction_is_not_vacuous() -> None:
    """The helper must read the tuple, and would catch a hostname put back."""
    text = (_REPO / gate.CORS_COPIES[0]).read_text(encoding="utf-8")
    body = _cors_default_tuple(text)
    assert "http://localhost:3000" in body, "helper did not capture the allow-list tuple"
    assert HOST not in body
    # Same helper, against a sample that does carry the hostname.
    poisoned = text.replace('    "http://127.0.0.1:3001",\n)', f'    "https://{HOST}",\n)', 1)
    assert HOST in _cors_default_tuple(poisoned), "helper would not notice the hostname coming back"


def test_no_cors_copy_ships_the_hosted_origin() -> None:
    """Regression: the shipped allow-list trusted one deployment's origin for
    credentialed cross-origin requests on every self-hosted install."""
    for rel in gate.CORS_COPIES:
        body = _cors_default_tuple((_REPO / rel).read_text(encoding="utf-8"))
        assert HOST not in body, f"{rel} ships the hosted origin in its default allow-list"


# ── regressions on the specific defaults that leaked ────────────────────────


@pytest.mark.parametrize(
    ("rel", "needle"),
    [
        # Canonical/OG/sitemap origin for every self-hosted page.
        ("apps/web/src/lib/site.ts", 'return "http://localhost:3000";'),
        # Realtime SSE/WebSocket allow-list.
        ("services/realtime/src/index.ts", "'http://127.0.0.1:3001',\n];"),
        # Seeded demo identity: RFC 2606 reserved, cannot be registered.
        ("services/api/app/api/v1/dev_auth.py", 'DEMO_USER_EMAIL: str = "demo@example.com"'),
        # One resolver behind both the replay share link and the tenant invite
        # link, so the two defaults cannot drift apart again.
        ("services/api/app/core/config.py", 'DEFAULT_CONSOLE_BASE_URL: str = "http://localhost:3000"'),
    ],
)
def test_neutral_default_is_present(rel: str, needle: str) -> None:
    assert needle in (_REPO / rel).read_text(encoding="utf-8"), f"{rel} lost its deployment-neutral default"


@pytest.mark.parametrize(
    "rel",
    [
        "apps/web/src/lib/site.ts",
        "services/realtime/src/index.ts",
        "services/ingest/internal/server/server.go",
        "services/enrichment/internal/server/server.go",
        "services/api/app/api/v1/dev_auth.py",
        "services/api/app/api/v1/endpoints/replay.py",
        "services/api/app/services/tenant_provision/provisioner.py",
        "services/api/app/services/email_approval.py",
        "services/osquery-tls/app/core/config.py",
        "plugins/aisoc-direct/plugin.yaml",
        "packages/aisoc-action/src/render.ts",
        "packages/aisoc-action/dist/index.js",
        "packages/report-card/src/index.ts",
        "apps/web/public/manifest.json",
        "apps/web/playwright.config.ts",
    ],
)
def test_runtime_default_carries_no_hosted_hostname(rel: str) -> None:
    """Each of these shipped a value an unconfigured self-hoster would hit."""
    assert HOST not in (_REPO / rel).read_text(encoding="utf-8"), f"{rel} regained the hosted hostname"
