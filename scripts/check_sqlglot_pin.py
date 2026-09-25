#!/usr/bin/env python3
"""Assert every install path declares the same sqlglot version range.

sqlglot is not an ordinary dependency. It is the component that enforces
tenant isolation on the ClickHouse lake: `services/api/app/services/lake_sql.py`
parses untrusted operator SQL with it, checks the table allowlist against the
parse tree, bans ClickHouse table functions, and injects the mandatory
`tenant_id` predicate into every relation. If two builds of the same commit
resolve different sqlglot versions, they have different isolation guarantees.

That is not hypothetical. `services/api/pyproject.toml` declared `<31.0.0`
while the Dockerfile and every CI workflow declared `<27`. sqlglot moved the
SELECT's FROM clause from `args["from"]` to `args["from_"]` in 27, so on the
versions only pyproject allowed, the rewriter's table walk found nothing,
concluded the query was a constant projection, and returned it untouched —
no allowlist check, no table-function ban, and no tenant predicate — while
reporting success. The unit tests would have caught it; they never ran on a
version pyproject permitted, because CI installed the narrow range.

So the property this gate enforces is *agreement*, not any particular bound.
Widening the supported range is fine; widening it in one place is not.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

REPO_ROOT = repo_root()
# Every file that installs sqlglot for a build or a test run. A new one must
# be added here; `test_every_declaration_is_registered` below is the backstop
# that notices when a declaration exists in a file this list does not name.
DECLARING_FILES = (
    "services/api/pyproject.toml",
    ".github/workflows/ci.yml",
    ".github/workflows/integration.yml",
    ".github/workflows/isolation-live.yml",
    ".github/workflows/cross-tenant-rbac.yml",
    ".github/workflows/check-openapi.yml",
    ".github/workflows/reproducible-builds.yml",
)

# `lake-isolation.yml` installs sqlglot from a build matrix, deliberately
# including a version outside the shipped range so a future bump cannot
# silently turn isolation off. It therefore cannot declare a single pin. What
# it *must* do is test the version we ship, so the matrix leg labelled
# `shipped` is checked against the agreed pin below.
MATRIX_WORKFLOW = ".github/workflows/lake-isolation.yml"
_SHIPPED_MATRIX_LEG = re.compile(r"""-\s*sqlglot:\s*["'](?P<spec>[^"']+)["']\s*\n\s*label:\s*shipped""")

# `services/api/Dockerfile` used to be on the list above, because its pip
# fallback carried its own copy of the dependency list. That fallback is gone:
# the image installs from `poetry.lock`, which no longer states a *range* but
# the single version that actually ships. So the lock is checked differently —
# its resolved version must fall inside the agreed range. Comparing the ranges
# to each other and never to the lock would leave this gate agreeing about a
# bound that nothing installs.
RESOLVED_FILE = "services/api/poetry.lock"
_LOCKED_VERSION = re.compile(r"""^name = "sqlglot"\nversion = "(?P<version>[^"]+)\"""", re.MULTILINE)


def _release(version: str) -> tuple[int, ...]:
    digits = re.match(r"(\d+(?:\.\d+)*)", version)
    return tuple(int(p) for p in digits.group(1).split(".")) if digits else (0,)


def satisfies(version: str, spec: str) -> bool:
    """Whether a concrete version falls inside a comma-joined specifier."""
    actual = _release(version)
    for clause in spec.replace(" ", "").split(","):
        match = re.fullmatch(r"(?P<op>[<>=!]+)(?P<ver>[0-9][0-9.]*)", clause)
        if not match:
            return False
        bound = _release(match.group("ver"))
        width = max(len(actual), len(bound))
        left = actual + (0,) * (width - len(actual))
        right = bound + (0,) * (width - len(bound))
        allowed = {
            ">=": left >= right,
            ">": left > right,
            "<=": left <= right,
            "<": left < right,
            "==": left == right,
            "!=": left != right,
        }.get(match.group("op"))
        if not allowed:
            return False
    return True


# Where we deliberately do not look: prose, and the archived prototype subtree.
SKIP_PREFIXES = ("plans/", "apps/docs/", "docs/", "scripts/check_sqlglot_pin.py")

# Three declaration shapes, matched precisely so that prose *about* sqlglot
# (this file is full of it, and so are the workflow comments) is not mistaken
# for a dependency declaration. The distinguishing feature of a real
# declaration is that the version operator is either assigned with `=` or
# attached to the package name with no space, exactly as pip and poetry
# require. A sentence writes "sqlglot >= 27" with spaces; a requirement
# never does.
_DECLARATIONS = (
    # poetry:  sqlglot = ">=23,<27"
    re.compile(r"""^\s*sqlglot\s*=\s*["'](?P<spec>[^"']*)["']""", re.MULTILINE),
    # pip requirement, quoted or bare:  "sqlglot>=23,<27"  /  sqlglot>=23,<27
    re.compile(r"""["']?sqlglot(?P<spec>[<>=!~][^"'\s]*)["']?"""),
    # pip requirement with no bound at all, alone on its line in an args list
    re.compile(r"""^\s*["']?sqlglot["']?\s*\\?\s*$""", re.MULTILINE),
)


def normalise(spec: str) -> str:
    """Reduce a specifier to a comparable form.

    `>=23.0.0,<27.0.0` and `>=23,<27` are the same constraint written two
    ways, and failing a build over trailing zeros would train people to
    silence this gate rather than read it.
    """
    parts = []
    for clause in spec.replace(" ", "").split(","):
        if not clause:
            continue
        match = re.match(r"^(?P<op>[<>=!~]+)(?P<ver>[\d.*]+)$", clause)
        if not match:
            parts.append(clause)
            continue
        version = match.group("ver").rstrip(".")
        while version.endswith(".0"):
            version = version[: -len(".0")]
        parts.append(f"{match.group('op')}{version}")
    return ",".join(sorted(parts))


def declarations_in(text: str) -> list[str]:
    """Every sqlglot dependency declaration in one file, as written.

    An unbounded declaration yields the empty string so it surfaces as a
    disagreement rather than vanishing from the comparison.
    """
    found: list[str] = []
    for pattern in _DECLARATIONS:
        for match in pattern.finditer(text):
            spec = (match.groupdict().get("spec") or "").strip().strip(",").strip()
            found.append(spec if any(c.isdigit() for c in spec) else "")
    return found


def scan_for_unregistered() -> list[str]:
    """Find sqlglot installs in files `DECLARING_FILES` does not name."""
    registered = {REPO_ROOT / p for p in (*DECLARING_FILES, MATRIX_WORKFLOW)}
    stray: list[str] = []
    roots = [REPO_ROOT / ".github" / "workflows", REPO_ROOT / "services"]
    for root in roots:
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or path in registered:
                continue
            if path.suffix not in {".yml", ".yaml", ".toml", ".txt", ""}:
                continue
            if path.name not in {"Dockerfile"} and path.suffix == "":
                continue
            rel = path.relative_to(REPO_ROOT).as_posix()
            if rel.startswith(SKIP_PREFIXES):
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            if declarations_in(text):
                stray.append(rel)
    return stray


def main() -> int:
    seen: dict[str, list[str]] = {}
    missing: list[str] = []

    for rel in DECLARING_FILES:
        path = REPO_ROOT / rel
        if not path.exists():
            missing.append(rel)
            continue
        specs = declarations_in(path.read_text(encoding="utf-8"))
        if not specs:
            missing.append(rel)
            continue
        for spec in specs:
            seen.setdefault(normalise(spec), []).append(f"{rel} ({spec or 'no version bound'})")

    problems: list[str] = []
    if missing:
        problems.append("files registered as declaring sqlglot but not doing so: " + ", ".join(missing))
    if len(seen) > 1:
        detail = "; ".join(f"[{norm or 'unbounded'}] {', '.join(files)}" for norm, files in sorted(seen.items()))
        problems.append(f"sqlglot is pinned {len(seen)} different ways: {detail}")

    agreed_so_far = next(iter(seen)) if len(seen) == 1 else None
    lock_path = REPO_ROOT / RESOLVED_FILE
    locked_version: str | None = None
    if not lock_path.exists():
        problems.append(f"{RESOLVED_FILE} is missing — the api image would resolve sqlglot afresh on every build")
    else:
        match = _LOCKED_VERSION.search(lock_path.read_text(encoding="utf-8"))
        if match is None:
            problems.append(f"{RESOLVED_FILE} does not lock sqlglot, so the api image installs an unpinned parser")
        else:
            locked_version = match.group("version")
            if agreed_so_far is not None and not satisfies(locked_version, agreed_so_far):
                problems.append(f"{RESOLVED_FILE} resolved sqlglot {locked_version}, outside the declared {agreed_so_far}")

    stray = scan_for_unregistered()
    if stray:
        problems.append("sqlglot installed in unregistered file(s), add them to DECLARING_FILES: " + ", ".join(sorted(stray)))

    agreed = next(iter(seen)) if len(seen) == 1 else None
    matrix_path = REPO_ROOT / MATRIX_WORKFLOW
    if not matrix_path.exists():
        problems.append(f"{MATRIX_WORKFLOW} is missing — the rewriter would no longer be tested across sqlglot majors")
    elif agreed is not None:
        leg = _SHIPPED_MATRIX_LEG.search(matrix_path.read_text(encoding="utf-8"))
        if leg is None:
            problems.append(f"{MATRIX_WORKFLOW} has no matrix leg labelled `shipped`")
        elif normalise(leg.group("spec")) != agreed:
            problems.append(f"{MATRIX_WORKFLOW} tests the shipped rewriter against {leg.group('spec')}, but the declared pin is {agreed}")

    if problems:
        print("check_sqlglot_pin: FAIL")
        for problem in problems:
            print(f"  - {problem}")
        print("\n  sqlglot enforces lake tenant isolation. Every install path must agree.")
        return 1

    only = next(iter(seen))
    print(
        f"check_sqlglot_pin: OK — {len(DECLARING_FILES)} install paths all declare {only}, "
        f"and {RESOLVED_FILE} resolves {locked_version} inside it"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
