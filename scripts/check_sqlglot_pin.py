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

from gate_toolkit import SELF_TEST_FLAG, repo_root, self_test_main

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
# reaching past the shipped range so a future bump cannot silently turn
# isolation off. It therefore cannot declare a single pin, and is checked on
# its own terms instead of being exempted:
#
#   `shipped`       must equal the agreed pin, or the matrix proves a version
#                   nothing installs still works.
#   `forward-compat` must carry no upper bound, and must not float below the
#                   shipped floor.
#
# The second rule is the one with history behind it. That leg used to read
# `>=27,<31`, which only reached past the pin while the pin sat below 27.
# With the pin on the 30 line there is no sqlglot 31 to name, so the leg is
# written unbounded and resolves whatever is newest: it re-runs the shipped
# version today and arms itself the day a higher major is published, with no
# edit and nobody remembering. A ceiling would take that away silently, which
# is exactly how 27 reached production — every install path pinned below the
# version that broke isolation, so nothing ever ran on it.
#
# What is deliberately *not* asserted here is that a higher major exists.
# Upstream's release schedule is not this repository's to require, and a gate
# that failed until sqlglot shipped 31 would be red for a reason no change in
# this tree could fix. The workflow's own `Forward coverage` step reports
# which of the two states it is in on every run.
MATRIX_WORKFLOW = ".github/workflows/lake-isolation.yml"
_MATRIX_LEG = re.compile(r"""-\s*sqlglot:\s*["'](?P<spec>[^"']+)["']\s*\n\s*label:\s*(?P<label>[\w-]+)""")

# The ceiling the workflow's `Forward coverage` step compares against. It is a
# second copy of the shipped range's `<N` bound, so it is checked against the
# first rather than trusted: a stale copy would report "above the shipped
# ceiling" about a version that is inside it.
_WORKFLOW_CEILING = re.compile(r"""^\s*SHIPPED_CEILING\s*=\s*(?P<major>\d+)\s*$""", re.MULTILINE)

SHIPPED_LABEL = "shipped"
FORWARD_LABEL = "forward-compat"

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


def _bound(spec: str, operators: tuple[str, ...]) -> tuple[int, ...] | None:
    """The version named by the first clause using one of ``operators``."""
    for clause in spec.replace(" ", "").split(","):
        match = re.fullmatch(r"(?P<op>[<>=!]+)(?P<ver>[0-9][0-9.]*)", clause)
        if match and match.group("op") in operators:
            return _release(match.group("ver"))
    return None


def upper_bound(spec: str) -> tuple[int, ...] | None:
    """The ceiling a specifier declares, or None when it has none."""
    return _bound(spec, ("<", "<="))


def lower_bound(spec: str) -> tuple[int, ...] | None:
    """The floor a specifier declares, or None when it has none."""
    return _bound(spec, (">=", ">"))


def matrix_problems(text: str, agreed: str) -> list[str]:
    """Everything wrong with the version matrix in ``lake-isolation.yml``.

    Pure, taking the workflow text rather than reading it, so ``--self-test``
    can inject each violation and require this function to report it. A rule
    that only ever runs against a tree already satisfying it is a rule nobody
    has seen fail.
    """
    legs = {match.group("label"): match.group("spec") for match in _MATRIX_LEG.finditer(text)}
    problems: list[str] = []

    shipped = legs.get(SHIPPED_LABEL)
    if shipped is None:
        problems.append(f"{MATRIX_WORKFLOW} has no matrix leg labelled `{SHIPPED_LABEL}`")
    elif normalise(shipped) != agreed:
        problems.append(
            f"{MATRIX_WORKFLOW} tests the shipped rewriter against {shipped}, but the declared pin is {agreed}"
        )

    forward = legs.get(FORWARD_LABEL)
    if forward is None:
        problems.append(
            f"{MATRIX_WORKFLOW} has no matrix leg labelled `{FORWARD_LABEL}` — the rewriter would only ever "
            f"be exercised on the version already shipping, which is the state sqlglot 27 reached production in"
        )
        return problems

    ceiling = upper_bound(forward)
    if ceiling is not None:
        problems.append(
            f"{MATRIX_WORKFLOW}'s `{FORWARD_LABEL}` leg is bounded above ({forward}), so it can never resolve a "
            f"version past the pin. That is the shape of the original break: every install path pinned below the "
            f"major that turned isolation off, so nothing ran on it. Leave the ceiling off"
        )
    if shipped is not None:
        floor, shipped_floor = lower_bound(forward), lower_bound(shipped)
        if floor is not None and shipped_floor is not None and floor < shipped_floor:
            problems.append(
                f"{MATRIX_WORKFLOW}'s `{FORWARD_LABEL}` leg floors at {forward}, below the shipped floor "
                f"{shipped}. Retargeting it downwards turns forward coverage into regression coverage for "
                f"versions nothing installs, and leaves nothing between the next major and production"
            )
        shipped_ceiling = upper_bound(shipped)
        declared = _WORKFLOW_CEILING.search(text)
        if shipped_ceiling is None:
            problems.append(f"{MATRIX_WORKFLOW}'s `{SHIPPED_LABEL}` leg {shipped} has no upper bound to compare against")
        elif declared is None:
            problems.append(
                f"{MATRIX_WORKFLOW} declares no `SHIPPED_CEILING`, so the `Forward coverage` step cannot say "
                f"whether the leg reached past the pin — and a leg that cannot report that is a leg that "
                f"reports a duplicate green as evidence"
            )
        elif int(declared.group("major")) != shipped_ceiling[0]:
            problems.append(
                f"{MATRIX_WORKFLOW}'s `Forward coverage` step compares against SHIPPED_CEILING="
                f"{declared.group('major')} while the shipped leg is {shipped} — the step would report "
                f"forward coverage for a version inside the shipped range, or deny it for one above"
            )
    return problems


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
                problems.append(
                    f"{RESOLVED_FILE} resolved sqlglot {locked_version}, outside the declared {agreed_so_far}"
                )

    stray = scan_for_unregistered()
    if stray:
        problems.append("sqlglot installed in unregistered file(s), add them to DECLARING_FILES: " + ", ".join(sorted(stray)))

    agreed = next(iter(seen)) if len(seen) == 1 else None
    matrix_path = REPO_ROOT / MATRIX_WORKFLOW
    if not matrix_path.exists():
        problems.append(f"{MATRIX_WORKFLOW} is missing — the rewriter would no longer be tested across sqlglot majors")
    elif agreed is not None:
        problems += matrix_problems(matrix_path.read_text(encoding="utf-8"), agreed)

    if problems:
        print(f"check_sqlglot_pin: root {REPO_ROOT}")
        print("check_sqlglot_pin: FAIL")
        for problem in problems:
            print(f"  - {problem}")
        print("\n  sqlglot enforces lake tenant isolation. Every install path must agree.")
        return 1

    only = next(iter(seen))
    print(f"check_sqlglot_pin: root {REPO_ROOT}")
    print(
        f"check_sqlglot_pin: OK — {len(DECLARING_FILES)} install paths all declare {only}, "
        f"{RESOLVED_FILE} resolves {locked_version} inside it, and {MATRIX_WORKFLOW} tests "
        f"that range plus everything above it"
    )
    return 0


# ── Self-test ────────────────────────────────────────────────────────────────
#
# The empty-tree refusal comes from the shared body. What is added here is the
# matrix rule, because it is new and because a rule whose only exercise is a
# tree that already satisfies it has never been observed to fail.
_MATRIX_FIXTURE = """
        include:
          - sqlglot: '>=30,<31'
            label: shipped
          - sqlglot: '>=30'
            label: forward-compat
    steps:
      - run: |
          SHIPPED_CEILING = 31
"""


def _matrix_self_test() -> list[tuple[str, bool]]:
    agreed = normalise(">=30,<31")

    def detects(text: str, fragment: str) -> bool:
        return any(fragment in problem for problem in matrix_problems(text, agreed))

    return [
        ("the unperturbed matrix reports nothing", not matrix_problems(_MATRIX_FIXTURE, agreed)),
        (
            "a shipped leg that is not the agreed pin is reported",
            detects(_MATRIX_FIXTURE.replace("'>=30,<31'", "'>=23,<27'"), "but the declared pin is"),
        ),
        (
            "a forward leg bounded above is reported",
            detects(_MATRIX_FIXTURE.replace("- sqlglot: '>=30'", "- sqlglot: '>=30,<31'"), "is bounded above"),
        ),
        (
            "a forward leg retargeted below the shipped floor is reported",
            detects(_MATRIX_FIXTURE.replace("- sqlglot: '>=30'", "- sqlglot: '>=27'"), "below the shipped floor"),
        ),
        (
            "a missing forward leg is reported",
            detects(_MATRIX_FIXTURE.replace("label: forward-compat", "label: spare"), "has no matrix leg labelled"),
        ),
        (
            "a SHIPPED_CEILING that has drifted from the shipped leg is reported",
            detects(_MATRIX_FIXTURE.replace("SHIPPED_CEILING = 31", "SHIPPED_CEILING = 27"), "SHIPPED_CEILING="),
        ),
        (
            "a deleted SHIPPED_CEILING is reported",
            detects(_MATRIX_FIXTURE.replace("SHIPPED_CEILING = 31", "pass"), "declares no `SHIPPED_CEILING`"),
        ),
    ]


if __name__ == "__main__":
    if SELF_TEST_FLAG in sys.argv[1:]:
        sys.exit(self_test_main(Path(__file__).name, extra=_matrix_self_test()))
    sys.exit(main())
