#!/usr/bin/env python3
"""Find values in a dotenv file that are placeholders rather than settings.

Why this exists as a script rather than a grep
----------------------------------------------
``scripts/doctor.sh`` used to carry the check inline::

    grep -qE '^[A-Z_]*(SECRET|PASSWORD|KEY)=(change_me|changeme|)$' .env

That pattern matches neither placeholder this repository actually ships.
``.env.example`` sets ``AISOC_CREDENTIAL_KEY`` to
``replace-me-with-a-freshly-generated-fernet-key`` and ``SECRET_KEY`` to
``change-this-to-a-random-secret-key-at-least-32-chars``; the grep looks for
``change_me``, ``changeme`` or an empty value. So the one gate built to catch a
shipped placeholder was blind to every shipped placeholder, and the documented
quick start — ``cp .env.example .env`` — handed the API an invalid Fernet key
that only surfaced as an HTTP 500 at the connector wizard, minutes later and
several screens away from the cause.

The lesson is not "write a better regex". It is that the detector and the file
it inspects were two separate hand-maintained lists that nothing compared.
``tests/test_env_placeholder_gate.py`` compares them: every non-empty value in
``.env.example`` must be either flagged here or named in that test's list of
deliberate working defaults, so a new placeholder cannot be added without one
of the two failing.

An *empty* value is deliberately not a placeholder. Most of the optional
credentials in ``.env.example`` ship empty and empty is their correct value —
flagging them would produce a warning on a correctly configured deployment,
which is how an operator learns to ignore a check.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

#: The shapes a placeholder takes in this repository. Matched case-insensitively
#: against the *value*, anywhere in it — a placeholder is prose, so anchoring
#: would only make the pattern brittle.
#:
#: Each entry is here because something in the tree matches it, or because it is
#: the obvious spelling a contributor would reach for next. Keep it that way:
#: a pattern nothing matches is untested.
PLACEHOLDER_PATTERNS: tuple[str, ...] = (
    r"replace[-_ ]?me",  # AISOC_CREDENTIAL_KEY
    r"change[-_ ]?me",  # the historical spelling the old grep looked for
    r"change[-_ ]?this",  # SECRET_KEY
    r"fill[-_ ]?(me|this)",
    r"\byour[-_][a-z0-9]",  # OPENAI_API_KEY=sk-your-openai-api-key-here
    r"[-_]here$",  # …-api-key-here
    r"^<.+>$",  # <paste-your-token>
    r"placeholder",
    r"\btodo\b",
    r"\bxxxx+",
)

_COMPILED = tuple(re.compile(p, re.IGNORECASE) for p in PLACEHOLDER_PATTERNS)

#: `KEY=value`, tolerating leading whitespace and `export `.
_ASSIGNMENT = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$")


def is_placeholder(value: str) -> bool:
    """True when ``value`` is something the reader was meant to replace."""
    stripped = value.strip().strip("\"'")
    if not stripped:
        return False
    return any(pattern.search(stripped) for pattern in _COMPILED)


def parse_env(text: str) -> list[tuple[int, str, str]]:
    """Return ``(line_number, key, value)`` for every assignment in ``text``."""
    entries: list[tuple[int, str, str]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if line.lstrip().startswith("#"):
            continue
        match = _ASSIGNMENT.match(line)
        if match:
            entries.append((lineno, match.group(1), match.group(2)))
    return entries


def findings(path: Path) -> list[tuple[int, str, str]]:
    """Every placeholder assignment in the dotenv file at ``path``."""
    return [(lineno, key, value.strip()) for lineno, key, value in parse_env(path.read_text(encoding="utf-8")) if is_placeholder(value)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        help="dotenv files to inspect (default: .env.example at the repository root)",
    )
    parser.add_argument(
        "--allow-placeholders",
        action="store_true",
        help=(
            "exit 0 even when placeholders are found. This is how the template itself is "
            "inspected: .env.example is *supposed* to contain them, and the caller only "
            "wants the list."
        ),
    )
    args = parser.parse_args(argv)

    paths = args.paths or [repo_root() / ".env.example"]

    missing = [p for p in paths if not p.is_file()]
    if missing:
        for path in missing:
            print(f"check_env_placeholders: ERROR — {path} does not exist", file=sys.stderr)
        return 1

    found = 0
    for path in paths:
        for lineno, key, value in findings(path):
            found += 1
            print(f"{path}:{lineno}: {key} is still a placeholder ({value!r})")

    if not found:
        print(f"check_env_placeholders: OK — no placeholder values in {', '.join(str(p) for p in paths)}")
        return 0

    if args.allow_placeholders:
        return 0

    print(
        "\nThese are template values, not settings. A non-empty placeholder is worse than an "
        "empty one: AISOC_CREDENTIAL_KEY fails Fernet validation and the API answers HTTP 500 "
        "on every connector save, while an empty value takes the documented development path.\n"
        "Generate real values with: make env",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
