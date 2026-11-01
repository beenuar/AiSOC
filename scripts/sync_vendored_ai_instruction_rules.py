#!/usr/bin/env python3
"""Generate the API service's copy of the prompt-injection patterns.

Why a copy exists
-----------------
``PromptInjectionGuard`` lives in ``services/agents/app/prompting/envelope.py``
and is the control that protects the triage prompt. The repository scanner
in ``services/api/app/services/ai_repo_scan.py`` (wave-2 7.2) needs the same
patterns for a different job: an agent-instruction file or a skill checked
into a repository is attacker-controlled text that an agent reads verbatim,
so the scanner flags it at capture time and ``score_risk`` raises the
asset's exposure.

The two services are separate deployables and the API image's build context
is ``services/api``, so ``services/agents`` is not importable at runtime.
Hand-copying a subset of the patterns would drift: a pattern added to the
guard after a real incident would not reach the scanner, and nothing would
say so. So this script **generates** the vendored module from the guard's own
``_RULES`` table and ``--check`` fails when they differ, which is the same
two-directional arrangement as the vendored narrative and the vendored LLM
contract rules.

What the copy is not
--------------------
It is not the authorization control. A signal here raises an exposure score
and names a reason; nothing is blocked on it. The authorization property at
triage time is still claim-support, which the adversarial suite in
``services/agents/tests/adversarial/`` is what proves.

Run modes
---------
* ``python scripts/sync_vendored_ai_instruction_rules.py``          — regenerate.
* ``python scripts/sync_vendored_ai_instruction_rules.py --check``  — fail if stale.

AiSOC — open-source AI Security Operations Center (MIT License).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

REPO_ROOT = repo_root()
AGENTS_ROOT = REPO_ROOT / "services" / "agents"
VENDORED_FILE = REPO_ROOT / "services" / "api" / "app" / "_vendor" / "ai_instruction_rules.py"

#: Guard rules deliberately left out of the copy, each with the reason.
#: Checked against the guard's table on every run, so an exclusion cannot
#: outlive the rule it names and quietly become a silent gap.
EXCLUDED: dict[str, str] = {
    # Matches a fabricated *tool-result envelope*, which is a thing that
    # appears in a model's own output stream. A file checked into a
    # repository is not that channel, so the rule would only ever fire here
    # on a document that quotes one.
    #
    # It also cannot be copied faithfully: its pattern is assembled from a
    # set of registered tool names, so the alternation renders in a
    # different order in every process and no generated file would ever
    # match itself. Reordering the alternation to stabilise it would be
    # this script editing a security pattern it does not own.
    "fabricated_tool_result": (
        "model-output channel, not a repository file; and its pattern is built from a set, so it is not reproducible across processes"
    ),
}

_HEADER = '''"""Prompt-injection patterns, generated from the agents-service guard.

DO NOT EDIT. Regenerate with:

    python scripts/sync_vendored_ai_instruction_rules.py

Source of truth: ``services/agents/app/prompting/envelope.py::_RULES``. The
API service cannot import it — separate deployable, separate build context —
so the pattern table is generated here and
``scripts/sync_vendored_ai_instruction_rules.py --check`` fails when the two
drift.

Used by ``app/services/ai_repo_scan.py`` to flag an agent-instruction file,
a skill or an MCP configuration whose text tries to steer an agent. That is
a *capture-time signal on a file*, feeding the exposure score in
``app/services/ai_inventory.py::score_risk``. It is not an authorization
control: the authorization property at triage time is claim-support, proved
by the adversarial suite in ``services/agents/tests/adversarial/``.
"""

from __future__ import annotations

import re
import unicodedata

#: ``(kind, severity, compiled pattern)``, generated from the guard.
#:
#: ``fmt: off`` and ``noqa: E501`` are not style laziness. A detection
#: pattern is a single indivisible token: the formatter cannot wrap one
#: without changing the string, and a wrapped pattern that still compiled
#: would be a *different* pattern. Leaving the block alone is what lets the
#: generator produce a file that is byte-identical on every run, which is
#: the property ``--check`` rests on.
# fmt: off
RULES: tuple[tuple[str, str, re.Pattern[str]], ...] = (
'''

_FOOTER = ''')
# fmt: on


def scan_instruction_text(text: str) -> tuple[str, ...]:
    """Names of the patterns `text` matched, sorted, never the matched text.

    Returning names and not spans is deliberate. The caller stores the
    result on an asset record that a console renders, and a stored copy of
    the matching payload would put the attacker's text in a second place.

    The text is NFKC-normalised first, for the reason the guard documents:
    a homoglyph spelling of an instruction renders identically and would
    otherwise pass a literal match.
    """
    if not text:
        return ()
    normalised = unicodedata.normalize("NFKC", text)
    return tuple(sorted({kind for kind, _severity, pattern in RULES if pattern.search(normalised)}))


def severity_of(kind: str) -> str | None:
    """The guard's own severity for one pattern name."""
    for name, severity, _pattern in RULES:
        if name == kind:
            return severity
    return None
'''


def _load_rules() -> list[tuple[str, str, str, int]]:
    """``(kind, severity, pattern source, flags)`` from the guard's table."""
    sys.path.insert(0, str(AGENTS_ROOT))
    try:
        from app.prompting.envelope import _RULES  # noqa: PLC0415
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL: could not import the guard's rule table: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    rules = [(r.kind, r.severity, r.pattern.pattern, int(r.pattern.flags)) for r in _RULES]
    present = {kind for kind, _s, _p, _f in rules}
    stale = sorted(set(EXCLUDED) - present)
    if stale:
        print(
            f"FAIL: EXCLUDED names a rule the guard no longer has: {stale}. "
            "Remove the entry or fix the name; a stale exclusion is a silent gap.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    return [r for r in rules if r[0] not in EXCLUDED]


def _render() -> str:
    lines = [_HEADER]
    for kind, severity, pattern, flags in _load_rules():
        # `re.UNICODE` is implied for str patterns and is reported in
        # `flags`; emitting it changes nothing but makes the diff noisy, so
        # it is masked out. Everything else is reproduced exactly.
        effective = flags & ~int(__import__("re").UNICODE)
        flag_expr = f", {effective}" if effective else ""
        lines.append(f"    ({kind!r}, {severity!r}, re.compile({pattern!r}{flag_expr})),  # noqa: E501\n")
    lines.append(_FOOTER)
    return "".join(lines)


def _check() -> int:
    if not VENDORED_FILE.is_file():
        print(f"FAIL: vendored file missing: {VENDORED_FILE}", file=sys.stderr)
        return 1
    if VENDORED_FILE.read_text() != _render():
        print(
            "FAIL: services/api/app/_vendor/ai_instruction_rules.py is stale.\n"
            "      Run scripts/sync_vendored_ai_instruction_rules.py and commit the result.",
            file=sys.stderr,
        )
        return 1
    count = len(_load_rules())
    print(f"OK: vendored ai_instruction_rules.py matches the guard ({count} rules).")
    return 0


def _sync() -> int:
    VENDORED_FILE.parent.mkdir(parents=True, exist_ok=True)
    VENDORED_FILE.write_text(_render())
    print(f"wrote {VENDORED_FILE.relative_to(REPO_ROOT)} ({len(_load_rules())} rules)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Fail if the vendored file is out of sync.")
    args = parser.parse_args()
    return _check() if args.check else _sync()


if __name__ == "__main__":
    raise SystemExit(main())
