#!/usr/bin/env python3
"""A claim that a console surface is "not built" must still be true.

Wave 2, Phase 9.5, prerequisite.

The defect this exists for
--------------------------
`docs/audit/CLAIM_TO_GATE_MATRIX.md` carried, inside the caveat of a GATED
row, the sentence:

    Six console pages parity 4.5 also names — branding, SCIM tokens,
    retention, organisation members and grants, rule packs, delegations —
    are not built; this row covers the enforcement bullet only

Three of those six were built. `ScimTokensPanel.tsx` has shipped, is wired
into `SettingsView` and is **gated by another row of the same matrix**, so
two rows of one document disagreed about whether a surface exists.
`UsersView` and `RBACView` had shipped too.

Why that is worse than an ordinary stale number
-----------------------------------------------
It reads as modesty and works as an exemption. A surface recorded as "not
built" needs no claim row and no gate — that is precisely what the sentence
is doing in a caveat — so a shipped page inherits the coverage of a page
that does not exist. `UsersView` was exactly that: built, reachable at
`/settings/users`, and tested by nothing.

The repository's existing gates cannot see this. `check_claim_gate_matrix`
counts rows and statuses; it does not read a caveat's prose. A row can
therefore be GATED, accurate about its own claim, and carry a sentence that
excuses an entire surface from having one.

What this gate does
-------------------
It reads every "not built" assertion in the matrix, extracts the console
surfaces each one names, and resolves each name against the console tree. A
named surface that **exists** fails the gate.

Deliberately narrow, for the reason the machine-local-path gate records:
security and audit documents are supposed to contain the words "not built",
and a gate that flagged every occurrence would be switched off in a week.
So it matches an assertion about *console pages* specifically, resolves each
name through an explicit vocabulary, and says what it found.

The direction that is checked
-----------------------------
One only: **claimed absent, actually present.** The opposite — a page
claimed present that does not exist — is already covered, by the gates that
require a claim row to name a CI job that drives the production path. This
gate exists for the direction nobody checks, which is also the direction
that hands a shipped surface an exemption.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MATRIX = REPO_ROOT / "docs" / "audit" / "CLAIM_TO_GATE_MATRIX.md"
CONSOLE = REPO_ROOT / "apps" / "web" / "src"

#: Each operator surface parity 4.5 names, and how to tell whether it exists.
#:
#: A component file *and* a render site, because a component nothing renders
#: is not a console page — that is the "exists but nothing calls it" family
#: this repository keeps finding, and crediting it here would make this gate
#: the thing that certifies it.
SURFACES: dict[str, tuple[str, ...]] = {
    "branding": ("components/settings/BrandingPanel.tsx", "components/settings/BrandingView.tsx"),
    "scim tokens": ("components/settings/ScimTokensPanel.tsx",),
    "retention": ("components/settings/RetentionPanel.tsx", "components/settings/RetentionView.tsx"),
    "organisation members": ("components/settings/UsersView.tsx",),
    "grants": ("components/settings/RBACView.tsx",),
    "rule packs": ("components/settings/RulePacksPanel.tsx", "components/marketplace/RulePacksView.tsx"),
    "delegations": ("components/settings/DelegationsPanel.tsx", "components/settings/DelegationsView.tsx"),
}

#: Spellings a matrix caveat has used, or would plausibly use, for each key.
ALIASES: dict[str, str] = {
    "organisation members and grants": "organisation members",
    "organization members": "organisation members",
    "members": "organisation members",
    "scim": "scim tokens",
    "rbac": "grants",
}

#: The assertion itself. Scoped to console pages so an unrelated "not built"
#: elsewhere in the document is not a finding.
_NOT_BUILT = re.compile(
    r"(?P<names>[^|.]{0,400}?)\b(?:are|is)\s+not\s+built\b",
    re.IGNORECASE,
)
_CONSOLE_CONTEXT = re.compile(r"console page|console surface|parity 4\.5|operator page", re.IGNORECASE)


def _render_sites(component: str) -> bool:
    """Whether anything outside the component's own file renders it.

    A component with no render site is not a page a user can reach, so the
    claim that it is "not built" is defensible and this gate must not fire.
    """
    stem = Path(component).stem
    pattern = re.compile(rf"\b{re.escape(stem)}\b")
    for path in CONSOLE.rglob("*.tsx"):
        if path.name == Path(component).name or path.name.endswith(".test.tsx"):
            continue
        try:
            if pattern.search(path.read_text(encoding="utf-8", errors="replace")):
                return True
        except OSError:
            continue
    return False


def _existing(surface: str) -> str | None:
    """The component file proving ``surface`` exists, or None."""
    for candidate in SURFACES.get(surface, ()):
        path = CONSOLE / candidate
        if path.is_file() and _render_sites(candidate):
            return candidate
    return None


def _named_surfaces(fragment: str) -> list[str]:
    """Which known surfaces a "not built" fragment names."""
    lowered = fragment.lower()
    found: list[str] = []
    for alias, canonical in ALIASES.items():
        if alias in lowered and canonical not in found:
            found.append(canonical)
    for surface in SURFACES:
        if surface in lowered and surface not in found:
            found.append(surface)
    return found


def violations(matrix_text: str) -> list[str]:
    """Every surface asserted absent that is present. Pure, for the self-test."""
    found: list[str] = []
    for match in _NOT_BUILT.finditer(matrix_text):
        line_start = matrix_text.rfind("\n", 0, match.start()) + 1
        line_end = matrix_text.find("\n", match.end())
        line = matrix_text[line_start : line_end if line_end > 0 else len(matrix_text)]
        if not _CONSOLE_CONTEXT.search(line):
            continue
        lineno = matrix_text[:line_start].count("\n") + 1
        for surface in _named_surfaces(match.group("names")):
            component = _existing(surface)
            if component is None:
                continue
            found.append(
                f"CLAIM_TO_GATE_MATRIX.md:{lineno}: claims {surface!r} is not built, "
                f"but apps/web/src/{component} exists and is rendered. "
                "A surface recorded as absent needs no claim row and no gate, so this "
                "sentence hands a shipped page an exemption it did not earn. Correct the "
                "caveat and give the page a row naming the job that fails when it breaks."
            )
    return found


def _self_test() -> int:
    """Both directions, including the sentence that motivated the gate."""
    cases: tuple[tuple[str, str, bool], ...] = (
        (
            "the motivating sentence is caught",
            "| x | y | z | core | GATED | Six console pages parity 4.5 also names — branding, "
            "SCIM tokens, retention, organisation members and grants, rule packs, delegations — "
            "are not built; this row covers the enforcement bullet only |",
            True,
        ),
        (
            "a corrected caveat naming only absent pages passes",
            "| x | y | z | core | GATED | Four console pages parity 4.5 names — branding, "
            "retention, rule packs, delegations — are not built |",
            False,
        ),
        (
            "an unrelated 'not built' outside a console context is ignored",
            "| x | y | z | core | PARTIAL | The managed-cluster harness is not built |",
            False,
        ),
        (
            "naming one built page alone is still caught",
            "| x | y | z | core | GATED | The SCIM tokens console page is not built | parity 4.5 |",
            True,
        ),
    )
    failures = 0
    for name, text, should_flag in cases:
        flagged = bool(violations(text))
        ok = flagged == should_flag
        failures += 0 if ok else 1
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
        if not ok:
            print(f"        flagged={flagged} expected={should_flag}")

    # A component that exists but nothing renders is not a page, and
    # crediting it would make this gate certify the defect it is named for.
    ok = _existing("branding") is None
    failures += 0 if ok else 1
    print(f"  {'PASS' if ok else 'FAIL'}  an absent surface resolves to nothing")

    ok = _existing("scim tokens") is not None
    failures += 0 if ok else 1
    print(f"  {'PASS' if ok else 'FAIL'}  a built, rendered surface resolves")

    print()
    if failures:
        print(f"check_unbuilt_claims.py: self-test FAILED ({failures})")
        return 1
    print("check_unbuilt_claims.py: self-test OK")
    return 0


def check() -> int:
    if not MATRIX.is_file():
        print(f"check_unbuilt_claims.py: {MATRIX.relative_to(REPO_ROOT)} is missing", file=sys.stderr)
        return 2
    if not CONSOLE.is_dir():
        print(
            f"check_unbuilt_claims.py: {CONSOLE.relative_to(REPO_ROOT)} is missing — "
            "refusing to certify claims about a console it never opened",
            file=sys.stderr,
        )
        return 2

    text = MATRIX.read_text(encoding="utf-8")
    found = violations(text)
    built = sorted(s for s in SURFACES if _existing(s))
    print(
        f"unbuilt claims: scanned {len(text.splitlines())} matrix lines against "
        f"{len(SURFACES)} operator surfaces; {len(built)} built ({', '.join(built) or 'none'})"
    )
    if found:
        print()
        for line in found:
            print(f"  - {line}")
        return 1
    print("OK: every 'not built' claim about a console surface is still true.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    return _self_test() if args.self_test else check()


if __name__ == "__main__":
    raise SystemExit(main())
