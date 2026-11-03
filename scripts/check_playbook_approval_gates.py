#!/usr/bin/env python3
"""A step whose name promises an approval gate has to be one.

Why this exists
---------------
``playbooks/README.md`` is explicit that a human-approval gate is a step of
``type: approval`` — it suspends the run to Postgres and resumes on the
decision — and equally explicit that modelling a gate as a ``condition``
reading a flag somebody sets out of band does not work: the engine evaluates
a condition once against the run context and moves on, so the "wait" is a
single false evaluation and nothing anywhere flips the flag.

Three shipped packs did exactly that anyway. A live run of
``ato-impossible-travel-block-v1`` reached ``status: completed`` with the step
named **"Wait for human approval"** producing no result and not suspending,
and ``Force password reset`` — the step the card says needs approval —
running immediately after it. The pack was not broken in a way a reader
would see: the step is there, it is named correctly, and it is the wrong
type. Nothing compared the promise in the name against the mechanism behind
it, which is what this gate does.

Two arms, because the gate can be bypassed two ways
---------------------------------------------------
**A name that promises a gate must be ``type: approval``.** That is the
defect above.

**An ``approval`` step must declare ``on_failure: abort``.** This is the same
bypass one layer down and it is easy to miss. ``engine.py`` suspends the run
at an approval step, and when the pause cannot be written it deliberately
falls through to the ordinary step path and fails the step closed — with a
comment saying that continuing past an approval nobody can grant is the
original defect. "Fails closed" is only true under the *default*
``on_failure: abort``; six shipped packs carried ``continue``, so a pause the
database refused would have failed the gate and then run the containment
verb it gates. A preview is unaffected: a dry run answers SUCCESS for an
approval step, so ``abort`` changes nothing about what an author sees.

Why the pattern is narrow
-------------------------
A gate that flags correct content gets switched off, and in a playbook
corpus the tempting broad rule — "the name mentions approval" — is wrong
immediately. ``Release payment after approval`` is the *gated action* in the
BEC pack: it is an ``http`` step, it is correctly typed, and its name
describes when it happens rather than promising to wait. So a name is read
in two stages: a sequencing qualifier (``after``, ``once``, ``upon``,
``following``, ``when``, ``post-``) in front of the approval word exempts the
step outright, and only then is it tested against the shapes that promise to
hold the run.

The three gating shapes the corpus actually uses are ``Approval gate — …``,
``Approve …`` and ``Wait for human approval``; the patterns cover those plus
the obvious neighbours (``Require analyst sign-off``, ``Pause until
management authorization``) so renaming a gate cannot quietly drop it out of
scope. ``--self-test`` proves both directions on a fixed corpus.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_main, verdict_args  # noqa: E402

# No module-level `self_test_if_requested`: it would answer `--self-test`
# before the detector below is defined, and the one thing worth proving is
# that the detector still separates a gate from a step named after one.

REPO_ROOT = repo_root()

#: Where playbooks live. Both the source pack and the copy vendored into the
#: agents package, because the vendored copy is what the image runs and a
#: one-directional read would pass while the shipped artefact drifted.
SCAN_ROOTS = (
    REPO_ROOT / "playbooks",
    REPO_ROOT / "services" / "agents",
)
SCAN_GLOB = "*.playbook.json"
SKIP_DIR_PARTS = {"node_modules", ".git", ".venv", "venv", "dist", "build", "__pycache__"}

#: The noun an approval gate is named with. Bounded on both sides so
#: "approver" — a person, not a gate — does not match.
_APPROVAL_WORD = r"(?:approvals?|approved?|approving|sign[-\s]?offs?|authori[sz]ations?|authori[sz]ed?)"

#: The name describes *when* this step runs, not a decision it waits for.
#: Checked first and exempts the step, because this is how the gated action
#: is named and flagging it would be the gate's first false positive.
_SEQUENCING = re.compile(
    rf"\b(?:after|once|following|upon|when|subject\s+to|post[-\s]?)\b[^.]{{0,24}}\b{_APPROVAL_WORD}\b",
    re.IGNORECASE,
)

#: The name promises to hold the run until a person decides.
_GATE_SHAPES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("names itself an approval gate", re.compile(r"\bapprovals?\s+gate\b", re.IGNORECASE)),
    ("begins with the decision verb", re.compile(r"^\s*approv(?:e|al)\b", re.IGNORECASE)),
    (
        "promises to wait for a decision",
        re.compile(
            rf"\b(?:wait|waits|waiting|hold|holds|pause|pauses|block|blocks)\b[^.]{{0,12}}"
            rf"\b(?:for|on|until)\b[^.]{{0,40}}\b{_APPROVAL_WORD}\b",
            re.IGNORECASE,
        ),
    ),
    ("states a decision is required", re.compile(rf"\brequires?\b[^.]{{0,40}}\b{_APPROVAL_WORD}\b", re.IGNORECASE)),
    (
        "names whose decision it waits for",
        re.compile(
            r"\b(?:human|analyst|operator|manual|soc|security|management|owner|cfo|ciso)\s+"
            r"(?:approvals?|sign[-\s]?offs?|authori[sz]ations?)\b",
            re.IGNORECASE,
        ),
    ),
    ("asks somebody to approve", re.compile(r"\bask[a-z]*\b[^.]{0,30}\bto\s+approve\b", re.IGNORECASE)),
)

#: A step id that is the gate rather than merely mentioning one. Anchored, so
#: `approve`, `approval`, `approve-containment` and `approval_isolate` match
#: and `release` does not.
_GATE_ID = re.compile(r"^approv(?:e|al)(?:[_\-][a-z0-9_\-]*)?$", re.IGNORECASE)

APPROVAL_TYPE = "approval"
REQUIRED_ON_FAILURE = "abort"


def gate_promise(step: dict[str, Any]) -> str | None:
    """Why this step reads as a human-approval gate, or None if it does not."""
    name = str(step.get("name") or "")
    if _SEQUENCING.search(name):
        # "Release payment after approval" describes an ordering, not a wait.
        return None
    for reason, pattern in _GATE_SHAPES:
        if pattern.search(name):
            return reason
    if _GATE_ID.match(str(step.get("id") or "")):
        return "its id is the gate"
    return None


def violations_in(playbook: dict[str, Any]) -> list[str]:
    """Every way this playbook's approval gates could be walked past."""
    found: list[str] = []
    for step in playbook.get("steps", []):
        if not isinstance(step, dict):
            continue
        sid = step.get("id", "?")
        stype = step.get("type")
        name = step.get("name", "")

        promise = gate_promise(step)
        if promise and stype != APPROVAL_TYPE:
            found.append(
                f"step {sid!r} ({name!r}) {promise}, but is type {stype!r}. "
                f"A gate must be type {APPROVAL_TYPE!r} — a {stype!r} step does not suspend the run, "
                f"so the step it gates runs anyway."
            )
        if stype == APPROVAL_TYPE and step.get("on_failure") != REQUIRED_ON_FAILURE:
            found.append(
                f"step {sid!r} ({name!r}) is an approval gate with on_failure="
                f"{step.get('on_failure')!r}. It must be {REQUIRED_ON_FAILURE!r}: when the pause cannot be "
                f"written the engine fails the step, and 'continue' then runs the action the gate exists to hold."
            )
    return found


def playbook_files() -> list[Path]:
    files: list[Path] = []
    for root in SCAN_ROOTS:
        if not root.is_dir():
            continue
        for path in root.rglob(SCAN_GLOB):
            if SKIP_DIR_PARTS.intersection(path.parts):
                continue
            files.append(path)
    return sorted(set(files))


def main() -> int:
    files = playbook_files()
    if not files:
        # "scanned nothing" and "found nothing" must not print the same word.
        print("FAIL: no *.playbook.json files found; this gate graded nothing", file=sys.stderr)
        return 1

    failures = 0
    gates = 0
    for path in files:
        try:
            playbook = json.loads(path.read_text())
        except (OSError, ValueError) as exc:
            print(f"FAIL {path.relative_to(REPO_ROOT)}: unreadable ({exc})", file=sys.stderr)
            failures += 1
            continue
        gates += sum(1 for s in playbook.get("steps", []) if isinstance(s, dict) and s.get("type") == APPROVAL_TYPE)
        for problem in violations_in(playbook):
            print(f"FAIL {path.relative_to(REPO_ROOT)}: {problem}", file=sys.stderr)
            failures += 1

    if failures:
        print(
            f"\n{failures} approval-gate problem(s) across {len(files)} playbook file(s).\n"
            "See 'Human-approval gates' in playbooks/README.md.",
            file=sys.stderr,
        )
        return 1

    print(f"OK: {len(files)} playbook file(s), {gates} approval gate(s), every promised gate suspends the run")
    return 0


def _self_test() -> int:
    positives = [
        ({"id": "approve", "name": "Wait for human approval", "type": "condition"}, "the shipped defect"),
        ({"id": "g", "name": "Approval gate — isolate host", "type": "http"}, "an approval gate typed http"),
        ({"id": "g", "name": "Approve containment", "type": "notify"}, "a name beginning with the verb"),
        ({"id": "g", "name": "Require analyst sign-off", "type": "condition"}, "a required sign-off"),
        ({"id": "g", "name": "Pause until management authorization", "type": "wait"}, "a pause-until phrasing"),
        ({"id": "approve-reset", "name": "Checkpoint", "type": "condition"}, "a gate id with a neutral name"),
        (
            {"id": "a", "name": "Approval gate — isolate host", "type": "approval", "on_failure": "continue"},
            "an approval gate that continues when it cannot suspend",
        ),
    ]
    negatives = [
        ({"id": "release", "name": "Release payment after approval", "type": "http", "on_failure": "continue"}, "the gated action"),
        ({"id": "v", "name": "Verify state once approved", "type": "http", "on_failure": "continue"}, "an 'once approved' step"),
        ({"id": "n", "name": "Notify the approver", "type": "notify", "on_failure": "continue"}, "a step naming the approver"),
        ({"id": "t", "name": "Open change approval board ticket", "type": "create_ticket", "on_failure": "continue"}, "a CAB ticket"),
        (
            {"id": "a", "name": "Approval gate — isolate host", "type": "approval", "on_failure": "abort"},
            "a correctly declared gate",
        ),
    ]

    checks: list[tuple[str, bool]] = []
    for step, label in positives:
        checks.append((f"catches {label}", bool(violations_in({"steps": [step]}))))
    for step, label in negatives:
        checks.append((f"does not flag {label}", not violations_in({"steps": [step]})))

    script = Path(__file__)
    return self_test_main(script.name, verdict_args(script), extra=checks)


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        raise SystemExit(_self_test())
    raise SystemExit(main())
