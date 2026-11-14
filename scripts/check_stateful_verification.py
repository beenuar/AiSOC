#!/usr/bin/env python3
"""Gate: asking a person about their own activity is a workflow, not a message.

Depth plan 5.4. ``chatops_verify`` already posted a prompt and returned
"awaiting completion", and that was honest about one message. What makes it
a control rather than a notification is the four properties below, each of
which can be removed without any test failing — the step would keep sending,
the prompt would keep arriving, and the run would quietly stop branching.

What this checks, and what each catches when it goes
-----------------------------------------------------

**A signed answer, bound to its stage.** The link arrives in a chat message
to somebody holding no session, so the URL is the whole credential. Drop the
signature and the route takes an answer from anyone who can reach it; drop
the stage from the signature and the subject's own link answers on their
manager's behalf an hour later, which defeats the escalation.

**A deadline that escalates and then ends with an outcome.** A prompt nobody
answers has to become ``timed_out``, a value a playbook can branch on.
Without the sweep the run sits ``paused`` forever and the console shows a
containment that is neither done nor abandoned.

**Two refusals, in the right order.** Never on a confirmed true positive —
no opt-out, because the message tells an attacker holding the account that
they have been seen — and auto-sent only for classes a tenant opted into.
The order matters: checking the opt-in first would let a tenant opt into
messaging a compromised account.

**A writer for the opt-in table.** The refusal fails closed, so a table with
a reader and no writer is a feature that can never be switched on. That shape
has shipped in this repository more than once.

Run:
    python3 scripts/check_stateful_verification.py
    python3 scripts/check_stateful_verification.py --self-test
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import TREE_SHAPES, refuses_an_empty_tree, repo_root

REPO_ROOT = repo_root()

VERIFICATION_PY = Path("services/agents/app/playbook/verification.py")
ENGINE_PY = Path("services/agents/app/playbook/engine.py")
PAUSE_PY = Path("services/agents/app/playbook/pause.py")
SWEEPER_PY = Path("services/agents/app/playbook/sweeper.py")
ROUTES_PY = Path("services/agents/app/api/playbooks.py")
POLICY_ROUTES_PY = Path("services/api/app/api/v1/endpoints/verification_policies.py")
MIGRATION = Path("services/api/migrations/104_playbook_verification.sql")

#: Every outcome a run may branch on. Declared here so the three places that
#: spell them — the module, the migration's CHECK and the pause writer — are
#: compared against one list rather than against each other in a cycle.
OUTCOMES = ("acknowledged", "denied", "unsure", "timed_out", "no_manager")


def _function_body(source: str, name: str) -> str | None:
    """One top-level function's source, by name.

    Written as "until the next top-level def, or the end of the file"
    rather than as "until two blank lines". The first version of this gate
    matched `\n\n\n`, which silently found nothing for the *last* function
    in a module — so the ordering rule below was skipped entirely and the
    gate reported OK over an injected violation.
    """
    start = source.find(f"async def {name}(")
    if start < 0:
        start = source.find(f"def {name}(")
    if start < 0:
        return None
    rest = source[start:]
    nxt = re.search(r"\n(?:async def |def |class |@)", rest[1:])
    return rest if nxt is None else rest[: nxt.start() + 1]


def _read(root: Path, rel: Path) -> str | None:
    path = root / rel
    return path.read_text(encoding="utf-8") if path.is_file() else None


def evaluate(root: Path) -> list[str]:
    failures: list[str] = []
    read_any = False

    verification = _read(root, VERIFICATION_PY)
    if verification is None:
        failures.append(f"{VERIFICATION_PY} is missing: there is no stateful verification to check.")
    else:
        read_any = True
        failures.extend(_check_signature(verification))
        failures.extend(_check_refusals(verification))

    engine = _read(root, ENGINE_PY)
    if engine is None:
        failures.append(f"{ENGINE_PY} is missing.")
    else:
        read_any = True
        failures.extend(_check_engine(engine))

    pause = _read(root, PAUSE_PY)
    if pause is None:
        failures.append(f"{PAUSE_PY} is missing.")
    else:
        read_any = True
        failures.extend(_check_pause(pause))

    sweeper = _read(root, SWEEPER_PY)
    if sweeper is None:
        failures.append(f"{SWEEPER_PY} is missing.")
    else:
        read_any = True
        if "resume_due_verifications" not in sweeper:
            failures.append(
                f"{SWEEPER_PY} never calls resume_due_verifications, so a prompt nobody answers never escalates and "
                f"never times out. The run sits paused forever and the only symptom is a containment that did not happen."
            )

    routes = _read(root, ROUTES_PY)
    if routes is None:
        failures.append(f"{ROUTES_PY} is missing.")
    else:
        read_any = True
        if "verifications_router" not in routes:
            failures.append(f"{ROUTES_PY} declares no verification callback route, so every answer link in every prompt is a 404.")
        elif re.search(r"verifications_router\s*=\s*APIRouter\([^)]*dependencies\s*=", routes):
            failures.append(
                f"{ROUTES_PY}: the verification router declares an auth dependency. The person answering is the subject "
                f"of an alert and holds no session by construction; the signature is the credential."
            )

    policy_routes = _read(root, POLICY_ROUTES_PY)
    if policy_routes is None:
        failures.append(
            f"{POLICY_ROUTES_PY} is missing, so aisoc_verification_policies has a reader and no writer. The refusal "
            f"fails closed, so a tenant could never switch automatic verification on and the feature reads as broken."
        )
    else:
        read_any = True
        if "require_permission" not in policy_routes:
            failures.append(f"{POLICY_ROUTES_PY} does not check a permission, so any authenticated caller could grant this.")

    migration = _read(root, MIGRATION)
    if migration is None:
        failures.append(f"{MIGRATION} is missing: the pause has nowhere to record a stage or an answer.")
    else:
        read_any = True
        failures.extend(_check_migration(migration))

    if not read_any:
        failures.append(
            "none of the files this gate checks exist. A clean result over a tree with nothing in it is the shape "
            "this toolkit exists to refuse."
        )
    return failures


def _check_signature(source: str) -> list[str]:
    failures: list[str] = []
    match = re.search(r"def sign_answer\(.*?\n(?:.|\n)*?return hmac\.new\(key, (\w+), hashlib\.sha256\)", source)
    if not match:
        failures.append(
            f"{VERIFICATION_PY}: sign_answer does not end in an HMAC over a message. Without a signature the callback "
            f"takes an answer from anybody who reaches the route."
        )
        return failures

    message = re.search(r'message = f"\{([^"]*)\}"\.encode\(\)', source) or re.search(r"message = f\"([^\"]*)\"\.encode\(\)", source)
    signed = message.group(1) if message else ""
    for part, why in (
        ("resume_token", "a signature that omits the token is reusable across pauses"),
        ("answer", "a signature that omits the answer lets a holder of one link assert a different one"),
        ("stage", "a signature that omits the stage lets the subject's own link answer for their manager"),
    ):
        if part not in signed:
            failures.append(f"{VERIFICATION_PY}: sign_answer does not cover {part!r} — {why}.")

    if "compare_digest" not in source:
        failures.append(
            f"{VERIFICATION_PY}: the signature is not compared with hmac.compare_digest, so the comparison leaks "
            f"timing about how much of a forged signature was right."
        )
    if "VerificationConfigError" not in source:
        failures.append(
            f"{VERIFICATION_PY}: a missing secret does not raise. Returning an unsigned link instead would be a prompt "
            f"whose answer nothing can authenticate."
        )
    return failures


def _check_refusals(source: str) -> list[str]:
    failures: list[str] = []
    if "is_confirmed_true_positive" not in source:
        failures.append(
            f"{VERIFICATION_PY}: nothing refuses a confirmed true positive. Messaging an account an attacker holds "
            f"tells them they are seen, and neither answer is worth having."
        )
    if "aisoc_verification_policies" not in source:
        failures.append(f"{VERIFICATION_PY}: the opt-in table is never read, so a prompt is auto-sent for every alert class.")

    text = _function_body(source, "may_auto_send")
    if text:
        tp = text.find("is_confirmed_true_positive")
        opt_in = text.find("aisoc_verification_policies")
        if tp < 0:
            failures.append(f"{VERIFICATION_PY}: may_auto_send does not consult the true-positive refusal at all.")
        elif 0 <= opt_in < tp:
            failures.append(
                f"{VERIFICATION_PY}: may_auto_send reads the opt-in table before the true-positive refusal. The "
                f"true-positive rule has no opt-out, so it must be first — otherwise a tenant can opt into messaging "
                f"a compromised account."
            )
        if "Unreadable permission is not permission" not in text and "could not be read" not in text:
            failures.append(
                f"{VERIFICATION_PY}: may_auto_send does not fail closed when the policy cannot be read. An unreadable grant is not a grant."
            )
    return failures


def _check_engine(source: str) -> list[str]:
    failures: list[str] = []
    if "StepType.VERIFY_USER: _control_verify_user" not in source:
        failures.append(f"{ENGINE_PY}: verify_user is not in the control-flow table, so the engine would fail it closed.")
    if "resume_verification" not in source:
        failures.append(f"{ENGINE_PY}: no resume path for a verification answer, so a signed answer wakes nothing.")
    if "resume_due_verifications" not in source:
        failures.append(f"{ENGINE_PY}: nothing escalates or times out a verification.")
    if '"timed_out"' not in source:
        failures.append(
            f"{ENGINE_PY}: no timed_out outcome. An unanswered prompt would leave the run neither waiting nor finished, "
            f"which is not something a playbook can branch on."
        )
    if "escalate_to_manager" not in source:
        failures.append(f"{ENGINE_PY}: nothing escalates to a manager, so the second half of the workflow does not exist.")

    # The run-loop break. Without it a durable pause writes its row and the
    # run carries on into the steps the pause exists to hold back, then runs
    # them again when the callback resumes.
    if not re.search(r"StepStatus\.PENDING and result\.get\(\"paused\"\)", source):
        failures.append(
            f"{ENGINE_PY}: the run loop does not stop on a durable pause. A step that suspends to Postgres and returns "
            f"PENDING would keep running, and the resume would run everything after it a second time."
        )
    return failures


def _check_pause(source: str) -> list[str]:
    failures: list[str] = []
    for needed, why in (
        ("find_verification_by_token", "the callback cannot find the run that is waiting"),
        ("due_verifications", "nothing sweeps a stage deadline"),
        ("escalate_to_manager", "the question never reaches a second person"),
        ("record_verification_outcome", "the answer is never made durable"),
    ):
        if needed not in source:
            failures.append(f"{PAUSE_PY}: {needed} is missing — {why}.")

    escalation = _function_body(source, "escalate_to_manager")
    if escalation and not re.search(r"AND\s+verification_stage\s*=\s*'user'", escalation):
        failures.append(
            f"{PAUSE_PY}: escalate_to_manager does not require the row to still be on the user stage, so two sweeper "
            f"replicas would escalate the same pause twice and the manager would be asked twice."
        )
    outcome = _function_body(source, "record_verification_outcome")
    if outcome and not re.search(r"AND\s+verification_outcome\s+IS\s+NULL", outcome):
        failures.append(
            f"{PAUSE_PY}: record_verification_outcome does not require the row to be unanswered, so a double click "
            f"would overwrite the first answer."
        )
    lookup = _function_body(source, "find_verification_by_token")
    # The SQL clause, not the phrase. This function's own docstring quotes
    # the predicate, so a prose match survives deleting the clause — the
    # exact blindness that makes a gate report OK over the defect it exists
    # to catch.
    if lookup and not re.search(r"AND\s+kind\s*=\s*'verification'", lookup):
        failures.append(
            f"{PAUSE_PY}: find_verification_by_token does not filter on kind, so a wait token could resolve as a "
            f"verification and answer a question nobody asked."
        )
    return failures


def _check_migration(source: str) -> list[str]:
    failures: list[str] = []
    if "'verification'" not in source:
        failures.append(f"{MIGRATION}: the kind constraint does not admit 'verification', so every pause write would be refused.")
    for outcome in OUTCOMES:
        if f"'{outcome}'" not in source:
            failures.append(
                f"{MIGRATION}: the outcome constraint does not admit {outcome!r}. The code writes it, so Postgres would "
                f"refuse the row at the moment somebody answered."
            )
    if "ENABLE ROW LEVEL SECURITY" not in source:
        failures.append(
            f"{MIGRATION}: aisoc_verification_policies has no row-level security, so one tenant's opt-in list is readable by another."
        )
    if "manager_ref" not in source:
        failures.append(f"{MIGRATION}: no manager column, so the escalation has nobody to escalate to.")
    return failures


def _self_test() -> int:
    results: list[tuple[str, bool]] = []
    tracked = (VERIFICATION_PY, ENGINE_PY, PAUSE_PY, SWEEPER_PY, ROUTES_PY, POLICY_ROUTES_PY, MIGRATION)

    baseline = evaluate(REPO_ROOT)
    results.append(("the undisturbed tree is clean, so a caught case means something", not baseline))
    for line in baseline[:8]:
        print(f"        {line}")

    cases = (
        ("an answer signature that omits the stage", "NO_STAGE"),
        ("a signature compared with ==", "TIMING"),
        ("an opt-in read before the true-positive refusal", "WRONG_ORDER"),
        ("a sweeper that never escalates", "NO_SWEEP"),
        ("a run loop that does not stop on a durable pause", "NO_BREAK"),
        ("an escalation two replicas could run twice", "DOUBLE_ESCALATE"),
        ("an outcome that can be overwritten by a second click", "DOUBLE_ANSWER"),
        ("a verification token lookup that would match a wait", "KIND_BLIND"),
        ("an outcome the migration's CHECK would refuse", "CHECK_DRIFT"),
        ("an opt-in table with no writer", "NO_WRITER"),
        ("a callback route behind an auth dependency nobody answering holds", "GUARDED_CALLBACK"),
    )

    for label, kind in cases:
        tmp = Path(tempfile.mkdtemp(prefix="aisoc-verify-selftest-"))
        try:
            for rel in tracked:
                src = REPO_ROOT / rel
                if src.is_file():
                    (tmp / rel).parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src, tmp / rel)
            _inject(tmp, kind)
            results.append((f"catches {label}", bool(evaluate(tmp))))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    details: list[str] = []
    for shape in TREE_SHAPES:
        refused, detail = refuses_an_empty_tree(Path(__file__).name, shape=shape)
        results.append((f"refuses a {shape} tree rather than reporting it clean", refused))
        details.append(f"{shape}: {detail}")

    ok = True
    for description, passed in results:
        ok &= passed
        print(f"  {'PASS' if passed else 'FAIL'}  {description}")
    for line in "\n".join(details).splitlines():
        print(f"        {line}")
    print()
    if not ok:
        print(f"{Path(__file__).name}: self-test FAILED")
        return 1
    print(f"{Path(__file__).name}: self-test OK")
    return 0


def _inject(root: Path, kind: str) -> None:
    """One realistic regression per rule, written the way it would be written."""
    verification = root / VERIFICATION_PY
    engine = root / ENGINE_PY
    pause = root / PAUSE_PY

    if kind == "NO_STAGE":
        text = verification.read_text(encoding="utf-8")
        verification.write_text(text.replace('f"{resume_token}|{answer}|{stage}"', 'f"{resume_token}|{answer}"'), encoding="utf-8")
    elif kind == "TIMING":
        text = verification.read_text(encoding="utf-8")
        verification.write_text(text.replace('hmac.compare_digest(expected, signature or "")', "expected == signature"), encoding="utf-8")
    elif kind == "WRONG_ORDER":
        text = verification.read_text(encoding="utf-8")
        start = text.find("async def may_auto_send")
        head, tail = text[:start], text[start:]
        refusal_start = tail.find("    if is_confirmed_true_positive(context):")
        refusal_end = tail.find("    classes = _alert_classes(")
        refusal = tail[refusal_start:refusal_end]
        # Genuinely moved, not disabled: an injection that leaves the call
        # where it was would be caught by a gate reading the call's position
        # and would prove nothing about the ordering rule.
        tail = tail[:refusal_start] + tail[refusal_end:]
        anchor = tail.find("    if row is None:")
        verification.write_text(head + tail[:anchor] + refusal + tail[anchor:], encoding="utf-8")
    elif kind == "NO_SWEEP":
        path = root / SWEEPER_PY
        path.write_text(path.read_text(encoding="utf-8").replace("resume_due_verifications", "_unused_sweep"), encoding="utf-8")
    elif kind == "NO_BREAK":
        text = engine.read_text(encoding="utf-8")
        engine.write_text(re.sub(r'if step_status == StepStatus\.PENDING and result\.get\("paused"\)', "if False", text), encoding="utf-8")
    elif kind == "DOUBLE_ESCALATE":
        text = pause.read_text(encoding="utf-8")
        pause.write_text(text.replace("                   AND verification_stage = 'user'\n", "", 1), encoding="utf-8")
    elif kind == "DOUBLE_ANSWER":
        text = pause.read_text(encoding="utf-8")
        pause.write_text(text.replace("                   AND verification_outcome IS NULL\n", "", 1), encoding="utf-8")
    elif kind == "KIND_BLIND":
        text = pause.read_text(encoding="utf-8")
        start = text.find("async def find_verification_by_token")
        head, tail = text[:start], text[start:]
        pause.write_text(head + tail.replace("                   AND kind = 'verification'\n", "", 1), encoding="utf-8")
    elif kind == "CHECK_DRIFT":
        path = root / MIGRATION
        path.write_text(path.read_text(encoding="utf-8").replace("'no_manager'", "'no_mgr'"), encoding="utf-8")
    elif kind == "NO_WRITER":
        (root / POLICY_ROUTES_PY).unlink(missing_ok=True)
    elif kind == "GUARDED_CALLBACK":
        path = root / ROUTES_PY
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                'verifications_router = APIRouter(prefix="/api/v1/playbook-verifications", tags=["playbooks"])',
                'verifications_router = APIRouter(prefix="/api/v1/playbook-verifications", tags=["playbooks"], '
                "dependencies=[Depends(require_console_or_service_auth)])",
            ),
            encoding="utf-8",
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--self-test", action="store_true", help="inject one violation per rule and require each to be caught")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()

    failures = evaluate(REPO_ROOT)
    if failures:
        print("STATEFUL VERIFICATION GATE FAILED:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print(
        "stateful-verification: OK — the answer is signed and bound to its stage, an unanswered prompt escalates and "
        "then times out with an outcome, a confirmed true positive is never asked, and the opt-in table has a writer."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
