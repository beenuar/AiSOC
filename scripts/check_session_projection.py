#!/usr/bin/env python3
"""One producer of a session key, and three consumers that only read it.

ADR-0010 accepted writing sessions to Postgres *and* to the graph, on the
stated condition that the arrangement is held by a gate rather than by a
comment. This is that gate.

The hazard it exists for
------------------------
`services/ingest/internal/activity/session.go` reads the vendor's own session
field and labels how strong it is. Three places consume that block: the
Postgres store (`services/fusion/app/services/sessions.py`), the ClickHouse
writer (`lake_writer.py`) and the Neo4j writer in Go. The moment one of them
derives a key itself — reaching for `accessKeyId`, or synthesising a principal
plus a timestamp because the block was empty — the product has two producers
that agree today and will not agree after the next vendor-schema change. The
stores would then disagree about which session an event belongs to, and the
symptom is a session count that drifts rather than anything failing.

This repository has paid for a second copy of a producer several times, and
each time the copy was reasonable-looking code in the consumer.

What it checks
--------------
1. **One deriver.** Only `session.go` may read a session-identifying vendor
   field. Any other tracked source file that reads one is a finding.
2. **The closed set agrees in all three declarations.** The Go constants, the
   Python tuple and the CHECK constraint in migration `102_sessions.sql` must
   name exactly the same four kinds. Three hand-maintained copies of one
   vocabulary is the shape that drifts silently.
3. **Consumers do not invent a key.** A consumer may read `activity.session`
   and must not fall back to constructing one when it is absent, because an
   absent session is a real answer.

Run `--self-test` to see it detect each of those three, performed as the exact
edit a contributor would make.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

# `scripts/` is on sys.path when this file runs as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root  # noqa: E402

# Resolved through `git rev-parse`, not from `__file__`. Two levels above this
# script is whatever happens to be there -- and `scripts/` copied into an
# empty repository is exactly that, which is how a gate reports a tree clean
# without ever seeing the product. `check_gate_contract.py` refuses it.
ROOT = repo_root()

#: The one file allowed to read a vendor's session-identifying field.
PRODUCER = Path("services/ingest/internal/activity/session.go")

#: Where the closed set is declared, three times, by necessity: Go emits it,
#: Python validates against it, and Postgres constrains on it.
GO_KINDS = Path("services/ingest/internal/activity/session.go")
PY_KINDS = Path("services/fusion/app/services/sessions.py")
SQL_KINDS = Path("services/api/migrations/102_sessions.sql")

#: Vendor fields whose documented meaning is "this session" or "the credential
#: that is this session". Reading one of these is deriving a session key.
#:
#: Written as the field name in the position a lookup would use, so a mention
#: in prose or a column name does not match. `accessKeyId` is deliberately
#: scoped to the `userIdentity` and `credentials` objects it appears in,
#: because an AWS *connector* legitimately handles access keys as credentials
#: rather than as session identifiers.
SESSION_FIELD_PATTERNS: tuple[tuple[str, str], ...] = (
    (r'"externalSessionId"', "Okta session id"),
    (r'"AADSessionId"', "Entra session id carried on M365 records"),
    (r'"hashed_token"', "GitHub credential hash"),
    (r'"subjectFromWebIdentityToken"', "STS web-identity subject"),
    (r'"userIdentity"\s*,\s*"accessKeyId"', "CloudTrail temporary credential"),
    (r'"credentials"\s*,\s*"accessKeyId"', "STS issued credential"),
)

#: Files that read these fields for a reason other than deriving a session.
#: Each entry needs a reason; an empty allowlist is the goal and the list is
#: never a convenient place to put a new violation.
#:
#: The distinction that keeps the list honest: the hazard this gate exists for
#: is a **consumer of the session projection** — `sessions.py` (Postgres),
#: `lake_writer.py` (ClickHouse) or the Neo4j writer in Go — re-deriving the
#: key, after which the three stores disagree about which session an event
#: belongs to. A *connector* that lifts the vendor's session field into its
#: own normalized output is not that: it runs upstream of the one producer,
#: it writes nothing into `activity.session`, and the field it produces feeds
#: the detection engine's namespace, which `windowed_detection._fields()`
#: builds from the connector's `raw_data`/`raw_event` and **never** from
#: `activity.session`. So the AiTM rules cannot read the projection even in
#: principle, and the lift is the only way the session id reaches them. None
#: of the three store-consumers is on this list, and each would still trip.
ALLOWED: dict[str, str] = {
    "scripts/check_session_projection.py": "this gate, which has to name the patterns it looks for",
    "services/ingest/internal/activity/session_test.go": "the producer's own tests, which assert on these fields by name",
    "services/fusion/tests/test_sub_principal_baselines_reproduction.py": (
        "names the vendor field to assert the consumer **ignores** it. The "
        "sub-principal resolver used to read GitHub's digest itself and pin "
        "its normalisation against the Go side; that is a second derivation "
        "of a session key, so it now reads activity.session and this test is "
        "the negative control proving the old path resolves nothing. Naming "
        "the field is the assertion, which is the inverse of the hazard."
    ),
    "services/ingest/internal/activity/github_token_key_test.go": (
        "the producer's own test for the GitHub credential key, same reason as "
        "session_test.go beside it: it asserts that session.go reads the vendor "
        "field with TrimSpace and no case folding. Naming the field is the test's "
        "subject, and this file sits inside the one component allowed to derive "
        "the projection rather than downstream of it."
    ),
    "services/connectors/app/connectors/okta.py": (
        "the Okta connector lifts authenticationContext.externalSessionId to a top-level "
        "`session_id` in normalize() so the windowed AiTM rules (depth 7.3) can group on it — "
        "the detection namespace is built from the connector's output, not from activity.session, "
        "so this is detection-field normalization upstream of the producer, not a second consumer "
        "re-deriving the projection key. session.go stays the sole producer of activity.session."
    ),
    "services/connectors/tests/connectors/test_aitm_session_fields_reach_detection.py": (
        "asserts the connector's session_id lift reaches the detection engine; names the vendor "
        "field by name to build the fixture, same reason as the producer's own tests"
    ),
    "services/fusion/tests/test_okta_identity_rules_are_reachable.py": (
        "builds Okta fixtures that carry externalSessionId to prove the identity rules fire; "
        "names the vendor field to construct the event, not to derive a projection key"
    ),
}

#: A consumer that falls back to building a key when the block is absent.
#: The shape to catch is a join of identity-ish parts, which is what an
#: invented key looks like in every language this repo uses.
INVENTED_KEY = re.compile(
    r"(session[_a-z]*key\s*=\s*f?[\"'].*\{.*\}.*[\"'])"  # f-string assembly
    r"|(session[_a-z]*key\s*=\s*.*\+\s*.*\+)"  # concatenation of three parts
    r"|(strings\.Join\(\[\]string\{[^}]*\},\s*[\"']\|[\"']\))",  # Go pipe-join
    re.IGNORECASE,
)


def tracked_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "services", "scripts", "apps", "packages"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    keep = {".go", ".py", ".ts", ".tsx"}
    return [Path(line) for line in out.splitlines() if line and Path(line).suffix in keep]


def check_one_deriver(files: list[Path], root: Path) -> list[str]:
    findings: list[str] = []
    for rel in files:
        if rel == PRODUCER or rel.as_posix() in ALLOWED:
            continue
        try:
            text = (root / rel).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for pattern, what in SESSION_FIELD_PATTERNS:
            if re.search(pattern, text):
                findings.append(
                    f"{rel}: reads {what} directly. The session key has exactly one producer "
                    f"({PRODUCER}); read `activity.session` instead, or the two derivations will "
                    f"disagree after the next vendor-schema change and the stores will disagree "
                    f"about which session an event belongs to."
                )
                break
    return findings


def _read(root: Path, rel: Path) -> str | None:
    """The declaration's text, or None when the file is not there.

    A missing declaration is reported as a finding naming the file, never
    raised. A gate that dies on `FileNotFoundError` tells the reader the
    name of a path and nothing about which of the three declarations went
    missing or what that costs, and it does it in a traceback — which is
    how this one behaved the first time it was pointed at a tree that
    predates the projection.
    """
    try:
        return (root / rel).read_text(encoding="utf-8")
    except OSError:
        return None


def _go_kinds(root: Path) -> set[str]:
    text = _read(root, GO_KINDS)
    if text is None:
        return set()
    return set(re.findall(r'Session\w+\s+SessionKeyKind\s*=\s*"([a-z_]+)"', text))


def _py_kinds(root: Path) -> set[str]:
    text = _read(root, PY_KINDS)
    if text is None:
        return set()
    match = re.search(r"KEY_KINDS:\s*tuple\[str, \.\.\.\]\s*=\s*\(([^)]*)\)", text)
    if not match:
        return set()
    return {value.strip().strip("\"'") for value in match.group(1).split(",") if value.strip()}


def _sql_kinds(root: Path) -> set[str]:
    text = _read(root, SQL_KINDS)
    if text is None:
        return set()
    match = re.search(r"key_kind IN \(([^)]*)\)", text)
    if not match:
        return set()
    return {value.strip().strip("'") for value in match.group(1).split(",") if value.strip()}


def check_closed_set(root: Path) -> list[str]:
    # Named before they are compared, so "the file is gone" and "the file
    # disagrees" are different sentences. They need different fixes.
    missing = [
        f"{rel}: missing. The closed set is declared in three places by necessity — Go emits "
        f"it, Python validates against it and Postgres constrains on it — and the gate cannot "
        f"compare three declarations when one is absent."
        for rel in (GO_KINDS, PY_KINDS, SQL_KINDS)
        if _read(root, rel) is None
    ]
    if missing:
        return missing

    go, py, sql = _go_kinds(root), _py_kinds(root), _sql_kinds(root)
    if not go:
        return [f"{GO_KINDS}: no SessionKeyKind constants found; the gate cannot read the closed set"]
    findings = []
    if py != go:
        findings.append(
            f"{PY_KINDS}: KEY_KINDS is {sorted(py)} but the producer emits {sorted(go)}. "
            f"A kind the producer emits and this module rejects is silently dropped on the hot path."
        )
    if sql != go:
        findings.append(
            f"{SQL_KINDS}: the CHECK constraint allows {sorted(sql)} but the producer emits "
            f"{sorted(go)}. A kind the producer emits and the constraint rejects fails the insert."
        )
    return findings


def check_no_invented_keys(files: list[Path], root: Path) -> list[str]:
    findings = []
    for rel in files:
        if rel == PRODUCER or rel.as_posix() in ALLOWED:
            continue
        try:
            text = (root / rel).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if "activity" not in text and "session" not in text.lower():
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            if INVENTED_KEY.search(line):
                findings.append(
                    f"{rel}:{line_no}: builds a session key rather than reading one. An absent "
                    f'session is a real answer; a fabricated grouping makes "what else did this '
                    f'session do" answerable with a number that means nothing.'
                )
    return findings


def run(root: Path) -> list[str]:
    files = tracked_files()
    return check_one_deriver(files, root) + check_closed_set(root) + check_no_invented_keys(files, root)


def self_test() -> int:
    """Prove the gate detects each violation, as the edit a contributor makes."""
    failures = []

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / "repo"
        subprocess.run(["git", "worktree", "add", "--detach", str(work), "HEAD"], cwd=ROOT, capture_output=True, check=True)
        try:
            baseline = run(work)
            if baseline:
                failures.append(f"the clean tree is not clean: {baseline}")

            # 1. A second deriver, written the way a contributor reasonably would.
            consumer = work / "services/fusion/app/services/sessions.py"
            original = consumer.read_text()
            consumer.write_text(original + '\n\ndef _okta_key(vendor):\n    return vendor["authenticationContext"]["externalSessionId"]\n')
            if not any("one producer" in f for f in run(work)):
                failures.append("a second deriver of the Okta session id was not detected")
            consumer.write_text(original)

            # 2. The closed set drifting in one of its three declarations.
            consumer.write_text(
                original.replace(
                    '("vendor_session", "vendor_credential", "vendor_flow", "derived")',
                    '("vendor_session", "vendor_credential", "derived")',
                )
            )
            if not any("KEY_KINDS" in f for f in run(work)):
                failures.append("a shrunken Python closed set was not detected")
            consumer.write_text(original)

            migration = work / "services/api/migrations/102_sessions.sql"
            sql_original = migration.read_text()
            migration.write_text(sql_original.replace("'vendor_flow', ", ""))
            if not any("CHECK constraint" in f for f in run(work)):
                failures.append("a shrunken SQL CHECK constraint was not detected")
            migration.write_text(sql_original)

            # 3. A consumer inventing a key when the block is absent.
            consumer.write_text(
                original + '\n\ndef _fallback(principal, ip, ua):\n    session_key = f"{principal}|{ip}|{ua}"\n    return session_key\n'
            )
            if not any("builds a session key" in f for f in run(work)):
                failures.append("an invented fallback key was not detected")
            consumer.write_text(original)

            # 4. A declaration gone entirely. This is the state of every tree
            #    that predates the projection, and the first thing this gate
            #    was pointed at. It has to produce a sentence, not a
            #    traceback: a reader who gets `FileNotFoundError` learns a
            #    path and not which of the three declarations is missing.
            producer = work / GO_KINDS
            go_original = producer.read_text()
            producer.unlink()
            try:
                findings = run(work)
            except OSError as exc:  # pragma: no cover - the regression itself
                failures.append(f"a missing declaration raised instead of reporting: {exc!r}")
                findings = []
            if not any("missing" in f and GO_KINDS.name in f for f in findings):
                failures.append("a missing producer declaration was not reported as a finding")
            producer.write_text(go_original)
        finally:
            subprocess.run(["git", "worktree", "remove", "--force", str(work)], cwd=ROOT, capture_output=True)

    if failures:
        for failure in failures:
            print(f"SELF-TEST FAILED: {failure}")
        return 1
    print(
        "self-test OK: the gate detects a second deriver, a drifted closed set in either "
        "declaration, an invented fallback key, and a declaration that is missing entirely."
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--self-test", action="store_true", help="prove the gate detects each violation")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    findings = run(ROOT)
    if findings:
        print("Session projection: the one-producer rule is broken.\n")
        for finding in findings:
            print(f"  - {finding}")
        print(
            "\nADR-0010 accepted two stores for one projection on the condition that this stays "
            "true. Read `activity.session`; do not re-derive it."
        )
        return 1

    kinds = sorted(_go_kinds(ROOT))
    print(f"OK: one producer ({PRODUCER}), closed set agreed in Go, Python and SQL: {kinds}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
