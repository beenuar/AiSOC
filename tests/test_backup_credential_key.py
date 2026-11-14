"""The credential key travels with the backup, and only inside the envelope.

The defect this exists to prevent
---------------------------------
`scripts/backup.sh` covers six stores with AES-256-GCM and a SHA-256
manifest. `rg -i "credential_key|AISOC_CREDENTIAL|\\.env"` across both
`backup.sh` and `restore.sh` returned nothing, so a complete, verified,
restorable Postgres dump was useless for connector credentials: the `alerts`
and `connector_instances` rows come back and every `vault:v1:` token in them
fails its integrity check against a key that never encrypted it.
`CredentialVault` raises `ciphertext failed integrity check (key rotated
without re-encrypt?)` and every connector is dead, after a restore that
reported success.

The threat model the fix creates, and why encryption becomes mandatory
----------------------------------------------------------------------
Capturing the key puts it in the same bucket as the ciphertext it decrypts.
With `BACKUP_ENCRYPTION=off` — which `backup.sh` supports and documents —
those two halves would sit side by side in plaintext, and anyone who can read
the bucket holds every connector credential in the deployment. The AES-256-GCM
envelope is the only control standing between them, so for this one artifact
it cannot be optional: `BACKUP_ENCRYPTION=off` must refuse to capture the key
rather than capture it in the clear. The tests below pin both halves.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKUP = ROOT / "scripts" / "backup.sh"
RESTORE = ROOT / "scripts" / "restore.sh"
PARITY = ROOT / "scripts" / "check_backup_restore_parity.py"


def _fn(script: Path, name: str) -> str:
    """One shell function's body, by brace depth.

    Counting braces rather than matching a closing `}` at column zero,
    because a `case` arm or a subshell inside the function has its own.
    """
    text = script.read_text(encoding="utf-8")
    start = text.index(f"{name}() {{")
    depth, i = 0, start
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
        i += 1
    raise AssertionError(f"unbalanced braces in {name}")


# ── the component exists on both sides ───────────────────────────────────────


def test_backup_captures_the_credential_key() -> None:
    text = BACKUP.read_text(encoding="utf-8")
    assert "backup_credential_key()" in text, (
        "backup.sh does not capture AISOC_CREDENTIAL_KEY, so a verified restore still cannot decrypt a single connector credential"
    )
    assert "AISOC_CREDENTIAL_KEY" in text


def test_restore_has_a_path_for_it() -> None:
    text = RESTORE.read_text(encoding="utf-8")
    assert "restore_credential_key()" in text, "a backup nobody can restore is a backup nobody has proven they can use"


def test_it_is_reachable_from_the_component_switch_on_both_sides() -> None:
    """A function nothing dispatches to is the repository's most-repeated
    defect: it exists, it is correct, and no caller reaches it."""
    for script in (BACKUP, RESTORE):
        text = script.read_text(encoding="utf-8")
        case_arm = re.search(r"^\s*credential[_-]key\)", text, re.MULTILINE)
        assert case_arm, f"{script.name} has no `credential_key)` arm in its --component switch"
        # `all` has to run it too, or the default path silently skips it.
        all_arm = text[text.index("  all)") :]
        verb = "backup" if script is BACKUP else "restore"
        assert f"{verb}_credential_key" in all_arm.split("*)")[0], f"{script.name}: `--component all` does not run {verb}_credential_key"


def test_usage_text_lists_it() -> None:
    """An operator choosing `--component` from the usage line can only pick
    what the usage line names."""
    for script in (BACKUP, RESTORE):
        text = script.read_text(encoding="utf-8")
        header = text[: text.index("set -euo pipefail")]
        assert "credential" in header, f"{script.name} usage text never mentions the credential key"


# ── the threat model: never in the clear ─────────────────────────────────────


def test_capture_refuses_when_backup_encryption_is_off() -> None:
    """The whole threat model in one assertion.

    With encryption off the key and the ciphertext it decrypts would sit in
    the same bucket in plaintext, and the bucket's read ACL becomes the only
    thing protecting every connector credential in the deployment.
    """
    body = _fn(BACKUP, "backup_credential_key")
    assert 'BACKUP_ENCRYPTION" == "off"' in body or 'BACKUP_ENCRYPTION" = "off"' in body, (
        "backup_credential_key does not check BACKUP_ENCRYPTION, so "
        "`BACKUP_ENCRYPTION=off` would upload the vault key in plaintext "
        f"beside the tokens it decrypts:\n{body}"
    )


def test_capture_goes_through_the_sealing_path() -> None:
    """`seal_artifact` is the chokepoint that encrypts and records a digest.

    A component that calls `s3_upload` directly bypasses both, which is
    exactly what the plugins component does for its dry-run branch — so this
    is a mistake the file already contains an example of.
    """
    body = _fn(BACKUP, "backup_credential_key")
    assert "upload_sealed" in body, f"not sealed before upload:\n{body}"
    assert re.search(r"^\s*s3_upload ", body, re.MULTILINE) is None, (
        f"calls s3_upload directly, bypassing encryption and the manifest:\n{body}"
    )


def test_the_key_is_never_echoed() -> None:
    """A backup script that logs the secret has made a copy of it in the
    place logs go, which is usually somewhere with weaker access control
    than the bucket."""
    body = _fn(BACKUP, "backup_credential_key")
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith(("log ", "echo ")):
            assert "$AISOC_CREDENTIAL_KEY" not in stripped and "${AISOC_CREDENTIAL_KEY" not in stripped, f"the key is printed:\n{stripped}"


def test_plaintext_is_written_with_a_restrictive_umask() -> None:
    """`seal_artifact` writes the plaintext to disk before encrypting it.

    For every other component that file is a dump; for this one it is the
    key itself, so the window where it exists must not be world-readable on
    a shared host.
    """
    body = _fn(BACKUP, "backup_credential_key")
    assert "umask" in body or "chmod 600" in body, f"the plaintext key file is created at the default mode:\n{body}"


# ── restore does not quietly overwrite a different key ───────────────────────


def test_restore_refuses_to_clobber_a_different_key() -> None:
    """Writing the backup's key over a *different* one in `.env` orphans
    whatever the running deployment has encrypted since — the same defect in
    the other direction. The operator has to decide."""
    body = _fn(RESTORE, "restore_credential_key")
    assert ".env" in body, f"restore never mentions where the key belongs:\n{body}"
    assert "differs" in body or "different" in body, f"restore does not distinguish an empty .env key from a conflicting one:\n{body}"


# ── the parity gate covers it ────────────────────────────────────────────────


def test_parity_gate_sees_the_new_component() -> None:
    """The gate pairs `backup_X` with `restore_X` by name, so a new store is
    covered automatically — but only if the names match."""
    backup_fns = set(re.findall(r"^backup_([a-z0-9_]+)\(\)", BACKUP.read_text(encoding="utf-8"), re.MULTILINE))
    restore_fns = set(re.findall(r"^restore_([a-z0-9_]+)\(\)", RESTORE.read_text(encoding="utf-8"), re.MULTILINE))
    assert "credential_key" in backup_fns
    assert "credential_key" in restore_fns
    assert not backup_fns - restore_fns, f"backed up with no restore: {sorted(backup_fns - restore_fns)}"


# ── two defects the live run found, both pre-existing on main ───────────────


def test_restore_defines_the_dry_run_flag_it_reads() -> None:
    """`restore.sh` read `$DRY_RUN` in three functions and never set it.

    Under `set -euo pipefail` that is `DRY_RUN: unbound variable`, and the
    three functions are neo4j, qdrant and redis — the three wave 15 added
    precisely because "a backup nobody can restore is a backup nobody has
    proven they can use". They still could not be: each died at the line
    that decides whether the run is a rehearsal, and only once the artifact
    was actually present, so the crash arrived during a real recovery.

    Found by running the script rather than reading it. No gate in the tree
    could see it, because both halves look correct in isolation.
    """
    text = RESTORE.read_text(encoding="utf-8")
    reads = re.findall(r"\$\{?DRY_RUN\b", text)
    assert reads, "guard: this test is meaningless if nothing reads DRY_RUN"
    assert re.search(r"^DRY_RUN=", text, re.MULTILINE), (
        f"restore.sh reads DRY_RUN in {len(reads)} place(s) and never assigns it; "
        "under `set -u` every one of them is an unbound-variable crash"
    )
    assert "--dry-run)" in text, "restore.sh has no --dry-run arm, so the flag its own functions branch on cannot be set by a caller"


def test_array_expansions_are_safe_on_bash_3_2() -> None:
    """`"${arr[@]}"` over an *empty* array is an unbound variable under
    `set -u` on bash below 4.4 — which is macOS's `/bin/bash`, and the
    shebang is `#!/usr/bin/env bash`.

    Every upload in `backup.sh` went through one `s3_upload`, so a single
    occurrence broke all six components on that platform. CI runs Linux with
    bash 5, which is why it was invisible. The `auth_args` sites in the same
    file already used the guarded form, so this was five missed call sites
    rather than an unknown idiom.
    """
    for script in (BACKUP, RESTORE):
        text = script.read_text(encoding="utf-8")
        # The guarded form *contains* the unguarded one, so a naive search
        # flags a correct file. Remove the whole guarded expression first and
        # look at what is left.
        remaining = re.sub(r"\$\{([a-z_]+)\[@\]\+\"\$\{\1\[@\]\}\"\}", "GUARDED", text)
        bad = re.findall(r'"\$\{([a-z_]+)\[@\]\}"', remaining)
        assert not bad, (
            f"{script.name}: {sorted(set(bad))} expanded unguarded. Use "
            '`${arr[@]+"${arr[@]}"}`, which is empty when the array is and '
            "quoted when it is not."
        )


def test_parity_gate_also_enforces_mandatory_encryption() -> None:
    """Name-pairing alone would pass a credential-key component that shipped
    the key in plaintext. The property specific to this store needs its own
    arm, or the gate covers its existence and not the thing that makes it
    safe."""
    text = PARITY.read_text(encoding="utf-8")
    assert "MUST_BE_ENCRYPTED" in text, "the parity gate has no arm asserting that secret-bearing components refuse BACKUP_ENCRYPTION=off"
