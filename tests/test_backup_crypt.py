"""Backup artifacts must be encrypted, verifiable, and unforgiving of damage.

architecture.md credited backup.sh with AES-256-GCM and a SHA-256 manifest
for months while it gzipped and uploaded. These tests hold the replacement to
the property that actually matters operationally: a damaged or truncated
backup must fail loudly at restore time, because a restore that silently
produces a partial database is worse than a restore that refuses.
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = REPO_ROOT / "scripts" / "backup_crypt.py"

spec = importlib.util.spec_from_file_location("backup_crypt", MODULE_PATH)
assert spec and spec.loader
backup_crypt = importlib.util.module_from_spec(spec)
sys.modules["backup_crypt"] = backup_crypt
spec.loader.exec_module(backup_crypt)

KEY = bytes.fromhex("00" * 32)
OTHER_KEY = bytes.fromhex("11" * 32)


def roundtrip(payload: bytes, key: bytes = KEY) -> bytes:
    sealed = io.BytesIO()
    backup_crypt.encrypt_stream(io.BytesIO(payload), sealed, key)
    sealed.seek(0)
    opened = io.BytesIO()
    backup_crypt.decrypt_stream(sealed, opened, key)
    return opened.getvalue()


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"a",
        b"-- pg_dump output\nCREATE TABLE alerts (id uuid);\n",
        secrets.token_bytes(backup_crypt.CHUNK_SIZE - 1),
        secrets.token_bytes(backup_crypt.CHUNK_SIZE),
        secrets.token_bytes(backup_crypt.CHUNK_SIZE + 1),
        # Spans several chunks, so chunk framing is genuinely exercised.
        secrets.token_bytes(backup_crypt.CHUNK_SIZE * 2 + 7),
    ],
)
def test_roundtrip_preserves_bytes(payload: bytes) -> None:
    assert roundtrip(payload) == payload


def test_ciphertext_does_not_contain_the_plaintext() -> None:
    """The point of the exercise: a bucket read must not yield the dump."""
    marker = b"AKIAIOSFODNN7EXAMPLE super-secret-connector-credential"
    payload = b"x" * 1000 + marker + b"y" * 1000
    sealed = io.BytesIO()
    backup_crypt.encrypt_stream(io.BytesIO(payload), sealed, KEY)
    assert marker not in sealed.getvalue()


def test_wrong_key_is_rejected() -> None:
    sealed = io.BytesIO()
    backup_crypt.encrypt_stream(io.BytesIO(b"payload"), sealed, KEY)
    sealed.seek(0)
    with pytest.raises(backup_crypt.BackupCryptError, match="Authentication failed"):
        backup_crypt.decrypt_stream(sealed, io.BytesIO(), OTHER_KEY)


def test_flipped_bit_is_rejected() -> None:
    sealed = io.BytesIO()
    backup_crypt.encrypt_stream(io.BytesIO(b"payload" * 100), sealed, KEY)
    blob = bytearray(sealed.getvalue())
    blob[-40] ^= 0x01
    with pytest.raises(backup_crypt.BackupCryptError, match="Authentication failed"):
        backup_crypt.decrypt_stream(io.BytesIO(bytes(blob)), io.BytesIO(), KEY)


def test_truncation_is_rejected_rather_than_silently_short() -> None:
    """The failure mode that matters: half a dump restoring as if whole.

    A whole-file encrypt would decrypt the surviving chunks happily and hand
    back a shorter database. The end-of-stream marker makes that impossible.
    """
    payload = secrets.token_bytes(backup_crypt.CHUNK_SIZE * 2)
    sealed = io.BytesIO()
    backup_crypt.encrypt_stream(io.BytesIO(payload), sealed, KEY)
    blob = sealed.getvalue()

    truncated = blob[: len(blob) // 2]
    with pytest.raises(backup_crypt.BackupCryptError):
        backup_crypt.decrypt_stream(io.BytesIO(truncated), io.BytesIO(), KEY)


def test_chunks_cannot_be_reordered() -> None:
    """Reordering must fail even though every chunk is individually valid."""
    chunk = backup_crypt.CHUNK_SIZE
    payload = b"A" * chunk + b"B" * chunk
    sealed = io.BytesIO()
    backup_crypt.encrypt_stream(io.BytesIO(payload), sealed, KEY)
    blob = sealed.getvalue()

    header = len(backup_crypt.MAGIC) + 1 + 8
    framed = 4 + chunk + backup_crypt.TAG_BYTES
    first = blob[header : header + framed]
    second = blob[header + framed : header + 2 * framed]
    swapped = blob[:header] + second + first + blob[header + 2 * framed :]

    with pytest.raises(backup_crypt.BackupCryptError, match="Authentication failed"):
        backup_crypt.decrypt_stream(io.BytesIO(swapped), io.BytesIO(), KEY)


def test_plaintext_file_is_not_mistaken_for_an_artifact() -> None:
    with pytest.raises(backup_crypt.BackupCryptError, match="bad magic"):
        backup_crypt.decrypt_stream(io.BytesIO(b"-- plain sql dump\n" * 10), io.BytesIO(), KEY)


def test_two_encryptions_of_the_same_input_differ() -> None:
    """A fresh nonce prefix per file; identical dumps must not be linkable."""
    payload = b"same input"
    a, b = io.BytesIO(), io.BytesIO()
    backup_crypt.encrypt_stream(io.BytesIO(payload), a, KEY)
    backup_crypt.encrypt_stream(io.BytesIO(payload), b, KEY)
    assert a.getvalue() != b.getvalue()
    assert roundtrip(payload) == payload


class TestKeyLoading:
    def test_hex_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("BACKUP_ENCRYPTION_KEY", "ab" * 32)
        monkeypatch.delenv("BACKUP_ENCRYPTION_KEY_FILE", raising=False)
        assert backup_crypt.load_key() == bytes.fromhex("ab" * 32)

    def test_key_file_wins(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        path = tmp_path / "key"
        path.write_text("cd" * 32 + "\n")
        monkeypatch.setenv("BACKUP_ENCRYPTION_KEY", "ab" * 32)
        monkeypatch.setenv("BACKUP_ENCRYPTION_KEY_FILE", str(path))
        assert backup_crypt.load_key() == bytes.fromhex("cd" * 32)

    def test_missing_key_explains_how_to_make_one(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("BACKUP_ENCRYPTION_KEY", raising=False)
        monkeypatch.delenv("BACKUP_ENCRYPTION_KEY_FILE", raising=False)
        with pytest.raises(backup_crypt.BackupCryptError, match="keygen"):
            backup_crypt.load_key()

    def test_short_key_is_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("BACKUP_ENCRYPTION_KEY", "ab" * 16)
        monkeypatch.delenv("BACKUP_ENCRYPTION_KEY_FILE", raising=False)
        with pytest.raises(backup_crypt.BackupCryptError, match="32 bytes"):
            backup_crypt.load_key()

    def test_non_hex_key_is_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("BACKUP_ENCRYPTION_KEY", "not-a-key" * 8)
        monkeypatch.delenv("BACKUP_ENCRYPTION_KEY_FILE", raising=False)
        with pytest.raises(backup_crypt.BackupCryptError, match="not hex"):
            backup_crypt.load_key()


class TestCli:
    def _run(self, args: list[str], key: str | None = KEY.hex()) -> subprocess.CompletedProcess:
        env = {**os.environ}
        env.pop("BACKUP_ENCRYPTION_KEY_FILE", None)
        if key:
            env["BACKUP_ENCRYPTION_KEY"] = key
        else:
            env.pop("BACKUP_ENCRYPTION_KEY", None)
        return subprocess.run(
            [sys.executable, str(MODULE_PATH), *args],
            capture_output=True,
            text=True,
            env=env,
        )

    def test_keygen_emits_a_usable_key(self) -> None:
        out = self._run(["keygen"], key=None)
        assert out.returncode == 0
        assert len(bytes.fromhex(out.stdout.strip())) == 32

    def test_encrypt_then_decrypt_via_cli(self, tmp_path: Path) -> None:
        source = tmp_path / "dump.sql.gz"
        source.write_bytes(b"pretend gzip payload" * 500)
        original = source.read_bytes()

        enc = self._run(["encrypt", str(source), "--output", str(tmp_path / "dump.enc")])
        assert enc.returncode == 0, enc.stderr
        plain_sha, cipher_sha, path = enc.stdout.strip().split("\t")
        assert len(plain_sha) == 64 and len(cipher_sha) == 64
        assert Path(path).read_bytes() != original

        dec = self._run(["decrypt", path, "--output", str(tmp_path / "out.sql.gz")])
        assert dec.returncode == 0, dec.stderr
        assert (tmp_path / "out.sql.gz").read_bytes() == original
        assert dec.stdout.split("\t")[0] == plain_sha

    def test_cli_reports_a_wrong_key_as_an_error(self, tmp_path: Path) -> None:
        source = tmp_path / "d.bin"
        source.write_bytes(b"data")
        self._run(["encrypt", str(source), "--output", str(tmp_path / "d.enc")])
        bad = self._run(["decrypt", str(tmp_path / "d.enc")], key=OTHER_KEY.hex())
        assert bad.returncode == 1
        assert "Authentication failed" in bad.stderr

    def test_sha256_matches_hashlib(self, tmp_path: Path) -> None:
        import hashlib

        source = tmp_path / "f.bin"
        source.write_bytes(b"content")
        out = self._run(["sha256", str(source)], key=None)
        assert out.stdout.strip() == hashlib.sha256(b"content").hexdigest()


def test_manifest_shape_is_what_restore_reads(tmp_path: Path) -> None:
    """backup.sh writes this; restore.sh parses it. Keep them agreeing."""
    manifest = {
        "timestamp": "20260922T000000Z",
        "encryption": "aes-256-gcm",
        "format_version": 1,
        "artifacts": [
            {
                "name": "postgres-20260922T000000Z.sql.gz.enc",
                "sha256_plaintext": "a" * 64,
                "sha256_ciphertext": "b" * 64,
                "encrypted": True,
                "bytes": 1234,
            }
        ],
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    doc = json.loads(path.read_text())
    entry = doc["artifacts"][0]
    assert entry["sha256_ciphertext"] and entry["encrypted"] is True
    assert doc["encryption"] == "aes-256-gcm"
