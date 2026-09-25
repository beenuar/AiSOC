#!/usr/bin/env python3
"""Authenticated encryption for backup artifacts.

``scripts/backup.sh`` gzips a dump and uploads it. The architecture doc said
those artifacts were AES-256-GCM encrypted with a SHA-256 manifest; they were
not, so a bucket misconfiguration exposed every credential, token and event
row the platform had ever stored. This module is the missing half.

Why not ``openssl enc``: it refuses AEAD ciphers outright ("AEAD ciphers not
supported by the enc utility"), so the usual shell one-liner cannot produce
GCM. ``cryptography`` is already a dependency of services/api, so AESGCM is
available without adding one.

Format (little to gain from inventing more than needed):

    magic    8 bytes   b"AISOCBK1"
    version  1 byte    0x01
    prefix   8 bytes   random nonce prefix for this file
    chunks   repeated  4-byte big-endian plaintext length, then GCM output
                       (ciphertext || 16-byte tag)
    final    4 bytes   0x00000000, itself an authenticated empty chunk

Each chunk gets nonce ``prefix || counter`` (12 bytes total) and carries the
counter plus a final-chunk flag in its AAD. That buys three properties a
naive whole-file encrypt does not: chunks cannot be reordered, chunks cannot
be swapped between files, and a truncated file fails to decrypt rather than
silently returning a short but valid-looking dump. Truncation is the failure
that matters here, because a restore from a truncated backup looks like a
successful restore of a smaller database.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import secrets
import struct
import sys
from pathlib import Path
from typing import BinaryIO

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # pragma: no cover - surfaced as an actionable error below
    print(
        "backup_crypt: the 'cryptography' package is required.\n  pip install cryptography",
        file=sys.stderr,
    )
    raise SystemExit(2) from None

MAGIC = b"AISOCBK1"
VERSION = 1
CHUNK_SIZE = 4 * 1024 * 1024
KEY_BYTES = 32
TAG_BYTES = 16
_ENV_KEY = "BACKUP_ENCRYPTION_KEY"
_ENV_KEY_FILE = "BACKUP_ENCRYPTION_KEY_FILE"


class BackupCryptError(RuntimeError):
    """Raised for any key, format or authentication problem."""


def load_key() -> bytes:
    """Read the 32-byte key from the environment.

    Accepts 64 hex characters in ``BACKUP_ENCRYPTION_KEY`` or a path in
    ``BACKUP_ENCRYPTION_KEY_FILE`` (a file is preferable: an env var is
    visible in ``ps`` output and in most container introspection).
    """
    raw = os.environ.get(_ENV_KEY, "").strip()
    key_file = os.environ.get(_ENV_KEY_FILE, "").strip()

    if key_file:
        path = Path(key_file)
        if not path.is_file():
            raise BackupCryptError(f"{_ENV_KEY_FILE} points at a missing file: {key_file}")
        raw = path.read_text(encoding="utf-8").strip()

    if not raw:
        raise BackupCryptError(
            f"No backup encryption key. Set {_ENV_KEY} to 64 hex characters, or "
            f"{_ENV_KEY_FILE} to a file containing them. Generate one with:\n"
            f"  python3 scripts/backup_crypt.py keygen"
        )

    try:
        key = bytes.fromhex(raw)
    except ValueError as exc:
        raise BackupCryptError(f"Backup encryption key is not hex ({exc}). Expected 64 hex characters.") from exc

    if len(key) != KEY_BYTES:
        raise BackupCryptError(f"Backup encryption key must be {KEY_BYTES} bytes ({KEY_BYTES * 2} hex characters); got {len(key)}.")
    return key


def _aad(counter: int, *, final: bool) -> bytes:
    return MAGIC + bytes([VERSION]) + struct.pack(">I", counter) + (b"\x01" if final else b"\x00")


def encrypt_stream(src: BinaryIO, dst: BinaryIO, key: bytes) -> tuple[str, str, int]:
    """Encrypt ``src`` into ``dst``. Returns (plaintext sha256, ciphertext sha256, size)."""
    aead = AESGCM(key)
    prefix = secrets.token_bytes(8)

    plain_digest = hashlib.sha256()
    cipher_digest = hashlib.sha256()

    def emit(blob: bytes) -> None:
        dst.write(blob)
        cipher_digest.update(blob)

    emit(MAGIC + bytes([VERSION]) + prefix)

    counter = 0
    while True:
        chunk = src.read(CHUNK_SIZE)
        if not chunk:
            break
        plain_digest.update(chunk)
        nonce = prefix + struct.pack(">I", counter)
        sealed = aead.encrypt(nonce, chunk, _aad(counter, final=False))
        emit(struct.pack(">I", len(chunk)) + sealed)
        counter += 1

    # Authenticated end-of-stream marker, so truncation cannot pass as success.
    nonce = prefix + struct.pack(">I", counter)
    sealed = aead.encrypt(nonce, b"", _aad(counter, final=True))
    emit(struct.pack(">I", 0) + sealed)

    size = dst.tell() if dst.seekable() else -1
    return plain_digest.hexdigest(), cipher_digest.hexdigest(), size


def decrypt_stream(src: BinaryIO, dst: BinaryIO, key: bytes) -> str:
    """Decrypt ``src`` into ``dst``. Returns the plaintext sha256."""
    aead = AESGCM(key)

    header = src.read(len(MAGIC) + 1 + 8)
    if len(header) < len(MAGIC) + 1 + 8:
        raise BackupCryptError("File is too short to be an AiSOC backup artifact.")
    if header[: len(MAGIC)] != MAGIC:
        raise BackupCryptError(
            "Not an AiSOC encrypted backup (bad magic). If this artifact predates "
            "backup encryption, decrypt is not required — restore it directly."
        )
    version = header[len(MAGIC)]
    if version != VERSION:
        raise BackupCryptError(f"Unsupported backup format version {version}.")
    prefix = header[len(MAGIC) + 1 :]

    plain_digest = hashlib.sha256()
    counter = 0
    saw_final = False

    while True:
        raw_len = src.read(4)
        if not raw_len:
            break
        if len(raw_len) != 4:
            raise BackupCryptError("Truncated chunk header; the artifact is incomplete.")
        (length,) = struct.unpack(">I", raw_len)
        final = length == 0
        sealed = src.read(length + TAG_BYTES)
        if len(sealed) != length + TAG_BYTES:
            raise BackupCryptError("Truncated chunk body; the artifact is incomplete.")

        nonce = prefix + struct.pack(">I", counter)
        try:
            plain = aead.decrypt(nonce, sealed, _aad(counter, final=final))
        except InvalidTag as exc:
            raise BackupCryptError(
                f"Authentication failed on chunk {counter}. Either the key is wrong or the artifact was modified in transit or at rest."
            ) from exc

        if final:
            saw_final = True
            break
        plain_digest.update(plain)
        dst.write(plain)
        counter += 1

    if not saw_final:
        raise BackupCryptError(
            "Backup ended without its end-of-stream marker, so it is truncated. Restoring it would silently produce a partial database."
        )
    return plain_digest.hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(CHUNK_SIZE), b""):
            digest.update(block)
    return digest.hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("keygen", help="Print a fresh 256-bit key as hex.")

    enc = sub.add_parser("encrypt", help="Encrypt a file in place-adjacent (.enc).")
    enc.add_argument("source")
    enc.add_argument("--output", help="Defaults to <source>.enc")

    dec = sub.add_parser("decrypt", help="Decrypt a .enc artifact.")
    dec.add_argument("source")
    dec.add_argument("--output", help="Defaults to <source> without .enc")

    digest = sub.add_parser("sha256", help="Print the SHA-256 of a file.")
    digest.add_argument("source")

    args = parser.parse_args(argv)

    if args.command == "keygen":
        print(secrets.token_bytes(KEY_BYTES).hex())
        return 0

    if args.command == "sha256":
        print(sha256_file(Path(args.source)))
        return 0

    source = Path(args.source)
    if not source.is_file():
        print(f"backup_crypt: no such file: {source}", file=sys.stderr)
        return 2

    try:
        key = load_key()
        if args.command == "encrypt":
            target = Path(args.output) if args.output else source.with_suffix(source.suffix + ".enc")
            with source.open("rb") as src, target.open("wb") as dst:
                plain_sha, cipher_sha, _ = encrypt_stream(src, dst, key)
            # Emitted for the manifest that backup.sh assembles.
            print(f"{plain_sha}\t{cipher_sha}\t{target}")
        else:
            if args.output:
                target = Path(args.output)
            elif source.suffix == ".enc":
                target = source.with_suffix("")
            else:
                target = source.with_name(source.name + ".plain")
            with source.open("rb") as src, target.open("wb") as dst:
                plain_sha = decrypt_stream(src, dst, key)
            print(f"{plain_sha}\t{target}")
    except BackupCryptError as exc:
        print(f"backup_crypt: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
