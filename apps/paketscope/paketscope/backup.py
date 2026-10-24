"""Authenticated encrypted JSON backups for inventory metadata."""
from __future__ import annotations

import json
import secrets
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"PAKETSCOPE-ENC-BACKUP-V1\n"
AAD = b"PaketScope encrypted inventory backup v1"
SALT_BYTES = 16
NONCE_BYTES = 12
KEY_BYTES = 32
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
MAX_BACKUP_BYTES = 64 * 1024 * 1024


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    if len(passphrase) < 12:
        raise ValueError("Kata sandi cadangan minimal 12 karakter.")
    kdf = Scrypt(salt=salt, length=KEY_BYTES, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_backup(records: list[dict[str, Any]], passphrase: str) -> bytes:
    plaintext = json.dumps(
        {"format": 1, "application": "PaketScope", "records": records},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    estimated_size = len(MAGIC) + SALT_BYTES + NONCE_BYTES + len(plaintext) + 16
    if estimated_size > MAX_BACKUP_BYTES:
        raise ValueError("Cadangan melebihi batas maksimum 64 MiB.")
    salt = secrets.token_bytes(SALT_BYTES)
    nonce = secrets.token_bytes(NONCE_BYTES)
    key = _derive_key(passphrase, salt)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, AAD)
    return MAGIC + salt + nonce + ciphertext


def decrypt_backup(blob: bytes, passphrase: str) -> list[dict[str, Any]]:
    if len(blob) > MAX_BACKUP_BYTES:
        raise ValueError("Cadangan melebihi batas maksimum 64 MiB.")
    minimum = len(MAGIC) + SALT_BYTES + NONCE_BYTES + 16
    if not blob.startswith(MAGIC) or len(blob) < minimum:
        raise ValueError("Format cadangan tidak dikenali atau berkas rusak.")
    offset = len(MAGIC)
    salt = blob[offset:offset + SALT_BYTES]
    nonce_start = offset + SALT_BYTES
    nonce = blob[nonce_start:nonce_start + NONCE_BYTES]
    ciphertext = blob[nonce_start + NONCE_BYTES:]
    key = _derive_key(passphrase, salt)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, AAD)
    except InvalidTag as exc:
        raise ValueError("Kata sandi salah atau isi cadangan telah diubah.") from exc
    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Isi cadangan tidak valid.") from exc
    if not isinstance(payload, dict):
        raise ValueError("Struktur cadangan tidak valid.")
    if payload.get("format") != 1 or payload.get("application") != "PaketScope":
        raise ValueError("Versi format cadangan tidak didukung.")
    records = payload.get("records")
    if not isinstance(records, list) or not all(isinstance(row, dict) for row in records):
        raise ValueError("Daftar aplikasi dalam cadangan tidak valid.")
    return records
