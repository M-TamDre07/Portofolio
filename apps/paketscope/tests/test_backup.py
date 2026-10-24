import pytest

from paketscope.backup import decrypt_backup, encrypt_backup
from paketscope.services import PaketScopeService


def test_encrypted_backup_round_trip():
    rows = [{"name": "Browser", "version": "1.0", "source": "APT / dpkg"}]
    encrypted = encrypt_backup(rows, "a-unique-long-passphrase")
    assert b"Browser" not in encrypted
    assert decrypt_backup(encrypted, "a-unique-long-passphrase") == rows


def test_wrong_password_and_tampering_are_rejected():
    encrypted = encrypt_backup([{"name": "Editor"}], "a-unique-long-passphrase")
    with pytest.raises(ValueError, match="Kata sandi salah"):
        decrypt_backup(encrypted, "another-long-passphrase")
    changed = encrypted[:-1] + bytes([encrypted[-1] ^ 1])
    with pytest.raises(ValueError, match="Kata sandi salah"):
        decrypt_backup(changed, "a-unique-long-passphrase")


def test_short_passphrase_is_rejected():
    with pytest.raises(ValueError, match="minimal 12"):
        encrypt_backup([], "too-short")


def test_each_backup_uses_fresh_random_salt_and_nonce():
    rows = [{"name": "Editor"}]
    first = encrypt_backup(rows, "a-unique-long-passphrase")
    second = encrypt_backup(rows, "a-unique-long-passphrase")
    assert first != second
    assert decrypt_backup(first, "a-unique-long-passphrase") == rows
    assert decrypt_backup(second, "a-unique-long-passphrase") == rows


def test_oversized_backup_is_rejected_before_decryption(monkeypatch):
    monkeypatch.setattr("paketscope.backup.MAX_BACKUP_BYTES", 64)

    with pytest.raises(ValueError, match="batas maksimum 64 MiB"):
        decrypt_backup(b"x" * 65, "a-unique-long-passphrase")


def test_service_rejects_oversized_backup_before_reading_contents(tmp_path, monkeypatch):
    monkeypatch.setattr("paketscope.services.MAX_BACKUP_BYTES", 64)
    path = tmp_path / "oversized.psbackup"
    path.write_bytes(b"x" * 65)

    with pytest.raises(ValueError, match="batas maksimum 64 MiB"):
        PaketScopeService().restore_backup(path, "a-unique-long-passphrase")


def test_service_rejects_non_regular_backup_path(tmp_path):
    with pytest.raises(ValueError, match="file reguler"):
        PaketScopeService().restore_backup(tmp_path, "a-unique-long-passphrase")
