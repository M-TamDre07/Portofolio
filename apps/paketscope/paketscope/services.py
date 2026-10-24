"""Application services used by the native PaketScope frontend.

This module is the use-case boundary between Qt widgets and lower-level OS,
domain, encryption, and filesystem adapters. It intentionally has no network
client, account system, telemetry, or package-mutating operations.
"""
from __future__ import annotations

import csv
import io
import json
import os
import stat
from pathlib import Path
from typing import Any, Iterable

from .backup import MAX_BACKUP_BYTES, decrypt_backup, encrypt_backup
from .collectors import collect_inventory
from .domain import InstalledApplication, InventorySnapshot
from .exporting import csv_safe_record, write_private_file
from .updates import UpdateCheckResult, check_updates


class PaketScopeService:
    """Coordinate safe, local use cases for the desktop application."""

    def scan_inventory(self) -> InventorySnapshot:
        """Collect the supported local package inventory."""
        return collect_inventory()

    def check_updates(self) -> UpdateCheckResult:
        """Check updates only when explicitly requested by the user."""
        return check_updates()

    def export_csv(
        self,
        applications: Iterable[InstalledApplication],
        destination: str | Path,
    ) -> int:
        """Export the supplied (normally filtered/visible) rows as safe CSV."""
        rows = tuple(applications)
        if not rows:
            raise ValueError("Tidak ada aplikasi yang dapat diekspor.")
        buffer = io.StringIO(newline="")
        writer = csv.DictWriter(buffer, fieldnames=list(rows[0].to_record().keys()))
        writer.writeheader()
        writer.writerows(csv_safe_record(row.to_record()) for row in rows)
        write_private_file(destination, buffer.getvalue().encode("utf-8-sig"))
        return len(rows)

    def create_encrypted_backup(
        self,
        applications: Iterable[InstalledApplication],
        destination: str | Path,
        passphrase: str,
    ) -> int:
        """Create an authenticated encrypted backup without persisting secrets."""
        rows = tuple(applications)
        if not rows:
            raise ValueError("Pindai inventaris sebelum membuat cadangan.")
        records = [application.to_record() for application in rows]
        write_private_file(destination, encrypt_backup(records, passphrase))
        return len(records)

    def restore_backup(
        self,
        source: str | Path,
        passphrase: str,
    ) -> list[dict[str, Any]]:
        """Read a bounded regular backup file and decrypt it without executing contents."""
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(source, flags)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("Cadangan harus berupa file reguler, bukan direktori atau perangkat.")
            if info.st_size > MAX_BACKUP_BYTES:
                raise ValueError("Cadangan melebihi batas maksimum 64 MiB.")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                blob = handle.read(MAX_BACKUP_BYTES + 1)
            if len(blob) > MAX_BACKUP_BYTES:
                raise ValueError("Ukuran cadangan berubah atau melewati batas maksimum 64 MiB.")
        finally:
            os.close(descriptor)
        return decrypt_backup(blob, passphrase)

    def export_restored_json(
        self,
        destination: str | Path,
        records: list[dict[str, Any]],
    ) -> int:
        """Write restored records as explicitly requested, unencrypted JSON."""
        if not isinstance(records, list) or not all(isinstance(row, dict) for row in records):
            raise ValueError("Struktur inventaris untuk diekspor tidak valid.")
        payload = json.dumps(records, ensure_ascii=False, indent=2).encode("utf-8")
        write_private_file(destination, payload)
        return len(records)
