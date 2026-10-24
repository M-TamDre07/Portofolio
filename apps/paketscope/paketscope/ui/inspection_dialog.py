"""Native UI for local system and source-code inspection."""
from __future__ import annotations

import json
from typing import Callable

from PySide6.QtCore import Qt, Slot
from PySide6.QtWidgets import (
    QDialog, QFileDialog, QHBoxLayout, QLabel, QMessageBox, QPushButton,
    QPlainTextEdit, QTableWidget, QTableWidgetItem, QTabWidget, QVBoxLayout,
    QWidget,
)

from ..code_inspector import (
    CodeFileAnalysis, CodeInspectionReport, inspect_code_path, read_inspected_source,
)
from ..system_inspector import (
    collect_system_snapshot,
    run_privileged_metadata_inspection,
    run_privileged_text_file_read,
)
from .workers import Worker


class InspectionDialog(QDialog):
    """Read-only tools for understanding the host and locally selected code."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("PaketScope · System & Code Lab")
        self.setMinimumSize(920, 680)
        self.resize(1120, 800)
        self.admin_mode_enabled = False
        self.worker: Worker | None = None
        self._pending_handler: Callable[[object], None] | None = None
        self._busy_message = ""
        self._files: tuple[CodeFileAnalysis, ...] = ()

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 16, 18, 16)
        root.setSpacing(10)

        title = QLabel("System & Code Lab")
        title.setObjectName("title")
        description = QLabel(
            "Eksplorasi sistem lokal dan analisis statis kode yang kamu pilih. "
            "Semua hasil diproses lokal; kode tidak dijalankan dan tidak dikirim ke jaringan."
        )
        description.setObjectName("body-muted")
        description.setWordWrap(True)
        root.addWidget(title)
        root.addWidget(description)

        self.tabs = QTabWidget()
        self.system_tab = self._build_system_tab()
        self.code_tab = self._build_code_tab()
        self.tabs.addTab(self.system_tab, "Sistem Linux")
        self.tabs.addTab(self.code_tab, "Code Inspector")
        root.addWidget(self.tabs, 1)

        footer = QLabel(
            "READ-ONLY BY DEFAULT · NO TELEMETRY · POLKIT PER AKSI · "
            "TIDAK ADA SHELL ROOT UMUM"
        )
        footer.setObjectName("mono")
        footer.setWordWrap(True)
        root.addWidget(footer)

    def _build_system_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(8, 10, 8, 8)
        layout.setSpacing(8)

        explanation = QLabel(
            "Pemeriksaan dasar membaca informasi OS, kernel, CPU, RAM, storage, "
            "mount-level summary, layanan systemd, dan susunan direktori. Mode administrator "
            "dapat melihat metadata pada lokasi sistem yang dibatasi atau membaca satu file "
            "teks pilihan setelah persetujuan dan otorisasi Polkit. File rahasia dan biner "
            "ditolak; tidak ada perubahan sistem."
        )
        explanation.setWordWrap(True)
        explanation.setObjectName("body-muted")
        layout.addWidget(explanation)

        controls = QHBoxLayout()
        self.system_scan_button = QPushButton("Pindai sistem (read-only)")
        self.system_scan_button.clicked.connect(self.scan_system)
        controls.addWidget(self.system_scan_button)

        self.admin_toggle_button = QPushButton("Aktifkan mode Administrator")
        self.admin_toggle_button.setObjectName("secondary")
        self.admin_toggle_button.setToolTip(
            "Mode sementara untuk membuka pemeriksaan metadata yang memerlukan otorisasi Polkit."
        )
        self.admin_toggle_button.clicked.connect(self.toggle_admin_mode)
        controls.addWidget(self.admin_toggle_button)

        self.admin_scan_button = QPushButton("Inspeksi metadata terlindungi…")
        self.admin_scan_button.setObjectName("secondary")
        self.admin_scan_button.setEnabled(False)
        self.admin_scan_button.setToolTip(
            "Hanya metadata direktori/file dari allowlist tetap; otorisasi Polkit diminta untuk setiap pemindaian."
        )
        self.admin_scan_button.clicked.connect(self.scan_protected_metadata)
        controls.addWidget(self.admin_scan_button)

        self.admin_read_button = QPushButton("Baca file sistem…")
        self.admin_read_button.setObjectName("secondary")
        self.admin_read_button.setEnabled(False)
        self.admin_read_button.setToolTip(
            "Baca satu file teks dari allowlist sistem dengan batas 256 KiB; butuh konfirmasi dan Polkit."
        )
        self.admin_read_button.clicked.connect(self.read_system_text_file)
        controls.addWidget(self.admin_read_button)
        controls.addStretch(1)
        layout.addLayout(controls)

        self.system_status = QLabel("Pemeriksaan belum dijalankan.")
        self.system_status.setObjectName("body-muted")
        layout.addWidget(self.system_status)

        self.system_output = QPlainTextEdit()
        self.system_output.setReadOnly(True)
        self.system_output.setPlaceholderText(
            "Klik “Pindai sistem” untuk melihat ringkasan OS dan direktori."
        )
        self.system_output.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        layout.addWidget(self.system_output, 1)
        return page

    def _build_code_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(8, 10, 8, 8)
        layout.setSpacing(8)

        controls = QHBoxLayout()
        self.choose_folder_button = QPushButton("Analisis folder aplikasi…")
        self.choose_folder_button.clicked.connect(self.choose_code_folder)
        controls.addWidget(self.choose_folder_button)

        self.choose_file_button = QPushButton("Analisis satu file…")
        self.choose_file_button.setObjectName("secondary")
        self.choose_file_button.clicked.connect(self.choose_code_file)
        controls.addWidget(self.choose_file_button)

        self.code_status = QLabel("Pilih folder project atau satu file kode lokal.")
        self.code_status.setObjectName("body-muted")
        self.code_status.setWordWrap(True)
        controls.addWidget(self.code_status, 1)
        layout.addLayout(controls)

        self.code_table = QTableWidget(0, 5)
        self.code_table.setHorizontalHeaderLabels(["File", "Bahasa", "Jenis", "Baris", "Ukuran"])
        self.code_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.code_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.code_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.code_table.setAlternatingRowColors(True)
        self.code_table.verticalHeader().setVisible(False)
        self.code_table.horizontalHeader().setStretchLastSection(True)
        self.code_table.setColumnWidth(0, 330)
        self.code_table.setColumnWidth(1, 125)
        self.code_table.setColumnWidth(2, 115)
        self.code_table.setColumnWidth(3, 70)
        self.code_table.setColumnWidth(4, 90)
        self.code_table.itemSelectionChanged.connect(self.show_selected_file)
        layout.addWidget(self.code_table, 2)

        self.detail_tabs = QTabWidget()
        self.analysis_output = QPlainTextEdit()
        self.analysis_output.setReadOnly(True)
        self.analysis_output.setPlaceholderText(
            "Pilih sebuah file pada tabel untuk melihat ringkasan, hash, import, dan simbol."
        )
        self.detail_tabs.addTab(self.analysis_output, "Temuan")
        self.source_output = QPlainTextEdit()
        self.source_output.setReadOnly(True)
        self.source_output.setPlaceholderText(
            "Source code teks dari file terpilih akan ditampilkan di sini; tidak pernah dieksekusi."
        )
        self.source_output.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.detail_tabs.addTab(self.source_output, "Source (read-only)")
        layout.addWidget(self.detail_tabs, 2)
        return page

    def _set_busy(self, busy: bool, message: str = "") -> None:
        for button in (
            self.system_scan_button, self.admin_toggle_button, self.admin_scan_button,
            self.admin_read_button, self.choose_folder_button, self.choose_file_button,
        ):
            button.setEnabled(not busy)
        self.admin_scan_button.setEnabled(not busy and self.admin_mode_enabled)
        self.admin_read_button.setEnabled(not busy and self.admin_mode_enabled)
        if message:
            self._busy_message = message
            if self.tabs.currentWidget() is self.system_tab:
                self.system_status.setText(message)
            else:
                self.code_status.setText(message)

    def _start_task(
        self,
        message: str,
        function: Callable[[], object],
        on_result: Callable[[object], None],
    ) -> None:
        if self.worker is not None:
            return
        self._set_busy(True, message)
        worker = Worker(function)
        self.worker = worker
        self._pending_handler = on_result
        worker.signals.result.connect(self._worker_result, Qt.ConnectionType.QueuedConnection)
        worker.signals.error.connect(self._worker_failed, Qt.ConnectionType.QueuedConnection)
        from PySide6.QtCore import QThreadPool
        QThreadPool.globalInstance().start(worker)

    @Slot(object)
    def _worker_result(self, value: object) -> None:
        self.worker = None
        handler = self._pending_handler
        self._pending_handler = None
        self._set_busy(False)
        if handler is not None:
            handler(value)

    @Slot(str)
    def _worker_failed(self, error: str) -> None:
        self.worker = None
        self._pending_handler = None
        self._set_busy(False)
        QMessageBox.warning(self, "System & Code Lab", error)

    @Slot()
    def scan_system(self) -> None:
        self._start_task("Membaca snapshot sistem lokal…", collect_system_snapshot, self._system_ready)

    def _system_ready(self, value: object) -> None:
        if not isinstance(value, dict):
            QMessageBox.warning(self, "Inspeksi sistem", "Hasil inspeksi tidak valid.")
            return
        self.system_output.setPlainText(json.dumps(value, ensure_ascii=False, indent=2))
        self.system_status.setText(
            f"Snapshot selesai · mode read-only · {value.get('collected_at', '')}"
        )

    @Slot()
    def toggle_admin_mode(self) -> None:
        if self.admin_mode_enabled:
            self.admin_mode_enabled = False
            self.admin_toggle_button.setText("Aktifkan mode Administrator")
            self.admin_scan_button.setEnabled(False)
            self.admin_read_button.setEnabled(False)
            self.system_status.setText("Mode administrator dimatikan untuk sesi ini.")
            return

        message = (
            "Aktifkan mode administrator untuk sesi aplikasi ini?\n\n"
            "• Mode ini tidak menjalankan seluruh aplikasi sebagai root.\n"
            "• Metadata dibatasi ke direktori sistem tertentu dan jumlah entri.\n"
            "• Kamu dapat meminta pembacaan satu file teks pilihan (maksimum 256 KiB); "
            "file rahasia, symlink, dan biner ditolak.\n"
            "• Setiap pemindaian atau pembacaan file meminta otorisasi Polkit tersendiri.\n"
            "• Tidak ada perubahan sistem atau perintah shell bebas.\n\n"
            "Mode ini hanya tersedia dari paket Debian terpasang yang helper-nya tepercaya."
        )
        response = QMessageBox.warning(
            self, "Persetujuan mode Administrator", message,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if response != QMessageBox.StandardButton.Yes:
            return
        self.admin_mode_enabled = True
        self.admin_toggle_button.setText("Matikan mode Administrator")
        self.admin_scan_button.setEnabled(True)
        self.admin_read_button.setEnabled(True)
        self.system_status.setText(
            "Mode Administrator aktif untuk sesi ini. Otorisasi Polkit tetap diperlukan setiap kali."
        )

    @Slot()
    def scan_protected_metadata(self) -> None:
        if not self.admin_mode_enabled:
            QMessageBox.information(
                self, "Mode administrator belum aktif",
                "Aktifkan mode Administrator secara eksplisit terlebih dahulu.",
            )
            return
        response = QMessageBox.warning(
            self, "Setujui pemeriksaan terlindungi",
            "PaketScope akan meminta autentikasi Polkit untuk membaca metadata saja. "
            "Operasi hanya membaca metadata path, izin, pemilik, dan ukuran; file tidak diubah. "
            "Lanjutkan?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if response != QMessageBox.StandardButton.Yes:
            return
        self._start_task(
            "Meminta otorisasi Polkit untuk metadata read-only…",
            run_privileged_metadata_inspection,
            self._admin_metadata_ready,
        )

    @Slot()
    def read_system_text_file(self) -> None:
        if not self.admin_mode_enabled:
            QMessageBox.information(
                self, "Mode administrator belum aktif",
                "Aktifkan mode Administrator secara eksplisit terlebih dahulu.",
            )
            return
        path, _ = QFileDialog.getOpenFileName(
            self, "Pilih file teks sistem (read-only)", "/etc",
            "File teks dan konfigurasi (*);;Semua file (*)",
        )
        if not path:
            return
        response = QMessageBox.warning(
            self, "Setujui pembacaan file sistem",
            f"File yang dipilih:\n{path}\n\n"
            "PaketScope akan meminta autentikasi Polkit untuk membaca satu file teks "
            "dengan batas 256 KiB dari direktori sistem yang diizinkan. File rahasia, "
            "symlink, file biner, dan file di luar allowlist ditolak. Tidak ada file "
            "yang diubah dan kode tidak dijalankan. Lanjutkan?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if response != QMessageBox.StandardButton.Yes:
            return
        self._start_task(
            "Meminta otorisasi Polkit untuk membaca file teks terpilih…",
            lambda: run_privileged_text_file_read(path),
            self._system_text_file_ready,
        )

    def _system_text_file_ready(self, value: object) -> None:
        if not isinstance(value, dict) or value.get("scope") != "selected-text-file-read-only":
            QMessageBox.warning(self, "Pembacaan file sistem", "Format hasil tidak valid.")
            return
        file_path = str(value.get("path", ""))
        content = value.get("content")
        if not isinstance(content, str):
            QMessageBox.warning(self, "Pembacaan file sistem", "Konten file tidak valid.")
            return
        self.system_output.setPlainText(
            f"FILE SISTEM (READ-ONLY): {file_path}\n"
            f"Ukuran: {value.get('size_bytes', 0)} byte\n"
            "Catatan: file tidak diubah; kode tidak dijalankan.\n"
            "========================================\n\n"
            + content
        )
        self.system_status.setText(
            f"File teks berhasil dibaca · {file_path} · tidak ada perubahan sistem"
        )

    def _admin_metadata_ready(self, value: object) -> None:
        if not isinstance(value, dict) or value.get("scope") != "metadata-only":
            QMessageBox.warning(self, "Inspeksi administrator", "Format hasil tidak valid.")
            return
        self.system_output.setPlainText(json.dumps(value, ensure_ascii=False, indent=2))
        count = len(value.get("entries", []))
        self.system_status.setText(
            f"Metadata terlindungi selesai · {count} entri · isi file tidak dibaca"
        )

    @Slot()
    def choose_code_folder(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Pilih folder project lokal")
        if path:
            self._inspect_selected_path(path)

    @Slot()
    def choose_code_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Pilih satu file kode lokal")
        if path:
            self._inspect_selected_path(path)

    def _inspect_selected_path(self, path: str) -> None:
        self._start_task(
            f"Analisis statis lokal: {path}",
            lambda: inspect_code_path(path),
            self._code_report_ready,
        )

    def _code_report_ready(self, value: object) -> None:
        if not isinstance(value, CodeInspectionReport):
            QMessageBox.warning(self, "Code Inspector", "Laporan analisis tidak valid.")
            return
        self._files = value.files
        self.code_table.setRowCount(0)
        for index, item in enumerate(self._files):
            self.code_table.insertRow(index)
            row_values = (
                item.path, item.language, item.kind, str(item.line_count),
                f"{item.size_bytes:,} B",
            )
            for column, text in enumerate(row_values):
                cell = QTableWidgetItem(text)
                cell.setData(Qt.ItemDataRole.UserRole, index)
                self.code_table.setItem(index, column, cell)
        language_summary = ", ".join(
            f"{name}: {count}" for name, count in value.languages[:8]
        ) or "tidak ada file kode yang dikenali"
        finding_count = sum(len(item.findings) for item in value.files)
        self.code_status.setText(
            f"{value.root} · {value.scanned_files} file dianalisis · "
            f"{value.skipped_files} dilewati · {finding_count} pola untuk ditinjau · {language_summary}"
        )
        if value.diagnostics:
            self.code_status.setToolTip("\n".join(value.diagnostics[:20]))
        self.analysis_output.setPlainText(
            "Laporan analisis\n"
            f"Root: {value.root}\n"
            f"Dibuat: {value.created_at}\n"
            f"File dianalisis: {value.scanned_files}\n"
            f"File dilewati: {value.skipped_files}\n"
            "Batas: maksimum 2.500 file, 12 level direktori, 2 MiB per file, 128 MiB data total.\n"
            "Folder build/cache, symlink, dan nama file yang menyerupai rahasia dikecualikan.\n"
            "Tidak ada kode yang dijalankan; analisis biner hanya membaca metadata ELF/hash."
        )
        self.source_output.clear()
        if self._files:
            self.code_table.selectRow(0)
        elif value.diagnostics:
            self.analysis_output.appendPlainText("\nCatatan:\n" + "\n".join(value.diagnostics[:30]))

    @Slot()
    def show_selected_file(self) -> None:
        row = self.code_table.currentRow()
        if not (0 <= row < len(self._files)):
            return
        item = self._files[row]
        detail = [
            f"File: {item.path}",
            f"Jenis: {item.kind}",
            f"Bahasa: {item.language}",
            f"Ukuran: {item.size_bytes} byte",
            f"Jumlah baris: {item.line_count}",
            f"SHA-256: {item.sha256}",
            "",
            "Import/dependency yang terdeteksi:",
            *([f"  • {name}" for name in item.imports] or ["  (tidak terdeteksi / bukan source teks)"]),
            "",
            "Fungsi/kelas/simbol yang terdeteksi:",
            *([f"  • {name}" for name in item.symbols] or ["  (tidak terdeteksi / bukan source teks)"]),
            "",
            "Pola statis untuk ditinjau (bukan vonis kerentanan):",
            *([
                f"  • Baris {finding.line} [{finding.rule_id}] {finding.message}"
                for finding in item.findings
            ] or ["  • Tidak ada pola yang cocok dengan aturan terbatas ini. Ini bukan bukti bahwa kode bebas kerentanan."]),
            "",
            "Catatan:",
            *[f"  • {note}" for note in item.notes],
        ]
        self.analysis_output.setPlainText("\n".join(detail))
        try:
            source = read_inspected_source(item.full_path)
        except (OSError, ValueError):
            source = "Source teks tidak tersedia untuk file ini. Jika biner, hanya metadata dan hash yang dianalisis."
        self.source_output.setPlainText(source)
        self.detail_tabs.setCurrentIndex(0)
