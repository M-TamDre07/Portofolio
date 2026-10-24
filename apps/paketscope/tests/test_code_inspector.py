import struct

import pytest

from paketscope import code_inspector
from paketscope.code_inspector import (
    CodeInspectionError,
    inspect_code_path,
    read_inspected_source,
)


def test_python_source_analysis_reports_imports_symbols_and_hash(tmp_path):
    source = tmp_path / "app.py"
    source.write_text(
        "import json\nfrom pathlib import Path\n\n"
        "class Scanner:\n    pass\n\n"
        "def inspect_system():\n    return json.dumps(Path('.').name)\n",
        encoding="utf-8",
    )

    report = inspect_code_path(source)

    assert report.scanned_files == 1
    file = report.files[0]
    assert file.language == "Python"
    assert file.line_count == 8
    assert "json" in file.imports
    assert "pathlib" in file.imports
    assert {"Scanner", "inspect_system"}.issubset(set(file.symbols))
    assert len(file.sha256) == 64
    assert "import json" in read_inspected_source(source)


def test_inspection_does_not_execute_user_code(tmp_path):
    marker = tmp_path / "executed.txt"
    source = tmp_path / "sample.py"
    source.write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('unsafe')\n",
        encoding="utf-8",
    )

    report = inspect_code_path(source)

    assert report.scanned_files == 1
    assert not marker.exists()


def test_folder_scan_excludes_secret_names_symlinks_and_build_caches(tmp_path):
    app = tmp_path / "app.py"
    app.write_text("def main():\n    return 0\n", encoding="utf-8")
    (tmp_path / ".env").write_text("TOKEN=do-not-show", encoding="utf-8")
    (tmp_path / "id_rsa").write_text("private key", encoding="utf-8")
    cache = tmp_path / ".venv"
    cache.mkdir()
    (cache / "cached.py").write_text("def cached(): pass\n", encoding="utf-8")
    (tmp_path / "link.py").symlink_to(app)

    report = inspect_code_path(tmp_path)

    relative_paths = {item.path for item in report.files}
    assert relative_paths == {"app.py"}
    assert report.skipped_files >= 3
    assert all("TOKEN" not in item.path for item in report.files)


def test_selected_sensitive_file_and_symlink_root_are_rejected(tmp_path):
    secret = tmp_path / ".env.production"
    secret.write_text("SECRET=value", encoding="utf-8")
    alias = tmp_path / "alias.py"
    alias.symlink_to(secret)

    with pytest.raises(CodeInspectionError, match="rahasia"):
        inspect_code_path(secret)
    with pytest.raises(CodeInspectionError, match="symlink"):
        inspect_code_path(alias)


def test_large_file_is_skipped_without_loading_unbounded_content(tmp_path, monkeypatch):
    large = tmp_path / "large.py"
    large.write_bytes(b"x" * 100)
    monkeypatch.setattr(code_inspector, "MAX_FILE_BYTES", 32)

    report = inspect_code_path(large)

    assert report.scanned_files == 0
    assert report.skipped_files == 1
    assert "melebihi batas" in report.diagnostics[0]


def test_elf_binary_reports_metadata_without_disassembly(tmp_path):
    binary = tmp_path / "local-program"
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4] = 2
    header[5] = 1
    struct.pack_into("<H", header, 18, 62)
    binary.write_bytes(header)

    report = inspect_code_path(binary)

    assert report.scanned_files == 1
    item = report.files[0]
    assert item.kind == "ELF binary"
    assert "ELF64" in item.notes[0]
    assert "x86_64" in item.notes[0]
    assert "dijalankan" in item.notes[1]


def test_whole_root_and_pseudo_filesystems_are_not_scanned(tmp_path):
    for path in ("/", "/proc", "/sys", "/dev", "/run"):
        with pytest.raises(CodeInspectionError, match="pseudo-filesystem"):
            inspect_code_path(path)


def test_python_static_review_flags_dynamic_execution_shell_deserialization_and_network(tmp_path):
    source = tmp_path / "review.py"
    source.write_text(
        "import subprocess, pickle, requests\n"
        "def review(value):\n"
        "    eval(value)\n"
        "    subprocess.run(value, shell=True)\n"
        "    pickle.loads(value)\n"
        "    requests.get('https://example.invalid')\n",
        encoding="utf-8",
    )

    report = inspect_code_path(source)
    findings = {(item.rule_id, item.line) for item in report.files[0].findings}

    assert ("dynamic-execution", 3) in findings
    assert ("subprocess-shell", 4) in findings
    assert ("unsafe-deserialization", 5) in findings
    assert ("network-access", 6) in findings
    assert all(item.line > 0 for item in report.files[0].findings)
    assert len(report.files[0].findings) <= 80


def test_code_inspector_skips_sensitive_directory_and_rejects_viewer_access(tmp_path):
    private_store = tmp_path / ".aws"
    private_store.mkdir()
    config = private_store / "config"
    config.write_text("aws_access_key_id=not-for-display", encoding="utf-8")
    ordinary = tmp_path / "module.py"
    ordinary.write_text("def safe():\n    return True\n", encoding="utf-8")

    report = inspect_code_path(tmp_path)

    assert {item.path for item in report.files} == {"module.py"}
    with pytest.raises(CodeInspectionError, match="rahasia|lokasi"):
        inspect_code_path(config)
    with pytest.raises(CodeInspectionError, match="rahasia|lokasi"):
        read_inspected_source(config)


def test_non_python_source_reports_shell_and_dynamic_execution_review_hints(tmp_path):
    source = tmp_path / "sample.js"
    source.write_text(
        "const value = eval(input);\nconst options = { shell: true };\n",
        encoding="utf-8",
    )

    report = inspect_code_path(source)

    assert {item.rule_id for item in report.files[0].findings} == {
        "dynamic-execution", "shell-execution",
    }


def test_python_safe_yaml_loader_does_not_create_unsafe_deserialization_hint(tmp_path):
    source = tmp_path / "safe_yaml.py"
    source.write_text(
        "import yaml\n"
        "def parse(payload):\n"
        "    return yaml.load(payload, Loader=yaml.SafeLoader)\n",
        encoding="utf-8",
    )

    report = inspect_code_path(source)

    assert "yaml-deserialization" not in {
        item.rule_id for item in report.files[0].findings
    }


def test_folder_scan_enforces_total_bytes_budget(tmp_path, monkeypatch):
    (tmp_path / "a.py").write_text("def first(): return 1\\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("def second(): return 2\\n", encoding="utf-8")
    monkeypatch.setattr(code_inspector, "MAX_TOTAL_BYTES", 24)

    report = inspect_code_path(tmp_path)

    assert report.scanned_files == 1
    assert report.skipped_files == 1
    assert any("Batas data total" in note for note in report.diagnostics)
