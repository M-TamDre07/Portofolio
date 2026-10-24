"""Local, read-only source and ELF metadata inspection.

No inspected code is executed, no network is used, and likely secret files are
excluded by default. The analyzer is intentionally bounded for desktop safety.
"""
from __future__ import annotations

import ast
import hashlib
import os
from itertools import islice
import re
import stat
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

MAX_FILES = 2500
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_DEPTH = 12
MAX_DIRECTORIES = 10000
MAX_ENTRIES = 20000
MAX_DIAGNOSTICS = 100

IGNORED_DIRS = frozenset({
    ".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".tox", "dist", "build", "target", ".next", ".cache",
})
# Avoid traversing or previewing common private credential stores even when the
# selected file itself has an innocuous name such as "config" or "settings".
SENSITIVE_DIRS = frozenset({
    ".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker", ".pki",
    "private", "secrets", "credentials", "credential",
    "system-connections", "sudoers.d", "credstore",
})
SECRET_NAMES = frozenset({
    "credentials", "credentials.json", "secrets", "secrets.json",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "authorized_keys",
    "known_hosts", "shadow", "gshadow", "master.passwd", "auth.conf",
    "netrc", ".netrc",
})
SECRET_SUFFIXES = frozenset({".pem", ".key", ".p12", ".pfx", ".keystore", ".kdbx"})
TEXT_SUFFIXES = frozenset({
    ".py", ".pyw", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
    ".c", ".h", ".cc", ".cpp", ".hpp", ".hh", ".rs", ".go", ".java",
    ".kt", ".kts", ".sh", ".bash", ".zsh", ".php", ".rb", ".pl", ".lua",
    ".sql", ".html", ".htm", ".css", ".json", ".toml", ".yaml", ".yml",
    ".xml", ".desktop", ".ini", ".conf", ".service", ".md", ".txt",
    ".swift", ".cs", ".dart", ".ex", ".exs", ".erl", ".hs", ".vue",
    ".svelte", ".gradle", ".properties", ".make",
})
TEXT_FILENAMES = frozenset({
    "makefile", "dockerfile", "containerfile", "cmakelists.txt",
    "requirements.txt", "pipfile", "gemfile", "cargo.lock",
    "package.json", "pyproject.toml", "go.mod", "go.sum",
})
LANGUAGE_BY_SUFFIX = {
    ".py": "Python", ".pyw": "Python", ".js": "JavaScript", ".mjs": "JavaScript",
    ".cjs": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript",
    ".jsx": "JavaScript/JSX", ".c": "C", ".h": "C/C++ header",
    ".cc": "C++", ".cpp": "C++", ".hpp": "C++ header", ".hh": "C++ header",
    ".rs": "Rust", ".go": "Go", ".java": "Java", ".kt": "Kotlin",
    ".kts": "Kotlin", ".sh": "Shell", ".bash": "Shell", ".zsh": "Shell",
    ".php": "PHP", ".rb": "Ruby", ".pl": "Perl", ".lua": "Lua",
    ".sql": "SQL", ".html": "HTML", ".htm": "HTML", ".css": "CSS",
    ".json": "JSON", ".toml": "TOML", ".yaml": "YAML", ".yml": "YAML",
    ".xml": "XML", ".desktop": "Desktop entry", ".ini": "INI",
    ".conf": "Configuration", ".service": "systemd unit", ".md": "Markdown",
    ".txt": "Text", ".swift": "Swift", ".cs": "C#", ".dart": "Dart",
    ".ex": "Elixir", ".exs": "Elixir", ".erl": "Erlang", ".hs": "Haskell",
    ".vue": "Vue", ".svelte": "Svelte", ".gradle": "Gradle",
    ".properties": "Java properties", ".make": "Makefile",
}
SYMBOL_PATTERNS = (
    re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)", re.MULTILINE),
    re.compile(r"^\s*class\s+([A-Za-z_]\w*)", re.MULTILINE),
    re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)", re.MULTILINE),
    re.compile(r"^\s*(?:export\s+)?class\s+([A-Za-z_$][\w$]*)", re.MULTILINE),
    re.compile(r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_]\w*)", re.MULTILINE),
    re.compile(r"^\s*(?:pub\s+)?struct\s+([A-Za-z_]\w*)", re.MULTILINE),
    re.compile(r"^\s*(?:static\s+)?(?:int|void|char|bool|long|float|double)\s+([A-Za-z_]\w*)\s*\(", re.MULTILINE),
)
IMPORT_PATTERNS = (
    re.compile(r"^\s*import\s+([\w.$]+)", re.MULTILINE),
    re.compile(r"^\s*from\s+([\w.]+)\s+import\s+", re.MULTILINE),
    re.compile(r"^\s*(?:const|let|var)\s+.*?\s+from\s+['\"]([^'\"]+)['\"]", re.MULTILINE),
    re.compile(r"^\s*#\s*include\s*[<\"]([^>\"]+)", re.MULTILINE),
    re.compile(r"^\s*use\s+([\w:]+)", re.MULTILINE),
    re.compile(r"^\s*require\s*\(?\s*['\"]([^'\"]+)['\"]", re.MULTILINE),
)


@dataclass(frozen=True, slots=True)
class CodeFinding:
    """A static review hint, never a proof that source is vulnerable."""

    rule_id: str
    line: int
    message: str


@dataclass(frozen=True, slots=True)
class CodeFileAnalysis:
    path: str
    full_path: str
    kind: str
    language: str
    size_bytes: int
    line_count: int
    sha256: str
    imports: tuple[str, ...]
    symbols: tuple[str, ...]
    notes: tuple[str, ...]
    findings: tuple[CodeFinding, ...] = ()


@dataclass(frozen=True, slots=True)
class CodeInspectionReport:
    root: str
    scanned_files: int
    skipped_files: int
    languages: tuple[tuple[str, int], ...]
    files: tuple[CodeFileAnalysis, ...]
    diagnostics: tuple[str, ...]
    created_at: str


class CodeInspectionError(ValueError):
    """A selected path cannot be inspected safely."""


def is_sensitive_path(path: str | Path) -> bool:
    """Conservatively exclude secret filenames and common credential-store paths."""
    candidate = Path(path)
    if any(part.casefold() in SENSITIVE_DIRS for part in candidate.parts):
        return True
    name = candidate.name.casefold()
    if name.startswith(".env"):
        return True
    if name in SECRET_NAMES or candidate.suffix.casefold() in SECRET_SUFFIXES:
        return True
    if name.endswith((".pem", ".key", ".p12", ".pfx", ".keystore")):
        return True
    return bool(re.search(r"(?:secret|credential|private[-_]?key|token)(?:[._-]|$)", name))


def _safe_read(path: Path) -> bytes:
    """Read a bounded regular file without following a symlink."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise CodeInspectionError("Hanya file reguler yang dapat diperiksa.")
        if info.st_size > MAX_FILE_BYTES:
            raise CodeInspectionError(f"File melebihi batas {MAX_FILE_BYTES // 1024 // 1024} MiB.")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            content = handle.read(MAX_FILE_BYTES + 1)
        if len(content) > MAX_FILE_BYTES:
            raise CodeInspectionError("Ukuran file berubah melewati batas pemeriksaan.")
        return content
    finally:
        os.close(descriptor)


def _elf_description(content: bytes) -> str:
    if len(content) < 20 or not content.startswith(b"\x7fELF"):
        return "Biner; format tidak dikenali"
    elf_class = {1: "ELF32", 2: "ELF64"}.get(content[4], "ELF (kelas tidak dikenal)")
    endian_value = content[5]
    byte_order = "<" if endian_value == 1 else ">" if endian_value == 2 else ""
    if not byte_order:
        return f"{elf_class}; urutan byte tidak dikenal"
    machine_id = struct.unpack(f"{byte_order}H", content[18:20])[0]
    machines = {
        3: "x86", 8: "MIPS", 20: "PowerPC", 21: "PowerPC64",
        22: "s390x", 40: "ARM", 62: "x86_64", 183: "AArch64",
        243: "RISC-V",
    }
    return f"{elf_class}; arsitektur {machines.get(machine_id, f'e_machine={machine_id}')}"


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _add_finding(
    findings: list[CodeFinding], seen: set[tuple[str, int]],
    rule_id: str, line: int, message: str,
) -> None:
    key = (rule_id, line)
    if key not in seen and len(findings) < 80:
        seen.add(key)
        findings.append(CodeFinding(rule_id=rule_id, line=max(1, line), message=message))


def _python_details(text: str) -> tuple[list[str], list[str], list[str], list[CodeFinding]]:
    imports: list[str] = []
    symbols: list[str] = []
    notes: list[str] = []
    findings: list[CodeFinding] = []
    seen: set[tuple[str, int]] = set()
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        notes.append(f"Python AST tidak dapat diurai: baris {exc.lineno or '?'}")
        return imports, symbols, notes, findings

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.append("." * node.level + (node.module or ""))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            symbols.append(node.name)
        elif isinstance(node, ast.Call):
            name = _call_name(node.func)
            line = getattr(node, "lineno", 1)
            if name in {"eval", "exec", "compile"}:
                _add_finding(
                    findings, seen, "dynamic-execution", line,
                    "Eksekusi/evaluasi kode dinamis terdeteksi; periksa apakah input dapat dikendalikan pihak lain.",
                )
            elif name in {"os.system", "os.popen", "commands.getoutput", "commands.getstatusoutput"}:
                _add_finding(
                    findings, seen, "shell-execution", line,
                    "Pemanggilan shell/perintah sistem terdeteksi; periksa validasi input dan kebutuhan shell.",
                )
            elif name.startswith("subprocess.") and name.rsplit(".", 1)[-1] in {
                "run", "Popen", "call", "check_call", "check_output",
            }:
                shell_true = any(
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                    for keyword in node.keywords
                )
                if shell_true:
                    _add_finding(
                        findings, seen, "subprocess-shell", line,
                        "subprocess memakai shell=True; tinjau sumber argumen dan kemungkinan injeksi perintah.",
                    )
            elif name in {"pickle.load", "pickle.loads", "dill.load", "dill.loads"}:
                _add_finding(
                    findings, seen, "unsafe-deserialization", line,
                    "Deserialisasi pickle/dill terdeteksi; jangan memproses data yang tidak tepercaya.",
                )
            elif name == "yaml.load":
                safe_loader = any(
                    keyword.arg == "Loader"
                    and (
                        (isinstance(keyword.value, ast.Name)
                         and keyword.value.id in {"SafeLoader", "CSafeLoader"})
                        or (isinstance(keyword.value, ast.Attribute)
                            and keyword.value.attr in {"SafeLoader", "CSafeLoader"})
                    )
                    for keyword in node.keywords
                )
                if not safe_loader:
                    _add_finding(
                        findings, seen, "yaml-deserialization", line,
                        "yaml.load tanpa SafeLoader yang terlihat; tinjau loader dan kepercayaan input.",
                    )
            elif name in {"__import__", "importlib.import_module"}:
                _add_finding(
                    findings, seen, "dynamic-import", line,
                    "Import modul dinamis terdeteksi; tinjau apakah nama modul berasal dari input tepercaya.",
                )
            elif name.startswith(("requests.", "urllib.request.", "httpx.", "aiohttp.", "socket.")):
                _add_finding(
                    findings, seen, "network-access", line,
                    "Akses jaringan terdeteksi; periksa endpoint, validasi sertifikat, dan data yang dikirim.",
                )
    return sorted(set(imports))[:80], sorted(set(symbols))[:100], notes, findings


def _text_findings(text: str) -> tuple[CodeFinding, ...]:
    """Find a few review-worthy text patterns in non-Python languages."""
    rules = (
        (
            "dynamic-execution",
            re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE),
            "Eksekusi kode dinamis terdeteksi; periksa sumber input.",
        ),
        (
            "shell-execution",
            re.compile(r"\b(?:os\.(?:system|popen)\s*\(|shell\s*[:=]\s*true\b|Runtime\.getRuntime\(\)\.exec\s*\()", re.IGNORECASE),
            "Pola eksekusi shell/perintah terdeteksi; tinjau validasi input.",
        ),
        (
            "unsafe-deserialization",
            re.compile(r"\b(?:pickle\.(?:load|loads)|yaml\.load|unserialize\s*\()", re.IGNORECASE),
            "Pola deserialisasi terdeteksi; jangan memproses data yang tidak tepercaya.",
        ),
    )
    findings: list[CodeFinding] = []
    seen: set[tuple[str, int]] = set()
    for line_no, line in enumerate(text.splitlines(), start=1):
        for rule_id, pattern, message in rules:
            if pattern.search(line):
                _add_finding(findings, seen, rule_id, line_no, message)
    return tuple(findings)


def _analyze_regular_file(path: Path, relative: str) -> CodeFileAnalysis:
    content = _safe_read(path)
    digest = hashlib.sha256(content).hexdigest()
    suffix = path.suffix.casefold()
    language = LANGUAGE_BY_SUFFIX.get(suffix, "Source/config")
    if content.startswith(b"\x7fELF"):
        return CodeFileAnalysis(
            path=relative, full_path=str(path), kind="ELF binary",
            language="ELF", size_bytes=len(content), line_count=0,
            sha256=digest, imports=(), symbols=(),
            notes=(_elf_description(content), "Metadata saja; biner tidak dijalankan atau didekompilasi."),
        )
    if b"\x00" in content[:4096]:
        return CodeFileAnalysis(
            path=relative, full_path=str(path), kind="Binary file",
            language="Binary", size_bytes=len(content), line_count=0,
            sha256=digest, imports=(), symbols=(),
            notes=("Konten biner tidak ditafsirkan atau dijalankan.",),
        )
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        return CodeFileAnalysis(
            path=relative, full_path=str(path), kind="Binary/unknown",
            language="Binary", size_bytes=len(content), line_count=0,
            sha256=digest, imports=(), symbols=(),
            notes=("Bukan teks UTF-8 yang dapat dianalisis dengan aman.",),
        )
    lines = text.count("\n") + (1 if text and not text.endswith("\n") else 0)
    imports: list[str] = []
    symbols: list[str] = []
    findings: tuple[CodeFinding, ...] = ()
    notes: list[str] = ["Analisis statis; kode tidak pernah dieksekusi."]
    if suffix in {".py", ".pyw"}:
        imports, symbols, parse_notes, findings_list = _python_details(text)
        notes.extend(parse_notes)
        findings = tuple(findings_list)
    else:
        for pattern in IMPORT_PATTERNS:
            imports.extend(pattern.findall(text))
        for pattern in SYMBOL_PATTERNS:
            symbols.extend(pattern.findall(text))
        imports = sorted(set(imports))[:80]
        symbols = sorted(set(symbols))[:100]
        findings = _text_findings(text)
    return CodeFileAnalysis(
        path=relative, full_path=str(path), kind="Source/config",
        language=language, size_bytes=len(content), line_count=lines,
        sha256=digest, imports=tuple(imports), symbols=tuple(symbols),
        notes=tuple(notes), findings=findings,
    )


def inspect_code_path(selected_path: str | Path) -> CodeInspectionReport:
    """Inspect a user-selected file or directory with size/depth/file limits."""
    raw_path = Path(selected_path).expanduser()
    try:
        if raw_path.is_symlink():
            raise CodeInspectionError("Pilih file atau folder asli, bukan symlink.")
        root = raw_path.resolve(strict=True)
    except OSError as exc:
        raise CodeInspectionError(f"Path tidak dapat diakses: {exc}") from exc
    if is_sensitive_path(raw_path) or is_sensitive_path(root):
        raise CodeInspectionError("Path berpotensi memuat kredensial/rahasia tidak diperiksa oleh default.")
    if root in {Path("/"), Path("/proc"), Path("/sys"), Path("/dev"), Path("/run")}:
        raise CodeInspectionError("Pilih folder project atau direktori tertentu; root dan pseudo-filesystem tidak dipindai sebagai satu folder.")
    if not root.is_file() and not root.is_dir():
        raise CodeInspectionError("Pilih satu file atau folder lokal.")

    files: list[CodeFileAnalysis] = []
    diagnostics: list[str] = []
    skipped = 0
    pending: list[tuple[Path, int]] = [(root, 0)] if root.is_dir() else []
    candidates: list[tuple[Path, str]] = []
    visited_directories = 0
    visited_entries = 0
    if root.is_file():
        candidates.append((root, root.name))
    else:
        visited_directories = 0
        visited_entries = 0
        while pending and len(candidates) < MAX_FILES and visited_directories < MAX_DIRECTORIES and visited_entries < MAX_ENTRIES:
            current, depth = pending.pop()
            visited_directories += 1
            try:
                with os.scandir(current) as iterator:
                    remaining = max(1, MAX_ENTRIES - visited_entries + 1)
                    entries = sorted(islice(iterator, remaining), key=lambda entry: entry.name.casefold())
            except OSError as exc:
                skipped += 1
                if len(diagnostics) < MAX_DIAGNOSTICS:
                    diagnostics.append(f"{current}: tidak dapat dibaca ({exc.strerror or 'akses ditolak'}).")
                continue
            for entry in entries:
                visited_entries += 1
                if visited_entries > MAX_ENTRIES:
                    break
                if entry.is_symlink():
                    skipped += 1
                    continue
                entry_path = Path(entry.path)
                if entry.is_dir(follow_symlinks=False):
                    if entry.name in IGNORED_DIRS or is_sensitive_path(entry_path) or depth >= MAX_DEPTH:
                        skipped += 1
                        continue
                    pending.append((entry_path, depth + 1))
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
                if is_sensitive_path(entry_path):
                    skipped += 1
                    continue
                ext = entry_path.suffix.casefold()
                name = entry_path.name.casefold()
                if ext not in TEXT_SUFFIXES and name not in TEXT_FILENAMES:
                    try:
                        with entry_path.open("rb") as handle:
                            signature = handle.read(4)
                    except OSError:
                        skipped += 1
                        continue
                    if signature != b"\x7fELF":
                        skipped += 1
                        continue
                relative = entry_path.relative_to(root).as_posix()
                candidates.append((entry_path, relative))
                if len(candidates) >= MAX_FILES:
                    break
    if pending or len(candidates) >= MAX_FILES or visited_directories >= MAX_DIRECTORIES or visited_entries >= MAX_ENTRIES:
        skipped += len(pending)
        diagnostics.append(
            f"Batas pemindaian tercapai ({MAX_FILES} file, {MAX_DIRECTORIES} direktori, "
            f"{MAX_ENTRIES} entri); sebagian isi folder dilewati."
        )

    total_bytes = 0
    total_limit_reported = False
    for path, relative in candidates[:MAX_FILES]:
        try:
            estimated_size = path.stat().st_size
            if estimated_size > MAX_FILE_BYTES:
                raise CodeInspectionError(
                    f"File melebihi batas {MAX_FILE_BYTES // 1024 // 1024} MiB."
                )
            if total_bytes + estimated_size > MAX_TOTAL_BYTES:
                skipped += 1
                if not total_limit_reported and len(diagnostics) < MAX_DIAGNOSTICS:
                    diagnostics.append(
                        f"Batas data total {MAX_TOTAL_BYTES // (1024 * 1024)} MiB tercapai; "
                        "file berikutnya yang tidak muat dilewati."
                    )
                    total_limit_reported = True
                continue
            analysis = _analyze_regular_file(path, relative)
        except (OSError, CodeInspectionError) as exc:
            skipped += 1
            if len(diagnostics) < MAX_DIAGNOSTICS:
                diagnostics.append(f"{relative}: dilewati ({exc}).")
            continue
        total_bytes += analysis.size_bytes
        files.append(analysis)
    counts: dict[str, int] = {}
    for item in files:
        counts[item.language] = counts.get(item.language, 0) + 1
    files.sort(key=lambda item: item.path.casefold())
    return CodeInspectionReport(
        root=str(root), scanned_files=len(files), skipped_files=skipped,
        languages=tuple(sorted(counts.items(), key=lambda item: (-item[1], item[0].casefold()))),
        files=tuple(files), diagnostics=tuple(diagnostics),
        created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )


def read_inspected_source(selected_path: str | Path) -> str:
    """Read a selected UTF-8 source file for the local read-only code viewer."""
    raw_path = Path(selected_path).expanduser()
    if raw_path.is_symlink() or is_sensitive_path(raw_path):
        raise CodeInspectionError("File symlink atau file dalam lokasi rahasia tidak ditampilkan.")
    path = raw_path.resolve(strict=True)
    if is_sensitive_path(path):
        raise CodeInspectionError("File dalam lokasi rahasia tidak ditampilkan.")
    if path.suffix.casefold() not in TEXT_SUFFIXES and path.name.casefold() not in TEXT_FILENAMES:
        raise CodeInspectionError("Viewer hanya menampilkan file teks/kode yang didukung.")
    content = _safe_read(path)
    if b"\x00" in content[:4096]:
        raise CodeInspectionError("File biner tidak dapat ditampilkan sebagai source code.")
    try:
        return content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise CodeInspectionError("File bukan teks UTF-8 yang dapat ditampilkan.") from exc
