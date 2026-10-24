# PaketScope 3 — Native desktop (development preview)

PaketScope is a local-first desktop inventory for Debian-family Linux systems. The current v3 development build discovers installed APT/dpkg and Flatpak applications, searches the local APT index, and supports explicitly confirmed APT install, remove, and purge operations. Update checks and exports remain available; Flatpak inventory is visible but is not yet mutable from the app.

> Development preview: this branch is not yet a signed or packaged release. Run it from source and review the code before use.

## Native architecture

PaketScope 3 is a **native Linux desktop application**, not a website or browser wrapper. Its frontend is built with PySide6/Qt Widgets. The Python application-service layer coordinates use cases, domain models hold normalized inventory data, and OS adapters communicate with APT/dpkg and Flatpak through bounded, argument-list subprocess calls. User-selected exports and encrypted backups remain local.

The v3 branch adds a service boundary between the GUI and package operations. It remains a development preview: package changes are limited to APT/dpkg and require an APT simulation, explicit in-app confirmation, and a polkit authentication prompt. Flatpak mutation, a remote API, accounts, telemetry, and background updates remain out of scope.


## Current scope

- Local inventory using dpkg-query and flatpak list; source types are shown separately.
- A Qt desktop interface with searchable, sortable table data.
- On-demand update checks. APT is checked against local package-list metadata; Flatpak checks can contact configured remotes.
- CSV export and password-encrypted JSON backup (AES-256-GCM with a scrypt-derived key).
- No account, analytics, telemetry, background updater, or remote backend.
- The GUI itself runs as the regular user. APT mutation uses pkexec/polkit only after a preview and confirmation; commands use validated package identifiers, argument arrays, and no shell.
- APT installation refuses transactions that would remove other packages. PaketScope does not call autoremove or run bulk upgrades.
- APT remove and purge operate on one selected package at a time. Purge removes dpkg-managed system configuration but does not guarantee that data or settings in the user's home directory are removed.
- Flatpak packages remain read-only in this development build; no install/remove action is offered for them.
- System & Code Lab provides an on-demand system snapshot (OS, kernel, CPU, memory, storage, module counts and directory names) plus a local static source-code explorer.
- Code Inspector analyses user-selected files/folders without executing code or using the network. It reports common imports, classes/functions, file hashes, and basic ELF architecture metadata; it is not a binary decompiler. It also surfaces a small set of review hints for dynamic execution, shell execution, unsafe deserialization, dynamic imports, and common Python network calls. These are heuristic indicators, not a vulnerability verdict or replacement for a dedicated SAST tool.
- Optional administrator inspection uses a fixed allowlist of system locations with depth/entry caps. The user explicitly enables a temporary mode, confirms each operation, and authorizes it through Polkit. Metadata mode reports only paths, types, permissions, owner/group IDs, and sizes. A separate “Baca file sistem” action can read one user-selected UTF-8 text/config file (maximum 256 KiB) from approved locations; it rejects common credential/private-key paths, symlinks, binary files, traversal paths, and non-allowlisted locations. It never writes files, executes inspected code, accepts shell commands, or runs the main GUI as root.

Unsupported package formats and user-installed AppImages are deliberately not inferred as managed packages. Missing system tools are shown as diagnostics, not silently treated as an empty inventory.

## Compatibility status

**The only currently CI-validated native package target is Debian 13 (Trixie).** The Debian package workflow builds the `.deb`, installs it in a clean Debian 13 container, checks that the installed module and desktop launcher are present, then purges the package and checks package-owned files are removed. The source test job also runs across CPython 3.10–3.13; this validates the Python compatibility layer, not native installation on every distribution.

Ubuntu, Linux Mint, Pop!_OS, and other Debian derivatives are **not yet declared supported targets** for this development `.deb`. Being Debian-based is not sufficient: package names and available Qt/PySide versions can differ between distribution releases. Do not assume this `.deb` is compatible with them until dedicated install tests pass.

Running from source in a Python virtual environment is an experimental alternative, provided that the target system has a working desktop session, Python 3.10+, and can install the required PySide6 and cryptography libraries. Source-mode success on one distribution does not count as validation of the packaged build on that distribution.

Arch Linux, Fedora/RPM, openSUSE, and Alpine are out of the current scope. Future support should add and test distribution-specific package-manager adapters and build recipes without changing the core inventory and UI layers.

## Project structure and contributing

The codebase is organized by responsibility: domain parsing, OS command adapters,
application services, package operations, file workflows, and Qt UI modules live
in separate files. The UI's table models, visual theme, and background worker
are kept in `paketscope/ui/` rather than defined inside the application window.

Start with [the developer guide](docs/DEVELOPING.md) for the module map, data flow,
local test commands, package-backend guidance, and pull-request checklist. The
[architecture overview](docs/PAKETSCOPE_V3_ARCHITECTURE.md) describes the intended
boundaries between the interface, services, and operating-system adapters.

Changes should be incremental and covered by tests. The application window still
coordinates many use cases; further UI extraction should preserve behavior and
be reviewed in separate changes rather than mixing a large rewrite with package
manager or release changes.

## Requirements

- Python 3.10+
- Debian 13 (Trixie) for the currently validated `.deb` package
- PySide6 6.7+ and cryptography 42.0+ for source-mode development
- Optional system tools: dpkg-query, apt, and flatpak

## Run from source

From this directory:

~~~bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[test]'
python -m paketscope
~~~

Package names and versions may be visible in the UI and exported file. Store exports carefully. Encrypted backups cannot be recovered without the passphrase; use a unique, long passphrase and keep it separate from the backup file. Backup creation and restoration are capped at 64 MiB; oversized or non-regular inputs are rejected before their contents are read into memory.

## Tests

~~~bash
python -m pytest
~~~

The test suite covers inventory parsing and UI filtering, command-error handling, encrypted-backup integrity, CSV formula protection, owner-only file permissions on POSIX, and importing the Qt UI modules. These checks are not a substitute for testing against real Debian/Flatpak installations or a formal security audit.

## Privacy and security

- Inventory collection is local and read-only. The app does not send package names off the machine.
- The only intentional network-capable workflow is the user-triggered Flatpak remote update check. APT update visibility uses locally cached metadata and does not run apt update.
- Read-only subprocess calls run as the current user with shell=False and timeouts. A selected APT transaction is simulated first; only the specific apt-get operation is delegated via pkexec after an explicit confirmation.
- Installation is constrained with --no-remove and --no-install-recommends. No arbitrary command field, shell text, automatic cleanup, or background package mutation exists.
- Encrypted backup contents use AES-GCM authenticated encryption. A random salt and nonce are generated for every backup; scrypt derives the key from the passphrase. Backup creation and restoration are capped at 64 MiB.
- The application does not store passwords or passphrases. Plain CSV/JSON exports are intentionally not encrypted; choose the encrypted backup option for portable protected copies.
- System & Code Lab results stay in the local UI. The source inspector is bounded to at most 2,500 files, 12 directory levels, 2 MiB per file, and 128 MiB of total file data; symlinks, common build/cache folders, common credential-store directories (`.ssh`, `.gnupg`, `.aws`, `.azure`, `.kube`, and similar paths), and filenames that look like credentials or private keys are skipped by default. The rule-based code review hints are deliberately narrow and may produce false positives or miss issues; absence of a finding does not imply safety.
- Elevated metadata inspection is available only from the trusted installed Debian package path. It uses a root-owned helper with a fixed action and fixed path allowlist; each scan invokes Polkit and asks for authorization. Source/virtualenv mode does not grant administrator access.
- Administrator metadata mode returns only path/type/permissions/UID/GID/size. A separate, explicitly confirmed `--read-text` action can return one allowlisted UTF-8 text/config file up to 256 KiB after a second confirmation and Polkit authorization; symlinks, traversal, binary files, sensitive paths, and out-of-scope locations are rejected. Neither action writes files or executes inspected code, and the GUI never runs as root.
- CSV values that resemble spreadsheet formulas are neutralized during export. Export files and decrypted JSON are atomically written with owner-only POSIX permissions (`0600`); still treat them as sensitive data.
- Do not run this project with elevated privileges. Report security problems privately to the maintainer before making them public.

## Build the Debian development package

The repository contains a Debian package definition and GitHub Actions workflows for Python tests, static import checks, and a Debian 13 container build/install/smoke-test/purge cycle. A successful run stores a short-lived development artifact; it is not a signed stable release and must not be presented as a final public download.

For a Debian 13 build environment with debhelper installed:

~~~bash
chmod +x debian/rules
dpkg-buildpackage --build=binary --no-sign
~~~

The generated .deb is written to the parent directory. Install it only on a test system you control; inspect the package and its dependencies first.

## Remaining before a public release

- Test install, remove, and purge against clean Debian 13 systems and representative real systems.
- Add Flatpak install/remove only after the installation-scope behavior and confirmation UX are tested.
- Improve reliable provenance reporting. APT can show its configured repository candidates, but cannot always prove the historical repository from which an installed package originally came.
- Validate package contents, desktop launch behavior, accessibility, and failure/cancel flows.
- Produce a stable tagged release with a checksum and documented compatibility matrix.

Do not announce a stable release until all CI checks, real-system compatibility checks, package installation/uninstallation tests, and a security review have completed.
