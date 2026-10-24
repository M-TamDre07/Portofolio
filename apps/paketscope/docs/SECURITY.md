# PaketScope security notes

**Status:** PaketScope 3 is a development preview. These notes describe the
current implementation, not a formal audit or a guarantee of security.

## Security boundaries

PaketScope is a local desktop application. It does not require an account and
does not include analytics, telemetry, or a remote inventory service. Inventory
collection uses local system commands and configured package metadata.

The current build supports the following APT/dpkg operations on one selected
package at a time: install, remove, and purge. They are privileged system
changes, so use the application carefully:

1. Package identifiers are validated and passed as argument arrays, not shell
   command strings.
2. APT first produces a simulation; the application checks the plan and
   presents the changes for explicit user confirmation.
3. Only after confirmation does the application request system authentication
   through `pkexec`/polkit to run a fixed APT operation.
4. Installation includes `--no-remove` and `--no-install-recommends`. The app
   does not expose autoremove, bulk upgrades, arbitrary command input, or
   background package mutation.

Do not run PaketScope as root. APT package installation can run package
maintainer scripts and change system state. Test package mutations in a
disposable Debian virtual machine with a recoverable snapshot before trying
them on a daily-use computer.

Flatpak inventory is read-only. User-triggered Flatpak update checks can contact
configured remotes; APT update visibility is based on locally cached metadata
and does not run `apt update` by itself.

## System & Code Lab boundaries

The ordinary system snapshot reads selected local OS/kernel/resource metadata and
uses a fixed, read-only `systemctl list-units` invocation. It is intentionally
not a process-memory browser, raw disk editor, or root shell.

Code Inspector parses source as text/AST and computes a SHA-256 fingerprint. It
never imports or executes the inspected project. It skips common cache/build
directories and known credential-store paths, limits traversal, per-file size, and total bytes read in one scan,
and only displays UTF-8 source files matching its supported file types. Binary
inspection is limited to safe file metadata and basic ELF architecture details;
it does not decompile proprietary binaries, bypass DRM, or alter packages.

The new static review hints flag a small set of patterns such as dynamic
execution, shell invocation, unsafe deserialization, dynamic imports, and common
Python network calls. A match is a request for manual review, not proof of a
vulnerability. No match is not proof that code is safe; use dedicated static
analysis and review dependencies before relying on software.

The optional Administrator mode is session-scoped UI consent, not a persistent
root shell and not a guarantee that Polkit authorization remains cached. It is
only available when the trusted Debian-installed helper passes ownership and
permission checks. Every elevated scan or single-file text read has a separate
in-app confirmation and invokes Polkit. The helper accepts only fixed actions,
checks an allowlist of system paths, rejects symlinks and common secret paths,
returns capped metadata or one UTF-8 text file up to 256 KiB, and does not write
or execute inspected files. Source/virtualenv mode never gains elevated access.

## Local data and backups

Package names, versions, IDs, origins, and exports can disclose installed tools
or parts of a work environment. Treat CSV exports and decrypted JSON as private,
unencrypted files.

Encrypted backups use AES-GCM authenticated encryption with a random per-file
salt and nonce. A key is derived from the passphrase using scrypt. A weak
passphrase may still be guessed; a forgotten passphrase cannot be recovered.
The app does not store the passphrase. Backup creation and restoration are
capped at 64 MiB. Restoration opens only regular files and uses a bounded read,
rejecting oversized inputs before decryption to avoid unbounded memory use.

Exports and decrypted JSON are written locally using owner-only permissions on
POSIX systems and atomic replacement. These protections do not replace careful
handling of the resulting files or backups.

## Before a stable release

- Test install, launch, upgrade, remove, and purge paths on clean Debian 13
  desktop sessions, including authentication cancellation and failure paths.
- Validate compatibility separately for each supported distribution version.
- Review dependency advisories, Debian metadata, file permissions, and package
  contents.
- Publish checksums and release provenance; define a signing approach.
- Complete an independent security review. Do not claim a formal audit or
  guaranteed security until one has actually been completed.

## Reporting

Please report suspected vulnerabilities privately to the project maintainer
before public disclosure. Avoid including package inventories, credentials, or
personal data unless strictly necessary.
