# GentooSint

Local diagnostics, security checks, and modular planning for Gentoo Linux. Part of the GentooSec project.

**Version:** 0.2.0 · **Python:** 3.11+ · **Runtime dependencies:** Python standard library only.

[Original Portuguese documentation](README.pt-BR.md)

## Overview

GentooSint inspects local system information and produces reviewable reports and package plans. It does not install packages, change services, configure Tor, apply performance tuning, or scan networks. The CLI and generated messages currently use Portuguese.

## Quick start

From the project directory:

```sh
python gentoosint.py doctor
python gentoosint.py audit
python gentoosint.py verify
python gentoosint.py catalog
python gentoosint.py plan --modules tor,security,osint
python gentoosint.py optimize
```

On Gentoo, use `python3` if that is your interpreter name. Diagnostics do not require administrator privileges. You may optionally install the package inside a virtual environment:

```sh
python -m pip install -e .
gentoosint doctor
```

## Commands

| Command | Purpose |
| --- | --- |
| `doctor` | Inspect the OS, architecture, logical CPUs, memory, root disk space, profile, and init system. |
| `audit` | Check empty/relative PATH entries and selected Linux path ownership and permissions. |
| `verify` | Look for catalog package records in the local database and available executables. |
| `catalog` | List Tor, GnuPG, ExifTool, and DNS tools with their official sources. |
| `plan` | Describe the selected modules without installing packages. |
| `optimize` | Produce resource recommendations without applying changes. |

Use `verify --modules tor` to restrict verification to Tor. Records in `/var/db/pkg` do not establish package integrity or functionality: `functional_status` remains `not-tested`. An absent or inaccessible database is `unknown`; Portage checks on Windows are `not-applicable`.

`audit` checks `/etc/portage`, `/etc/portage/make.conf`, `/etc/tor/torrc`, and `/etc/ssh/sshd_config` without reading their contents. Symbolic links require review. A `pass` applies only to the individual check; this is not a CVE scanner or a complete security assessment.

## Reports

```sh
python gentoosint.py doctor --format json --output diagnostics.json
python gentoosint.py audit --output audit.md
```

Without `--output`, results appear in the terminal. File output creates a new UTF-8 `.json` or `.md` file and refuses to overwrite an existing file. The parent directory must already exist. Parent traversal (`..`), device names, alternate data streams, and redirected directories are rejected. POSIX files use mode `0600`; Windows files inherit directory ACLs. A failed write may leave a partial file.

Reports omit hostnames, IP addresses, serial numbers, full environment dumps, and raw configuration contents. They include general hardware and system characteristics; review them before sharing. Missing information remains unknown.

## Optional Portage resolution

On Gentoo:

```sh
python3 gentoosint.py plan --modules tor --resolve
```

This mode validates the target and reconstructs arguments from the catalog, then invokes `/usr/bin/emerge --pretend --verbose --autounmask=n` after checking path ownership and permissions. It does not use the user's PATH. The subprocess uses a restricted environment, discards standard input and raw output, and has a 120-second timeout. Timeout or interruption terminates the Linux process group created for the operation.

Portage and its local configuration must be trusted: even pretend mode may load code and create caches or logs. Gentoo Prefix and alternative emerge locations are unsupported. See the [security model (Portuguese)](docs/seguranca.md).

| Exit code | Meaning |
| --- | --- |
| `0` | Command completed; findings may still be present. |
| `2` | Invalid input, I/O, or target. |
| `3` | Resolution failed, timed out, or was unavailable. |
| `130` | Interrupted. |

## Development and limitations

```sh
python -m unittest discover -s tests -v
```

The project does not include an `apply` command. Verification inspects records, not functional behavior. Root disk space does not represent every volume, and recommendations use a single snapshot; no performance gains have been demonstrated.

The original project notes report Windows testing with simulated Linux cases. Real Gentoo/Portage integration, POSIX controls, minimum-version compatibility, and package installation still require validation. This README update does not establish additional runtime support.

## Project layout

- `gentoosint.py`: source-tree entry point.
- `src/gentoosint/`: CLI, diagnostics, checks, catalog, planning, and output handling.
- `tests/`: unit tests.
- `docs/`: security model and catalog references in Portuguese.

[Catalog sources (Portuguese)](docs/fontes.md) · [Changelog (Portuguese)](CHANGELOG.md)

## License

Licensed under the GNU General Public License, version 3 only (GPL-3.0-only). See [LICENSE](LICENSE) for the full terms.
