# PyrsistenceSniper

[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-blue)](#)

We took PersistenceSniper, merged it with Python, and misspelled it on purpose. Meet **Py**rsistenceSniper.

Point it at a KAPE dump, a Velociraptor collection, or a mounted disk image and get offline Windows persistence detection in seconds. No live system access, no admin privileges, no PowerShell. Runs on Windows, Linux, and macOS because investigators don't always get to pick their workstation.

---

## Background

Two tools come up every single time someone talks about Windows persistence detection: PersistenceSniper by Federico Lagrasta and Autoruns by Sysinternals. Both are excellent. Both were direct inspiration for this project. And both have a limitation that kept biting us in practice: they want a live Windows system.

In incident response, you rarely have that luxury. You have forensic collections sitting on a Linux analysis box. You have twenty systems from the same engagement and you need to stack the results to find the outlier. You need to add a check for a new technique without reverse-engineering a monolithic codebase. And ideally you want to do all of this before your coffee gets cold.

PyrsistenceSniper was built to solve these problems. It scans registry hives, filesystem artifacts, scheduled task definitions, and WMI repositories for persistence indicators. Registry parsing uses libregf by Joachim Metz, a C library that makes offline hive access absurdly fast. Findings are enriched with file metadata and Authenticode signatures, then filtered through detection profiles to separate real persistence from OS noise. On most systems that cuts output by 80-90%, which is the difference between a useful report and a wall of text.

---

## Features

- **Wide coverage.** Checks for persistence across Run keys, services, COM hijacking, scheduled tasks, WMI subscriptions, Office add-ins, IFEO injection, accessibility backdoors, startup folders, LSA packages, and many more. Every check is mapped to MITRE ATT&CK with references to relevant documentation.
- **Signature-based filtering.** Validates Authenticode signatures to separate real persistence from OS defaults, instead of relying on value-based whitelists that can't catch swapped binaries or DLL proxying.
- **Custom detection profiles.** YAML-based allow and block rules, globally or per-check, so the tool adapts to your environment rather than the other way around.
- **Flexible output.** Console view for interactive analysis, CSV for cross-system stacking, and HTML for standalone reports. Suppression can be fully disabled when you want the complete picture.
- **Extensible plugin system.** Adding a new persistence check is a single file. Most checks are declarative. Complex logic gets a single method override. No framework plumbing required.
- **Finding enrichment.** Every finding is automatically enriched with file existence, hashes, signer information, and LOLBin classification before it reaches you.

---

## Setup

### Prerequisites

PyrsistenceSniper requires **Python 3.10+** (3.10–3.13 recommended). It depends on [libregf-python](https://github.com/libyal/libregf), a C extension for offline Windows registry hive parsing. On Windows, pre-built wheels are available for Python 3.10–3.13 and `poetry install` works out of the box. On Linux and macOS the package compiles from source, so a C compiler is required:

| Platform | Requirement |
|----------|-------------|
| **Windows** | None. Pre-built wheels are installed automatically. |
| **Linux** | `gcc`, `make`, and Python headers (`sudo apt install build-essential python3-dev` on Debian/Ubuntu). |
| **macOS** | Xcode Command Line Tools (`xcode-select --install`). |

> **Note:** If no pre-built wheel is available for your platform or Python version, pip will fall back to building libregf from source. In that case, Windows users also need the [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) (MSVC 14.0+) with the **"Desktop development with C++"** workload selected.

### Install

```bash
git clone https://github.com/Hexastrike/PyrsistenceSniper.git
cd PyrsistenceSniper
poetry install
```

## Run

```text
C:\PyrsistenceSniper> poetry run pyrsistencesniper -h


    ██████╗ ██╗   ██╗██████╗ ███████╗██╗███████╗████████╗███████╗███╗   ██╗ ██████╗███████╗
    ██╔══██╗╚██╗ ██╔╝██╔══██╗██╔════╝██║██╔════╝╚══██╔══╝██╔════╝████╗  ██║██╔════╝██╔════╝
    ██████╔╝ ╚████╔╝ ██████╔╝███████╗██║███████╗   ██║   █████╗  ██╔██╗ ██║██║     █████╗
    ██╔═══╝   ╚██╔╝  ██╔══██╗╚════██║██║╚════██║   ██║   ██╔══╝  ██║╚██╗██║██║     ██╔══╝
    ██║        ██║   ██║  ██║███████║██║███████║   ██║   ███████╗██║ ╚████║╚██████╗███████╗
    ╚═╝        ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═══╝ ╚═════╝╚══════╝


    ███████╗███╗   ██╗██╗██████╗ ███████╗██████╗
    ██╔════╝████╗  ██║██║██╔══██╗██╔════╝██╔══██╗
    ███████╗██╔██╗ ██║██║██████╔╝█████╗  ██████╔╝
    ╚════██║██║╚██╗██║██║██╔═══╝ ██╔══╝  ██╔══██╗
    ███████║██║ ╚████║██║██║     ███████╗██║  ██║
    ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝

    by Maurice Fielenbach (Hexastrike Cybersecurity)

usage: pyrsistencesniper [-h] [--hostname HOSTNAME] [--format {console,csv,html}] [--output OUTPUT] [--profile PROFILE]
                         [--technique TECHNIQUE [TECHNIQUE ...]] [--list-checks] [--update-lolbins] [--raw] [-v] [--log-format LOG_FORMAT]
                         [paths ...]

Detect Windows persistence mechanisms from offline forensic artifacts.

positional arguments:
  paths                 Image root directory or individual artifact files

options:
  -h, --help            show this help message and exit
  --hostname HOSTNAME   Override hostname (otherwise read from SYSTEM hive)
  --format {console,csv,html}
                        Output format (default: console)
  --output OUTPUT       Output file path (default: stdout)
  --profile PROFILE     YAML detection profile for allow/block overrides
  --technique TECHNIQUE [TECHNIQUE ...]
                        Filter by MITRE ATT&CK IDs or check IDs
  --list-checks         List all available checks and exit
  --update-lolbins      Download the latest LOLBin list from the LOLBAS project and exit
  --raw                 Disable all suppression (OS filters and allow rules)
  -v, --verbose         Enable debug logging to stderr
  --log-format LOG_FORMAT
                        Override the log line format string
```

The `paths` argument is the root of your forensic collection. This is wherever the `Windows/` directory lives. KAPE output, Velociraptor collections, mounted E01s, raw directory copies: as long as the registry hives and filesystem artifacts are in their expected paths relative to the root, PyrsistenceSniper will find them.

---

## Development

The project uses Poetry for dependency management, ruff for linting and formatting, mypy in strict mode for type checking, and pytest for testing. The full test suite runs in about a second. If it takes longer than that, something is probably wrong.

```bash
poetry install                    # Install with dev dependencies
poetry run pytest                 # Run tests
poetry run ruff check             # Lint
poetry run ruff format            # Format
poetry run mypy --strict          # Type check
make all                          # All of the above
```

### Project layout

```
pyrsistencesniper/
  cli.py              # Entry point and argument parsing
  plugins/            # Detection plugins, grouped by MITRE technique
    base.py           # PersistencePlugin, CheckDefinition, RegistryTarget
    T1547/            # Boot/logon autostart execution
    T1546/            # Event-triggered execution
    T1574/            # Hijack execution flow
    T1543/            # Services
    ...               # And so on
  core/               # Registry parsing, filesystem ops, image handling,
                      #   Authenticode extraction, path normalization
  models/             # Finding, AllowRule, Enrichment dataclasses
  output/             # Console, CSV, HTML renderers
  enrichment/         # Optional enrichment plugins
```

### Adding a plugin

Plugins live in `pyrsistencesniper/plugins/`, organized by technique ID. Here is the short version:

1. Create a file in the appropriate technique directory (e.g., `T1547/my_check.py`).
2. Define a class that extends `PersistencePlugin` with a `CheckDefinition`.
3. Add the `@register_plugin` decorator.

For declarative checks, that is literally it. The base class reads the registry targets, extracts values, and builds findings. For custom logic, override `run()` and return a `list[Finding]`. Your plugin gets dependency-injected helpers for registry access (`self.registry`), filesystem operations (`self.filesystem`), image metadata (`self.image`), and profile configuration (`self.profile`).

---

## Roadmap

- BITS jobs: parse modern `qmgr.db` ESE database (not only legacy `.dat` files)
- SCM security descriptor: analyze DACL ACEs for weakened service permissions
- VirusTotal enrichment for discovered artifacts
- Improved HTML reports with filtering and sorting
- XLSX output format

---

## Credits

- [PersistenceSniper](https://github.com/last-byte/PersistenceSniper) by Federico Lagrasta
- [Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns) by Sysinternals
- [libregf](https://github.com/libyal/libregf) by Joachim Metz
- [MITRE ATT&CK](https://attack.mitre.org/)

---

## License

Distributed under the **MIT License**. See [LICENSE](LICENSE).
