# PyrsistenceSniper

[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-blue)](#)

We took PersistenceSniper, merged it with Python, and misspelled it on purpose. Meet **Py**rsistenceSniper.

Point it at a KAPE dump, a Velociraptor collection, or a mounted disk image and get offline Windows persistence detection in seconds. No live system access, no admin privileges, no PowerShell. Runs on Windows, Linux, and macOS because investigators don't always get to pick their workstation.

---

## Features

- **Wide coverage:** Checks for persistence across Run keys, services, COM hijacking, scheduled tasks, WMI subscriptions, Office add-ins, IFEO injection, accessibility backdoors, startup folders, LSA packages, and many more.
- **Signature-based filtering:** PyrsistenceSniper works best against full disk images. It validates Authenticode signatures to separate real persistence from OS defaults. Rather than relying on value-based whitelists that can't catch swapped binaries or DLL proxying, filtering is performed against verified signer information.
- **Custom detection profiles:** YAML-based allow and block rules, globally or per-check, so the tool adapts to your environment rather than the other way around. This allows filtering certain paths globally, for example when the investigated environment has known-good baselines.
- **Flexible output:** Console, CSV, and HTML with a simple extensibility model that makes adding new output formats straightforward. Enrichments are hooked in automatically without touching the core code.
- **Extensible plugin system:** Adding a new persistence check is a single file. Most checks are declarative. Complex logic gets a single method override. No framework plumbing required.
- **Finding enrichment:** Every finding is automatically enriched with file existence, hashes, signer information, and LOLBin classification before it reaches you. The enrichment plugin system makes extending this just as easy.
- **Speed:** PyrsistenceSniper was built to work at scale. The biggest bottleneck was registry access — libraries like winreg offer broad OS support and simpler installation, but are up to 200x slower than native hive parsing. With libregf under the hood, scans complete in roughly 10–30 seconds on heavily used systems, depending on hardware.

---

## Getting Started

### Prerequisites

PyrsistenceSniper requires **Python 3.10+** (3.10–3.12 recommended). It depends on [libregf-python](https://github.com/libyal/libregf), a C extension for offline Windows registry hive parsing. On Windows, pre-built wheels are available for Python 3.10–3.12 and `poetry install` works out of the box. On Linux and macOS the package compiles from source, so a C compiler is required:

| Platform | Requirement |
|----------|-------------|
| **Windows** | None. Pre-built wheels are installed automatically. |
| **Linux** | `gcc`, `make`, and Python headers (`sudo apt install build-essential python3-dev` on Debian/Ubuntu). |
| **macOS** | Xcode Command Line Tools (`xcode-select --install`). |

> **Note:** If no pre-built wheel is available for your platform or Python version, pip will fall back to building libregf from source. Compiling takes up to a minute on first install. In that case, Windows users also need the [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) (MSVC 14.0+) with the **"Desktop development with C++"** workload selected.

### Installation

```bash
git clone https://github.com/Hexastrike/PyrsistenceSniper.git
cd PyrsistenceSniper
poetry install
```

### Docker

No Python, no compiler, no dependencies. Just Docker.

```bash
docker build -t pyrsistencesniper .
```

Mount your triage output and scan:

```bash
docker run --rm -v /path/to/triage:/evidence:ro pyrsistencesniper /evidence
```

All CLI flags work as normal:

```bash
docker run --rm -v /path/to/triage:/evidence:ro pyrsistencesniper /evidence --format csv --output /evidence/results.csv
docker run --rm -v /path/to/triage:/evidence:ro pyrsistencesniper /evidence --raw --format html --output /evidence/report.html
```

### Usage

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

### Examples

Scan a KAPE collection and print to console:

```bash
pyrsistencesniper /mnt/case042/C
```

Export findings as CSV for stacking across multiple systems:

```bash
pyrsistencesniper /mnt/case042/C --format csv --output host1.csv
```

Generate an HTML report:

```bash
pyrsistencesniper /mnt/case042/C --format html --output report.html
```

Show all findings including OS defaults (no filtering):

```bash
pyrsistencesniper /mnt/case042/C --raw
```

Only check for specific MITRE ATT&CK techniques:

```bash
pyrsistencesniper /mnt/case042/C --technique T1547 T1546
```

Apply a custom detection profile to suppress known-good entries:

```bash
pyrsistencesniper /mnt/case042/C --profile ./profiles/customer_baseline.yaml
```

List all available persistence checks:

```bash
pyrsistencesniper --list-checks
```

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

## Background

[PersistenceSniper](https://github.com/last-byte/PersistenceSniper) by Federico Lagrasta and [Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns) by Sysinternals are the two tools that come up every time someone talks about Windows persistence detection. Both are great, both were direct inspiration for this project. Autoruns even supports offline analysis against disk images, and PersistenceSniper has registry-level coverage that few other tools match.

Where we kept running into friction was the workflow around them. Autoruns is a Windows binary — if your analysis box runs Linux, you're out of luck. PersistenceSniper is PowerShell, which is powerful on live systems but awkward when you have twenty KAPE collections on a SIFT workstation and want to batch-process them. And when a new persistence technique drops, adding a check to either tool means working through a larger codebase rather than dropping in a single file.

None of that makes them bad tools. It just meant we kept writing one-off scripts to cover the gaps, and at some point it made more sense to build something purpose-built. PyrsistenceSniper parses registry hives offline with libregf (fast C library by Joachim Metz), walks filesystem artifacts, scheduled task XMLs, and WMI repositories, enriches everything with file metadata and Authenticode signatures, and filters through detection profiles to strip out OS noise. On most systems that cuts output by 80–90%, which is the difference between a useful report and a wall of text.

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
