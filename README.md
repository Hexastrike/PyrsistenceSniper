# PyrsistenceSniper — Offline Windows Persistence Detection

[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-blue)](#)

We took PersistenceSniper, merged it with Python, and misspelled it on purpose. Meet **Py**rsistenceSniper.

Point it at a KAPE dump, a Velociraptor collection, or a mounted disk image and get offline Windows persistence detection in seconds. No live system access, no admin privileges, no PowerShell. Runs on Windows, Linux, and macOS because investigators don't always get to pick their workstation.

---

## 🚀 Key Features

- **Wide coverage** — 94 checks across Run keys, services, COM hijacking, scheduled tasks, WMI subscriptions, Office add-ins, IFEO injection, accessibility backdoors, startup folders, LSA packages, and more.
- **Signature-based filtering** — Validates Authenticode signatures to separate real persistence from OS defaults. No value-based whitelists that miss swapped binaries or DLL proxying.
- **Custom detection profiles** — YAML-based allow and block rules, globally or per-check. Adapt the tool to your environment, not the other way around.
- **Flexible output** — Console, CSV, and HTML. Adding new formats is straightforward.
- **Extensible plugin system** — Adding a new persistence check is a single file. Most checks are declarative. Complex logic gets one method override.
- **Finding enrichment** — Every finding is automatically enriched with file existence, SHA-256 hashes, signer information, and LOLBin classification.
- **Speed** — Native registry parsing via libregf. Scans complete in roughly 10–30 seconds on heavily used systems.

---

## 📋 Prerequisites

**Python 3.10+** required (3.10–3.12 recommended). PyrsistenceSniper depends on [libregf-python](https://github.com/libyal/libregf), a C extension for offline registry hive parsing. Pre-built wheels are available on Windows. Linux and macOS compile from source:

| Platform | Requirement |
|----------|-------------|
| **Windows** | None. Pre-built wheels are installed automatically. |
| **Linux** | `gcc`, `make`, and Python headers (`sudo apt install build-essential python3-dev`). |
| **macOS** | Xcode Command Line Tools (`xcode-select --install`). |

> **Note:** If no pre-built wheel is available for your platform or Python version, pip will build libregf from source (takes up to a minute). Windows users may also need the [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) with the **"Desktop development with C++"** workload.

---

## 📦 Installation

### From source

```bash
git clone https://github.com/Hexastrike/PyrsistenceSniper.git
cd PyrsistenceSniper
poetry install
```

### Docker

No Python, no compiler, no dependencies. Just Docker.

```bash
# Build the image
docker build -t pyrsistencesniper .

# Scan a triage collection
docker run --rm -v /path/to/triage:/evidence:ro pyrsistencesniper /evidence

# Export as CSV
docker run --rm -v /path/to/triage:/evidence:ro pyrsistencesniper /evidence --format csv --output /evidence/results.csv

# Full HTML report with no filtering
docker run --rm -v /path/to/triage:/evidence:ro pyrsistencesniper /evidence --raw --format html --output /evidence/report.html
```

---

## 🎯 Usage

The `paths` argument is the root of your forensic collection — wherever the `Windows/` directory lives. KAPE output, Velociraptor collections, mounted E01s, raw directory copies. As long as the hives and filesystem artifacts are in their expected paths relative to the root, PyrsistenceSniper will find them.

```
pyrsistencesniper [-h] [--hostname HOSTNAME] [--format {console,csv,html}]
                  [--output OUTPUT] [--profile PROFILE]
                  [--technique TECHNIQUE ...] [--list-checks]
                  [--update-lolbins] [--raw] [-v] [paths ...]
```

| Flag | Description |
|------|-------------|
| `--format {console,csv,html}` | Output format (default: `console`) |
| `--output FILE` | Write output to file instead of stdout |
| `--profile FILE` | YAML detection profile for allow/block overrides |
| `--technique ID [...]` | Filter by MITRE ATT&CK technique or check ID |
| `--hostname NAME` | Override hostname (otherwise read from SYSTEM hive) |
| `--list-checks` | List all available checks and exit |
| `--update-lolbins` | Download the latest LOLBin list from the LOLBAS project |
| `--raw` | Disable all suppression (OS filters and allow rules) |
| `-v, --verbose` | Enable debug logging to stderr |

### Examples

```bash
# Scan a KAPE collection
pyrsistencesniper /mnt/case042/C

# Export as CSV for stacking across multiple systems
pyrsistencesniper /mnt/case042/C --format csv --output host1.csv

# Generate an HTML report
pyrsistencesniper /mnt/case042/C --format html --output report.html

# Show everything, including OS defaults
pyrsistencesniper /mnt/case042/C --raw

# Only check specific MITRE ATT&CK techniques
pyrsistencesniper /mnt/case042/C --technique T1547 T1546

# Apply a custom detection profile
pyrsistencesniper /mnt/case042/C --profile ./profiles/customer_baseline.yaml

# List all available persistence checks
pyrsistencesniper --list-checks
```

### Working with loose hive files

PyrsistenceSniper expects a full image root. The real power comes from cross-referencing registry entries against the filesystem — validating signatures, checking if binaries exist, computing hashes. A loose hive can't give you that.

If you only have individual hive files, place them in the expected directory structure:

```bash
mkdir -p /tmp/evidence/Windows/System32/config
cp SYSTEM SOFTWARE /tmp/evidence/Windows/System32/config/
mkdir -p /tmp/evidence/Users/unknown
cp NTUSER.DAT /tmp/evidence/Users/unknown/
pyrsistencesniper /tmp/evidence
```

---

## 🔍 How It Works

PyrsistenceSniper runs each finding through a multi-stage pipeline:

1. **Plugin execution** — Each check scans registry hives, filesystem artifacts, scheduled task XMLs, or WMI repositories for persistence indicators.
2. **Resolution** — Findings are enriched with file existence, SHA-256 hash, Authenticode signer, LOLBin classification, and OS directory detection.
3. **Filtering** — Plugin-level and profile-level allow/block rules suppress known-good entries. In most environments this cuts output by 80–90%.
4. **Enrichment** — Optional enrichment plugins can attach additional metadata before output.
5. **Output** — Findings are rendered in the requested format (console, CSV, or HTML).

Each finding carries:

| Field | Description |
|-------|-------------|
| `path` | Registry key or file path |
| `value` | Registry value, command line, or DLL path |
| `technique` | Human-readable technique name |
| `mitre_id` | MITRE ATT&CK technique ID |
| `access_gained` | `USER` or `SYSTEM` |
| `sha256` | SHA-256 hash of the referenced binary |
| `signer` | Authenticode signer name |
| `is_lolbin` | Whether the binary is a known LOLBin |
| `exists` | Whether the referenced file exists on disk |

Console output groups findings by MITRE technique and flags anomalies. CSV output includes all fields plus dynamic enrichment columns. HTML produces a standalone report suitable for client delivery.

---

## 🛡️ Supported Checks

113 persistence checks across 9 MITRE ATT&CK techniques. Run `pyrsistencesniper --list-checks` for a quick overview in the terminal.

| MITRE ID | Technique | Checks |
|----------|-----------|--------|
| T1037 | Boot/Logon Initialization Scripts | `gp_scripts`, `logon_scripts` |
| T1053 | Scheduled Task/Job | `ghost_task`, `scheduled_task_files` |
| T1098 | Account Manipulation | `rid_hijacking`, `rid_suborner` |
| T1137 | Office Application Startup | `office_addins`, `office_ai_hijack`, `office_dll_override`, `office_templates`, `office_test_dll`, `vba_monitors` |
| T1543 | Create or Modify System Process | `service_failure_command`, `windows_service_dll`, `windows_service_image_path` |
| T1546 | Event Triggered Execution | `accessibility_tools`, `ae_debug`, `ae_debug_protected`, `amsi_providers`, `app_paths`, `appcert_dlls`, `appinit_dlls`, `assistive_technology`, `cmd_autorun`, `com_treat_as`, `disk_cleanup_handler`, `dotnet_dbg_managed_debugger`, `error_handler_cmd`, `explorer_clsid_hijack`, `ifeo_debugger`, `ifeo_delegated_ntdll`, `ifeo_silent_process_exit`, `lsm_debugger`, `netsh_helper`, `power_automate`, `powershell_profiles`, `screensaver`, `telemetry_controller`, `wer_debugger`, `wer_hangs`, `wer_reflect_debugger`, `wer_runtime_exception`, `windows_terminal`, `wmi_event_subscription` |
| T1547 | Boot/Logon Autostart Execution | `active_setup`, `authentication_packages`, `boot_execute`, `boot_verification_program`, `dsrm_backdoor`, `explorer_app_key`, `explorer_bho`, `explorer_context_menu`, `explorer_load`, `platform_execute`, `rdp_clx_dll`, `rdp_virtual_channel`, `rdp_wds_startup`, `run_keys`, `s0_initial_command`, `scm_extension`, `security_packages`, `session_manager_execute`, `setup_execute`, `shell_folders_startup`, `shell_launcher`, `startup_folder`, `ts_initial_program`, `winlogon_mpnotify`, `winlogon_notify_packages`, `winlogon_shell`, `winlogon_userinit` |
| T1556 | Modify Authentication Process | `lsa_password_filter` |
| T1574 | Hijack Execution Flow | `autodial_dll`, `chm_helper_dll`, `cor_profiler`, `coreclr_profiler`, `crypto_expo_offload`, `diagtrack_dll`, `diagtrack_listener_dll`, `direct3d_dll`, `dotnet_startup_hooks`, `gp_extension_dlls`, `hhctrl_ocx_dll`, `known_managed_debugging_dlls`, `lsa_extensions`, `mapi32_dll_path`, `minidump_auxiliary_dlls`, `msdtc_xa_dll`, `nldp_dll`, `rdp_test_dvc_plugin`, `search_indexer_dll`, `server_level_plugin_dll`, `winsock_auto_proxy`, `wu_service_startup_dll` |

---

## ⚙️ Detection Profiles

Detection profiles let you suppress known-good findings or flag specific values. Rules are defined in YAML and can be applied globally or per-check.

```yaml
# Trusted signers (suppress signed Microsoft binaries by default)
trusted_signers:
  - "microsoft windows"
  - "microsoft corporation"

# Global allow rules — applied to all checks
allow:
  - signer: "microsoft"
    not_lolbin: true
    reason: "Microsoft-signed, not a LOLBin"

  - path_contains: "\\Contoso\\"
    reason: "Known enterprise software"

# Global block rules — force-flag regardless of other rules
block:
  - value_contains: "suspicious.exe"
    reason: "Known malicious binary"

# Per-check overrides
checks:
  run_keys:
    allow:
      - value_contains: "SecurityHealthSystray"
        reason: "Built-in Windows Security tray icon"

  ghost_task:
    enabled: false  # Disable this check entirely
```

### Rule fields

All fields are optional. When multiple fields are present, **all** must match (AND logic). Comparisons are case-insensitive.

| Field | Match Type | Description |
|-------|-----------|-------------|
| `signer` | substring | Authenticode signer name |
| `path_equals` | exact | Full registry or file path |
| `path_contains` | substring | Partial path match |
| `value_equals` | exact | Registry value or command |
| `value_contains` | substring | Partial value match |
| `hash` | exact | SHA-256 hash of the referenced file |
| `not_lolbin` | boolean | Only match if the binary is **not** a LOLBin |
| `reason` | — | Human-readable justification (shown in verbose output) |

---

## 🛠️ Development

Poetry for dependency management, ruff for linting and formatting, mypy in strict mode, pytest for testing. The full test suite runs in about a second.

```bash
poetry install                    # Install with dev dependencies
poetry run pytest                 # Run tests
poetry run ruff check             # Lint
poetry run ruff format            # Format
poetry run mypy --strict          # Type check
make all                          # All of the above
make cov                          # Tests with coverage report
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
    ...
  core/               # Registry parsing, filesystem ops, image handling,
                      #   Authenticode extraction, path normalization
  models/             # Finding, FilterRule, Enrichment dataclasses
  output/             # Console, CSV, HTML renderers
  enrichment/         # Optional enrichment plugins
```

### Adding a plugin

Plugins live in `pyrsistencesniper/plugins/`, organized by technique ID. Most checks are fully declarative:

```python
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import (
    CheckDefinition, HiveScope, PersistencePlugin, RegistryTarget,
)

@register_plugin
class LogonScripts(PersistencePlugin):
    definition = CheckDefinition(
        id="logon_scripts",
        technique="Logon Scripts (UserInitMprLogonScript)",
        mitre_id="T1037.001",
        description=(
            "UserInitMprLogonScript runs a script at user logon "
            "before the desktop loads."
        ),
        references=("https://attack.mitre.org/techniques/T1037/001/",),
        targets=(
            RegistryTarget(
                path=r"Environment",
                values="UserInitMprLogonScript",
                scope=HiveScope.HKU,
            ),
        ),
    )
```

The base class handles registry scanning, value extraction, and finding creation. For checks that need custom logic (filesystem walking, cross-referencing multiple hives, etc.), override `run()` and return a `list[Finding]`. The plugin gets dependency-injected helpers via `self.registry`, `self.filesystem`, `self.image`, and `self.profile`.

---

## 📖 Background

[PersistenceSniper](https://github.com/last-byte/PersistenceSniper) by Federico Lagrasta and [Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns) by Sysinternals are the two tools that come up every time someone talks about Windows persistence detection. Both are great. Both were direct inspiration for this project.

Where we kept running into friction was the workflow. Autoruns is a Windows binary — if your analysis box runs Linux, you're out of luck. PersistenceSniper is PowerShell, which is powerful on live systems but awkward when you have twenty KAPE collections on a SIFT workstation. And when a new persistence technique drops, adding a check means working through a larger codebase rather than dropping in a single file.

We kept writing one-off scripts to cover the gaps, and at some point it made more sense to build something purpose-built. PyrsistenceSniper parses hives offline with libregf, walks filesystem artifacts and scheduled task XMLs, enriches everything with file metadata and Authenticode signatures, and filters through detection profiles to strip out OS noise. On most systems that cuts output by 80–90%.

---

## 🗺️ Roadmap

- BITS jobs — parse modern `qmgr.db` ESE database (not only legacy `.dat` files)
- SCM security descriptors — analyze DACL ACEs for weakened service permissions
- VirusTotal enrichment for discovered artifacts
- Improved HTML reports with filtering and sorting
- XLSX output format

---

## 🙏 Credits

- [PersistenceSniper](https://github.com/last-byte/PersistenceSniper) by Federico Lagrasta
- [Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns) by Sysinternals
- [libregf](https://github.com/libyal/libregf) by Joachim Metz
- [MITRE ATT&CK](https://attack.mitre.org/)

---

## ⚖️ License

Distributed under the **MIT License**. See [LICENSE](LICENSE).
