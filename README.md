# PyrsistenceSniper — Offline Windows Persistence Detection

[![CI](https://github.com/Hexastrike/PyrsistenceSniper/actions/workflows/ci.yml/badge.svg)](https://github.com/Hexastrike/PyrsistenceSniper/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Hexastrike/PyrsistenceSniper/graph/badge.svg)](https://codecov.io/gh/Hexastrike/PyrsistenceSniper)
[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-blue)](#)

We took PersistenceSniper, merged it with Python, and misspelled it on purpose. Meet **Py**rsistenceSniper.

Point it at a KAPE dump, a Velociraptor collection, or a mounted disk image and get offline Windows persistence detection in seconds. No live system access, no admin privileges, no PowerShell. Runs on Windows, Linux, and macOS because investigators don't always get to pick their workstation.

## 🚀 Key Features

- **Wide persistence coverage** — 117 checks across Run keys, services, COM hijacking, scheduled tasks, WMI subscriptions, Office add-ins, IFEO injection, accessibility backdoors, startup folders, LSA packages, and more.
- **Signature-based filtering** — Validates Authenticode signatures to separate real persistence from OS defaults. No value-based whitelists that miss swapped binaries or DLL proxying.
- **Custom detection profiles** — YAML-based allow and block rules, globally or per-check. Adapt the tool to your environment, not the other way around.
- **Flexible output** — Console, CSV, HTML, and XLSX. Adding new formats is straightforward.
- **Extensible plugin system** — Adding a new persistence check is a single file. Most checks are declarative. Complex logic gets one method override.
- **Finding enrichment** — Every finding is automatically enriched with file existence, SHA-256 hashes, signer information, and LOLBin classification.
- **Speed** — Native registry parsing via libregf. Scans complete in roughly 10–30 seconds on heavily used systems.

## 📋 Prerequisites

**Python 3.10+** required (3.10–3.12 recommended). PyrsistenceSniper depends on [libregf-python](https://github.com/libyal/libregf), a C extension for offline registry hive parsing. Pre-built wheels are available on Windows. Linux and macOS compile from source:

| Platform | Requirement |
|----------|-------------|
| **Windows** | None. Pre-built wheels are installed automatically. |
| **Linux** | `gcc`, `make`, and Python headers (`sudo apt install build-essential python3-dev`). |
| **macOS** | Xcode Command Line Tools (`xcode-select --install`). |

> **Note:** If no pre-built wheel is available for your platform or Python version, pip will build libregf from source (takes up to a minute). Windows users may also need the [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) with the **"Desktop development with C++"** workload.

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
docker run --rm -v /path/to/triage:/evidence:ro pyrsistencesniper /evidence --min-severity info --format html --output /evidence/report.html
```

## 🎯 Usage

The `paths` argument is the root of your forensic collection — wherever the `Windows/` directory lives. KAPE output, Velociraptor collections, mounted E01s, raw directory copies. As long as the hives and filesystem artifacts are in their expected paths relative to the root, PyrsistenceSniper will find them.

```
pyrsistencesniper [-h] [--hostname HOSTNAME] [--format {console,csv,html,xlsx}]
                  [--output OUTPUT] [--profile PROFILE]
                  [--technique TECHNIQUE ...] [--list-checks]
                  [--update-lolbins] [--min-severity {info,low,medium,high}]
                  [-v] [paths ...]
```

| Flag | Description |
|------|-------------|
| `--format {console,csv,html,xlsx}` | Output format (default: `console`) |
| `--output FILE` | Write output to file instead of stdout |
| `--profile FILE` | YAML detection profile for allow/block overrides |
| `--technique ID [...]` | Filter by MITRE ATT&CK technique or check ID |
| `--hostname NAME` | Override hostname (otherwise read from SYSTEM hive) |
| `--list-checks` | List all available checks and exit |
| `--update-lolbins` | Download the latest LOLBin list from the LOLBAS project |
| `--min-severity {info,low,medium,high}` | Minimum severity to include (default: `medium`). Use `info` to show everything |
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
pyrsistencesniper /mnt/case042/C --min-severity info

# Only check specific MITRE ATT&CK techniques
pyrsistencesniper /mnt/case042/C --technique T1547 T1546

# Apply a custom detection profile
pyrsistencesniper /mnt/case042/C --profile ./profiles/customer_baseline.yaml

# Scan a standalone NTUSER.DAT hive
pyrsistencesniper /path/to/NTUSER.DAT

# Scan a standalone SYSTEM hive with verbose output
pyrsistencesniper /path/to/SYSTEM -v

# List all available persistence checks
pyrsistencesniper --list-checks
```

### Standalone artifact scanning

Pass a single hive file directly — no directory structure needed:

```bash
# Scan a standalone NTUSER.DAT
pyrsistencesniper /path/to/NTUSER.DAT

# Scan a standalone SYSTEM hive
pyrsistencesniper /path/to/SYSTEM

# Scan a standalone SOFTWARE hive with CSV output
pyrsistencesniper /path/to/SOFTWARE --format csv --output results.csv
```

Supported standalone artifacts: `SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, `NTUSER.DAT`, `UsrClass.dat`, `DEFAULT`, `Amcache.hve`.

PyrsistenceSniper auto-detects standalone mode and runs only the checks that apply to the given hive. Note that resolution features (file existence, hashes, signatures) are unavailable in standalone mode since there's no filesystem to cross-reference.

## 🔍 How It Works

PyrsistenceSniper runs each finding through a multi-stage pipeline:

1. **Plugin execution** — Each check scans registry hives, filesystem artifacts, scheduled task XMLs, or WMI repositories for persistence indicators.
2. **Resolution** — Findings are enriched with file existence, SHA-256 hash, Authenticode signer, LOLBin classification, and OS directory detection.
3. **Severity classification** — Each finding is classified as `HIGH` (block rule match), `MEDIUM` (no rules match), `LOW` (partial allow match), or `INFO` (full allow match). The `--min-severity` flag controls the threshold (default: `medium`). Use `--min-severity info` to show everything. Plugins also reject invalid data (empty values, non-executable flags) unconditionally. In most environments this cuts output by 80–90%.
4. **Enrichment** — Optional enrichment plugins can attach additional metadata before output.
5. **Output** — Findings are rendered in the requested format (console, CSV, HTML, or XLSX).

Each finding carries:

| Field | Description |
|-------|-------------|
| `path` | Registry key or file path |
| `value` | Registry value, command line, or DLL path |
| `technique` | Human-readable technique name |
| `mitre_id` | MITRE ATT&CK technique ID |
| `access_gained` | `USER` or `SYSTEM` |
| `severity` | `INFO`, `LOW`, `MEDIUM`, or `HIGH` |
| `sha256` | SHA-256 hash of the referenced binary |
| `signer` | Authenticode signer name |
| `is_lolbin` | Whether the binary is a known LOLBin |
| `exists` | Whether the referenced file exists on disk |

Console output groups findings by MITRE technique and flags anomalies. CSV and XLSX output include all fields plus dynamic enrichment columns. HTML produces a standalone report suitable for client delivery.

## 🛡️ Supported Checks

117 persistence checks across 9 MITRE ATT&CK techniques. Run `pyrsistencesniper --list-checks` for a quick overview in the terminal.

| MITRE ID | Technique | Checks |
|----------|-----------|--------|
| T1037 | Boot/Logon Initialization Scripts | `gp_scripts`, `logon_scripts` |
| T1053 | Scheduled Task/Job | `ghost_task`, `scheduled_task_files` |
| T1098 | Account Manipulation | `rid_hijacking`, `rid_suborner` |
| T1137 | Office Application Startup | `office_addins`, `office_ai_hijack`, `office_dll_override`, `office_templates`, `office_test_dll`, `outlook_home_page`, `vba_monitors` |
| T1543 | Create or Modify System Process | `service_failure_command`, `windows_service_dll`, `windows_service_image_path` |
| T1546 | Event Triggered Execution | `accessibility_tools`, `ae_debug`, `ae_debug_protected`, `amsi_providers`, `app_paths`, `appcert_dlls`, `appinit_dlls`, `assistive_technology`, `cmd_autorun`, `com_treat_as`, `disk_cleanup_handler`, `dotnet_dbg_managed_debugger`, `error_handler_cmd`, `explorer_clsid_hijack`, `file_association_hijack`, `ifeo_debugger`, `ifeo_delegated_ntdll`, `ifeo_silent_process_exit`, `lsm_debugger`, `netsh_helper`, `power_automate`, `powershell_profiles`, `protocol_handler_hijack`, `recycle_bin_com_extension`, `screensaver`, `search_protocol_handler`, `shared_task_scheduler`, `shell_execute_hooks`, `telemetry_controller`, `typelib_hijack`, `wer_debugger`, `wer_hangs`, `wer_reflect_debugger`, `wer_runtime_exception`, `windows_terminal`, `wmi_event_subscription` |
| T1547 | Boot/Logon Autostart Execution | `active_setup`, `authentication_packages`, `boot_execute`, `boot_verification_program`, `dsrm_backdoor`, `explorer_app_key`, `explorer_bho`, `explorer_context_menu`, `explorer_load`, `font_drivers`, `lsa_cfg_flags`, `lsa_run_as_ppl`, `platform_execute`, `print_monitors`, `print_processors`, `rdp_clx_dll`, `rdp_virtual_channel`, `rdp_wds_startup`, `run_keys`, `run_services`, `run_services_once`, `s0_initial_command`, `scm_extension`, `security_packages`, `session_manager_execute`, `session_manager_subsystems`, `setup_execute`, `shell_folders_startup`, `shell_launcher`, `startup_folder`, `time_providers`, `ts_initial_program`, `winlogon_mpnotify`, `winlogon_notify_packages`, `winlogon_shell`, `winlogon_userinit` |
| T1556 | Modify Authentication Process | `lsa_password_filter`, `network_provider_dll` |
| T1574 | Hijack Execution Flow | `appdomain_manager`, `autodial_dll`, `chm_helper_dll`, `content_index_dll`, `cor_profiler`, `coreclr_profiler`, `crypto_expo_offload`, `diagtrack_dll`, `diagtrack_listener_dll`, `direct3d_dll`, `dotnet_framework_profiler`, `dotnet_startup_hooks`, `gp_extension_dlls`, `hhctrl_ocx_dll`, `known_dlls`, `known_managed_debugging_dlls`, `lsa_extensions`, `mapi32_dll_path`, `minidump_auxiliary_dlls`, `msdtc_xa_dll`, `nldp_dll`, `rdp_test_dvc_plugin`, `search_indexer_dll`, `server_level_plugin_dll`, `snmp_extension_agent`, `winsock_auto_proxy`, `wu_service_startup_dll` |

## ⚙️ Detection Profiles

Detection profiles let you suppress known-good findings or flag specific values. Rules are defined in YAML and can be applied globally or per-check.

```yaml
# Global allow rules — applied to all checks
allow:
  - signer: "microsoft"
    not_lolbin: true
    reason: "Microsoft-signed, not a LOLBin"

  - path_matches: "\\\\Contoso\\\\"
    reason: "Known enterprise software"

# Global block rules — force-flag regardless of other rules
block:
  - value_matches: "suspicious\\.exe"
    reason: "Known malicious binary"

# Per-check overrides
checks:
  run_keys:
    allow:
      - value_matches: "SecurityHealthSystray"
        reason: "Built-in Windows Security tray icon"

  ghost_task:
    enabled: false  # Disable this check entirely
```

### Rule fields

All fields are optional. When multiple fields are present, **all** must match (AND logic). Comparisons are case-insensitive.

| Field | Match Type | Description |
|-------|-----------|-------------|
| `signer` | substring | Authenticode signer name |
| `path_matches` | regex | Registry key or file path (case-insensitive) |
| `value_matches` | regex | Registry value or command line (case-insensitive) |
| `hash` | exact | SHA-256 hash of the referenced file |
| `not_lolbin` | boolean | Only match if the binary is **not** a LOLBin |
| `reason` | — | Human-readable justification (shown in verbose output) |

### Rule evaluation

Rules come from three layers, all evaluated together:

| Layer | Source | Scope |
|-------|--------|-------|
| **Plugin built-in** | Hardcoded in each check's definition | That check only |
| **Profile global** | Top-level `allow`/`block` in the YAML | All checks |
| **Profile per-check** | `checks.<id>.allow`/`block` in the YAML | That check only |

Per-check profile rules **add to** global rules — they don't replace them. A check with one per-check allow rule and two global allow rules has three allow rules total.

**Block rules win.** The pipeline evaluates block rules first. If any block rule from any layer matches, the finding is `HIGH` — allow rules are not considered. Allow rules only affect findings that no block rule matched.

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
  config/             # Default detection profile
  core/               # Domain models, pipeline orchestration, offline artifact I/O,
                      #   path normalization, metadata resolution, detection profiles, logging
  data/               # Bundled data files (LOLBin list)
  enrichment/         # Optional enrichment plugins
  output/             # Console, CSV, HTML, XLSX renderers
  plugins/            # Detection plugins, grouped by MITRE ATT&CK technique
    base.py           # PersistencePlugin base class with composable helpers
    runner.py         # Plugin discovery and registration
    T1547/            # Boot/logon autostart execution
    T1546/            # Event-triggered execution
    T1574/            # Hijack execution flow
    T1543/            # Services
    ...
  ui/                 # CLI presentation — banner, progress display
```

### Adding a plugin

Plugins live in `pyrsistencesniper/plugins/`, organized by technique ID. Most checks are fully declarative:

```python
from pyrsistencesniper.core.models import CheckDefinition, HiveScope, RegistryTarget
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

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

The base class handles registry scanning, value extraction, and finding creation. For checks that need custom logic (filesystem walking, cross-referencing multiple hives, etc.), override `run()` and return a `list[Finding]`. The plugin gets dependency-injected helpers via `self.context` — including `self.registry`, `self.filesystem`, `self.profile`, and `self.hive_ops` for high-level registry operations like iterating user hives, resolving CLSIDs, or loading subtrees.

## 📖 Background

[PersistenceSniper](https://github.com/last-byte/PersistenceSniper) by Federico Lagrasta and [Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns) by Sysinternals are the two tools that come up every time someone talks about Windows persistence detection. Both are great. Both were direct inspiration for this project.

Where we kept running into friction was the workflow. Autoruns is a Windows binary — if your analysis box runs Linux, you're out of luck. PersistenceSniper is PowerShell, which is powerful on live systems but awkward when you have twenty KAPE collections on a SIFT workstation. And when a new persistence technique drops, adding a check means working through a larger codebase rather than dropping in a single file.

We kept writing one-off scripts to cover the gaps, and at some point it made more sense to build something purpose-built. PyrsistenceSniper parses hives offline with libregf, walks filesystem artifacts and scheduled task XMLs, enriches everything with file metadata and Authenticode signatures, and filters through detection profiles to strip out OS noise. On most systems that cuts output by 80–90%.

## 🙏 Credits

- [PersistenceSniper](https://github.com/last-byte/PersistenceSniper) by Federico Lagrasta
- [Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns) by Sysinternals
- [libregf](https://github.com/libyal/libregf) by Joachim Metz
- [MITRE ATT&CK](https://attack.mitre.org/)

## ⚖️ License

Distributed under the **MIT License**. See [LICENSE](LICENSE).
