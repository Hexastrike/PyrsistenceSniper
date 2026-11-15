# PyrsistenceSniper: Offline Windows Persistence Detection

[![PyPI](https://img.shields.io/pypi/v/pyrsistencesniper?color=blue)](https://pypi.org/project/pyrsistencesniper/)
[![CI](https://github.com/Hexastrike/PyrsistenceSniper/actions/workflows/ci.yml/badge.svg)](https://github.com/Hexastrike/PyrsistenceSniper/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Hexastrike/PyrsistenceSniper/graph/badge.svg)](https://codecov.io/gh/Hexastrike/PyrsistenceSniper)
[![Python](https://img.shields.io/badge/python-3.11--3.14-3776AB?logo=python&logoColor=white)](https://pypi.org/project/pyrsistencesniper/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/Hexastrike/PyrsistenceSniper/blob/main/LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-blue)](https://github.com/Hexastrike/PyrsistenceSniper)

We took PersistenceSniper, merged it with Python, and misspelled it on purpose. Meet **Py**rsistenceSniper.

Point it at a KAPE dump, a Velociraptor collection, or a mounted disk image and get offline Windows persistence detection in seconds. No live system access, no admin privileges, no PowerShell. Runs on Windows, Linux, and macOS.

## 🚀 Key Features

- **Wide persistence coverage**: 130 checks across 11 MITRE ATT&CK techniques, covering Run keys, services, COM hijacking, scheduled tasks, WMI subscriptions, Office add-ins, IFEO injection, accessibility backdoors, startup folders, LSA packages, and more.
- **Signature-based filtering**: Authenticode signatures separate real persistence from OS defaults, instead of value-based whitelists that miss swapped binaries and DLL proxying.
- **Custom detection profiles**: YAML allow and block rules, globally or per check.
- **Finding context**: Every finding carries file existence, SHA-256, signer, LOLBin classification, and an approximate last-change timestamp.
- **Flexible output**: Console, CSV, HTML, and XLSX.
- **Extensible plugin system**: A new persistence check is one file, usually declarative.
- **Speed**: Native registry parsing via libregf. Scans complete in roughly 10 to 30 seconds on heavily used systems.

## 📦 Installation

### From PyPI

```bash
pip install pyrsistencesniper
```

### From source

```bash
git clone https://github.com/Hexastrike/PyrsistenceSniper.git
cd PyrsistenceSniper
poetry install
```

### Docker

```bash
# Build the image
docker build -t pyrsistencesniper .

# Scan a triage collection
docker run --rm -v /path/to/triage:/evidence:ro pyrsistencesniper /evidence

# Export as CSV (evidence stays read-only, reports go to a separate writable mount)
docker run --rm -v /path/to/triage:/evidence:ro -v "$PWD/out":/out pyrsistencesniper /evidence --format csv --output /out/results.csv

# Full HTML report with no filtering
docker run --rm -v /path/to/triage:/evidence:ro -v "$PWD/out":/out pyrsistencesniper /evidence --min-severity info --format html --output /out/report.html
```

## 🎯 Usage

The `path` argument is the root of your forensic collection, wherever the `Windows/` directory lives: KAPE output, Velociraptor collections, mounted E01s, raw directory copies. As long as the hives and filesystem artifacts sit at their expected paths relative to the root, PyrsistenceSniper will find them.

```
python -m pyrsistencesniper [-h] [--hostname HOSTNAME] [--format {console,csv,html,xlsx}]
                            [--output OUTPUT] [--profile PROFILE]
                            [--technique TECHNIQUE [TECHNIQUE ...]] [--list-checks]
                            [--update-lolbins] [--min-severity {info,low,medium,high}]
                            [--mft MFT] [--no-timeline] [-v] [path]
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
| `--mft FILE` | Externally collected `$MFT` for change timestamps. Takes precedence over one auto-discovered in the collection |
| `--no-timeline` | Skip last-change timestamp resolution |
| `-v, --verbose` | Enable debug logging to stderr |

### Examples

```bash
# Scan a KAPE collection
python -m pyrsistencesniper /mnt/case042/C

# Export as CSV for stacking across multiple systems
python -m pyrsistencesniper /mnt/case042/C --format csv --output host1.csv

# Generate an HTML report
python -m pyrsistencesniper /mnt/case042/C --format html --output report.html

# Show everything, including OS defaults
python -m pyrsistencesniper /mnt/case042/C --min-severity info

# Only check specific MITRE ATT&CK techniques
python -m pyrsistencesniper /mnt/case042/C --technique T1547 T1546

# Apply a custom detection profile
python -m pyrsistencesniper /mnt/case042/C --profile ./profiles/customer_baseline.yaml

# Correlate change times against an externally collected $MFT
python -m pyrsistencesniper /mnt/case042/C --mft /mnt/case042/'$MFT' --format html --output report.html

# List all available persistence checks
python -m pyrsistencesniper --list-checks
```

### Standalone artifact scanning

Pass a single hive file directly, no directory structure needed:

```bash
# Scan a standalone NTUSER.DAT
python -m pyrsistencesniper /path/to/NTUSER.DAT

# Scan a standalone SYSTEM hive with verbose output
python -m pyrsistencesniper /path/to/SYSTEM -v

# Scan a standalone SOFTWARE hive with CSV output
python -m pyrsistencesniper /path/to/SOFTWARE --format csv --output results.csv
```

Supported standalone artifacts: `SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, `NTUSER.DAT`, `UsrClass.dat`, `DEFAULT`, `Amcache.hve`.

PyrsistenceSniper auto-detects standalone mode and runs only the checks that apply to the given hive. Resolution features (file existence, hashes, signatures) are unavailable there, since there is no filesystem to cross-reference.

## 🔍 How It Works

PyrsistenceSniper runs each finding through a multi-stage pipeline:

1. **Plugin execution**: Each check scans registry hives, filesystem artifacts, scheduled task XMLs, or WMI repositories for persistence indicators.
2. **Resolution**: Findings are enriched with file existence, SHA-256 hash, Authenticode signer, LOLBin classification, OS directory detection, and short triage notes.
3. **Severity classification**: Each finding is classified as `HIGH` (block rule match), `MEDIUM` (no rules match), `LOW` (partial allow match), or `INFO` (full allow match), then filtered by `--min-severity`. Plugins also reject invalid data (empty values, non-executable flags) unconditionally. In most environments this cuts output by 80 to 90%.
4. **Change timeline**: Each finding gets an approximate last-change timestamp from `$MFT` records and event logs.
5. **Output**: Findings are rendered in the requested format.

Each finding carries:

| Field | Description |
|-------|-------------|
| `path` | Registry key or file path |
| `value` | Registry value, command line, or DLL path |
| `technique` | Human-readable technique name |
| `mitre_id` | MITRE ATT&CK technique ID |
| `access_gained` | `USER` or `SYSTEM` |
| `severity` | `INFO`, `LOW`, `MEDIUM`, or `HIGH` |
| `last_change` | Approximate UTC time the mechanism last changed |
| `change_source` | Which evidence set `last_change` (`$MFT` or `event log`) |
| `change_evidence` | Why `last_change` holds what it holds |
| `sha256` | SHA-256 hash of the referenced binary |
| `signer` | Authenticode signer name |
| `is_lolbin` | Whether the entry executes via a known LOLBin, as launcher or payload |
| `launcher` | The launcher the value proxies through, empty when it runs its image directly |
| `exists` | Whether the referenced file exists on disk |

`is_lolbin` describes **how the entry executes**, not just what it points at. A value like
`rundll32.exe C:\ProgramData\evil.dll,Start` resolves its payload to the DLL, which is what
gets hashed and signer-checked, while `is_lolbin` stays true and `launcher` records
`rundll32.exe`. Adding an argument cannot make a finding look less suspicious than the bare
tool would.

The LOLBin set is the LOLBAS project's list plus the shells LOLBAS deliberately omits
(`powershell.exe`, `pwsh.exe`, `cmd.exe`). LOLBAS excludes them because a shell is not a
binary repurposed to do something it was not built for; for persistence triage a payload
launched through PowerShell is exactly as notable as one launched through `mshta`.

Console output groups findings by MITRE technique and warns when a hive or check produced nothing because it failed. CSV and XLSX include all fields. HTML produces a standalone report: searchable, sortable, with a chevron on every row that expands the full finding and every timestamp candidate that was considered.

### Last change timestamps

The `Last Change` and `Change Source` columns approximate when each persistence mechanism was last modified. A timestamp appears only when it comes from evidence that copying cannot rewrite: a file's `$MFT` record, or a matching event log entry (task creation `4698`/`106`, service install `7045`). Plugins declare which artifact and which events date their findings; otherwise a file-backed finding falls back to its own `$MFT` record, and a registry finding stays blank.

Two sources are excluded on purpose. Filesystem modification times can be copy times in a repacked collection, indistinguishable from the originals. Registry key write times stamp the key, not the value, so any value in a shared key bumps them. An empty cell is the honest answer in both cases.

`Change Evidence` says which kind of empty a blank cell is. `NOT_APPLICABLE`: nothing could ever date this kind of finding. `NO_ARTIFACT`: evidence was declared, but the `$MFT` or event log it needs was absent or cleared, so going back for that artifact would fill the cell. `NO_MATCH`: the artifact was read and had nothing to say about this entry. `REJECTED`: times were found and every one of them was implausible.

Supply an externally collected `$MFT` with `--mft` (it wins over one auto-discovered in the collection), or turn the pass off with `--no-timeline`.

## 🛡️ Supported Checks

130 persistence checks across 11 MITRE ATT&CK techniques. Run `python -m pyrsistencesniper --list-checks` for the same list in the terminal.

| MITRE ID | Technique | Checks |
|----------|-----------|--------|
| T1037 | Boot/Logon Initialization Scripts | `gp_scripts`, `logon_scripts` |
| T1053 | Scheduled Task/Job | `ghost_task`, `hidden_scheduled_task`, `scheduled_task_files` |
| T1098 | Account Manipulation | `admin_group_membership`, `rid_hijacking`, `rid_suborner` |
| T1137 | Office Application Startup | `office_addins`, `office_ai_hijack`, `office_dll_override`, `office_templates`, `office_test_dll`, `outlook_home_page`, `vba_monitors` |
| T1197 | BITS Jobs | `bits_notify_command` |
| T1543 | Create or Modify System Process | `service_failure_command`, `windows_service_dll`, `windows_service_image_path` |
| T1546 | Event Triggered Execution | `accessibility_tools`, `ae_debug`, `ae_debug_protected`, `amsi_providers`, `app_paths`, `appcert_dlls`, `appinit_dlls`, `assistive_technology`, `cmd_autorun`, `com_treat_as`, `disk_cleanup_handler`, `dotnet_dbg_managed_debugger`, `error_handler_cmd`, `explorer_clsid_hijack`, `file_association_hijack`, `ifeo_debugger`, `ifeo_delegated_ntdll`, `ifeo_silent_process_exit`, `installed_sdb`, `lsm_debugger`, `netsh_helper`, `power_automate`, `powershell_profiles`, `protocol_handler_hijack`, `recycle_bin_com_extension`, `screensaver`, `search_protocol_handler`, `shared_task_scheduler`, `shell_execute_hooks`, `shim_custom`, `telemetry_controller`, `typelib_hijack`, `wer_debugger`, `wer_hangs`, `wer_reflect_debugger`, `wer_runtime_exception`, `windows_terminal`, `wmi_event_subscription` |
| T1547 | Boot/Logon Autostart Execution | `active_setup`, `authentication_packages`, `boot_execute`, `boot_verification_program`, `dsrm_backdoor`, `explorer_app_key`, `explorer_bho`, `explorer_context_menu`, `explorer_load`, `font_drivers`, `lsa_cfg_flags`, `lsa_run_as_ppl`, `platform_execute`, `print_monitors`, `print_processors`, `rdp_clx_dll`, `rdp_virtual_channel`, `rdp_wds_startup`, `run_keys`, `run_services`, `run_services_once`, `s0_initial_command`, `scm_extension`, `security_packages`, `session_manager_execute`, `session_manager_subsystems`, `setup_execute`, `shell_folders_startup`, `shell_launcher`, `startup_folder`, `time_providers`, `ts_initial_program`, `winlogon_appsetup`, `winlogon_gina_dll`, `winlogon_mpnotify`, `winlogon_notify_packages`, `winlogon_shell`, `winlogon_system`, `winlogon_taskman`, `winlogon_userinit`, `winlogon_vmapplet` |
| T1556 | Modify Authentication Process | `lsa_password_filter`, `network_provider_dll` |
| T1564 | Hide Artifacts | `hidden_account` |
| T1574 | Hijack Execution Flow | `appdomain_manager`, `autodial_dll`, `chm_helper_dll`, `content_index_dll`, `cor_profiler`, `coreclr_profiler`, `crypto_expo_offload`, `diagtrack_dll`, `diagtrack_listener_dll`, `direct3d_dll`, `dll_search_mode`, `dotnet_framework_profiler`, `dotnet_startup_hooks`, `exclude_from_known_dlls`, `gp_extension_dlls`, `hhctrl_ocx_dll`, `known_dlls`, `known_managed_debugging_dlls`, `lsa_extensions`, `mapi32_dll_path`, `minidump_auxiliary_dlls`, `msdtc_xa_dll`, `nldp_dll`, `rdp_test_dvc_plugin`, `search_indexer_dll`, `server_level_plugin_dll`, `snmp_extension_agent`, `winsock_auto_proxy`, `wu_service_startup_dll` |

## ⚙️ Detection Profiles

Detection profiles suppress known-good findings or force-flag specific values. Rules are written in YAML and apply globally or per check.

```yaml
# Global allow rules, applied to all checks. Keep these narrow: a global rule
# merges into every check, so it cannot be anchored to any one artifact.
allow:
  - path_matches: "\\\\Contoso\\\\"
    reason: "Known enterprise software"

# Global block rules, force-flag regardless of other rules
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

All fields are optional. Comparisons are case-insensitive.

`path_matches`, `value_matches`, `hash` and `not_lolbin` are **hard** conditions: every one
present must match or the rule does not apply at all. `signer` is a **soft** condition. A rule
whose hard conditions all match but whose `signer` does not still matches partially, which
lowers the finding to `LOW` rather than clearing it to `INFO`. Offline, a binary the
collection never captured has no signer to compare, and it must not lose its allowlist match
entirely.

| Field | Match Type | Description |
|-------|-----------|-------------|
| `signer` | substring | Authenticode signer name |
| `path_matches` | regex | Registry key or file path (case-insensitive) |
| `value_matches` | regex | Registry value or command line (case-insensitive) |
| `hash` | exact | SHA-256 hash of the referenced file |
| `not_lolbin` | boolean | Only match if the entry does **not** execute via a LOLBin. Evaluated on the resolved payload *and* its launcher, so it rejects `rundll32.exe <payload>` as well as a bare `rundll32.exe`. The shipped profile no longer uses it: on a legitimate default that happens to be a LOLBin (`msedge.exe`, `wab.exe`) it silently prevents the rule from ever matching. |
| `reason` | n/a | Human-readable justification (shown in verbose output) |

### Rule evaluation

Rules come from three layers, all evaluated together:

| Layer | Source | Scope |
|-------|--------|-------|
| **Plugin built-in** | Hardcoded in each check's definition | That check only |
| **Profile global** | Top-level `allow`/`block` in the YAML | All checks |
| **Profile per-check** | `checks.<id>.allow`/`block` in the YAML | That check only |

Per-check profile rules **add to** global rules, they don't replace them. A check with one per-check allow rule and two global allow rules has three allow rules total.

**Block rules win.** The pipeline evaluates block rules first. If any block rule from any layer matches, the finding is `HIGH` and allow rules are not considered. Allow rules only affect findings that no block rule matched.

## 🛠️ Development

Poetry for dependency management, ruff for linting and formatting, mypy in strict mode, pytest for testing.

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
  core/               # Domain models, offline artifact I/O, path normalization,
                      #   metadata resolution, SAM and shell link parsing,
                      #   detection profiles, logging
  data/               # Bundled data files (LOLBin list)
  detection/          # Pipeline orchestration and the declarative check engine
  output/             # Console, CSV, HTML, XLSX renderers
  plugins/            # Detection plugins, grouped by MITRE ATT&CK technique
    __init__.py       # Plugin discovery and registration
    base.py           # PersistencePlugin base class
    T1547/            # Boot/logon autostart execution
    T1546/            # Event-triggered execution
    T1574/            # Hijack execution flow
    T1543/            # Services
    ...
  timeline/           # Last-change evidence: $MFT parser, event log correlation
  ui/                 # CLI presentation: banner, progress display
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

The base class handles registry scanning, value extraction, and finding creation. For custom logic (filesystem walking, cross-referencing multiple hives), override `run()` and return a `list[Finding]`. The plugin gets `self.context`, `self.registry` and `self.filesystem`. High-level registry operations live on the context: `load_subtree`, `open_hive_by_name`, `iter_user_hives`, `iter_usrclass_hives`, `resolve_clsid_default` and `resolve_clsid_inproc`.

Pass `time_evidence` to `_make_finding` to tell the timeline stage what dates a finding: a `FileWriteTime` for the artifact's `$MFT` record, an `EventLogTime` to correlate against a log channel, or both.

## 🗺️ Roadmap

PyrsistenceSniper today is an offline Windows registry and filesystem hunter. These are the directions being considered, roughly in the order they are likely to land.

| Area | What it would add | Notes |
|------|-------------------|-------|
| **Live mode** | Scan the running host directly instead of a mounted image | The engine is deliberately offline-only today: every read goes through `pyregf` against hive files. Live mode means a second registry backend behind the same `AnalysisContext` API, plus the privilege and locked-hive handling that comes with it. |
| **Linux persistence** | systemd units and timers, cron, shell profiles, PAM, `LD_PRELOAD`, udev rules | A separate artifact model and check family. The pipeline, profile and output layers are OS-agnostic already; the access layer is not. |
| **macOS persistence** | Launch agents and daemons, login items, `emond`, configuration profiles, TCC abuse | Same shape as the Linux work, sharing whatever cross-platform artifact model that establishes. |
| **Entra ID** | Tenant-side persistence: app registrations and consent grants, federation trust changes, long-lived refresh tokens, role assignments | Identity persistence rather than host persistence. Would read exported tenant data rather than a disk image, so it is the furthest from the current architecture. |

## 📖 Background

[PersistenceSniper](https://github.com/last-byte/PersistenceSniper) by Federico Lagrasta and [Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns) by Sysinternals are the two tools that come up every time someone talks about Windows persistence detection. Both are great. Both were direct inspiration for this project.

Where we kept running into friction was the workflow. Autoruns is a Windows binary. If your analysis box runs Linux, you're out of luck. PersistenceSniper is PowerShell, which is powerful on live systems but awkward when you have twenty KAPE collections on a SIFT workstation. And when a new persistence technique drops, adding a check means working through a larger codebase rather than dropping in a single file.

We kept writing one-off scripts to cover the gaps, and at some point it made more sense to build something purpose-built.

## 🙏 Credits

- [PersistenceSniper](https://github.com/last-byte/PersistenceSniper) by Federico Lagrasta
- [Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns) by Sysinternals
- [libregf](https://github.com/libyal/libregf) by Joachim Metz
- [MITRE ATT&CK](https://attack.mitre.org/)

## ⚖️ License

Distributed under the **MIT License**. See [LICENSE](https://github.com/Hexastrike/PyrsistenceSniper/blob/main/LICENSE).
