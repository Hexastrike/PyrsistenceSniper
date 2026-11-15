# CHANGELOG


## v0.10.0 (2026-11-15)

### Bug Fixes

- **core**: Cap every whole-file read of an image-supplied file
  ([`fea78d8`](https://github.com/Hexastrike/PyrsistenceSniper/commit/fea78d8b6d0930301dc9ff0679fdd2ebaf15db1f))

- **plugins**: Tighten check descriptions and correct two technique names
  ([`6cd59d4`](https://github.com/Hexastrike/PyrsistenceSniper/commit/6cd59d43b9529af60bb316050ce28aa2d868ddc8))

### Build System

- Drop python 3.10 and clear the dependabot alerts
  ([`ebae90b`](https://github.com/Hexastrike/PyrsistenceSniper/commit/ebae90b5093550118256cf20db8495f56419a5e4))

- Fetch the lolbas list with the standard library
  ([`475b223`](https://github.com/Hexastrike/PyrsistenceSniper/commit/475b22330407c8779cbfefe0b0c0c051d38de707))

### Documentation

- Correct stale and inaccurate comments
  ([`71452e4`](https://github.com/Hexastrike/PyrsistenceSniper/commit/71452e41b9c734110bf2a2fff863cd95c4628a1b))

- **core**: Drop comments that restate a constant and fix a stale one
  ([`f065f03`](https://github.com/Hexastrike/PyrsistenceSniper/commit/f065f03b619e7e1715bd57d65f1757dedf5599fa))

### Features

- **output**: Report scan errors as rows in every report format
  ([`4e50bc5`](https://github.com/Hexastrike/PyrsistenceSniper/commit/4e50bc56a19c0ece0d936ff5934e0a1589f61e1b))

### Performance Improvements

- **core**: Read registry subkeys on first use
  ([`f37d05f`](https://github.com/Hexastrike/PyrsistenceSniper/commit/f37d05fa9487037856ec8b4ddfa56f67e0e28d2a))

- **core**: Resolve the image root once and probe each file once
  ([`fa9e67b`](https://github.com/Hexastrike/PyrsistenceSniper/commit/fa9e67b1f1ef5341092c5253e5b5c742482b3037))

### Refactoring

- **checks**: Group the telemetry controller rules under T1546
  ([`6e5ea41`](https://github.com/Hexastrike/PyrsistenceSniper/commit/6e5ea41d4b92869a3686efebf9d6f59d1730bff1))

- **core**: Drop the dead optional-import guards in the signer
  ([`63f49a7`](https://github.com/Hexastrike/PyrsistenceSniper/commit/63f49a7282f2151633fee293e1146a4184e30ece))

- **core**: Fill resolution fields from one cached record
  ([`88dbfd8`](https://github.com/Hexastrike/PyrsistenceSniper/commit/88dbfd817ccafb1c9b85abcc79ccd6afa6562ece))

- **core**: Keep what a scan lost in one ledger
  ([`a629aa1`](https://github.com/Hexastrike/PyrsistenceSniper/commit/a629aa14f1ade99b974ba2bf31fd35164344e19a))

- **core**: Publish the shared helpers and inline one-line wrappers
  ([`aaa1bee`](https://github.com/Hexastrike/PyrsistenceSniper/commit/aaa1bee546e7f9e66993b5d4065bd56700706e96))

- **detection**: Run the per-finding stages through one loop
  ([`f579180`](https://github.com/Hexastrike/PyrsistenceSniper/commit/f579180bb90fa0c96bf97d1dd9bb781820096e2b))

- **output**: Carry triage notes on the finding
  ([`be4fbae`](https://github.com/Hexastrike/PyrsistenceSniper/commit/be4fbae06383f5a9cef4fce4f1ab37a0e2b44ae1))

- **output**: Hand renderers one scan report
  ([`8b26d3c`](https://github.com/Hexastrike/PyrsistenceSniper/commit/8b26d3c3036914464363d11e6eb4efc2ea29c103))

- **plugins**: Derive the mitre link from the technique id
  ([`658da95`](https://github.com/Hexastrike/PyrsistenceSniper/commit/658da9584e51f4890466628f41aec54f698f03b8))

- **plugins**: Move two checks onto the engine and share duplicated helpers
  ([`d82b261`](https://github.com/Hexastrike/PyrsistenceSniper/commit/d82b261d3a2da7be4630a52cf7aab1339b23a70f))


## v0.9.1 (2026-09-04)

### Bug Fixes

- **checks**: Give two allow rules a condition attackers cannot forge
  ([`d762966`](https://github.com/Hexastrike/PyrsistenceSniper/commit/d762966788fd0e35baf6c703425dcfa629bd7a66))

- **core**: Reject an embedded nul rather than relying on the host
  ([`8601cb2`](https://github.com/Hexastrike/PyrsistenceSniper/commit/8601cb2b205a637878173ec637d3f82f845f5392))

- **output**: Keep one unencodable name from destroying the report
  ([`90b137c`](https://github.com/Hexastrike/PyrsistenceSniper/commit/90b137c837b7f98b8c80d8b7759972c4458490c5))

- **T1546**: Enforce the wmi record cap before appending a window
  ([`0f74b1c`](https://github.com/Hexastrike/PyrsistenceSniper/commit/0f74b1ce452063834a8b28f0cb742382725c25e6))

### Build System

- Fix the pyyaml floor and the release configuration
  ([`328ce3a`](https://github.com/Hexastrike/PyrsistenceSniper/commit/328ce3a195d0a7bbfca89bbd477be869bd25ff6d))

- Refresh the lockfile for the pyyaml floor
  ([`d064cb5`](https://github.com/Hexastrike/PyrsistenceSniper/commit/d064cb5e5beb89a31c6793d9dd69d91c8473e794))

- Support python 3.13 and 3.14
  ([`110b4bb`](https://github.com/Hexastrike/PyrsistenceSniper/commit/110b4bb48441e1fd54a4e06f9de2b78592fdb5df))


## v0.9.0 (2026-09-03)

### Bug Fixes

- **checks**: Read the wow64 view for office and profiler keys
  ([`98c1a03`](https://github.com/Hexastrike/PyrsistenceSniper/commit/98c1a0367ffbbada1e423c16356f59c5936f1d64))

Two checks that were blind to the 32-bit registry view and are fixed by
  RegistryTarget.include_wow64: office_test_dll, where no T1137 HKLM scan looked under WOW6432Node
  so 32-bit Office persistence was invisible, and dotnet_profiler_registry, where the COR_PROFILER
  check was HKLM-only and missed both HKCU and the Wow6432Node .NETFramework keys. Both gain their
  first dedicated tests.

Wow6432Node IFEO is deliberately not added: it is a volatile symbolic link to the native key, so
  scanning it would double-report every Debugger.

- **checks**: Widen file-backed checks to the real windows paths
  ([`1b42f28`](https://github.com/Hexastrike/PyrsistenceSniper/commit/1b42f28bcbb6ffa8d029d8ecf8f63440da74bf0d))

Five image-walking checks, each fixed to cover the locations Windows actually uses:

- gp_scripts scanned only System32\GroupPolicy, missing per-user local GPO scripts under
  GroupPolicyUsers, and one malformed line in scripts.ini discarded every CmdLine in the file; -
  office_templates checked two exact filenames and missed the Word STARTUP and Excel XLSTART
  global-template folders, and omitted resolve_target so a template under a profile name containing
  a space never resolved; - accessibility_tools matched only byte-identical copies of four binaries,
  so a modified sethc.exe or utilman.exe went unreported; - powershell_profiles missed both
  PowerShell 7 system-wide profiles and every OneDrive-redirected Documents folder; - power_automate
  used Path.is_dir(), which can raise mid-scan, and now uses safe_is_dir().

- **log**: Keep warnings out of the rich progress region
  ([`6b82ee0`](https://github.com/Hexastrike/PyrsistenceSniper/commit/6b82ee05a9aa21285e5fd2fccf80740119dab752))

Logging is configured before Rich's progress bar swaps sys.stderr for its live-region proxy, so a
  StreamHandler holding the original stream wrote past the proxy and into the live region,
  repainting the whole progress block a second time. _CurrentStderrHandler re-resolves sys.stderr on
  every record instead of binding it at setup.

The module docstring also records the package-wide logging policy the rest of this release follows:
  WARNING plus a DEBUG traceback for lost coverage, DEBUG only for a recovered failure, silence only
  inside a _try_* helper.

- **plugins**: Report import failures instead of dropping checks
  ([`9999363`](https://github.com/Hexastrike/PyrsistenceSniper/commit/99993633de964552c2421ae1c66d7c580d44c4f2))

A plugin module that failed to import was logged at WARNING and then silently dropped, so the tool
  exited 0 and reported a clean host with whole check families missing. Discovery now records
  _import_failures with reset_import_failures()/failed_imports() so lost coverage is surfaced,
  guards against two checks registering the same id instead of letting one silently overwrite the
  other, and replaces pkgutil.walk_packages with _import_module_tree/_package_search_paths so a
  package whose own __init__ raised no longer hides its siblings.

plugins/runner.py is deleted; its contents live in plugins/__init__.py, which only imports
  PersistencePlugin for typing and is unaffected by the base.py rewrite that follows. Ordered before
  the re-layering commit because detection/pipeline.py imports failed_imports from here.

- **T1546**: Bound the wmi repository read and the heap window
  ([`6ada55e`](https://github.com/Hexastrike/PyrsistenceSniper/commit/6ada55eb8c5c222a97542f8562e6e40af78e5832))

wmi_subscriptions read the whole OBJECTS.DATA into memory with no size cap, so a large or
  attacker-inflated repository could exhaust it, and the flat 256-byte per-record heap window
  silently truncated the instance name of any consumer whose payload was longer - an encoded
  PowerShell command being the median real payload, so the most interesting subscriptions lost their
  identity. The window is now bounded by each record's own declared heap length.

- **tests**: Gate the long-path precondition on the actual policy
  ([`c1b533b`](https://github.com/Hexastrike/PyrsistenceSniper/commit/c1b533b59aacb75853a472833fbf22215a6f16e1))

test_over_length_tree_is_readable asserted that plain pathlib cannot see a file past MAX_PATH. That
  holds only where Win32 still enforces the limit: this repo's dev host has LongPathsEnabled at 0,
  but GitHub's windows-latest runners ship with it at 1, so the precondition failed there while
  every assertion the test exists for still passed.

The policy is now read from HKLM\SYSTEM\CurrentControlSet\Control\FileSystem and gates that single
  assert, so the exists/sha256/safe_iterdir checks keep running on both kinds of host rather than
  the test being skipped.

### Build System

- **deps**: Relax pins and add python-evtx
  ([`51f2cca`](https://github.com/Hexastrike/PyrsistenceSniper/commit/51f2cca4fbd7cac7087ff0553cc8d71fae2bb6a0))

Relax every exact runtime and dev pin to a range, add the python-evtx dependency the new event-log
  tier needs, adopt PEP 639 `license = "MIT"` (dropping the now-redundant License classifier and
  Developers audience), widen poetry-core, and register the Evtx.* mypy override.

poetry.lock is the regenerated result of exactly those edits. The image follows: .dockerignore stops
  excluding poetry.lock and the Dockerfile COPYs it and pins poetry to >=2.0,<3.0, so the image
  builds from the lock instead of resolving fresh.

pyproject.toml is staged whole, so the [tool.ruff.lint] changes that belong with the tooling commit
  ride along here: PLC0415 and S101 leave the global ignore list, PLR0917 joins it, PLC0415 moves to
  the tests per-file-ignores, and isort gains required-imports for `from __future__ import
  annotations`.

version = "0.8.0" is deliberately untouched; semantic-release owns it.

### Chores

- **tooling**: Drop redundant --strict and bump the ruff hook
  ([`028a53e`](https://github.com/Hexastrike/PyrsistenceSniper/commit/028a53eec45fad4ae3855628f187aff1be149cac))

strict = true already lives in [tool.mypy], so removing --strict from the Makefile target, the local
  pre-commit hook and the CI type-check step drops a redundant flag rather than weakening anything.
  The Makefile also gains PACKAGE/SOURCES variables, makes `fix` depend on `format`, and collapses
  three find invocations in `clean` into one. The ruff pre-commit rev moves v0.15.6 -> v0.16.2.

The matching pyproject [tool.ruff.*] hunks are in the preceding commit because pyproject.toml is
  staged as a whole file.

### Code Style

- Add module docstrings and descriptive local names
  ([`3c5663f`](https://github.com/Hexastrike/PyrsistenceSniper/commit/3c5663fb40c6bb6bae46d828855ed4a44b977b40))

The readability sweep's residue, in the files whose entire diff is that sweep: one-line module and
  class docstrings across 21 plugin modules and the package entry points, logon_scripts.py's
  collapsed docstring and reworded description string, and ui/progress.py's prog -> progress_bar
  rename with the on_progress closure documented.

Verified docstring-only for the plugin modules by stripping docstrings and comparing the unparsed
  ASTs. pyrsistencesniper/__init__.py changes by one docstring line only; __version__ stays at 0.8.0
  for semantic-release to bump. Landed last so it never sits between a behaviour change and its
  test; the same header additions in files with behaviour hunks rode along with those commits.

- **core**: Use descriptive names in the lolbin fetcher
  ([`e895c10`](https://github.com/Hexastrike/PyrsistenceSniper/commit/e895c107170c3ec8f21649bed412fd8b9daa12b1))

Rename ref/raw -> resource, x -> name and resp -> response in core/lolbins.py and lift the
  status-code comparison into a local. No behaviour change; the test file changes only in the same
  way.

### Documentation

- **readme**: Document the timeline, new checks and layout
  ([`983b18c`](https://github.com/Hexastrike/PyrsistenceSniper/commit/983b18cd4bd89b251ff30afbb1d009a935d4a306))

One commit landing last, so the README describes the finished state rather than half-describing it
  six times: the check count 117 -> 130 across 9 -> 11 techniques with T1197 and T1564 added to the
  table, the new last-change timestamps section with the --mft and --no-timeline flag rows and the
  new pipeline step, the last_change / change_source / change_evidence / launcher rows in the
  finding-fields table, the rewritten is_lolbin semantics and the note that the shipped profile no
  longer uses not_lolbin, the hard-versus-soft rule condition explanation, the updated source tree
  (core/pipeline.py and plugins/runner.py gone, detection/ and timeline/ added), Docker examples
  mounting a separate writable /out, a new roadmap table, and an em-dash-to-colon prose sweep.

### Features

- **core**: Add tri-state filesystem probes and a skip ledger
  ([`85df430`](https://github.com/Hexastrike/PyrsistenceSniper/commit/85df430316f986159ac028d3536447f3631c869e))

safe_is_file/safe_is_dir/safe_exists return None ("could not look") distinctly from False ("not
  there"), so a report never claims a binary is absent when the path was merely unreadable. A
  module-level ledger (reset_skips/skipped_paths) records why a path was skipped,
  _is_reparse_point() suppresses junction noise, every syscall goes through _io_path(),
  FilesystemHelper.resolve() no longer raises on oversized or NUL-bearing paths, and
  image_relative() is added.

FilesystemHelper.exists() widens from bool to bool | None; its only consumer, core/resolver.py,
  still compiles and follows later.

tests/core/test_safe_probes.py is new and holds two of the suite's three Windows-only skips; every
  other _io_path case uses PureWindowsPath with a monkeypatched _on_windows so Windows semantics are
  exercised on Linux too.

- **core**: Flag findings that execute through a lolbin launcher
  ([`3759c2e`](https://github.com/Hexastrike/PyrsistenceSniper/commit/3759c2e7ed178b724d1baa223b50b1855fdcb4b3))

is_lolbin now means "executes via a LOLBin": a value that runs its payload through cmd.exe,
  powershell.exe, rundll32.exe and friends is flagged, and the launcher name is recorded on
  Finding.launcher so the payload and the proxy stay distinguishable. This is what made not_lolbin
  unfireable in the shipped allow rules, which no longer use it.

_is_path_like() keeps Finding.exists at None for CLSIDs and flags rather than claiming a binary was
  searched for and absent; _select_target() honours Finding.resolve_target and gains a bare-name
  Windows\ fallback beside the existing Windows\System32\ one; _CacheEntry.exists widens to bool |
  None to match FilesystemHelper.exists().

The duplicated SignerExtractor is removed here and imported from core/signer.py instead.

- **enrichment**: Add triage notes and fold runner into base
  ([`8d48f11`](https://github.com/Hexastrike/PyrsistenceSniper/commit/8d48f116739109efa7b70334966bf11d64f78a6a))

TriageEnrichment emits a notes column saying why a finding deserves attention: LOLBin proxy
  execution, a missing referenced binary, an unsigned binary, execution from outside the OS
  directories. It reads the tri-state finding.exists / is_in_os_directory added earlier in the
  release. Being the first shipped enrichment, it also establishes the
  registration-by-side-effect-import pattern in enrichment/__init__.py.

enrichment/runner.py is deleted in the same commit and its contents (_ENRICHMENT_REGISTRY,
  register_enrichment, the per-plugin try/except now named _enrich_one, run_enrichments) move beside
  the EnrichmentPlugin ABC in enrichment/base.py, which gains provider: str = "". __init__.py
  re-exports from base and gains a real __all__; it carries the triage registration too, which is
  why the merge and the new enrichment are one commit rather than two.

Git does not see this as a rename. tests/test_enrichment_runner.py keeps its name although runner.py
  is gone; renaming it is left as a separate cosmetic change.

- **html**: Rebuild report filters and add integrity blocks
  ([`28f3089`](https://github.com/Hexastrike/PyrsistenceSniper/commit/28f30894b18dc2c79ec8f578c7c1a08e731326d6))

report.html.j2 is a rewrite whose stories are interleaved inside the same hunks, so it lands as one
  commit:

- accent recoloured from purple to #E65064 via new :root --accent / --accent-soft / --sev-* tokens
  replacing hard-coded #d6336c, #a78bfa and the per-severity stat colours; - filter menu rebuilt as
  a fixed-position menu on body with per-column filters, search and chips, and the "Select all" row
  no longer shows a count, because a count there would mean distinct values while every other row
  counts rows; - scan-integrity blocks for unreadable hives, failed checks and a softer dirty-hive
  notice; - an expandable chevron row with the change-candidate list and the column-help info icons.

html_output.py belongs with it: it supplies unreadable_hives, dirty_hives, failed_checks,
  column_help and each row's change candidates, and adopts the shared label_for(). Neither the
  recolour nor the "Select all" fix has any test; both are template-only.

- **output**: Report unread hives and failed checks
  ([`2b8cf02`](https://github.com/Hexastrike/PyrsistenceSniper/commit/2b8cf024b977d8bf4f574174894dc733b006e379))

One contract change, so all four renderers move together: OutputBase.render and the abstract _write
  gain keyword-only inventory: tuple[HiveRecord, ...] and failures: tuple[CheckFailure, ...].

base.py gains the shared unreadable_hives() filter, label_for() for enrichment.* columns,
  sanitize_cell() promoted out of csv_output.py and hardened against illegal control characters, and
  _console_stream() which reconfigures stdout to backslashreplace so one unencodable artifact name
  cannot truncate a report. An unresolved field now renders as "" instead of False, with build_flags
  switching to `row["exists"] is False`.

console_output.py gains the ruled SCAN INCOMPLETE banners and the last-change columns;
  xlsx_output.py gains "Hives" and "Failed Checks" sheets plus extracted header/row/column helpers;
  csv_output.py explicitly discards both arguments, because that format exists to be parsed.

- **T1197**: Report bits job notification commands
  ([`22fab26`](https://github.com/Hexastrike/PyrsistenceSniper/commit/22fab268366f089c17c3de88ea2c4dccbcbc3d7e))

New technique family. bits_notify_command parses the BITS job state file (qmgr.db / qmgr*.dat),
  handling job-id GUID formatting and record framing, and reports each job's SetNotifyCmdLine
  notification command - a SYSTEM-context persistence store the scanner never examined.

- **T1546**: Detect registered shim databases and custom shims
  ([`9bb1b10`](https://github.com/Hexastrike/PyrsistenceSniper/commit/9bb1b10c530a012683ba857ebfb30e334fc0c62a))

T1546.011 Application Shimming had no check anywhere. Two declarative checks in one module:
  installed_sdb (AppCompatFlags\InstalledSDB, registered shim databases) and shim_custom
  (AppCompatFlags\Custom, executables with a custom shim attached). Deliberately not
  location-anchored: sdbinst.exe writes attacker and legitimate .sdb files to the same folder, so
  anchoring would only hide the interesting case.

- **T1564**: Report hidden accounts and unexpected local admins
  ([`442338c`](https://github.com/Hexastrike/PyrsistenceSniper/commit/442338cd5900bf1e75236f048560c10e5e8b9e2d))

Two checks that share the SAM helpers extracted into core/sam.py:

- hidden_account (T1564.002): accounts hidden from the sign-in screen via SpecialAccounts\UserList
  or SAM alias headers; - admin_group_membership (T1098): non-default members of the local
  Administrators alias.

T1098 previously covered only RID edits, leaving both hidden-account and Administrators-group
  persistence unchecked anywhere. They ship together because they import the same
  iter_hidden_accounts/alias helpers; those helpers live in core/sam.py precisely so neither plugin
  has to import the other. core/sam.py has no dedicated test module - these two tests and
  test_rid_hijacking.py are its coverage.

- **timeline**: Resolve last-change times from $mft and evtx
  ([`1baab28`](https://github.com/Hexastrike/PyrsistenceSniper/commit/1baab28d6aa9a060e02a182bf150588b70d91531))

New timeline/ package answering "when was this last changed":

- base.py: Precision, TimeCandidate, from_filetime, is_implausible and the plausibility window. -
  mft.py / mft_index.py: a from-scratch FILE-record parser (USA fixups, $SI/$FN timestamps,
  full-path reconstruction) and lazy discovery of an $MFT beside or below the image root. -
  file_resolver.py: FileWriteTime -> $SI candidate, including the $SI-predates-$FN timestomping
  hint. - evtx_index.py: lazily indexes a channel per (channel, event-id set), refuses oversized
  logs, detects a cleared log from chunk count plus next-record-number, and keeps "unreadable"
  distinct from "read, matched nothing". - regpath.py: the spellings a Sysmon TargetObject may carry
  for one finding (HKU rewritten onto the owner SID, ControlSet001 vs CurrentControlSet). -
  executor.py: resolves each finding's declared TimeEvidence, supplies the fallbacks, and ranks
  candidates EXACT before WEAK with a 2-second tie window and an $MFT-before-event-log preference.

Shipped as one commit and ordered before the re-layering commit because detection/pipeline.py
  imports timeline.executor. file_resolver.py and executor.py reference
  FileWriteTime/ChangeEvidence, which arrive with core/models.py in the next commit, so this commit
  is not importable on its own.

### Refactoring

- **core**: Add windows.py as the successor to winutil
  ([`7c6e31f`](https://github.com/Hexastrike/PyrsistenceSniper/commit/7c6e31ff2e393cfecd8eafaf855652d99329dc6f))

core/windows.py carries winutil's whole public API (ENV_VAR_TABLE, expand_env_vars,
  normalize_windows_path, canonicalize_windows_path, extract_executable_from_cmdline, is_lolbin,
  is_builtin, is_in_os_directory, BUILTIN_NAMES, OS_SYSTEM_PATHS, SCRIPT_LAUNCHERS) plus the
  primitives the rest of the release needs: is_representable_windows_path(), the _on_windows()
  host-OS seam, the _io_path() \\?\ long-path wrapper, extract_launcher_from_cmdline() and
  _lolbin_names() folding the shells back in.

Purely additive: core/winutil.py stays until its last importer moves, so the tree remains
  importable. canonicalize_registry_path() has no successor here; registry_key_join() in
  core/registry.py covers the surviving need.

The old tests/core/test_winutil.py is split three ways along the module's own seams (paths, cmdline,
  classify) and is deleted with winutil itself later in the sequence, so coverage is briefly
  duplicated rather than lost.

- **core**: Extract the authenticode signer into signer.py
  ([`1834faf`](https://github.com/Hexastrike/PyrsistenceSniper/commit/1834faff836854777d3c30b37b97f3d2b5b74b38))

SignerExtractor and the CMS/Authenticode parsing leave core/resolver.py for core/signer.py, and the
  catalog path is rewritten: instead of holding every .cat file's raw bytes in memory and
  substring-searching for the authentihash, each catalog's CertTrustList is parsed once into a
  {member_hash: signer_name} index. _signer_from_certificates() is added as a fallback for catalogs
  carrying no SpcSpOpusInfo.

Additive here on purpose: resolver.py keeps its own copy until its own commit, so the tree stays
  importable across the seam.

- **core**: Re-layer core into evidence access and detection
  ([`7613429`](https://github.com/Hexastrike/PyrsistenceSniper/commit/7613429c63fc902e1a31fd0c05216df0109022cb))

The unavoidable mass commit. core becomes layer 1 (evidence access plus Windows domain knowledge)
  and a new detection/ package becomes layer 2. Two API removals admit no intermediate state with
  whole-file staging, and between them they pin 46 plugin modules to this commit:

- HiveOps is absorbed into AnalysisContext (open_hive_by_name, load_subtree, iter_user_hives,
  iter_usrclass_hives, resolve_clsid_*), so 36 plugins move from self.hive_ops to self.context. -
  CheckDefinition.allow/.block are removed from core/models.py, so 30 plugins lose their inline
  FilterRule tuples; the shipped ruleset now lives in config/default_profile.yaml, which grows from
  a never-loaded 3-line stub to 506 lines and drops not_lolbin from all 40 rules.

core/pipeline.py is deleted and reborn as detection/pipeline.py: run_all_checks -> run_pipeline, the
  profile is an argument rather than a field on the context, a bare T1547 selects its
  sub-techniques, findings are de-duplicated, every stage traps per-item failures as a CheckFailure
  instead of losing the run, and a new stage drives TimelineExecutor. registry.execute_definition
  becomes detection/engine.py, rewritten around a _HiveContext with WOW64 views, UsrClass.dat class
  hives and cross-hive dedup. core/profile.py takes over severity classification (CheckPolicy with
  classify(), policy_for()), loads the bundled profile by default and validates rules at parse time.

Also here: the scan-integrity channel (HiveStatus/HiveRecord/CheckFailure, REGF header checks,
  hive-bin-list repair, partial-read and artifact-failure ledgers); the timeline vocabulary and
  Finding.launcher / resolve_target on the models; new core/signer-adjacent modules core/shortcut.py
  (MS-SHLLINK parser) and core/sam.py (shared SAM and SpecialAccounts helpers); and cli.py's switch
  to run_pipeline, its new --mft/--no-timeline flags, and the exit code 2 for an incomplete scan.

Cost, stated plainly: 24 measured detection fixes and 8 new check ids are buried in this commit
  because their files are pinned by the two API removals above. Among them: winlogon userinit
  comma-append and the appsetup/gina/system/taskman/vmapplet checks, ghost_task Tarrask SD deletion
  plus orphan TaskCache entries, ComHandler task actions, driver services with no ImagePath,
  per-user HKCU CLSID servers, Wow6432Node COM/AeDebug/WER/IFEO/Active Setup views, RunOnceEx/RunEx
  section subkeys, IFEO filter subkeys, protocol handlers without URL Protocol, JSONC Windows
  Terminal settings, the telemetry_controller key path, .lnk target resolution, the Startup redirect
  blowup and its image-root guard, dll_search_mode and exclude_from_known_dlls.

- **core**: Retire winutil and enforce the layer boundaries
  ([`53549c6`](https://github.com/Hexastrike/PyrsistenceSniper/commit/53549c60cda7b43a6a9c8445fd68100af6fb0770))

core/winutil.py is deleted now that every importer - filesystem, registry, resolver and the four
  plugins that still referenced it (file_association, windows_terminal, shell_folders,
  startup_folder) - has moved to core/windows.py. tests/core/test_winutil.py goes with it; its
  coverage has lived in the three test_windows_* modules since the successor landed.

tests/test_import_boundaries.py is rewritten as the enforcement test for the finished layering:
  core(1) < detection/plugins/enrichment/timeline(2) < output/ui(3), core/registry.py imports no
  context, detection or plugin module, detection/ outside pipeline.py never imports plugins/, and no
  module references a retired path. All of that is only true once every commit above has landed.

### Testing

- **plugins**: Add first tests for eight untested checks
  ([`d5d9416`](https://github.com/Hexastrike/PyrsistenceSniper/commit/d5d9416fcaeb02fcb2ae416bcd5e69a6290c8bb1))

Eight checks shipped in v0.8.0 with no dedicated test file and now have one: appdomain_manager,
  boot_verification, cmd_autorun, error_handler_cmd, explorer_clsid_hijack, font_drivers,
  recycle_bin_com and snmp_extension.

They are grouped rather than paired with their modules because those modules change only by gaining
  a docstring header, which lands in the readability sweep; there is no behaviour for these tests to
  accompany. Several are named in the path-blind caller list frozen by the declarative target
  harness, so they land after it.

- **plugins**: Add the declarative target and engine view harness
  ([`58488ea`](https://github.com/Hexastrike/PyrsistenceSniper/commit/58488eae8d9b29a0ac13d5720686d0e651aaedeb))

test_declarative_targets.py walks every registered declarative check and proves it reads exactly the
  registry location its CheckDefinition declares, plus a decoy key it must not read.
  test_engine_views.py covers the engine's Wow6432Node view and per-user class registrations.

Together they take over the location and enumeration coverage the per-plugin tests used to
  duplicate. The four test modules whose engine-generic cases were removed in favour of the harness
  come along here; the same deletions in migrated plugins' tests happened one commit earlier, so
  that generic coverage is thin for exactly one commit.


## v0.8.0 (2026-03-30)

### Bug Fixes

- Broaden PermissionError to OSError for long/URL-encoded path handling (fixes #1)
  ([`c4d6b3f`](https://github.com/Hexastrike/PyrsistenceSniper/commit/c4d6b3f6c181b9d23b787f8194aa3cb82b461375))

- Include Poetry lockfile
  ([`f88c356`](https://github.com/Hexastrike/PyrsistenceSniper/commit/f88c3568d84a2dbe052eb01f3409abf9fb90ff8e))

### Chores

- Pin all dependencies to exact versions
  ([`3f17692`](https://github.com/Hexastrike/PyrsistenceSniper/commit/3f176921e8db8eb94de6d86a6544f9cd8a13481b))

### Code Style

- Modernize HTML report with clean dark theme and remove glow effects
  ([`8dc9101`](https://github.com/Hexastrike/PyrsistenceSniper/commit/8dc910111d486355e9a0ed13196c540c70ad893b))

### Documentation

- Use python -m pyrsistencesniper as primary CLI usage
  ([`082e37c`](https://github.com/Hexastrike/PyrsistenceSniper/commit/082e37c940a8e62549417403f89c8e15d54ccb07))

### Features

- Add exclude matching rows option to HTML report context menu
  ([`576a677`](https://github.com/Hexastrike/PyrsistenceSniper/commit/576a6774da6b879149e5c92d52c53e5c3d20dfac))


## v0.7.1 (2026-03-22)

### Bug Fixes

- Prevent column resize from triggering sort in HTML report
  ([`00c6036`](https://github.com/Hexastrike/PyrsistenceSniper/commit/00c603603463d5ea462af676fd681e03d9d74d34))

- Use official semantic-release action and skip CI on release commits
  ([`4667bb4`](https://github.com/Hexastrike/PyrsistenceSniper/commit/4667bb4f7f5e77f8478fb8b9f1d5e18d136df551))


## v0.7.0 (2026-03-22)

### Bug Fixes

- Add path traversal guard and debug logging to all plugin except blocks
  ([`e3a593a`](https://github.com/Hexastrike/PyrsistenceSniper/commit/e3a593a41d67afcd121f44a979844faaa0278f99))

- Bump version to 0.6.1.1
  ([`a90dc7d`](https://github.com/Hexastrike/PyrsistenceSniper/commit/a90dc7ddf06e664214925861d52cf4d945378797))

- Handle PermissionError on directory access, move tracebacks to debug level
  ([`c660fe6`](https://github.com/Hexastrike/PyrsistenceSniper/commit/c660fe6592a3f5620de644299463e3d044a8a4bd))

- Pass CODECOV_TOKEN to codecov upload action
  ([`961d813`](https://github.com/Hexastrike/PyrsistenceSniper/commit/961d813eea0059c9e9b3b162cf052e3ce9e07c54))

- Prevent standalone mode from loading sibling hive files
  ([`6350506`](https://github.com/Hexastrike/PyrsistenceSniper/commit/63505068eaf5b0eaa1a6da699e9759c0a48b86ce))

- Use absolute URLs in README for PyPI rendering
  ([`a6da982`](https://github.com/Hexastrike/PyrsistenceSniper/commit/a6da982b7d2e3389f6b0b9849d3945f85fde7a8d))

### Chores

- **release**: V0.7.0
  ([`27c2d35`](https://github.com/Hexastrike/PyrsistenceSniper/commit/27c2d358e172b288a5cfc9347a177228d433cc76))

### Documentation

- Clarify paths argument, add loose hive example, remove dead code
  ([`d48f0be`](https://github.com/Hexastrike/PyrsistenceSniper/commit/d48f0be9481394aee5cf687a2ded9807d925a723))

- Rewrite README with full check reference, detection profile guide, and pipeline overview
  ([`6bc1b35`](https://github.com/Hexastrike/PyrsistenceSniper/commit/6bc1b354bff3b181394a557391a097a10ff6a28b))

- Rewrite README with usage examples and add Dockerfile
  ([`22695ef`](https://github.com/Hexastrike/PyrsistenceSniper/commit/22695efda7c6129b1f315fe324da538a2e899f8f))

- Update README title
  ([`7c1df07`](https://github.com/Hexastrike/PyrsistenceSniper/commit/7c1df07ef0f70edad04b8caacc9373a2043ca060))

### Features

- Add CI workflow with Codecov and replace signify/oscrypto with lief
  ([`1d464ac`](https://github.com/Hexastrike/PyrsistenceSniper/commit/1d464ac81765b5328486938c07972489901bb9b3))

- Add interactive dark-mode HTML report output with filtering, sorting, and column resizing
  ([`cc789f6`](https://github.com/Hexastrike/PyrsistenceSniper/commit/cc789f66f6e86e91beb58c6a4dcbbea935ea95dc))

- Add persistence detection plugins, XLSX output, and refactored code codebase
  ([`4a3d14a`](https://github.com/Hexastrike/PyrsistenceSniper/commit/4a3d14afc8c9e597ab38b6a2bdf8b03919833341))

- Add PyPI metadata, publish workflow, and pip install instructions
  ([`0a9bb44`](https://github.com/Hexastrike/PyrsistenceSniper/commit/0a9bb44c61505d7362a911d6b9dc3ec2bce1cff8))

- Add python-semantic-release for automated versioning
  ([`e7b173e`](https://github.com/Hexastrike/PyrsistenceSniper/commit/e7b173e00d4142b2f1175ea88487cd62de3ed3fc))

- Capitalize signer values and add wab.exe, 7-zip, explorer.exe whitelist rules
  ([`f1d3ccd`](https://github.com/Hexastrike/PyrsistenceSniper/commit/f1d3ccdaa9d099b5e761906637aac07f5458d581))

- Improve HTML report with checkbox filters, dual-axis scrolling, and column resize
  ([`cbe18f3`](https://github.com/Hexastrike/PyrsistenceSniper/commit/cbe18f33343034798bd8235f88fccacb65847704))

### Refactoring

- Add recurse flag to declarative plugin engine and pre-commit hooks
  ([`a70c445`](https://github.com/Hexastrike/PyrsistenceSniper/commit/a70c445fafc5778c43028141b1a8f4f8e65d2e0e))

- Change paths positional arg to single path
  ([`30cc48c`](https://github.com/Hexastrike/PyrsistenceSniper/commit/30cc48c20277bd083b7b699f3a8c5ef5c8870d1b))

- Consolidate domain layer into core and simplify plugin architecture
  ([`95c168f`](https://github.com/Hexastrike/PyrsistenceSniper/commit/95c168f9d239693c02fc45e5dd9956fff8fdfa8d))

- Quality-pass all plugins, expand test coverage, clean up core internals
  ([`e107aa1`](https://github.com/Hexastrike/PyrsistenceSniper/commit/e107aa14b2c4aeda301f3560db4a191ba55e8815))

- Rename AllowRule to FilterRule
  ([`b17d6fc`](https://github.com/Hexastrike/PyrsistenceSniper/commit/b17d6fc94dc20bef0db2cb3bb25d146295c624d6))

- Simplify SignerExtractor by extracting catalog lookup and dropping unused Path from cache
  ([`bdb339e`](https://github.com/Hexastrike/PyrsistenceSniper/commit/bdb339e64e56abab25736e391139dd5998a427ed))

- Update directory structure, remove ForensicImage, add Context object
  ([`6148756`](https://github.com/Hexastrike/PyrsistenceSniper/commit/6148756ba17b7cac03b87c593d4319b3aad3f85c))
