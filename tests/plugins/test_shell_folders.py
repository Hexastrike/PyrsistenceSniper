"""Tests for the ShellFoldersStartup plugin (T1547): startup folder redirection."""

from __future__ import annotations

from pathlib import Path

from pyrsistencesniper.core.ledger import artifact_failures
from pyrsistencesniper.core.models import Finding
from pyrsistencesniper.plugins.T1547.shell_folders import ShellFoldersStartup

from ..core.test_shortcut import build_shell_link
from .conftest import (
    make_deps,
    make_node,
    make_user_profiles,
    setup_filesystem,
    setup_keys,
)

_HKLM_USER_SHELL_FOLDERS = (
    "Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"
)
_HKU_SHELL_FOLDERS = (
    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders"
)
_HKU_USER_SHELL_FOLDERS = (
    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"
)

_DEFAULT_COMMON_VALUE = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
_DEFAULT_COMMON_DIR = "ProgramData/Microsoft/Windows/Start Menu/Programs/Startup"

_DEFAULT_USER_VALUE = (
    r"C:\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
)
_DEFAULT_USER_DIR = (
    "Users/victim/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
)

_REDIRECT_VALUE = r"C:\ProgramData\Updater\Startup"
_REDIRECT_DIR = "ProgramData/Updater/Startup"

_USER_REDIRECT_VALUE = r"C:\Users\victim\AppData\Local\Updater\Startup"
_USER_REDIRECT_DIR = "Users/victim/AppData/Local/Updater/Startup"


def _make_plugin(
    tmp_path: Path, usernames: tuple[str, ...] = ()
) -> ShellFoldersStartup:
    """Build a ShellFoldersStartup on mock deps; callers still stub the hive reads."""
    profiles = make_user_profiles(*usernames) if usernames else []
    context, registry, _filesystem = make_deps(tmp_path, user_profiles=profiles)
    context.registry = registry
    return ShellFoldersStartup(context=context)


def _machine_plugin(tmp_path: Path, common_startup: str) -> ShellFoldersStartup:
    """Wire HKLM Common Startup to one value, with no user profiles in the image."""
    plugin = _make_plugin(tmp_path)
    setup_keys(
        plugin,
        {
            _HKLM_USER_SHELL_FOLDERS: make_node(
                name="UserShellFolders", values={"Common Startup": common_startup}
            )
        },
    )
    return plugin


def _user_plugin(
    tmp_path: Path, shell_folders: str, user_shell_folders: str
) -> ShellFoldersStartup:
    """Wire both per-user Startup values for the profile named victim."""
    plugin = _make_plugin(tmp_path, usernames=("victim",))
    setup_keys(
        plugin,
        {
            _HKU_SHELL_FOLDERS: make_node(
                name="ShellFolders", values={"Startup": shell_folders}
            ),
            _HKU_USER_SHELL_FOLDERS: make_node(
                name="UserShellFolders", values={"Startup": user_shell_folders}
            ),
        },
    )
    return plugin


def _redirects(findings: list[Finding]) -> list[Finding]:
    """Keep only the findings that report a redirected Startup path."""
    return [
        finding for finding in findings if "redirected" in finding.description.lower()
    ]


def _named(findings: list[Finding], name: str) -> list[Finding]:
    """Keep only the findings whose artifact path names the given file."""
    return [finding for finding in findings if name in finding.path]


def test_default_common_startup_reports_nothing(tmp_path: Path) -> None:
    """The default folder belongs to startup_folder; scanning it here doubles it."""
    plugin = _machine_plugin(tmp_path, _DEFAULT_COMMON_VALUE)
    setup_filesystem(
        plugin,
        {
            f"{_DEFAULT_COMMON_DIR}/evil.bat": "echo pwned",
            f"{_DEFAULT_COMMON_DIR}/desktop.ini": "[.ShellClassInfo]",
        },
    )

    assert plugin.run() == []


def test_redirected_common_startup_is_reported(tmp_path: Path) -> None:
    """Repointing Common Startup hides persistence from anyone reading the folder."""
    plugin = _machine_plugin(tmp_path, _REDIRECT_VALUE)

    findings = _redirects(plugin.run())
    assert len(findings) == 1
    assert findings[0].path == (
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
        r"\User Shell Folders\Common Startup"
    )
    assert findings[0].value == _REDIRECT_VALUE


def test_redirected_common_startup_folder_is_scanned(tmp_path: Path) -> None:
    """The redirect target is the folder that runs at logon, so it must be walked."""
    plugin = _machine_plugin(tmp_path, _REDIRECT_VALUE)
    setup_filesystem(
        plugin,
        {
            f"{_REDIRECT_DIR}/evil.bat": "echo pwned",
            f"{_REDIRECT_DIR}/desktop.ini": "[.ShellClassInfo]",
        },
    )

    findings = plugin.run()
    assert (
        _named(findings, "evil.bat")[0].path == r"ProgramData\Updater\Startup\evil.bat"
    )
    assert _named(findings, "desktop.ini") == []


def test_env_var_redirect_expands_and_scans(tmp_path: Path) -> None:
    """A redirect written with an environment variable is still a redirect."""
    plugin = _machine_plugin(tmp_path, r"%SYSTEMDRIVE%\ProgramData\Updater\Startup")
    setup_filesystem(plugin, {f"{_REDIRECT_DIR}/evil.bat": "echo pwned"})

    findings = plugin.run()
    assert len(_redirects(findings)) == 1
    assert len(_named(findings, "evil.bat")) == 1


def test_default_user_startup_reports_nothing(tmp_path: Path) -> None:
    """Both per-user keys at their default is the state of every clean profile."""
    plugin = _user_plugin(tmp_path, _DEFAULT_USER_VALUE, _DEFAULT_USER_VALUE)
    setup_filesystem(plugin, {f"{_DEFAULT_USER_DIR}/evil.bat": "echo pwned"})

    assert plugin.run() == []


def test_redirected_user_startup_is_scanned_and_default_is_not(tmp_path: Path) -> None:
    """A per-user redirect fires once and only the redirect target is walked."""
    plugin = _user_plugin(tmp_path, _DEFAULT_USER_VALUE, _USER_REDIRECT_VALUE)
    setup_filesystem(
        plugin,
        {
            f"{_DEFAULT_USER_DIR}/benign.bat": "echo hello",
            f"{_USER_REDIRECT_DIR}/beacon.exe": "MZ",
        },
    )

    findings = plugin.run()
    redirects = _redirects(findings)
    assert len(redirects) == 1
    assert redirects[0].path == (
        r"HKU\victim\Software\Microsoft\Windows\CurrentVersion\Explorer"
        r"\User Shell Folders\Startup"
    )
    assert _named(findings, "beacon.exe")[0].path == (
        r"Users\victim\AppData\Local\Updater\Startup\beacon.exe"
    )
    assert _named(findings, "benign.bat") == []


def test_user_hive_uses_software_prefix(tmp_path: Path) -> None:
    """User hive queries prepend Software\\ to the registry key path."""
    plugin = _make_plugin(tmp_path, usernames=("victim",))
    setup_keys(plugin, {})
    plugin.context.hive_path.return_value = None  # type: ignore[union-attr]

    plugin.run()

    key_paths = [
        call.args[1]
        for call in plugin.registry.load_subtree.call_args_list  # type: ignore[union-attr]
    ]
    assert key_paths
    for key_path in key_paths:
        assert key_path.startswith("Software\\"), (
            f"User hive key missing Software\\ prefix: {key_path}"
        )


def test_shortcut_reports_the_binary_it_launches(tmp_path: Path) -> None:
    """A dropped .lnk persists its target, so the target is what must be resolved."""
    plugin = _machine_plugin(tmp_path, _REDIRECT_VALUE)
    setup_filesystem(
        plugin,
        {
            f"{_REDIRECT_DIR}/OneDrive.lnk": build_shell_link(
                local_base_path=r"C:\Users\bob\AppData\Local\Temp\svchost.exe"
            )
        },
    )

    findings = _named(plugin.run(), "OneDrive.lnk")
    payload = r"Users\bob\AppData\Local\Temp\svchost.exe"
    assert len(findings) == 1
    assert findings[0].value == payload
    assert findings[0].resolve_target == payload
    assert findings[0].path == r"ProgramData\Updater\Startup\OneDrive.lnk"


def test_shortcut_arguments_are_reported_with_the_target(tmp_path: Path) -> None:
    """A LOLBin shortcut persists through its arguments, which must reach the report."""
    plugin = _machine_plugin(tmp_path, _REDIRECT_VALUE)
    setup_filesystem(
        plugin,
        {
            f"{_REDIRECT_DIR}/updater.lnk": build_shell_link(
                local_base_path=r"C:\Windows\System32\cmd.exe",
                arguments=r"/c C:\ProgramData\stage.bat",
            )
        },
    )

    findings = _named(plugin.run(), "updater.lnk")
    assert len(findings) == 1
    assert findings[0].value == r"Windows\System32\cmd.exe /c C:\ProgramData\stage.bat"
    assert findings[0].resolve_target == r"Windows\System32\cmd.exe"


def test_non_shortcut_file_keeps_its_own_name(tmp_path: Path) -> None:
    """A plain executable is its own payload and must not be renamed or re-targeted."""
    plugin = _machine_plugin(tmp_path, _REDIRECT_VALUE)
    setup_filesystem(plugin, {f"{_REDIRECT_DIR}/evil.bat": "echo pwned"})

    findings = _named(plugin.run(), "evil.bat")
    assert len(findings) == 1
    assert findings[0].value == "evil.bat"
    assert findings[0].resolve_target == findings[0].path
    assert artifact_failures() == ()


def test_shortcut_naming_no_file_falls_back_to_its_own_name(tmp_path: Path) -> None:
    """A .lnk that names no file at all is still reported, under its own name."""
    plugin = _machine_plugin(tmp_path, _REDIRECT_VALUE)
    setup_filesystem(
        plugin,
        {f"{_REDIRECT_DIR}/empty.lnk": build_shell_link(id_list=b"\x04\x00\x00\x00")},
    )

    findings = _named(plugin.run(), "empty.lnk")
    assert len(findings) == 1
    assert findings[0].value == "empty.lnk"
    assert findings[0].resolve_target == findings[0].path
    assert artifact_failures() == ()


def test_unparsable_shortcut_reports_lost_coverage(tmp_path: Path) -> None:
    """A .lnk that is present but will not parse is coverage the scan lost."""
    plugin = _machine_plugin(tmp_path, _REDIRECT_VALUE)
    setup_filesystem(plugin, {f"{_REDIRECT_DIR}/corrupt.lnk": b"not a shell link"})

    findings = _named(plugin.run(), "corrupt.lnk")
    assert len(findings) == 1
    assert findings[0].value == "corrupt.lnk"
    failures = artifact_failures()
    assert len(failures) == 1
    assert failures[0].label.startswith("shell_folders_startup artifact ")
    assert "corrupt.lnk" in failures[0].label


def test_user_shortcut_expands_against_the_owning_profile(tmp_path: Path) -> None:
    """A per-user shortcut names %USERPROFILE%, which only that user's name expands."""
    plugin = _user_plugin(tmp_path, _DEFAULT_USER_VALUE, _USER_REDIRECT_VALUE)
    setup_filesystem(
        plugin,
        {
            f"{_USER_REDIRECT_DIR}/sync.lnk": build_shell_link(
                environment_target=r"%USERPROFILE%\AppData\Local\beacon.exe"
            )
        },
    )

    findings = _named(plugin.run(), "sync.lnk")
    payload = r"Users\victim\AppData\Local\beacon.exe"
    assert len(findings) == 1
    assert findings[0].value == payload
    assert findings[0].resolve_target == payload
