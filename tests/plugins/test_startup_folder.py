"""Tests for StartupFolder: system, user, and registry-overridden paths (T1547.001)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, PropertyMock

from pyrsistencesniper.core.ledger import artifact_failures
from pyrsistencesniper.core.models import AccessLevel, Finding, UserProfile
from pyrsistencesniper.plugins.T1547.startup_folder import StartupFolder

from ..core.test_shortcut import build_shell_link
from .conftest import make_deps, make_node

_STARTUP_TAIL = (
    "Microsoft",
    "Windows",
    "Start Menu",
    "Programs",
    "Startup",
)
_SYSTEM_STARTUP_PARTS = ("ProgramData", *_STARTUP_TAIL)
_USER_STARTUP_PARTS = ("Users", "victim", "AppData", "Roaming", *_STARTUP_TAIL)


def _make_plugin(tmp_path: Path) -> StartupFolder:
    """Build a StartupFolder on tmp_path; callers must still stub hive_path."""
    context, registry, _filesystem = make_deps(tmp_path)
    context.registry = registry
    return StartupFolder(context=context)


def _system_startup(tmp_path: Path) -> Path:
    """Create and return the all-users Startup folder under an image root."""
    startup = tmp_path.joinpath(*_SYSTEM_STARTUP_PARTS)
    startup.mkdir(parents=True)
    return startup


def _user_startup(tmp_path: Path) -> Path:
    """Create and return the Startup folder of the profile named victim."""
    startup = tmp_path.joinpath(*_USER_STARTUP_PARTS)
    startup.mkdir(parents=True)
    return startup


def _victim_plugin(tmp_path: Path) -> StartupFolder:
    """Build the check over the victim profile, whose NTUSER hive is empty."""
    profiles = [
        UserProfile(
            username="victim",
            profile_path=tmp_path / "Users" / "victim",
            ntuser_path=tmp_path / "Users" / "victim" / "NTUSER.DAT",
        ),
    ]
    context, registry, _filesystem = make_deps(tmp_path, user_profiles=profiles)
    context.registry = registry

    plugin = StartupFolder(context=context)
    plugin.context.hive_path.return_value = None  # type: ignore[union-attr]
    plugin.registry.open_hive.return_value = MagicMock()  # type: ignore[union-attr]
    plugin.registry.load_subtree.return_value = None  # type: ignore[union-attr]
    return plugin


def _run_on_system_startup(tmp_path: Path) -> list[Finding]:
    """Run the check with no user profiles, so only the system folder is scanned."""
    plugin = _make_plugin(tmp_path)
    plugin.context.hive_path.return_value = None  # type: ignore[union-attr]
    type(plugin.context).user_profiles = PropertyMock(return_value=[])  # type: ignore[union-attr]
    return plugin.run()


def test_system_startup_files_detected(tmp_path: Path) -> None:
    """The all-users startup folder grants SYSTEM; desktop.ini is not a finding."""
    startup = _system_startup(tmp_path)
    (startup / "backdoor.lnk").write_bytes(
        build_shell_link(id_list=b"\x04\x00\x00\x00")
    )
    (startup / "desktop.ini").write_text("[.ShellClassInfo]")

    findings = _run_on_system_startup(tmp_path)
    assert len(findings) == 1
    assert findings[0].value == "backdoor.lnk"
    assert findings[0].access_gained == AccessLevel.SYSTEM
    assert findings[0].resolve_target == findings[0].path


def test_user_startup_files_detected(tmp_path: Path) -> None:
    """A per-user startup folder grants only that user's access, not SYSTEM."""
    (_user_startup(tmp_path) / "payload.exe").write_bytes(b"\x00")

    findings = _victim_plugin(tmp_path).run()

    assert len(findings) == 1
    assert findings[0].value == "payload.exe"
    assert findings[0].access_gained == AccessLevel.USER


def test_user_hive_uses_software_prefix(tmp_path: Path) -> None:
    """NTUSER.DAT has no HKCU root, so the Software\\ prefix must be added by hand."""
    _user_startup(tmp_path)
    plugin = _victim_plugin(tmp_path)

    plugin.run()

    key_paths = [
        call.args[1]
        for call in plugin.registry.load_subtree.call_args_list  # type: ignore[union-attr]
    ]
    for key_path in key_paths:
        assert key_path.startswith("Software\\"), (
            f"User hive key missing Software\\ prefix: {key_path}"
        )


def test_multiple_startup_files_detected(tmp_path: Path) -> None:
    """Each file is a separate finding, and desktop.ini is still excluded."""
    startup = _system_startup(tmp_path)
    (startup / "evil1.bat").write_text("echo 1")
    (startup / "evil2.lnk").write_bytes(build_shell_link(id_list=b"\x04\x00\x00\x00"))
    (startup / "desktop.ini").write_text("[.ShellClassInfo]")

    values = {finding.value for finding in _run_on_system_startup(tmp_path)}
    assert "evil1.bat" in values
    assert "evil2.lnk" in values
    assert "desktop.ini" not in values


def test_registry_override_startup_path(tmp_path: Path) -> None:
    """A redirected Common Startup folder is what actually runs at logon."""
    custom_startup = tmp_path / "custom_startup"
    custom_startup.mkdir()
    (custom_startup / "implant.exe").write_bytes(b"\x00")

    # A relative path so filesystem.resolve maps it under image_root.
    node = make_node(
        name="UserShellFolders",
        values={"Common Startup": "custom_startup"},
    )

    plugin = _make_plugin(tmp_path)
    plugin.context.hive_path.return_value = Path("/fake/SOFTWARE")  # type: ignore[union-attr]
    hive = MagicMock()
    plugin.registry.open_hive.return_value = hive  # type: ignore[union-attr]
    plugin.registry.load_subtree.return_value = node  # type: ignore[union-attr]
    type(plugin.context).user_profiles = PropertyMock(return_value=[])  # type: ignore[union-attr]

    findings = plugin.run()
    assert any(finding.value == "implant.exe" for finding in findings)


def test_shortcut_reports_its_target_not_the_shortcut(tmp_path: Path) -> None:
    """A .lnk dropped in Startup must resolve to the binary it launches."""
    startup = _system_startup(tmp_path)
    (startup / "OneDrive.lnk").write_bytes(
        build_shell_link(local_base_path=r"C:\Users\bob\AppData\Local\Temp\svchost.exe")
    )

    findings = _run_on_system_startup(tmp_path)
    assert len(findings) == 1
    assert findings[0].path.endswith("OneDrive.lnk")
    assert findings[0].value == r"Users\bob\AppData\Local\Temp\svchost.exe"
    assert findings[0].resolve_target == r"Users\bob\AppData\Local\Temp\svchost.exe"
    assert not artifact_failures()


def test_shortcut_relative_target_and_arguments_are_reported(tmp_path: Path) -> None:
    """A link with only RELATIVE_PATH still names the launcher and its arguments."""
    startup = _system_startup(tmp_path)
    (startup / "disable-defender.lnk").write_bytes(
        build_shell_link(
            relative_path=r"..\..\..\..\..\..\Windows\System32"
            r"\WindowsPowerShell\v1.0\powershell.exe",
            arguments="-ExecutionPolicy Bypass -File C:\\evil.ps1",
        )
    )

    findings = _run_on_system_startup(tmp_path)
    assert len(findings) == 1
    assert findings[0].resolve_target == (
        r"Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    )
    assert findings[0].value == (
        r"Windows\System32\WindowsPowerShell\v1.0\powershell.exe "
        "-ExecutionPolicy Bypass -File C:\\evil.ps1"
    )


def test_shortcut_environment_target_is_expanded(tmp_path: Path) -> None:
    """A target recorded as %windir%\\... resolves to an image-relative path."""
    startup = _system_startup(tmp_path)
    (startup / "rdp.lnk").write_bytes(
        build_shell_link(environment_target=r"%windir%\system32\mstsc.exe")
    )

    findings = _run_on_system_startup(tmp_path)
    assert findings[0].resolve_target == r"Windows\system32\mstsc.exe"


def test_shortcut_without_a_file_target_stays_quiet(tmp_path: Path) -> None:
    """A link to a virtual folder parses fine, so it must not claim lost coverage."""
    startup = _system_startup(tmp_path)
    (startup / "Control Panel.lnk").write_bytes(
        build_shell_link(id_list=b"\x08\x00\x00\x00\x00\x00\x00\x00")
    )

    findings = _run_on_system_startup(tmp_path)
    assert len(findings) == 1
    assert findings[0].value == "Control Panel.lnk"
    assert findings[0].resolve_target == findings[0].path
    assert not artifact_failures()


def test_unreadable_shortcut_is_reported_as_lost_coverage(tmp_path: Path) -> None:
    """A .lnk that will not parse is coverage lost, not a shortcut with no target."""
    startup = _system_startup(tmp_path)
    (startup / "broken.lnk").write_bytes(b"\xff" * 128)

    findings = _run_on_system_startup(tmp_path)
    assert len(findings) == 1
    assert findings[0].resolve_target == findings[0].path
    failures = artifact_failures()
    assert len(failures) == 1
    assert failures[0].label.startswith("startup_folder artifact ")
    assert failures[0].label.endswith("broken.lnk")
    assert "ValueError" in failures[0].error


def test_non_shortcut_entry_keeps_its_own_name(tmp_path: Path) -> None:
    """A dropped executable is its own payload and must not be parsed as a link."""
    startup = _system_startup(tmp_path)
    (startup / "payload.exe").write_bytes(b"\x00" * 64)

    findings = _run_on_system_startup(tmp_path)
    assert findings[0].value == "payload.exe"
    assert findings[0].resolve_target == findings[0].path
    assert not artifact_failures()


def test_redirected_folder_is_bounded_and_reported(tmp_path: Path) -> None:
    """A shell-folder redirect cannot turn one registry string into a flood of rows."""
    startup = _system_startup(tmp_path)
    for index in range(300):
        (startup / f"planted{index:04d}.exe").write_bytes(b"\x00")

    findings = _run_on_system_startup(tmp_path)
    assert len(findings) == 256
    failures = artifact_failures()
    assert len(failures) == 1
    assert failures[0].label.endswith("Startup")
    assert "300 files" in failures[0].error
    assert "first 256" in failures[0].error


def test_ordinary_startup_folder_is_never_truncated(tmp_path: Path) -> None:
    """The bound sits far above any real Startup folder, so nothing is capped."""
    startup = _system_startup(tmp_path)
    for index in range(24):
        (startup / f"vendor{index:02d}.lnk").write_bytes(
            build_shell_link(local_base_path=rf"C:\Program Files\Vendor{index}\app.exe")
        )

    findings = _run_on_system_startup(tmp_path)
    assert len(findings) == 24
    assert not artifact_failures()
