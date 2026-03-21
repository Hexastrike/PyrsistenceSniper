from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, PropertyMock

from pyrsistencesniper.core.models import AccessLevel, UserProfile
from pyrsistencesniper.plugins.T1547.startup_folder import StartupFolder

from .conftest import make_deps, make_node


def _make_plugin(tmp_path: Path) -> StartupFolder:
    context, registry, _filesystem, _profile = make_deps(tmp_path)
    context.registry = registry
    return StartupFolder(context=context)


def test_system_startup_files_detected(tmp_path: Path) -> None:
    startup = (
        tmp_path
        / "ProgramData"
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "Startup"
    )
    startup.mkdir(parents=True)
    (startup / "backdoor.lnk").write_bytes(b"\x00" * 32)
    (startup / "desktop.ini").write_text("[.ShellClassInfo]")

    plugin = _make_plugin(tmp_path)
    plugin.context.hive_path.return_value = None  # type: ignore[union-attr]
    type(plugin.context).user_profiles = PropertyMock(return_value=[])  # type: ignore[union-attr]

    findings = plugin.run()
    assert len(findings) == 1
    assert findings[0].value == "backdoor.lnk"
    assert findings[0].access_gained == AccessLevel.SYSTEM


def test_user_startup_files_detected(tmp_path: Path) -> None:
    user_startup = (
        tmp_path
        / "Users"
        / "victim"
        / "AppData"
        / "Roaming"
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "Startup"
    )
    user_startup.mkdir(parents=True)
    (user_startup / "payload.exe").write_bytes(b"\x00")

    profiles = [
        UserProfile(
            username="victim",
            profile_path=tmp_path / "Users" / "victim",
            ntuser_path=tmp_path / "Users" / "victim" / "NTUSER.DAT",
        ),
    ]
    context, registry, _filesystem, _profile = make_deps(
        tmp_path, user_profiles=profiles
    )
    context.registry = registry

    plugin = StartupFolder(context=context)
    plugin.context.hive_path.return_value = None  # type: ignore[union-attr]

    ntuser_hive = MagicMock()
    plugin.registry.open_hive.return_value = ntuser_hive  # type: ignore[union-attr]
    plugin.registry.load_subtree.return_value = None  # type: ignore[union-attr]

    findings = plugin.run()
    assert len(findings) == 1
    assert findings[0].value == "payload.exe"
    assert findings[0].access_gained == AccessLevel.USER


def test_user_hive_uses_software_prefix(tmp_path: Path) -> None:
    """User hive queries prepend Software\\ to the registry key path."""
    user_startup = (
        tmp_path
        / "Users"
        / "victim"
        / "AppData"
        / "Roaming"
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "Startup"
    )
    user_startup.mkdir(parents=True)

    profiles = [
        UserProfile(
            username="victim",
            profile_path=tmp_path / "Users" / "victim",
            ntuser_path=tmp_path / "Users" / "victim" / "NTUSER.DAT",
        ),
    ]
    context, registry, _filesystem, _profile = make_deps(
        tmp_path, user_profiles=profiles
    )
    context.registry = registry

    plugin = StartupFolder(context=context)
    plugin.context.hive_path.return_value = None  # type: ignore[union-attr]

    ntuser_hive = MagicMock()
    plugin.registry.open_hive.return_value = ntuser_hive  # type: ignore[union-attr]
    plugin.registry.load_subtree.return_value = None  # type: ignore[union-attr]

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
    """Multiple files in startup folder are each reported."""
    startup = (
        tmp_path
        / "ProgramData"
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "Startup"
    )
    startup.mkdir(parents=True)
    (startup / "evil1.bat").write_text("echo 1")
    (startup / "evil2.lnk").write_bytes(b"\x00" * 16)
    (startup / "desktop.ini").write_text("[.ShellClassInfo]")

    plugin = _make_plugin(tmp_path)
    plugin.context.hive_path.return_value = None  # type: ignore[union-attr]
    type(plugin.context).user_profiles = PropertyMock(return_value=[])  # type: ignore[union-attr]

    findings = plugin.run()
    values = {f.value for f in findings}
    assert "evil1.bat" in values
    assert "evil2.lnk" in values
    assert "desktop.ini" not in values


def test_registry_override_startup_path(tmp_path: Path) -> None:
    """Registry points to a non-default startup path that exists on disk."""
    custom_startup = tmp_path / "custom_startup"
    custom_startup.mkdir()
    (custom_startup / "implant.exe").write_bytes(b"\x00")

    # Use a Windows-style relative path so filesystem.resolve maps it under image_root
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
    assert any(f.value == "implant.exe" for f in findings)
