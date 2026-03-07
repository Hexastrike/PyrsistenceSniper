from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, PropertyMock

from pyrsistencesniper.core.image import UserProfile
from pyrsistencesniper.models.finding import AccessLevel
from pyrsistencesniper.plugins.T1547.startup_folder import StartupFolder

from .conftest import make_deps


def _make_plugin(tmp_path: Path) -> StartupFolder:
    image, registry, filesystem, profile = make_deps(tmp_path)
    return StartupFolder(
        registry=registry, filesystem=filesystem, image=image, profile=profile
    )


def test_no_startup_folder_returns_empty(tmp_path: Path) -> None:
    plugin = _make_plugin(tmp_path)
    plugin.image.hive_path.return_value = None  # type: ignore[union-attr]
    plugin.registry.open_hive.return_value = None  # type: ignore[union-attr]
    type(plugin.image).user_profiles = PropertyMock(return_value=[])  # type: ignore[union-attr]

    assert plugin.run() == []


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
    plugin.image.hive_path.return_value = None  # type: ignore[union-attr]
    type(plugin.image).user_profiles = PropertyMock(return_value=[])  # type: ignore[union-attr]

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
    image, registry, filesystem, profile = make_deps(tmp_path, user_profiles=profiles)

    plugin = StartupFolder(
        registry=registry, filesystem=filesystem, image=image, profile=profile
    )
    plugin.image.hive_path.return_value = None  # type: ignore[union-attr]

    ntuser_hive = MagicMock()
    plugin.registry.open_hive.return_value = ntuser_hive  # type: ignore[union-attr]
    plugin.registry.load_subtree.return_value = None  # type: ignore[union-attr]

    findings = plugin.run()
    assert len(findings) == 1
    assert findings[0].value == "payload.exe"
    assert findings[0].access_gained == AccessLevel.USER
