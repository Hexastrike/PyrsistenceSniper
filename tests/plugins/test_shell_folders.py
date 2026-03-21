from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, PropertyMock

from pyrsistencesniper.core.models import UserProfile
from pyrsistencesniper.plugins.T1547.shell_folders import ShellFoldersStartup

from .conftest import make_deps, make_node, setup_hklm


def _make_plugin(tmp_path: Path) -> ShellFoldersStartup:
    context, registry, _filesystem, _profile = make_deps(tmp_path)
    context.registry = registry
    return ShellFoldersStartup(context=context)


def test_default_path_no_redirect_finding(tmp_path: Path) -> None:
    default_path = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    node = make_node(name="ShellFolders", values={"Common Startup": default_path})

    plugin = _make_plugin(tmp_path)
    setup_hklm(plugin, node)
    type(plugin.context).user_profiles = PropertyMock(return_value=[])  # type: ignore[union-attr]

    findings = plugin.run()
    redirect_findings = [f for f in findings if "redirected" in f.description.lower()]
    assert redirect_findings == []


def test_nondefault_path_redirect_detected(tmp_path: Path) -> None:
    evil_path = r"C:\evil\startup"
    node = make_node(name="ShellFolders", values={"Common Startup": evil_path})

    plugin = _make_plugin(tmp_path)
    setup_hklm(plugin, node)
    type(plugin.context).user_profiles = PropertyMock(return_value=[])  # type: ignore[union-attr]

    findings = plugin.run()
    redirect_findings = [f for f in findings if "redirected" in f.description.lower()]
    assert len(redirect_findings) == 1


def test_files_in_startup_folder_reported(tmp_path: Path) -> None:
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
    (startup / "evil.bat").write_text("echo pwned")
    (startup / "desktop.ini").write_text("[.ShellClassInfo]")

    default_path = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    node = make_node(name="ShellFolders", values={"Common Startup": default_path})

    plugin = _make_plugin(tmp_path)
    plugin.context.hive_path.return_value = Path("/fake/SOFTWARE")  # type: ignore[union-attr]
    plugin.registry.open_hive.return_value = MagicMock()  # type: ignore[union-attr]
    plugin.registry.load_subtree.return_value = node  # type: ignore[union-attr]
    type(plugin.context).user_profiles = PropertyMock(return_value=[])  # type: ignore[union-attr]

    findings = plugin.run()
    file_findings = [f for f in findings if "evil.bat" in f.value]
    assert len(file_findings) == 1
    ini_findings = [f for f in findings if "desktop.ini" in f.value]
    assert ini_findings == []


def test_user_hive_uses_software_prefix(tmp_path: Path) -> None:
    """User hive queries prepend Software\\ to the registry key path."""
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
    plugin = ShellFoldersStartup(context=context)

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


def test_env_var_path_redirected(tmp_path: Path) -> None:
    """Registry value with environment variable pointing to non-default path."""
    evil_path = r"%SYSTEMDRIVE%\evil\startup"
    node = make_node(name="ShellFolders", values={"Common Startup": evil_path})

    plugin = _make_plugin(tmp_path)
    setup_hklm(plugin, node)
    type(plugin.context).user_profiles = PropertyMock(return_value=[])  # type: ignore[union-attr]

    findings = plugin.run()
    redirect_findings = [f for f in findings if "redirected" in f.description.lower()]
    assert len(redirect_findings) >= 1
