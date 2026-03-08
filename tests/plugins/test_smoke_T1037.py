from __future__ import annotations

from pathlib import Path

from pyrsistencesniper.models.finding import AccessLevel

from .conftest import make_plugin


def test_gp_scripts(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1037.gp_scripts import GpScripts

    p = make_plugin(GpScripts, tmp_path)
    scripts_dir = (
        tmp_path / "Windows" / "System32" / "GroupPolicy" / "Machine" / "Scripts"
    )
    scripts_dir.mkdir(parents=True)
    ini = scripts_dir / "scripts.ini"
    ini.write_text(
        "[Startup]\n0CmdLine=C:\\evil.bat\n0Parameters=-silent\n", encoding="utf-8"
    )
    findings = p.run()
    assert len(findings) == 1
    f = findings[0]
    assert "evil.bat" in f.value
    assert f.access_gained == AccessLevel.SYSTEM
    assert f.mitre_id == "T1037.001"
