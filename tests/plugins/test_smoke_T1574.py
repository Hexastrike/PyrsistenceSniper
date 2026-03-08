from __future__ import annotations

from pathlib import Path

from pyrsistencesniper.models.finding import AccessLevel

from .conftest import make_node, make_plugin, setup_hklm


def test_dotnet_startup_hooks(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1574.dotnet_startup_hooks import DotNetStartupHooks

    env_node = make_node(values={"DOTNET_STARTUP_HOOKS": "C:\\evil_hook.dll"})
    p = make_plugin(DotNetStartupHooks, tmp_path)
    p.context.hive_path.return_value = Path("/fake/SYSTEM")
    from unittest.mock import MagicMock

    hive = MagicMock()
    p.registry.open_hive.return_value = hive
    p.registry.load_subtree.return_value = env_node
    findings = p.run()
    assert len(findings) >= 1
    assert any("evil_hook.dll" in f.value for f in findings)
    assert all(f.access_gained == AccessLevel.SYSTEM for f in findings)
    assert all("T1574" in f.mitre_id for f in findings)


def test_cor_profiler(tmp_path: Path) -> None:
    from pyrsistencesniper.plugins.T1574.profiler_env_vars import CorProfiler

    env_node = make_node(
        values={"COR_PROFILER": "{evil-guid}", "COR_ENABLE_PROFILING": "1"}
    )
    p = make_plugin(CorProfiler, tmp_path)
    setup_hklm(p, env_node, hive_path="/fake/SYSTEM")
    findings = p.run()
    assert len(findings) >= 1
    assert any("evil-guid" in f.value for f in findings)
    assert all(f.access_gained == AccessLevel.SYSTEM for f in findings)
