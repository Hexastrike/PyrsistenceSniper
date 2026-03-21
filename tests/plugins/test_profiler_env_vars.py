"""Tests for CorProfiler and CoreClrProfiler plugins in T1574/profiler_env_vars.py."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from pyrsistencesniper.core.models import AccessLevel, UserProfile
from pyrsistencesniper.plugins.T1574.profiler_env_vars import (
    CoreClrProfiler,
    CorProfiler,
)

from .conftest import make_node, make_plugin, setup_hklm


class TestCorProfiler:
    def test_system_cor_profiler_detected(self, tmp_path: Path) -> None:
        env_node = make_node(
            values={"COR_PROFILER": "{evil-guid}", "COR_ENABLE_PROFILING": "1"}
        )
        p = make_plugin(CorProfiler, tmp_path)
        setup_hklm(p, env_node, hive_path="/fake/SYSTEM")
        findings = p.run()
        assert len(findings) >= 1
        assert any("evil-guid" in f.value for f in findings)
        assert all(f.access_gained == AccessLevel.SYSTEM for f in findings)
        assert all("T1574" in f.mitre_id for f in findings)

    def test_user_cor_profiler_detected(self, tmp_path: Path) -> None:
        profile = UserProfile(
            username="testuser",
            profile_path=Path("/fake/Users/testuser"),
            ntuser_path=Path("/fake/ntuser.dat"),
        )
        env_node = make_node(values={"COR_PROFILER_PATH": r"C:\evil_profiler.dll"})
        p = make_plugin(CorProfiler, tmp_path, user_profiles=[profile])
        # System hive returns nothing
        p.context.hive_path.return_value = None
        # User hive returns the env node
        user_hive = MagicMock()
        p.registry.open_hive.return_value = user_hive
        p.registry.load_subtree.return_value = env_node
        findings = p.run()
        assert len(findings) >= 1
        assert any("evil_profiler.dll" in f.value for f in findings)
        assert all(f.access_gained == AccessLevel.USER for f in findings)

    def test_env_key_without_profiler_vars(self, tmp_path: Path) -> None:
        env_node = make_node(values={"PATH": r"C:\Windows"})
        p = make_plugin(CorProfiler, tmp_path)
        setup_hklm(p, env_node, hive_path="/fake/SYSTEM")
        findings = p.run()
        assert findings == []


class TestCoreClrProfiler:
    def test_system_coreclr_profiler_detected(self, tmp_path: Path) -> None:
        env_node = make_node(
            values={
                "CORECLR_PROFILER": "{evil-coreclr}",
                "CORECLR_ENABLE_PROFILING": "1",
            }
        )
        p = make_plugin(CoreClrProfiler, tmp_path)
        setup_hklm(p, env_node, hive_path="/fake/SYSTEM")
        findings = p.run()
        assert len(findings) >= 1
        assert any("evil-coreclr" in f.value for f in findings)
        assert all(f.access_gained == AccessLevel.SYSTEM for f in findings)
        assert all("T1574" in f.mitre_id for f in findings)
