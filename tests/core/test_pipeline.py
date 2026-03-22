from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import ClassVar
from unittest.mock import MagicMock, PropertyMock, create_autospec, patch

from pyrsistencesniper.core.context import AnalysisContext
from pyrsistencesniper.core.filesystem import FilesystemHelper
from pyrsistencesniper.core.models import CheckDefinition, FilterRule, Finding, Severity
from pyrsistencesniper.core.pipeline import run_all_checks
from pyrsistencesniper.core.profile import DetectionProfile
from pyrsistencesniper.core.registry import RegistryHelper
from pyrsistencesniper.plugins.base import PersistencePlugin

_RESOLVER_CLS = "pyrsistencesniper.core.pipeline.ResolutionPipeline"
_RUN_ENRICHMENTS = "pyrsistencesniper.core.pipeline.run_enrichments"

# -- Helpers ------------------------------------------------------------------


class _StubPluginA(PersistencePlugin):
    definition: ClassVar[CheckDefinition] = CheckDefinition(
        id="stub_a", technique="Stub A", mitre_id="T0000"
    )

    def run(self) -> list[Finding]:
        return [Finding(path="stub_a_path", check_id="stub_a")]


class _StubPluginB(PersistencePlugin):
    definition: ClassVar[CheckDefinition] = CheckDefinition(
        id="stub_b", technique="Stub B", mitre_id="T0001"
    )

    def run(self) -> list[Finding]:
        return [Finding(path="stub_b_path", check_id="stub_b")]


class _ExplodingPlugin(PersistencePlugin):
    definition: ClassVar[CheckDefinition] = CheckDefinition(
        id="exploding", technique="Exploding", mitre_id="T9999"
    )

    def run(self) -> list[Finding]:
        raise RuntimeError("boom")


def _make_context(tmp_path: Path) -> MagicMock:
    context = create_autospec(AnalysisContext, instance=True)
    type(context).hostname = PropertyMock(return_value="TESTHOST")
    type(context).active_controlset = PropertyMock(return_value="ControlSet001")
    type(context).user_profiles = PropertyMock(return_value=[])
    context.profile = DetectionProfile()
    context.filesystem = FilesystemHelper(image_root=tmp_path)
    context.registry = RegistryHelper()
    return context


def _fake_resolve(f: Finding) -> Finding:
    return dataclasses.replace(f, is_in_os_directory=True, is_lolbin=False, signer="")


# -- Tests --------------------------------------------------------------------


def test_run_all_checks_sequential(tmp_path: Path) -> None:
    """Sequential loop should collect all findings."""
    ctx = _make_context(tmp_path)

    with (
        patch(
            "pyrsistencesniper.core.pipeline._PLUGIN_REGISTRY",
            {"stub_a": _StubPluginA, "stub_b": _StubPluginB},
        ),
        patch("pyrsistencesniper.core.pipeline._discover_plugins"),
        patch(_RESOLVER_CLS) as mock_resolver_cls,
        patch(
            _RUN_ENRICHMENTS,
            side_effect=lambda f, **kw: [(x, []) for x in f],
        ),
    ):
        mock_resolver_cls.return_value.resolve.side_effect = lambda f: f

        results = run_all_checks(ctx)

    paths = {r[0].path for r in results}
    assert paths == {"stub_a_path", "stub_b_path"}


def test_run_all_checks_plugin_exception_isolated(tmp_path: Path) -> None:
    """A failing plugin should not prevent others from returning findings."""
    ctx = _make_context(tmp_path)

    with (
        patch(
            "pyrsistencesniper.core.pipeline._PLUGIN_REGISTRY",
            {"stub_a": _StubPluginA, "exploding": _ExplodingPlugin},
        ),
        patch("pyrsistencesniper.core.pipeline._discover_plugins"),
        patch(_RESOLVER_CLS) as mock_resolver_cls,
        patch(
            _RUN_ENRICHMENTS,
            side_effect=lambda f, **kw: [(x, []) for x in f],
        ),
    ):
        mock_resolver_cls.return_value.resolve.side_effect = lambda f: f

        results = run_all_checks(ctx)

    assert len(results) == 1
    assert results[0][0].path == "stub_a_path"


def test_run_all_checks_progress_callback(tmp_path: Path) -> None:
    """Progress callback should be invoked for each pipeline stage."""
    ctx = _make_context(tmp_path)
    calls: list[tuple[str, int, int]] = []

    def on_progress(stage: str, current: int, total: int) -> None:
        calls.append((stage, current, total))

    with (
        patch(
            "pyrsistencesniper.core.pipeline._PLUGIN_REGISTRY",
            {"stub_a": _StubPluginA, "stub_b": _StubPluginB},
        ),
        patch("pyrsistencesniper.core.pipeline._discover_plugins"),
        patch(_RESOLVER_CLS) as mock_resolver_cls,
        patch(
            _RUN_ENRICHMENTS,
            side_effect=lambda f, **kw: [(x, []) for x in f],
        ),
    ):
        mock_resolver_cls.return_value.resolve.side_effect = lambda f: f

        results = run_all_checks(ctx, progress=on_progress)

    assert len(results) == 2

    # Verify "Running checks" stage was called for each plugin
    check_calls = [(s, c, t) for s, c, t in calls if s == "Running checks"]
    assert check_calls == [("Running checks", 1, 2), ("Running checks", 2, 2)]

    # Verify "Resolving findings" stage was called for each finding
    resolve_calls = [(s, c, t) for s, c, t in calls if s == "Resolving findings"]
    assert resolve_calls == [
        ("Resolving findings", 1, 2),
        ("Resolving findings", 2, 2),
    ]


# -- Severity classification --------------------------------------------------


def test_run_all_checks_min_severity_info_includes_all(tmp_path: Path) -> None:
    """min_severity=INFO should include all findings regardless of severity."""
    ctx = _make_context(tmp_path)

    with (
        patch(
            "pyrsistencesniper.core.pipeline._PLUGIN_REGISTRY",
            {"stub_a": _StubPluginA},
        ),
        patch("pyrsistencesniper.core.pipeline._discover_plugins"),
        patch(_RESOLVER_CLS) as mock_resolver_cls,
        patch(
            _RUN_ENRICHMENTS,
            side_effect=lambda f, **kw: [(x, []) for x in f],
        ),
    ):
        mock_resolver_cls.return_value.resolve.side_effect = _fake_resolve

        results = run_all_checks(ctx, min_severity=Severity.INFO)

    assert len(results) == 1
    assert results[0][0].is_in_os_directory is True


def test_run_all_checks_allow_rule_suppression(tmp_path: Path) -> None:
    """Full allow-rule match classifies as INFO (suppressed at default severity)."""

    ctx = _make_context(tmp_path)

    class _StubWithAllow(PersistencePlugin):
        definition: ClassVar[CheckDefinition] = CheckDefinition(
            id="stub_allow",
            technique="Stub Allow",
            mitre_id="T0000",
            allow=(FilterRule(signer="Microsoft", not_lolbin=True),),
        )

        def run(self) -> list[Finding]:
            return [Finding(path="stub_path", check_id="stub_allow")]

    def _resolve_with_signer(f: Finding) -> Finding:
        return dataclasses.replace(f, signer="Microsoft Windows", is_lolbin=False)

    with (
        patch(
            "pyrsistencesniper.core.pipeline._PLUGIN_REGISTRY",
            {"stub_allow": _StubWithAllow},
        ),
        patch("pyrsistencesniper.core.pipeline._discover_plugins"),
        patch(_RESOLVER_CLS) as mock_resolver_cls,
        patch(
            _RUN_ENRICHMENTS,
            side_effect=lambda f, **kw: [(x, []) for x in f],
        ),
    ):
        mock_resolver_cls.return_value.resolve.side_effect = _resolve_with_signer

        # Default min_severity=MEDIUM should suppress INFO findings
        results = run_all_checks(ctx)
    assert len(results) == 0

    # With min_severity=INFO, the finding should appear with severity=INFO
    with (
        patch(
            "pyrsistencesniper.core.pipeline._PLUGIN_REGISTRY",
            {"stub_allow": _StubWithAllow},
        ),
        patch("pyrsistencesniper.core.pipeline._discover_plugins"),
        patch(_RESOLVER_CLS) as mock_resolver_cls,
        patch(
            _RUN_ENRICHMENTS,
            side_effect=lambda f, **kw: [(x, []) for x in f],
        ),
    ):
        mock_resolver_cls.return_value.resolve.side_effect = _resolve_with_signer
        results = run_all_checks(ctx, min_severity=Severity.INFO)

    assert len(results) == 1
    assert results[0][0].severity is Severity.INFO


def test_run_all_checks_partial_allow_match_low(tmp_path: Path) -> None:
    """Partial allow-rule match (core passes, signer fails) classifies as LOW."""

    ctx = _make_context(tmp_path)

    class _StubPartial(PersistencePlugin):
        definition: ClassVar[CheckDefinition] = CheckDefinition(
            id="stub_partial",
            technique="Stub Partial",
            mitre_id="T0000",
            allow=(FilterRule(signer="Unknown_signer", path_matches=r"stub"),),
        )

        def run(self) -> list[Finding]:
            return [Finding(path="stub_path", check_id="stub_partial")]

    def _resolve_with_signer(f: Finding) -> Finding:
        return dataclasses.replace(f, signer="Microsoft Windows")

    with (
        patch(
            "pyrsistencesniper.core.pipeline._PLUGIN_REGISTRY",
            {"stub_partial": _StubPartial},
        ),
        patch("pyrsistencesniper.core.pipeline._discover_plugins"),
        patch(_RESOLVER_CLS) as mock_resolver_cls,
        patch(
            _RUN_ENRICHMENTS,
            side_effect=lambda f, **kw: [(x, []) for x in f],
        ),
    ):
        mock_resolver_cls.return_value.resolve.side_effect = _resolve_with_signer

        # Default min_severity=MEDIUM excludes LOW
        results = run_all_checks(ctx)
    assert len(results) == 0

    with (
        patch(
            "pyrsistencesniper.core.pipeline._PLUGIN_REGISTRY",
            {"stub_partial": _StubPartial},
        ),
        patch("pyrsistencesniper.core.pipeline._discover_plugins"),
        patch(_RESOLVER_CLS) as mock_resolver_cls,
        patch(
            _RUN_ENRICHMENTS,
            side_effect=lambda f, **kw: [(x, []) for x in f],
        ),
    ):
        mock_resolver_cls.return_value.resolve.side_effect = _resolve_with_signer
        results = run_all_checks(ctx, min_severity=Severity.LOW)

    assert len(results) == 1
    assert results[0][0].severity is Severity.LOW


def test_run_all_checks_block_rule_high(tmp_path: Path) -> None:
    """Block-rule match classifies as HIGH."""

    ctx = _make_context(tmp_path)

    class _StubBlocked(PersistencePlugin):
        definition: ClassVar[CheckDefinition] = CheckDefinition(
            id="stub_block",
            technique="Stub Block",
            mitre_id="T0000",
            block=(FilterRule(value_matches=r"evil"),),
        )

        def run(self) -> list[Finding]:
            return [Finding(path="stub_path", value="evil.exe", check_id="stub_block")]

    with (
        patch(
            "pyrsistencesniper.core.pipeline._PLUGIN_REGISTRY",
            {"stub_block": _StubBlocked},
        ),
        patch("pyrsistencesniper.core.pipeline._discover_plugins"),
        patch(_RESOLVER_CLS) as mock_resolver_cls,
        patch(
            _RUN_ENRICHMENTS,
            side_effect=lambda f, **kw: [(x, []) for x in f],
        ),
    ):
        mock_resolver_cls.return_value.resolve.side_effect = lambda f: f
        results = run_all_checks(ctx)

    assert len(results) == 1
    assert results[0][0].severity is Severity.HIGH


def test_run_all_checks_no_rules_medium(tmp_path: Path) -> None:
    """No allow/block rules match → severity MEDIUM."""
    ctx = _make_context(tmp_path)

    with (
        patch(
            "pyrsistencesniper.core.pipeline._PLUGIN_REGISTRY",
            {"stub_a": _StubPluginA},
        ),
        patch("pyrsistencesniper.core.pipeline._discover_plugins"),
        patch(_RESOLVER_CLS) as mock_resolver_cls,
        patch(
            _RUN_ENRICHMENTS,
            side_effect=lambda f, **kw: [(x, []) for x in f],
        ),
    ):
        mock_resolver_cls.return_value.resolve.side_effect = lambda f: f
        results = run_all_checks(ctx)

    assert len(results) == 1
    assert results[0][0].severity is Severity.MEDIUM


def test_run_all_checks_lolbin_partial_allow(tmp_path: Path) -> None:
    """LOLBin with signer+not_lolbin rule: not_lolbin is core and fails → MEDIUM."""

    ctx = _make_context(tmp_path)

    class _StubWithAllow(PersistencePlugin):
        definition: ClassVar[CheckDefinition] = CheckDefinition(
            id="stub_allow",
            technique="Stub Allow",
            mitre_id="T0000",
            allow=(FilterRule(signer="Microsoft", not_lolbin=True),),
        )

        def run(self) -> list[Finding]:
            return [Finding(path="stub_path", check_id="stub_allow")]

    def _resolve_lolbin(f: Finding) -> Finding:
        return dataclasses.replace(f, signer="Microsoft Windows", is_lolbin=True)

    with (
        patch(
            "pyrsistencesniper.core.pipeline._PLUGIN_REGISTRY",
            {"stub_allow": _StubWithAllow},
        ),
        patch("pyrsistencesniper.core.pipeline._discover_plugins"),
        patch(_RESOLVER_CLS) as mock_resolver_cls,
        patch(
            _RUN_ENRICHMENTS,
            side_effect=lambda f, **kw: [(x, []) for x in f],
        ),
    ):
        mock_resolver_cls.return_value.resolve.side_effect = _resolve_lolbin

        # LOLBin shows at default min_severity=MEDIUM
        # (core condition fails -> NONE -> MEDIUM)
        results = run_all_checks(ctx)

    assert len(results) == 1
    assert results[0][0].is_lolbin is True
    assert results[0][0].severity is Severity.MEDIUM
