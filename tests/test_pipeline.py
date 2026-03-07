from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import ClassVar
from unittest.mock import MagicMock, patch

from pyrsistencesniper.core.filesystem import FilesystemHelper
from pyrsistencesniper.core.image import ForensicImage
from pyrsistencesniper.core.profile import DetectionProfile
from pyrsistencesniper.core.registry import RegistryHelper
from pyrsistencesniper.models.finding import Finding
from pyrsistencesniper.plugins import run_all_checks
from pyrsistencesniper.plugins.base import CheckDefinition, PersistencePlugin

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


def _make_deps(
    tmp_path: Path,
) -> tuple[ForensicImage, RegistryHelper, FilesystemHelper, DetectionProfile]:
    image = MagicMock(spec=ForensicImage)
    image.hostname = "TESTHOST"
    image.active_controlset = "ControlSet001"
    image.user_profiles = []

    registry = RegistryHelper()
    filesystem = FilesystemHelper(image_root=tmp_path)
    profile = DetectionProfile.default()
    return image, registry, filesystem, profile


def _fake_resolve(f: Finding) -> Finding:
    return dataclasses.replace(f, is_in_os_directory=True, is_lolbin=False, signer="")


# -- Tests --------------------------------------------------------------------


def test_run_all_checks_sequential(tmp_path: Path) -> None:
    """Sequential loop should collect all findings."""
    image, registry, filesystem, profile = _make_deps(tmp_path)

    with (
        patch(
            "pyrsistencesniper.plugins._PLUGIN_REGISTRY",
            {"stub_a": _StubPluginA, "stub_b": _StubPluginB},
        ),
        patch("pyrsistencesniper.plugins._discover_plugins"),
        patch("pyrsistencesniper.plugins.ResolutionPipeline") as mock_resolver_cls,
        patch(
            "pyrsistencesniper.plugins.run_enrichments",
            side_effect=lambda f, **kw: [(x, []) for x in f],
        ),
    ):
        mock_resolver_cls.return_value.resolve.side_effect = lambda f: f

        results = run_all_checks(
            image=image,
            registry=registry,
            filesystem=filesystem,
            profile=profile,
        )

    paths = {r[0].path for r in results}
    assert paths == {"stub_a_path", "stub_b_path"}


def test_run_all_checks_plugin_exception_isolated(tmp_path: Path) -> None:
    """A failing plugin should not prevent others from returning findings."""
    image, registry, filesystem, profile = _make_deps(tmp_path)

    with (
        patch(
            "pyrsistencesniper.plugins._PLUGIN_REGISTRY",
            {"stub_a": _StubPluginA, "exploding": _ExplodingPlugin},
        ),
        patch("pyrsistencesniper.plugins._discover_plugins"),
        patch("pyrsistencesniper.plugins.ResolutionPipeline") as mock_resolver_cls,
        patch(
            "pyrsistencesniper.plugins.run_enrichments",
            side_effect=lambda f, **kw: [(x, []) for x in f],
        ),
    ):
        mock_resolver_cls.return_value.resolve.side_effect = lambda f: f

        results = run_all_checks(
            image=image,
            registry=registry,
            filesystem=filesystem,
            profile=profile,
        )

    assert len(results) == 1
    assert results[0][0].path == "stub_a_path"


def test_run_all_checks_progress_callback(tmp_path: Path) -> None:
    """Progress callback should be invoked for each pipeline stage."""
    image, registry, filesystem, profile = _make_deps(tmp_path)
    calls: list[tuple[str, int, int]] = []

    def on_progress(stage: str, current: int, total: int) -> None:
        calls.append((stage, current, total))

    with (
        patch(
            "pyrsistencesniper.plugins._PLUGIN_REGISTRY",
            {"stub_a": _StubPluginA, "stub_b": _StubPluginB},
        ),
        patch("pyrsistencesniper.plugins._discover_plugins"),
        patch("pyrsistencesniper.plugins.ResolutionPipeline") as mock_resolver_cls,
        patch(
            "pyrsistencesniper.plugins.run_enrichments",
            side_effect=lambda f, **kw: [(x, []) for x in f],
        ),
    ):
        mock_resolver_cls.return_value.resolve.side_effect = lambda f: f

        results = run_all_checks(
            image=image,
            registry=registry,
            filesystem=filesystem,
            profile=profile,
            progress=on_progress,
        )

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


# -- Raw mode -----------------------------------------------------------------


def test_run_all_checks_raw_skips_suppression(tmp_path: Path) -> None:
    """raw=True should skip all filtering, including auto-suppression."""
    image, registry, filesystem, profile = _make_deps(tmp_path)

    with (
        patch(
            "pyrsistencesniper.plugins._PLUGIN_REGISTRY",
            {"stub_a": _StubPluginA},
        ),
        patch("pyrsistencesniper.plugins._discover_plugins"),
        patch("pyrsistencesniper.plugins.ResolutionPipeline") as mock_resolver_cls,
        patch(
            "pyrsistencesniper.plugins.run_enrichments",
            side_effect=lambda f, **kw: [(x, []) for x in f],
        ),
    ):
        mock_resolver_cls.return_value.resolve.side_effect = _fake_resolve

        results = run_all_checks(
            image=image,
            registry=registry,
            filesystem=filesystem,
            profile=profile,
            raw=True,
        )

    # In raw mode, finding is NOT suppressed even though is_in_os_directory=True
    assert len(results) == 1
    assert results[0][0].is_in_os_directory is True


def test_run_all_checks_allow_rule_suppression(tmp_path: Path) -> None:
    """Plugin allow rules suppress matching findings (non-raw mode)."""
    from pyrsistencesniper.models.finding import AllowRule

    image, registry, filesystem, profile = _make_deps(tmp_path)

    class _StubWithAllow(PersistencePlugin):
        definition: ClassVar[CheckDefinition] = CheckDefinition(
            id="stub_allow",
            technique="Stub Allow",
            mitre_id="T0000",
            allow=(AllowRule(signer="microsoft", not_lolbin=True),),
        )

        def run(self) -> list[Finding]:
            return [Finding(path="stub_path", check_id="stub_allow")]

    def _resolve_with_signer(f: Finding) -> Finding:
        return dataclasses.replace(f, signer="Microsoft Windows", is_lolbin=False)

    with (
        patch(
            "pyrsistencesniper.plugins._PLUGIN_REGISTRY",
            {"stub_allow": _StubWithAllow},
        ),
        patch("pyrsistencesniper.plugins._discover_plugins"),
        patch("pyrsistencesniper.plugins.ResolutionPipeline") as mock_resolver_cls,
        patch(
            "pyrsistencesniper.plugins.run_enrichments",
            side_effect=lambda f, **kw: [(x, []) for x in f],
        ),
    ):
        mock_resolver_cls.return_value.resolve.side_effect = _resolve_with_signer

        results = run_all_checks(
            image=image,
            registry=registry,
            filesystem=filesystem,
            profile=profile,
        )

    # MS-signed non-LOLBin should be suppressed by plugin allow rule
    assert len(results) == 0


def test_run_all_checks_lolbin_not_suppressed(tmp_path: Path) -> None:
    """LOLBin findings bypass not_lolbin allow rules."""
    from pyrsistencesniper.models.finding import AllowRule

    image, registry, filesystem, profile = _make_deps(tmp_path)

    class _StubWithAllow(PersistencePlugin):
        definition: ClassVar[CheckDefinition] = CheckDefinition(
            id="stub_allow",
            technique="Stub Allow",
            mitre_id="T0000",
            allow=(AllowRule(signer="microsoft", not_lolbin=True),),
        )

        def run(self) -> list[Finding]:
            return [Finding(path="stub_path", check_id="stub_allow")]

    def _resolve_lolbin(f: Finding) -> Finding:
        return dataclasses.replace(f, signer="Microsoft Windows", is_lolbin=True)

    with (
        patch(
            "pyrsistencesniper.plugins._PLUGIN_REGISTRY",
            {"stub_allow": _StubWithAllow},
        ),
        patch("pyrsistencesniper.plugins._discover_plugins"),
        patch("pyrsistencesniper.plugins.ResolutionPipeline") as mock_resolver_cls,
        patch(
            "pyrsistencesniper.plugins.run_enrichments",
            side_effect=lambda f, **kw: [(x, []) for x in f],
        ),
    ):
        mock_resolver_cls.return_value.resolve.side_effect = _resolve_lolbin

        results = run_all_checks(
            image=image,
            registry=registry,
            filesystem=filesystem,
            profile=profile,
        )

    # LOLBin should NOT be suppressed even with signer allow rule
    assert len(results) == 1
    assert results[0][0].is_lolbin is True
