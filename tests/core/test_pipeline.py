"""Tests for run_pipeline: check selection, dedup, severity gating, and timeline."""

from __future__ import annotations

import dataclasses
from collections.abc import Callable, Iterator, Sequence
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import ClassVar
from unittest.mock import MagicMock, PropertyMock, create_autospec, patch

from pyrsistencesniper.core import ledger
from pyrsistencesniper.core.context import AnalysisContext
from pyrsistencesniper.core.filesystem import FilesystemHelper
from pyrsistencesniper.core.models import CheckDefinition, FilterRule, Finding, Severity
from pyrsistencesniper.core.profile import CheckPolicy, DetectionProfile
from pyrsistencesniper.core.registry import RegistryHelper
from pyrsistencesniper.detection.pipeline import (
    _technique_matches,
    run_pipeline,
)
from pyrsistencesniper.plugins.base import PersistencePlugin

PLUGIN_REGISTRY = "pyrsistencesniper.detection.pipeline.PLUGIN_REGISTRY"
_DISCOVER_PLUGINS = "pyrsistencesniper.detection.pipeline.discover_plugins"
_RESOLVER_CLS = "pyrsistencesniper.detection.pipeline.ResolutionPipeline"
_TIMELINE_CLS = "pyrsistencesniper.detection.pipeline.TimelineExecutor"

_FindingStub = Callable[[Finding], Finding]


class _StubPluginA(PersistencePlugin):
    """Plugin producing one fixed finding, standing in for a real check."""

    definition: ClassVar[CheckDefinition] = CheckDefinition(
        id="stub_a", technique="Stub A", mitre_id="T0000"
    )

    def run(self) -> list[Finding]:
        """Emit a single finding whose path identifies this stub."""
        return [Finding(path="stub_a_path", check_id="stub_a")]


class _StubPluginB(PersistencePlugin):
    """Second stub so a result can be attributed to the check that made it."""

    definition: ClassVar[CheckDefinition] = CheckDefinition(
        id="stub_b", technique="Stub B", mitre_id="T0001"
    )

    def run(self) -> list[Finding]:
        """Emit a single finding with a path distinct from stub A's."""
        return [Finding(path="stub_b_path", check_id="stub_b")]


class _ExplodingPlugin(PersistencePlugin):
    """Plugin that raises on run, standing in for a check with a bug."""

    definition: ClassVar[CheckDefinition] = CheckDefinition(
        id="exploding", technique="Exploding", mitre_id="T9999"
    )

    def run(self) -> list[Finding]:
        """Fail the way a broken check fails: an uncaught exception."""
        raise RuntimeError("boom")


class _StubSubTechnique(PersistencePlugin):
    """Plugin tagged with a sub-technique id, for technique-token matching."""

    definition: ClassVar[CheckDefinition] = CheckDefinition(
        id="stub_sub", technique="Stub Sub", mitre_id="T1547.001"
    )

    def run(self) -> list[Finding]:
        """Emit one finding; only the definition's mitre_id matters here."""
        return [Finding(path="stub_sub_path", check_id="stub_sub")]


def _make_context(tmp_path: Path) -> MagicMock:
    """Autospec context with canned host facts and real filesystem/registry helpers."""
    context = create_autospec(AnalysisContext, instance=True)
    type(context).hostname = PropertyMock(return_value="TESTHOST")
    type(context).active_controlset = PropertyMock(return_value="ControlSet001")
    type(context).user_profiles = PropertyMock(return_value=[])
    context.filesystem = FilesystemHelper(image_root=tmp_path)
    context.registry = RegistryHelper()
    return context


def _unchanged(finding: Finding) -> Finding:
    """Stand-in stage that hands the finding on exactly as it arrived."""
    return finding


def _resolve_os_binary(finding: Finding) -> Finding:
    """Resolver stand-in: an OS-directory file, not a LOLBin, no signer."""
    return dataclasses.replace(
        finding, is_in_os_directory=True, is_lolbin=False, signer=""
    )


@contextmanager
def _patched_pipeline(
    plugins: dict[str, type[PersistencePlugin]],
    *,
    resolve: _FindingStub = _unchanged,
    stub_timeline: bool = False,
    timestamp: _FindingStub = _unchanged,
    extra: Sequence[object] = (),
) -> Iterator[MagicMock]:
    """Patch the pipeline's collaborators and yield the TimelineExecutor mock."""
    # The executor is stubbed only on request, so the tests that do not name it
    # keep exercising the real timeline stage.
    with ExitStack() as stack:
        stack.enter_context(patch(PLUGIN_REGISTRY, plugins))
        stack.enter_context(patch(_DISCOVER_PLUGINS))
        resolver_cls = stack.enter_context(patch(_RESOLVER_CLS))
        resolver_cls.return_value.resolve.side_effect = resolve
        for patcher in extra:
            stack.enter_context(patcher)
        timeline_cls = MagicMock()
        if stub_timeline:
            timeline_cls = stack.enter_context(patch(_TIMELINE_CLS))
            timeline_cls.return_value.timestamp.side_effect = timestamp
        yield timeline_cls


def test_technique_parent_token_selects_subtechnique() -> None:
    """A parent technique token should select checks tagged with a sub-technique."""
    assert _technique_matches(_StubSubTechnique, {"T1547"}) is True


def test_technique_exact_subtechnique_token_matches() -> None:
    """A full sub-technique token should match the check tagged with that exact id."""
    assert _technique_matches(_StubSubTechnique, {"T1547.001"}) is True


def test_technique_check_id_token_matches() -> None:
    """A check-id token should match its own check."""
    assert _technique_matches(_StubSubTechnique, {"stub_sub"}) is True


def test_technique_unrelated_token_does_not_match() -> None:
    """An unrelated technique token should not select the check."""
    assert _technique_matches(_StubSubTechnique, {"T1055"}) is False


def test_run_pipeline_sequential(tmp_path: Path) -> None:
    """Every registered check contributes its findings to one result list."""
    context = _make_context(tmp_path)

    with _patched_pipeline({"stub_a": _StubPluginA, "stub_b": _StubPluginB}):
        results = run_pipeline(context, profile=DetectionProfile())

    assert {finding.path for finding in results} == {
        "stub_a_path",
        "stub_b_path",
    }


def test_run_pipeline_deduplicates_within_a_check(tmp_path: Path) -> None:
    """One check naming the same artifact twice is reported once."""
    context = _make_context(tmp_path)

    class _StubRepeats(PersistencePlugin):
        """Plugin naming one artifact three times, the last differing only in case."""

        definition: ClassVar[CheckDefinition] = CheckDefinition(
            id="stub_repeats", technique="Stub Repeats", mitre_id="T0002"
        )

        def run(self) -> list[Finding]:
            """Return the same finding twice plus a case-variant of its path."""
            finding = Finding(
                path="HKLM\\SOFTWARE\\Repeat", value="evil.exe", check_id="stub_repeats"
            )
            return [
                finding,
                finding,
                dataclasses.replace(finding, path="hklm\\software\\repeat"),
            ]

    with _patched_pipeline({"stub_repeats": _StubRepeats}):
        results = run_pipeline(context, profile=DetectionProfile())

    assert len(results) == 1


def test_run_pipeline_keeps_cross_check_collisions(tmp_path: Path) -> None:
    """Two checks reaching one artifact both survive: that agreement is evidence."""
    context = _make_context(tmp_path)

    class _StubOne(PersistencePlugin):
        """One of two independent checks that reach the same artifact."""

        definition: ClassVar[CheckDefinition] = CheckDefinition(
            id="stub_one", technique="Stub One", mitre_id="T0003"
        )

        def run(self) -> list[Finding]:
            """Emit the shared artifact under this check's id."""
            return [Finding(path="shared", value="evil.exe", check_id="stub_one")]

    class _StubTwo(PersistencePlugin):
        """The second check reaching that artifact, differing only in check id."""

        definition: ClassVar[CheckDefinition] = CheckDefinition(
            id="stub_two", technique="Stub Two", mitre_id="T0004"
        )

        def run(self) -> list[Finding]:
            """Emit the same path and value as stub one."""
            return [Finding(path="shared", value="evil.exe", check_id="stub_two")]

    with _patched_pipeline({"stub_one": _StubOne, "stub_two": _StubTwo}):
        results = run_pipeline(context, profile=DetectionProfile())

    assert len(results) == 2


def test_run_pipeline_plugin_exception_isolated(tmp_path: Path) -> None:
    """A failing plugin should not prevent others from returning findings."""
    context = _make_context(tmp_path)

    with _patched_pipeline({"stub_a": _StubPluginA, "exploding": _ExplodingPlugin}):
        results = run_pipeline(context, profile=DetectionProfile())

    assert len(results) == 1
    assert results[0].path == "stub_a_path"


def test_run_pipeline_records_failed_check(tmp_path: Path) -> None:
    """A check that raises is recorded, so its silence can be reported and costed."""
    context = _make_context(tmp_path)

    with _patched_pipeline({"stub_a": _StubPluginA, "exploding": _ExplodingPlugin}):
        run_pipeline(context, profile=DetectionProfile())

    failures = ledger.failures()
    assert [failure.check_id for failure in failures] == ["exploding"]
    assert failures[0].error


def test_run_pipeline_progress_callback(tmp_path: Path) -> None:
    """Progress callback should be invoked for each pipeline stage."""
    context = _make_context(tmp_path)
    calls: list[tuple[str, int, int]] = []

    def on_progress(stage: str, current: int, total: int) -> None:
        """Record every progress call so the stage sequence can be asserted."""
        calls.append((stage, current, total))

    with _patched_pipeline({"stub_a": _StubPluginA, "stub_b": _StubPluginB}):
        results = run_pipeline(
            context, profile=DetectionProfile(), progress=on_progress
        )

    assert len(results) == 2
    assert [call for call in calls if call[0] == "Running checks"] == [
        ("Running checks", 1, 2),
        ("Running checks", 2, 2),
    ]
    assert [call for call in calls if call[0] == "Resolving findings"] == [
        ("Resolving findings", 1, 2),
        ("Resolving findings", 2, 2),
    ]


def test_run_pipeline_min_severity_info_includes_all(tmp_path: Path) -> None:
    """min_severity=INFO should include all findings regardless of severity."""
    context = _make_context(tmp_path)

    with _patched_pipeline({"stub_a": _StubPluginA}, resolve=_resolve_os_binary):
        results = run_pipeline(
            context, profile=DetectionProfile(), min_severity=Severity.INFO
        )

    assert len(results) == 1
    assert results[0].is_in_os_directory is True


def test_run_pipeline_allow_rule_suppression(tmp_path: Path) -> None:
    """Full allow-rule match classifies as INFO (suppressed at default severity)."""
    context = _make_context(tmp_path)
    profile = DetectionProfile(
        checks={
            "stub_allow": CheckPolicy(
                allow=(FilterRule(signer="Microsoft", not_lolbin=True),)
            )
        },
    )

    class _StubWithAllow(PersistencePlugin):
        """Plugin whose check id carries the allow policy defined above."""

        definition: ClassVar[CheckDefinition] = CheckDefinition(
            id="stub_allow",
            technique="Stub Allow",
            mitre_id="T0000",
        )

        def run(self) -> list[Finding]:
            """Emit one finding; its signer arrives later from the resolver."""
            return [Finding(path="stub_path", check_id="stub_allow")]

    def _resolve_with_signer(finding: Finding) -> Finding:
        """Resolver stand-in supplying the Microsoft signer the allow rule wants."""
        return dataclasses.replace(finding, signer="Microsoft Windows", is_lolbin=False)

    plugins = {"stub_allow": _StubWithAllow}
    with _patched_pipeline(plugins, resolve=_resolve_with_signer):
        assert run_pipeline(context, profile=profile) == []

    with _patched_pipeline(plugins, resolve=_resolve_with_signer):
        results = run_pipeline(context, profile=profile, min_severity=Severity.INFO)

    assert len(results) == 1
    assert results[0].severity is Severity.INFO


def test_run_pipeline_partial_allow_match_low(tmp_path: Path) -> None:
    """Partial allow-rule match (core passes, signer fails) classifies as LOW."""
    context = _make_context(tmp_path)
    profile = DetectionProfile(
        checks={
            "stub_partial": CheckPolicy(
                allow=(FilterRule(signer="Unknown_signer", path_matches=r"stub"),)
            )
        },
    )

    class _StubPartial(PersistencePlugin):
        """Plugin whose check id carries an allow rule only partly satisfied."""

        definition: ClassVar[CheckDefinition] = CheckDefinition(
            id="stub_partial",
            technique="Stub Partial",
            mitre_id="T0000",
        )

        def run(self) -> list[Finding]:
            """Emit a finding whose path matches the rule's path_matches half."""
            return [Finding(path="stub_path", check_id="stub_partial")]

    def _resolve_with_signer(finding: Finding) -> Finding:
        """Resolver stand-in supplying a signer the allow rule will not accept."""
        return dataclasses.replace(finding, signer="Microsoft Windows")

    plugins = {"stub_partial": _StubPartial}
    with _patched_pipeline(plugins, resolve=_resolve_with_signer):
        assert run_pipeline(context, profile=profile) == []

    with _patched_pipeline(plugins, resolve=_resolve_with_signer):
        results = run_pipeline(context, profile=profile, min_severity=Severity.LOW)

    assert len(results) == 1
    assert results[0].severity is Severity.LOW


def test_run_pipeline_block_rule_high(tmp_path: Path) -> None:
    """Block-rule match classifies as HIGH."""
    context = _make_context(tmp_path)
    profile = DetectionProfile(
        checks={"stub_block": CheckPolicy(block=(FilterRule(value_matches=r"evil"),))},
    )

    class _StubBlocked(PersistencePlugin):
        """Plugin emitting a finding whose value matches the block rule."""

        definition: ClassVar[CheckDefinition] = CheckDefinition(
            id="stub_block",
            technique="Stub Block",
            mitre_id="T0000",
        )

        def run(self) -> list[Finding]:
            """Emit the evil.exe value the block rule is written against."""
            return [Finding(path="stub_path", value="evil.exe", check_id="stub_block")]

    with _patched_pipeline({"stub_block": _StubBlocked}):
        results = run_pipeline(context, profile=profile)

    assert len(results) == 1
    assert results[0].severity is Severity.HIGH


def test_run_pipeline_no_rules_medium(tmp_path: Path) -> None:
    """No allow/block rules match → severity MEDIUM."""
    context = _make_context(tmp_path)

    with _patched_pipeline({"stub_a": _StubPluginA}):
        results = run_pipeline(context, profile=DetectionProfile())

    assert len(results) == 1
    assert results[0].severity is Severity.MEDIUM


def test_run_pipeline_lolbin_partial_allow(tmp_path: Path) -> None:
    """LOLBin with signer+not_lolbin rule: not_lolbin is core and fails → MEDIUM."""
    context = _make_context(tmp_path)
    profile = DetectionProfile(
        checks={
            "stub_allow": CheckPolicy(
                allow=(FilterRule(signer="Microsoft", not_lolbin=True),)
            )
        },
    )

    class _StubWithAllow(PersistencePlugin):
        """Plugin for the LOLBin case, sharing the stub_allow policy id."""

        definition: ClassVar[CheckDefinition] = CheckDefinition(
            id="stub_allow",
            technique="Stub Allow",
            mitre_id="T0000",
        )

        def run(self) -> list[Finding]:
            """Emit one finding; the resolver marks it a LOLBin afterwards."""
            return [Finding(path="stub_path", check_id="stub_allow")]

    def _resolve_lolbin(finding: Finding) -> Finding:
        """Resolver stand-in: the signer matches, the LOLBin flag does not."""
        return dataclasses.replace(finding, signer="Microsoft Windows", is_lolbin=True)

    with _patched_pipeline({"stub_allow": _StubWithAllow}, resolve=_resolve_lolbin):
        results = run_pipeline(context, profile=profile)

    assert len(results) == 1
    assert results[0].is_lolbin is True
    assert results[0].severity is Severity.MEDIUM


def test_run_pipeline_timeline_invokes_executor(tmp_path: Path) -> None:
    """With timeline enabled (default), each surviving finding is timestamped."""
    context = _make_context(tmp_path)

    with _patched_pipeline(
        {"stub_a": _StubPluginA}, stub_timeline=True
    ) as timeline_cls:
        results = run_pipeline(context, profile=DetectionProfile())

    timeline_cls.assert_called_once()
    timeline_cls.return_value.timestamp.assert_called_once()
    assert len(results) == 1


def test_run_pipeline_timeline_disabled_skips_executor(tmp_path: Path) -> None:
    """timeline=False must not construct or call the executor."""
    context = _make_context(tmp_path)

    with _patched_pipeline(
        {"stub_a": _StubPluginA}, stub_timeline=True
    ) as timeline_cls:
        results = run_pipeline(context, profile=DetectionProfile(), timeline=False)

    timeline_cls.assert_not_called()
    assert len(results) == 1


def test_run_pipeline_threads_mft_path_to_executor(tmp_path: Path) -> None:
    """The mft_path kwarg is forwarded to the TimelineExecutor constructor."""
    context = _make_context(tmp_path)
    mft = tmp_path / "$MFT"

    with _patched_pipeline(
        {"stub_a": _StubPluginA}, stub_timeline=True
    ) as timeline_cls:
        run_pipeline(context, profile=DetectionProfile(), mft_path=mft)

    _args, kwargs = timeline_cls.call_args
    assert kwargs["mft_path"] == mft


def test_run_pipeline_timeline_receives_only_surviving_findings(
    tmp_path: Path,
) -> None:
    """Findings filtered out below min_severity never reach the timestamp stage."""
    context = _make_context(tmp_path)

    with _patched_pipeline(
        {"stub_a": _StubPluginA}, stub_timeline=True
    ) as timeline_cls:
        results = run_pipeline(
            context, profile=DetectionProfile(), min_severity=Severity.HIGH
        )

    assert results == []
    timeline_cls.return_value.timestamp.assert_not_called()
