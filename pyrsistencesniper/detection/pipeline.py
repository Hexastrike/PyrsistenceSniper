"""Detection pipeline: discover, execute, resolve, classify, and enrich findings."""

from __future__ import annotations

import dataclasses
import logging
from collections.abc import Callable
from pathlib import Path

from pyrsistencesniper.core import ledger
from pyrsistencesniper.core.context import AnalysisContext
from pyrsistencesniper.core.models import (
    Finding,
    Severity,
)
from pyrsistencesniper.core.profile import DetectionProfile
from pyrsistencesniper.core.resolver import ResolutionPipeline
from pyrsistencesniper.plugins import (
    PLUGIN_REGISTRY,
    discover_plugins,
)
from pyrsistencesniper.plugins.base import PersistencePlugin
from pyrsistencesniper.timeline.executor import TimelineExecutor

logger = logging.getLogger(__name__)


def _technique_matches(plugin_cls: type[PersistencePlugin], tokens: set[str]) -> bool:
    """Match a check id or MITRE id; a bare T1547 also selects its sub-techniques."""
    definition = plugin_cls.definition
    if definition.id in tokens or definition.mitre_id in tokens:
        return True
    parent_technique = definition.mitre_id.split(".", 1)[0]
    return parent_technique in tokens


def _select_plugins(
    profile: DetectionProfile,
    technique_filter: tuple[str, ...],
) -> list[type[PersistencePlugin]]:
    """Discover plugins and filter by profile + technique selection."""
    discover_plugins()
    tokens = set(technique_filter)

    return [
        plugin_cls
        for plugin_cls in PLUGIN_REGISTRY.values()
        if profile.policy_for(plugin_cls.definition.id).enabled
        and (not tokens or _technique_matches(plugin_cls, tokens))
    ]


def _execute_plugins(
    plugins: list[type[PersistencePlugin]],
    context: AnalysisContext,
    progress: Callable[[str, int, int], None] | None,
) -> list[Finding]:
    """Execute each plugin and collect raw findings, isolating failures."""
    findings: list[Finding] = []
    total = len(plugins)

    for index, plugin_cls in enumerate(plugins):
        if progress is not None:
            progress("Running checks", index + 1, total)
        try:
            plugin = plugin_cls(context=context)
            findings.extend(plugin.run())
        except Exception as exc:
            logger.warning(
                "Check %s failed and produced no findings: %s: %s",
                plugin_cls.definition.id,
                type(exc).__name__,
                exc,
            )
            logger.debug("Check error details:", exc_info=True)
            ledger.record_check_failure(plugin_cls.definition.id, exc)

    return findings


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    """Drop repeats within one check; the same value from two checks is signal."""
    seen: set[tuple[str, str, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        identity = (finding.check_id, finding.path.casefold(), finding.value)
        if identity in seen:
            continue
        seen.add(identity)
        unique.append(finding)
    return unique


# A stage that fails on one finding keeps that finding as it was: losing the
# detail a stage adds must never cost the report the finding itself.
def _apply_stage(
    findings: list[Finding],
    stage: str,
    detail: str,
    operation: Callable[[Finding], Finding],
    progress: Callable[[str, int, int], None] | None,
) -> list[Finding]:
    """Run one per-finding stage, keeping a finding the stage could not process."""
    total = len(findings)
    processed: list[Finding] = []
    for index, finding in enumerate(findings):
        if progress is not None:
            progress(stage, index + 1, total)
        try:
            processed.append(operation(finding))
        except Exception as exc:
            logger.warning(
                "Could not resolve %s for %s finding: %s: %s",
                detail,
                finding.check_id,
                type(exc).__name__,
                exc,
            )
            logger.debug("%s error details:", stage, exc_info=True)
            processed.append(finding)
    return processed


def _classify_and_filter(
    findings: list[Finding],
    profile: DetectionProfile,
    min_severity: Severity,
) -> list[Finding]:
    """Classify each finding's severity. Keep only those at or above the threshold."""
    result: list[Finding] = []
    for finding in findings:
        severity = profile.policy_for(finding.check_id).classify(finding)
        updated = dataclasses.replace(finding, severity=severity)
        if severity >= min_severity:
            result.append(updated)
    return result


def run_pipeline(
    context: AnalysisContext,
    *,
    profile: DetectionProfile,
    technique_filter: tuple[str, ...] = (),
    min_severity: Severity = Severity.MEDIUM,
    mft_path: Path | None = None,
    timeline: bool = True,
    progress: Callable[[str, int, int], None] | None = None,
) -> list[Finding]:
    """Run the full detection pipeline and return resolved, classified findings."""
    plugins = _select_plugins(profile, technique_filter)
    if not plugins:
        return []

    raw = _execute_plugins(plugins, context, progress)
    resolved = _apply_stage(
        _deduplicate(raw),
        "Resolving findings",
        "metadata",
        ResolutionPipeline(context.filesystem).resolve,
        progress,
    )
    classified = _classify_and_filter(resolved, profile, min_severity)
    if timeline:
        classified = _apply_stage(
            classified,
            "Resolving timestamps",
            "timestamps",
            TimelineExecutor(context, mft_path=mft_path).timestamp,
            progress,
        )
    return classified
