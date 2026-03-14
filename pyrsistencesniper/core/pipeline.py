"""Detection pipeline: discover, execute, resolve, classify, and enrich findings."""

from __future__ import annotations

import dataclasses
import logging
from collections.abc import Callable

from pyrsistencesniper.core.context import AnalysisContext
from pyrsistencesniper.core.profile import DetectionProfile
from pyrsistencesniper.enrichment import run_enrichments
from pyrsistencesniper.models.finding import (
    MATCH_TO_SEVERITY,
    AnnotatedResult,
    FilterRule,
    Finding,
    MatchResult,
    Severity,
)
from pyrsistencesniper.plugins import _PLUGIN_REGISTRY, _discover_plugins
from pyrsistencesniper.plugins.base import PersistencePlugin
from pyrsistencesniper.resolution.resolver import ResolutionPipeline

_PluginRegistry = dict[str, type[PersistencePlugin]]

logger = logging.getLogger(__name__)


def _is_blocked(
    check_id: str,
    finding: Finding,
    profile: DetectionProfile,
    registry: _PluginRegistry,
) -> bool:
    """Return True if the finding matches any block rule (plugin or profile)."""
    plugin_cls = registry.get(check_id)
    if plugin_cls is not None and any(
        rule.matches(finding) for rule in plugin_cls.definition.block
    ):
        return True
    return profile.matches_block(check_id, finding)


def _best_allow_match(
    check_id: str,
    finding: Finding,
    profile: DetectionProfile,
    registry: _PluginRegistry,
) -> MatchResult:
    """Return the best match result across all applicable allow rules."""
    rules: list[FilterRule] = []
    plugin_cls = registry.get(check_id)
    if plugin_cls is not None:
        rules.extend(plugin_cls.definition.allow)
    rules.extend(profile.allow_rules_for(check_id))

    best = MatchResult.NONE
    for rule in rules:
        result = rule.match_result(finding)
        if result == MatchResult.FULL:
            return MatchResult.FULL
        if result == MatchResult.PARTIAL:
            best = MatchResult.PARTIAL
    return best


def _classify_severity(
    check_id: str,
    finding: Finding,
    profile: DetectionProfile,
    registry: _PluginRegistry,
) -> Severity:
    """Assign a severity based on block/allow rule matching."""
    if _is_blocked(check_id, finding, profile, registry):
        return Severity.HIGH
    best = _best_allow_match(check_id, finding, profile, registry)
    return MATCH_TO_SEVERITY[best]


def _select_plugins(
    profile: DetectionProfile,
    technique_filter: tuple[str, ...],
) -> list[type[PersistencePlugin]]:
    """Discover plugins and filter by profile + technique selection."""
    _discover_plugins()
    plugins = list(_PLUGIN_REGISTRY.values())

    if not technique_filter:
        return [
            plugin_cls
            for plugin_cls in plugins
            if profile.is_enabled(plugin_cls.definition.id)
        ]

    technique_ids = set(technique_filter)
    return [
        plugin_cls
        for plugin_cls in plugins
        if profile.is_enabled(plugin_cls.definition.id)
        and (
            plugin_cls.definition.id in technique_ids
            or plugin_cls.definition.mitre_id in technique_ids
        )
    ]


def _execute_plugins(
    plugins: list[type[PersistencePlugin]],
    context: AnalysisContext,
    include_defaults: bool,
    progress: Callable[[str, int, int], None] | None,
) -> list[Finding]:
    """Execute each plugin and collect raw findings, isolating failures."""
    findings: list[Finding] = []
    total = len(plugins)

    for index, plugin_cls in enumerate(plugins):
        if progress is not None:
            progress("Running checks", index + 1, total)
        try:
            plugin = plugin_cls(context=context, include_defaults=include_defaults)
            findings.extend(plugin.run())
        except Exception:
            logger.warning(
                "Plugin %s raised an exception",
                plugin_cls.definition.id,
            )
            logger.debug("Plugin error details:", exc_info=True)

    return findings


def _resolve_findings(
    findings: list[Finding],
    context: AnalysisContext,
    progress: Callable[[str, int, int], None] | None,
) -> list[Finding]:
    """Resolve file metadata (exists, sha256, signer, ...) for each finding."""
    resolver = ResolutionPipeline(context.filesystem)
    total = len(findings)
    resolved: list[Finding] = []

    for index, finding in enumerate(findings):
        if progress is not None:
            progress("Resolving findings", index + 1, total)
        resolved.append(resolver.resolve(finding))

    return resolved


def _classify_and_filter(
    findings: list[Finding],
    profile: DetectionProfile,
    min_severity: Severity,
) -> list[Finding]:
    """Classify each finding's severity. Keep only those at or above the threshold."""
    result: list[Finding] = []
    for finding in findings:
        severity = _classify_severity(
            finding.check_id, finding, profile, _PLUGIN_REGISTRY
        )
        updated = dataclasses.replace(finding, severity=severity)
        if severity >= min_severity:
            result.append(updated)
    return result


def run_all_checks(
    context: AnalysisContext,
    *,
    technique_filter: tuple[str, ...] = (),
    min_severity: Severity = Severity.MEDIUM,
    progress: Callable[[str, int, int], None] | None = None,
) -> list[AnnotatedResult]:
    """Run the full detection pipeline: discover plugins, execute checks,
    resolve file metadata, classify severity, and run enrichments.
    """
    plugins = _select_plugins(context.profile, technique_filter)
    if not plugins:
        return []

    include_defaults = min_severity == Severity.INFO
    raw = _execute_plugins(plugins, context, include_defaults, progress)
    resolved = _resolve_findings(raw, context, progress)
    classified = _classify_and_filter(resolved, context.profile, min_severity)
    return run_enrichments(classified, progress=progress)
