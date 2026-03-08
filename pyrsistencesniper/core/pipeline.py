from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from pyrsistencesniper.core import ProgressFn
from pyrsistencesniper.core.context import AnalysisContext
from pyrsistencesniper.core.profile import DetectionProfile
from pyrsistencesniper.models.finding import AnnotatedResult, FilterRule, Finding

if TYPE_CHECKING:
    from pyrsistencesniper.plugins.base import PersistencePlugin

    _PluginRegistry = dict[str, type[PersistencePlugin]]

logger = logging.getLogger(__name__)


def run_all_checks(
    context: AnalysisContext,
    *,
    technique_filter: tuple[str, ...] = (),
    raw: bool = False,
    progress: ProgressFn | None = None,
) -> list[AnnotatedResult]:
    """Run the full detection pipeline: discover plugins, execute checks,
    resolve file metadata, apply allow/block policy, and run enrichments.

    Returns a list of ``AnnotatedResult`` tuples, each pairing a resolved
    ``Finding`` with any ``Enrichment`` objects produced by enrichment plugins.
    """
    from pyrsistencesniper.enrichment import run_enrichments
    from pyrsistencesniper.plugins import _PLUGIN_REGISTRY, _discover_plugins
    from pyrsistencesniper.resolution.resolver import ResolutionPipeline

    _discover_plugins()

    profile = context.profile
    plugins = list(_PLUGIN_REGISTRY.values())

    if not technique_filter:
        plugins_to_run = [p for p in plugins if profile.is_enabled(p.definition.id)]
    else:
        tf = set(technique_filter)
        plugins_to_run = [
            p
            for p in plugins
            if profile.is_enabled(p.definition.id)
            and (p.definition.id in tf or p.definition.mitre_id in tf)
        ]

    if not plugins_to_run:
        return []

    all_findings: list[Finding] = []
    total_plugins = len(plugins_to_run)

    for i, plugin_cls in enumerate(plugins_to_run):
        if progress is not None:
            progress("Running checks", i + 1, total_plugins)
        try:
            plugin = plugin_cls(context=context, raw=raw)
            all_findings.extend(plugin.run())
        except Exception:
            logger.warning(
                "Plugin %s raised an exception",
                plugin_cls.definition.id,
            )
            logger.debug("Plugin error details:", exc_info=True)

    resolver = ResolutionPipeline(context.filesystem)
    total_findings = len(all_findings)
    resolved: list[Finding] = []
    for i, f in enumerate(all_findings):
        if progress is not None:
            progress("Resolving findings", i + 1, total_findings)
        resolved.append(resolver.resolve(f))

    if not raw:
        filtered: list[Finding] = []
        for finding in resolved:
            check_id = finding.check_id

            if _is_blocked(check_id, finding, profile, _PLUGIN_REGISTRY):
                filtered.append(finding)
                continue

            if _is_allowed(check_id, finding, profile, _PLUGIN_REGISTRY):
                continue

            filtered.append(finding)
        resolved = filtered

    results = run_enrichments(resolved, progress=progress)
    return results


def _any_rule_matches(rules: tuple[FilterRule, ...], finding: Finding) -> bool:
    """Return True if at least one rule matches the given finding."""
    return any(rule.matches(finding) for rule in rules)


def _is_blocked(
    check_id: str,
    finding: Finding,
    profile: DetectionProfile,
    registry: _PluginRegistry,
) -> bool:
    """Return True if the finding matches any block rule (plugin or profile)."""
    plugin_cls = registry.get(check_id)
    if plugin_cls is not None and _any_rule_matches(
        plugin_cls.definition.block, finding
    ):
        return True
    return profile.matches_block(check_id, finding)


def _is_allowed(
    check_id: str,
    finding: Finding,
    profile: DetectionProfile,
    registry: _PluginRegistry,
) -> bool:
    """Return True if the finding matches any allow rule (plugin or profile)."""
    plugin_cls = registry.get(check_id)
    if plugin_cls is not None and _any_rule_matches(
        plugin_cls.definition.allow, finding
    ):
        return True
    return profile.matches_allow(check_id, finding)
