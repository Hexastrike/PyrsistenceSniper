from __future__ import annotations

import logging
import pkgutil
from collections.abc import Callable

from pyrsistencesniper.core.filesystem import FilesystemHelper
from pyrsistencesniper.core.image import ForensicImage
from pyrsistencesniper.core.profile import DetectionProfile
from pyrsistencesniper.core.registry import RegistryHelper
from pyrsistencesniper.core.resolver import ResolutionPipeline
from pyrsistencesniper.enrichment import run_enrichments
from pyrsistencesniper.models.finding import AllowRule, AnnotatedResult, Finding
from pyrsistencesniper.plugins.base import PersistencePlugin

logger = logging.getLogger(__name__)

ProgressFn = Callable[[str, int, int], None]


_PLUGIN_REGISTRY: dict[str, type[PersistencePlugin]] = {}


def register_plugin(cls: type[PersistencePlugin]) -> type[PersistencePlugin]:
    """Class decorator that adds a plugin to the global plugin registry."""
    check_id = cls.definition.id
    _PLUGIN_REGISTRY[check_id] = cls
    return cls


def _discover_plugins() -> None:
    """Walk and import all plugin submodules to trigger registration decorators."""
    for _importer, modname, _ispkg in pkgutil.walk_packages(
        __path__, prefix=__name__ + "."
    ):
        try:
            __import__(modname)
        except Exception:
            logger.warning("Failed to import plugin module %s", modname, exc_info=True)


def run_all_checks(
    image: ForensicImage,
    registry: RegistryHelper,
    filesystem: FilesystemHelper,
    profile: DetectionProfile,
    *,
    technique_filter: tuple[str, ...] = (),
    raw: bool = False,
    progress: ProgressFn | None = None,
) -> list[AnnotatedResult]:
    """Run the full detection pipeline: discover plugins, execute checks,
    resolve file metadata, apply allow/block policy, and run enrichments.
    """
    _discover_plugins()

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
            plugin = plugin_cls(
                registry=registry,
                filesystem=filesystem,
                image=image,
                profile=profile,
                raw=raw,
            )
            all_findings.extend(plugin.run())
        except Exception:
            logger.warning(
                "Plugin %s raised an exception",
                plugin_cls.definition.id,
                exc_info=True,
            )

    resolver = ResolutionPipeline(filesystem)
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

            if _is_blocked(check_id, finding, profile):
                filtered.append(finding)
                continue

            if _is_allowed(check_id, finding, profile):
                continue

            filtered.append(finding)
        resolved = filtered

    results = run_enrichments(resolved, progress=progress)
    return results


def _any_rule_matches(rules: tuple[AllowRule, ...], finding: Finding) -> bool:
    """Return True if at least one rule matches the given finding."""
    return any(rule.matches(finding) for rule in rules)


def _is_blocked(check_id: str, finding: Finding, profile: DetectionProfile) -> bool:
    """Return True if the finding matches any block rule (plugin or profile)."""
    plugin_cls = _PLUGIN_REGISTRY.get(check_id)
    if plugin_cls is not None and _any_rule_matches(
        plugin_cls.definition.block, finding
    ):
        return True
    return profile.matches_block(check_id, finding)


def _is_allowed(check_id: str, finding: Finding, profile: DetectionProfile) -> bool:
    """Return True if the finding matches any allow rule (plugin or profile)."""
    plugin_cls = _PLUGIN_REGISTRY.get(check_id)
    if plugin_cls is not None and _any_rule_matches(
        plugin_cls.definition.allow, finding
    ):
        return True
    return profile.matches_allow(check_id, finding)
