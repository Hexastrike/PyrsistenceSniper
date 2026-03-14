"""Enrichment runner: apply enrichment plugins to findings and collect results."""

from __future__ import annotations

import logging
from collections.abc import Callable

from pyrsistencesniper.enrichment.base import EnrichmentPlugin
from pyrsistencesniper.models.finding import AnnotatedResult, Enrichment, Finding

logger = logging.getLogger(__name__)

_ENRICHMENT_REGISTRY: list[type[EnrichmentPlugin]] = []


def register_enrichment(
    cls: type[EnrichmentPlugin],
) -> type[EnrichmentPlugin]:
    """Class decorator that adds an enrichment plugin to the global registry."""
    _ENRICHMENT_REGISTRY.append(cls)
    return cls


def _try_enrich(
    plugin_cls: type[EnrichmentPlugin], finding: Finding
) -> Enrichment | None:
    """Run a single enrichment plugin, returning None on failure."""
    try:
        plugin = plugin_cls()
        return plugin.enrich(finding)
    except Exception as exc:
        logger.warning(
            "Enrichment plugin %s failed: %s",
            plugin_cls.__name__,
            exc,
        )
        logger.debug("Enrichment plugin error details:", exc_info=True)
        return None


def run_enrichments(
    findings: list[Finding],
    *,
    progress: Callable[[str, int, int], None] | None = None,
) -> list[AnnotatedResult]:
    """Run all enrichment plugins and return annotated results."""
    results: list[AnnotatedResult] = []
    total = len(findings)
    for i, finding in enumerate(findings):
        if progress is not None:
            progress("Enriching results", i + 1, total)
        enrichments: list[Enrichment] = []
        for plugin_cls in _ENRICHMENT_REGISTRY:
            enrichment = _try_enrich(plugin_cls, finding)
            if enrichment is not None:
                enrichments.append(enrichment)
        results.append((finding, tuple(enrichments)))
    return results
