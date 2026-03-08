from __future__ import annotations

import logging

from pyrsistencesniper.core import ProgressFn
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


def run_enrichments(
    findings: list[Finding],
    *,
    progress: ProgressFn | None = None,
) -> list[AnnotatedResult]:
    """Run all enrichment plugins and return annotated results."""
    results: list[AnnotatedResult] = []
    total = len(findings)
    for i, finding in enumerate(findings):
        if progress is not None:
            progress("Enriching results", i + 1, total)
        enrichments: list[Enrichment] = []
        for plugin_cls in _ENRICHMENT_REGISTRY:
            try:
                plugin = plugin_cls()
                enrichment = plugin.enrich(finding)
                if enrichment is not None:
                    enrichments.append(enrichment)
            except Exception as exc:
                logger.warning(
                    "Enrichment plugin %s failed: %s",
                    plugin_cls.__name__,
                    exc,
                )
                logger.debug("Enrichment plugin error details:", exc_info=True)
        results.append((finding, tuple(enrichments)))
    return results
