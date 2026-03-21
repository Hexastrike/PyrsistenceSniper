"""Abstract base class for enrichment plugins."""

from __future__ import annotations

from abc import ABC, abstractmethod

from pyrsistencesniper.core.models import Enrichment, Finding


class EnrichmentPlugin(ABC):
    """Abstract base for plugins that attach supplementary data to findings."""

    @abstractmethod
    def enrich(self, finding: Finding) -> Enrichment | None:
        """Return an Enrichment for the given finding, or None to skip."""
        ...
