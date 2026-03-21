"""Tests for the enrichment runner: error isolation and result collection."""

from __future__ import annotations

from pyrsistencesniper.core.models import AccessLevel, Enrichment, Finding
from pyrsistencesniper.enrichment.base import EnrichmentPlugin
from pyrsistencesniper.enrichment.runner import _try_enrich, run_enrichments


def _make_finding(value: str = "test.exe") -> Finding:
    return Finding(
        path="HKLM\\Run",
        value=value,
        technique="Test",
        mitre_id="T0000",
        description="d",
        access_gained=AccessLevel.SYSTEM,
        hostname="HOST",
        check_id="test_check",
    )


class _GoodPlugin(EnrichmentPlugin):
    def enrich(self, finding: Finding) -> Enrichment | None:
        return Enrichment(provider="good", data={"score": "10"})


class _NonePlugin(EnrichmentPlugin):
    def enrich(self, finding: Finding) -> Enrichment | None:
        return None


class _CrashingPlugin(EnrichmentPlugin):
    def enrich(self, finding: Finding) -> Enrichment | None:
        raise RuntimeError("plugin exploded")


def test_try_enrich_success() -> None:
    """A working plugin returns its enrichment."""
    result = _try_enrich(_GoodPlugin, _make_finding())
    assert result is not None
    assert result.provider == "good"


def test_try_enrich_returns_none() -> None:
    """A plugin that returns None is passed through."""
    result = _try_enrich(_NonePlugin, _make_finding())
    assert result is None


def test_try_enrich_exception_returns_none() -> None:
    """A crashing plugin returns None instead of propagating."""
    result = _try_enrich(_CrashingPlugin, _make_finding())
    assert result is None


def test_run_enrichments_collects_results(monkeypatch: object) -> None:
    """run_enrichments pairs findings with collected enrichments."""
    import pyrsistencesniper.enrichment.runner as runner_mod

    monkeypatch.setattr(runner_mod, "_ENRICHMENT_REGISTRY", [_GoodPlugin])

    findings = [_make_finding("a.exe"), _make_finding("b.exe")]
    results = run_enrichments(findings)

    assert len(results) == 2
    for _finding, enrichments in results:
        assert len(enrichments) == 1
        assert enrichments[0].provider == "good"


def test_run_enrichments_skips_none(monkeypatch: object) -> None:
    """Enrichments returning None are excluded from the result tuple."""
    import pyrsistencesniper.enrichment.runner as runner_mod

    monkeypatch.setattr(runner_mod, "_ENRICHMENT_REGISTRY", [_NonePlugin])

    results = run_enrichments([_make_finding()])
    assert len(results) == 1
    _finding, enrichments = results[0]
    assert enrichments == ()


def test_run_enrichments_isolates_crash(monkeypatch: object) -> None:
    """A crashing plugin does not prevent other enrichments from running."""
    import pyrsistencesniper.enrichment.runner as runner_mod

    monkeypatch.setattr(
        runner_mod, "_ENRICHMENT_REGISTRY", [_CrashingPlugin, _GoodPlugin]
    )

    results = run_enrichments([_make_finding()])
    assert len(results) == 1
    _finding, enrichments = results[0]
    assert len(enrichments) == 1
    assert enrichments[0].provider == "good"
