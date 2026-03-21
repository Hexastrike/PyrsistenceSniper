"""Tests for OutputBase helpers: result_to_dict and build_flags."""

from __future__ import annotations

from pyrsistencesniper.core.models import AccessLevel, Enrichment, Finding
from pyrsistencesniper.output.base import OutputBase


def _make_finding(**kwargs: object) -> Finding:
    defaults = {
        "path": "HKLM\\Run",
        "value": "test.exe",
        "technique": "Test",
        "mitre_id": "T0000",
        "description": "d",
        "access_gained": AccessLevel.SYSTEM,
        "hostname": "HOST",
        "check_id": "test_check",
    }
    defaults.update(kwargs)
    return Finding(**defaults)


def test_result_to_dict_enum_to_value() -> None:
    """Enum fields are converted to their .value string."""
    finding = _make_finding(access_gained=AccessLevel.USER)
    row = OutputBase.result_to_dict((finding, ()))
    assert row["access_gained"] == "USER"


def test_result_to_dict_tuple_joined() -> None:
    """Tuple fields are joined with ' | '."""
    finding = _make_finding(references=("ref1", "ref2"))
    row = OutputBase.result_to_dict((finding, ()))
    assert row["references"] == "ref1 | ref2"


def test_result_to_dict_none_becomes_false() -> None:
    """None fields (e.g. is_lolbin before enrichment) become False."""
    finding = _make_finding(is_lolbin=None)
    row = OutputBase.result_to_dict((finding, ()))
    assert row["is_lolbin"] is False


def test_result_to_dict_enrichment_keys() -> None:
    """Enrichment data is flattened into the row dict with dotted keys."""
    finding = _make_finding()
    enrichment = Enrichment(provider="vt", data={"score": "5/70"})
    row = OutputBase.result_to_dict((finding, (enrichment,)))
    assert row["enrichment.vt.score"] == "5/70"


def test_build_flags_lolbin() -> None:
    row = OutputBase.result_to_dict(
        (
            _make_finding(
                is_lolbin=True, is_builtin=False, is_in_os_directory=False, exists=True
            ),
            (),
        )
    )
    assert OutputBase.build_flags(row) == "LOLBin"


def test_build_flags_not_found() -> None:
    row = OutputBase.result_to_dict(
        (
            _make_finding(
                is_lolbin=False,
                is_builtin=False,
                is_in_os_directory=False,
                exists=False,
            ),
            (),
        )
    )
    assert "NOT_FOUND" in OutputBase.build_flags(row)


def test_build_flags_multiple() -> None:
    row = OutputBase.result_to_dict(
        (
            _make_finding(
                is_lolbin=True, is_builtin=True, is_in_os_directory=True, exists=True
            ),
            (),
        )
    )
    flags = OutputBase.build_flags(row)
    assert "LOLBin" in flags
    assert "Builtin" in flags
    assert "OS_DIR" in flags


def test_build_flags_empty() -> None:
    row = OutputBase.result_to_dict(
        (
            _make_finding(
                is_lolbin=False, is_builtin=False, is_in_os_directory=False, exists=True
            ),
            (),
        )
    )
    assert OutputBase.build_flags(row) == ""
