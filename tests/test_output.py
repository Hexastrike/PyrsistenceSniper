from __future__ import annotations

import io

from pyrsistencesniper.models.finding import AccessLevel, Enrichment, Finding
from pyrsistencesniper.output.csv_output import CsvOutput, _sanitize_cell
from pyrsistencesniper.output.html_output import HtmlOutput

# -- CSV formula injection tests -----------------------------------------------


def test_sanitize_cell_equals() -> None:
    assert _sanitize_cell("=CMD()") == "'=CMD()"


def test_sanitize_cell_plus() -> None:
    assert _sanitize_cell("+1+2") == "'+1+2"


def test_sanitize_cell_minus() -> None:
    assert _sanitize_cell("-1-2") == "'-1-2"


def test_sanitize_cell_at() -> None:
    assert _sanitize_cell("@SUM(A1)") == "'@SUM(A1)"


def test_sanitize_cell_tab() -> None:
    assert _sanitize_cell("\t=CMD()") == "'\t=CMD()"


def test_sanitize_cell_carriage_return() -> None:
    assert _sanitize_cell("\r=CMD()") == "'\r=CMD()"


def test_sanitize_cell_newline() -> None:
    assert _sanitize_cell("\n=CMD()") == "'\n=CMD()"


def test_sanitize_cell_whitespace_prefix() -> None:
    """Leading whitespace before a formula character should be caught."""
    assert _sanitize_cell(" =CMD()") == "' =CMD()"


def test_sanitize_cell_safe_value() -> None:
    assert _sanitize_cell("explorer.exe") == "explorer.exe"


def test_sanitize_cell_empty() -> None:
    assert _sanitize_cell("") == ""


def test_sanitize_cell_number() -> None:
    assert _sanitize_cell(42) == "42"


# -- HTML autoescaping tests ---------------------------------------------------


def _make_result(
    path: str = "HKLM\\Run", value: str = "test.exe"
) -> tuple[Finding, tuple[Enrichment, ...]]:
    finding = Finding(
        path=path,
        value=value,
        technique="Test",
        mitre_id="T0000",
        description="Test description",
        access_gained=AccessLevel.SYSTEM,
        hostname="HOST",
        check_id="test_check",
    )
    return (finding, ())


def test_html_autoescaping_value() -> None:
    """A <script> tag in value must be escaped in HTML output."""
    result = _make_result(value="<script>alert(1)</script>")
    out = io.StringIO()
    renderer = HtmlOutput()
    renderer._write([result], out)
    html = out.getvalue()
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_html_autoescaping_path() -> None:
    """A <script> tag in path must be escaped in HTML output."""
    result = _make_result(path='HKLM\\<img src=x onerror="alert(1)">')
    out = io.StringIO()
    renderer = HtmlOutput()
    renderer._write([result], out)
    html = out.getvalue()
    assert 'onerror="alert(1)"' not in html
    assert "&lt;img" in html


def test_csv_output_sanitizes_all_fields() -> None:
    """All cell values in CSV output should be sanitized."""
    result = _make_result(value="=HYPERLINK()")
    out = io.StringIO()
    renderer = CsvOutput()
    renderer._write([result], out)
    csv_text = out.getvalue()
    assert "'=HYPERLINK()" in csv_text
