from __future__ import annotations

from pyrsistencesniper.output.base import OutputBase
from pyrsistencesniper.output.console_output import ConsoleOutput
from pyrsistencesniper.output.csv_output import CsvOutput
from pyrsistencesniper.output.html_output import HtmlOutput
from pyrsistencesniper.output.xlsx_output import XlsxOutput

_RENDERERS: dict[str, type[OutputBase]] = {
    "console": ConsoleOutput,
    "csv": CsvOutput,
    "html": HtmlOutput,
    "xlsx": XlsxOutput,
}


def get_renderer(format_name: str) -> type[OutputBase]:
    """Look up an output renderer class by format name."""
    try:
        return _RENDERERS[format_name.lower()]
    except KeyError:
        raise ValueError(
            f"Unknown format {format_name!r}. Choose from: {', '.join(_RENDERERS)}"
        ) from None
