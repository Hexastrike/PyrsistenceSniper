from __future__ import annotations

from importlib.resources import files
from typing import IO, Any

from jinja2 import Environment

from pyrsistencesniper.core.models import AnnotatedResult, Finding
from pyrsistencesniper.output.base import OutputBase

_HTML_TEMPLATE = (
    files("pyrsistencesniper.output").joinpath("report.html.j2").read_text("utf-8")
)


def _count_severities(rows: list[dict[str, Any]]) -> dict[str, int]:
    """Count findings per severity level for the stats bar."""
    counts: dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for row in rows:
        sev = row.get("severity", "")
        if sev in counts:
            counts[sev] += 1
    return counts


class HtmlOutput(OutputBase):
    """Renders findings into a dark-mode interactive HTML report."""

    def _write(self, results: list[AnnotatedResult], out: IO[str]) -> None:
        env = Environment(autoescape=True)
        env.policies["json.dumps_kwargs"] = {"default": str}
        template = env.from_string(_HTML_TEMPLATE)
        rows, fieldnames = self._flatten_results(results)
        labels = {field: Finding.FIELDS.get(field, field) for field in fieldnames}
        out.write(
            template.render(
                results=rows,
                fieldnames=fieldnames,
                labels=labels,
                total=len(rows),
                severity_counts=_count_severities(rows),
            )
        )
