from __future__ import annotations

from typing import IO

from jinja2 import Environment

from pyrsistencesniper.models.finding import AnnotatedResult
from pyrsistencesniper.output.base import OutputBase

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>PyrsistenceSniper Report</title>
<style>
  body { font-family: sans-serif; margin: 2em; }
  table { border-collapse: collapse; width: 100%; margin-top: 1em; }
  th, td { border: 1px solid #ccc; padding: 0.5em; text-align: left; }
  th { background: #f0f0f0; }
  tr:nth-child(even) { background: #fafafa; }
  .summary { margin-bottom: 1em; }
</style>
</head>
<body>
<h1>PyrsistenceSniper Report</h1>
<p class="summary">Total findings: {{ results|length }}</p>
<table>
<thead>
<tr>
  <th>Technique</th>
  <th>MITRE ID</th>
  <th>Check ID</th>
  <th>Path</th>
  <th>Value</th>
  <th>Description</th>
  <th>Access</th>
  <th>SHA256</th>
  <th>Signer</th>
  <th>Flags</th>
  <th>References</th>
</tr>
</thead>
<tbody>
{% for row in results %}
<tr>
  <td>{{ row.technique }}</td>
  <td>{{ row.mitre_id }}</td>
  <td>{{ row.check_id }}</td>
  <td>{{ row.path }}</td>
  <td>{{ row.value }}</td>
  <td>{{ row.description }}</td>
  <td>{{ row.access_gained }}</td>
  <td>{{ row.sha256 }}</td>
  <td>{{ row.signer }}</td>
  <td>{{ row.flags }}</td>
  <td>{{ row.references }}</td>
</tr>
{% endfor %}
</tbody>
</table>
</body>
</html>
"""


class HtmlOutput(OutputBase):
    """Renders findings into a standalone HTML report using Jinja2."""

    def _write(self, results: list[AnnotatedResult], out: IO[str]) -> None:
        env = Environment(autoescape=True)
        template = env.from_string(_HTML_TEMPLATE)

        rows = []
        for result in results:
            d = self.result_to_dict(result)
            d["flags"] = self.build_flags(d)
            rows.append(d)

        out.write(template.render(results=rows))
