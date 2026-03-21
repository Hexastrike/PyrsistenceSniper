from __future__ import annotations

from typing import IO

from pyrsistencesniper.core.models import AnnotatedResult, Finding
from pyrsistencesniper.output.base import OutputBase


class ConsoleOutput(OutputBase):
    """Renders findings as grouped, human-readable text to a stream."""

    def _write(self, results: list[AnnotatedResult], out: IO[str]) -> None:
        if not results:
            out.write("No findings.\n")
            return

        grouped: dict[str, list[AnnotatedResult]] = {}
        for result in results:
            finding = result[0]
            key = f"[{finding.mitre_id}] {finding.technique}"
            grouped.setdefault(key, []).append(result)

        total = 0
        for technique, items in sorted(grouped.items()):
            out.write(f"\n{'=' * 60}\n")
            out.write(f"{technique} ({len(items)} finding(s))\n")
            out.write(f"{'=' * 60}\n")
            field_labels = Finding.FIELDS
            for result in items:
                row = self.result_to_dict(result)
                if row["hostname"]:
                    out.write(f"{field_labels['hostname']}: {row['hostname']}\n")
                out.write(f"{field_labels['path']}: {row['path']}\n")
                out.write(f"{field_labels['value']}: {row['value']}\n")
                out.write(f"{field_labels['description']}: {row['description']}\n")
                out.write(f"{field_labels['access_gained']}: {row['access_gained']}\n")
                out.write(f"{field_labels['severity']}: {row['severity']}\n")
                out.write(f"{field_labels['check_id']}: {row['check_id']}\n")
                if row["sha256"]:
                    out.write(f"{field_labels['sha256']}: {row['sha256']}\n")
                if row["signer"]:
                    out.write(f"{field_labels['signer']}: {row['signer']}\n")
                flags_str = self.build_flags(row)
                if flags_str:
                    out.write(f"Flags: {flags_str}\n")
                if row["references"]:
                    out.write(f"{field_labels['references']}: {row['references']}\n")
                out.write("\n")
                total += 1

        out.write(f"Total: {total} finding(s)\n")
