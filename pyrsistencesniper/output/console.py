from __future__ import annotations

from typing import IO

from pyrsistencesniper.models.finding import AnnotatedResult
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
            for result in items:
                d = self.result_to_dict(result)
                if d["hostname"]:
                    out.write(f"Host: {d['hostname']}\n")
                out.write(f"Path: {d['path']}\n")
                out.write(f"Value: {d['value']}\n")
                out.write(f"Description: {d['description']}\n")
                out.write(f"Access: {d['access_gained']}\n")
                out.write(f"Severity: {d['severity']}\n")
                out.write(f"Check ID: {d['check_id']}\n")
                if d["sha256"]:
                    out.write(f"SHA256: {d['sha256']}\n")
                if d["signer"]:
                    out.write(f"Signer: {d['signer']}\n")
                flags_str = self.build_flags(d)
                if flags_str:
                    out.write(f"Flags: {flags_str}\n")
                if d["references"]:
                    out.write(f"References: {d['references']}\n")
                out.write("\n")
                total += 1

        out.write(f"Total: {total} finding(s)\n")
