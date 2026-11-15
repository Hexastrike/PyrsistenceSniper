"""Console renderer that groups findings by technique for terminal review."""

from __future__ import annotations

from typing import IO

from pyrsistencesniper.core.models import (
    CheckFailure,
    Finding,
    HiveRecord,
)
from pyrsistencesniper.output.base import OutputBase

_RULE = "!" * 60


def _write_incomplete_banner(out: IO[str], headline: str) -> None:
    """Write the ruled SCAN INCOMPLETE banner that precedes the findings."""
    out.write(f"\n{_RULE}\n{headline}\n{_RULE}\n")


class ConsoleOutput(OutputBase):
    """Renders findings as grouped, human-readable text to a stream."""

    def _write(
        self,
        results: list[Finding],
        out: IO[str],
        *,
        inventory: tuple[HiveRecord, ...] = (),
        failures: tuple[CheckFailure, ...] = (),
        hostname: str = "",
    ) -> None:
        del hostname
        self._write_scan_integrity(out, inventory)
        self._write_failed_checks(out, failures)
        if not results:
            out.write("No findings.\n")
            return

        grouped: dict[str, list[Finding]] = {}
        for finding in results:
            key = f"[{finding.mitre_id}] {finding.technique}"
            grouped.setdefault(key, []).append(finding)

        field_labels = Finding.FIELDS
        total = 0
        for technique, items in sorted(grouped.items()):
            out.write(f"\n{'=' * 60}\n")
            out.write(f"{technique} ({len(items)} finding(s))\n")
            out.write(f"{'=' * 60}\n")
            for finding in items:
                row = self.result_to_dict(finding)
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
                if row["last_change"]:
                    out.write(
                        f"{field_labels['last_change']}: {row['last_change']}"
                        f" ({row['change_source']})\n"
                    )
                elif row["change_evidence"] not in ("", "NOT_RUN"):
                    out.write(
                        f"{field_labels['change_evidence']}: {row['change_evidence']}\n"
                    )
                flags_str = self.build_flags(row)
                if flags_str:
                    out.write(f"Flags: {flags_str}\n")
                if row["references"]:
                    out.write(f"{field_labels['references']}: {row['references']}\n")
                out.write("\n")
                total += 1

        out.write(f"Total: {total} finding(s)\n")

    def _write_scan_integrity(
        self, out: IO[str], inventory: tuple[HiveRecord, ...]
    ) -> None:
        """Warn before the findings about hives that were never read."""
        unreadable = self.unreadable_hives(inventory)
        if not unreadable:
            return
        _write_incomplete_banner(
            out, f"SCAN INCOMPLETE: {len(unreadable)} hive(s) were not read"
        )
        for record in unreadable:
            owner = f" [{record.owner}]" if record.owner else ""
            out.write(f"{record.name}{owner}: {record.status.value}\n")
            if record.error:
                out.write(f"  {record.error}\n")
        out.write(
            "Checks reading these hives produced nothing, "
            "which is not the same as finding nothing.\n"
        )

    @staticmethod
    def _write_failed_checks(out: IO[str], failures: tuple[CheckFailure, ...]) -> None:
        """Name every check and artifact that produced nothing because it failed."""
        if not failures:
            return
        _write_incomplete_banner(
            out,
            f"SCAN INCOMPLETE: {len(failures)} check(s) or artifact(s) "
            "produced nothing",
        )
        for failure in failures:
            out.write(f"{failure.label}: {failure.error}\n")
        out.write(
            "These produced nothing because they failed, "
            "which is not the same as finding nothing.\n"
        )
