from __future__ import annotations

import logging
import re
from pathlib import Path as _Path
from pathlib import PureWindowsPath

from pyrsistencesniper.models.finding import AccessLevel, Finding
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import CheckDefinition, PersistencePlugin

logger = logging.getLogger(__name__)

_CIM_PATHS: tuple[_Path, ...] = (
    _Path("Windows") / "System32" / "wbem" / "Repository" / "OBJECTS.DATA",
    _Path("Windows") / "System32" / "wbem" / "Repository" / "FS" / "OBJECTS.DATA",
)

_CMDLINE_PATTERN = re.compile(
    rb"C\x00o\x00m\x00m\x00a\x00n\x00d\x00L\x00i\x00n\x00e\x00"
    rb"T\x00e\x00m\x00p\x00l\x00a\x00t\x00e\x00"
    rb"[\x00-\x20]{0,20}"
    rb"((?:[^\x00]\x00){5,250})",
    re.IGNORECASE,
)

_SCRIPT_PATTERN = re.compile(
    rb"S\x00c\x00r\x00i\x00p\x00t\x00T\x00e\x00x\x00t\x00"
    rb"[\x00-\x20]{0,20}"
    rb"((?:[^\x00]\x00){5,500})",
    re.IGNORECASE,
)

_CMDLINE_PATTERN_ASCII = re.compile(
    rb"CommandLineTemplate"
    rb"[\x00-\x20]{1,20}"
    rb"([\x20-\x7e]{5,250})",
    re.IGNORECASE,
)

_SCRIPT_PATTERN_ASCII = re.compile(
    rb"ScriptText"
    rb"[\x00-\x20]{1,20}"
    rb"([\x20-\x7e]{5,500})",
    re.IGNORECASE,
)

_PATTERNS: tuple[tuple[re.Pattern[bytes], str, str, int], ...] = (
    (_CMDLINE_PATTERN, "utf-16-le", "CommandLineEventConsumer", 0),
    (_SCRIPT_PATTERN, "utf-16-le", "ActiveScriptEventConsumer", 200),
    (_CMDLINE_PATTERN_ASCII, "ascii", "CommandLineEventConsumer", 0),
    (_SCRIPT_PATTERN_ASCII, "ascii", "ActiveScriptEventConsumer", 200),
)


@register_plugin
class WmiEventSubscription(PersistencePlugin):
    definition = CheckDefinition(
        id="wmi_event_subscription",
        technique="WMI Event Subscription",
        mitre_id="T1546.003",
        description=(
            "WMI permanent event subscriptions (CommandLineEventConsumer, "
            "ActiveScriptEventConsumer) execute commands or scripts in "
            "response to system events. These persist in the CIM repository "
            "and survive reboots."
        ),
        references=("https://attack.mitre.org/techniques/T1546/003/",),
    )

    def run(self) -> list[Finding]:
        """Search OBJECTS.DATA for WMI event consumer command and script patterns."""
        findings: list[Finding] = []

        for cim_rel in _CIM_PATHS:
            cim_path = self.filesystem.image_root / cim_rel
            if not cim_path.is_file():
                continue

            try:
                data = cim_path.read_bytes()
            except Exception:
                logger.debug(
                    "Failed to read WMI repository: %s",
                    cim_path,
                    exc_info=True,
                )
                continue

            for pattern, encoding, consumer_type, truncate in _PATTERNS:
                findings.extend(
                    self._scan_pattern(
                        data, pattern, encoding, consumer_type, truncate, cim_rel
                    )
                )

        return findings

    def _scan_pattern(
        self,
        data: bytes,
        pattern: re.Pattern[bytes],
        encoding: str,
        consumer_type: str,
        truncate: int,
        cim_rel: _Path,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for match in pattern.finditer(data):
            try:
                text = match.group(1).decode(encoding, errors="replace")
                if encoding == "utf-16-le":
                    text = text.rstrip("\x00")
                text = text.strip()
            except Exception:
                logger.debug("Failed to decode WMI data: %s", cim_rel, exc_info=True)
                continue
            if text:
                if truncate and len(text) > truncate:
                    display = text[:truncate] + "..."
                else:
                    display = text
                findings.append(
                    self._make_finding(
                        path=str(PureWindowsPath(cim_rel)),
                        value=f"{consumer_type}: {display}",
                        access=AccessLevel.SYSTEM,
                    )
                )
        return findings
