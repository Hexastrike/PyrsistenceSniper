"""Detection for Accessibility Features Backdoor."""

from __future__ import annotations

import logging
from pathlib import Path

import lief

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
)
from pyrsistencesniper.core.signer import SignerExtractor
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

logger = logging.getLogger(__name__)

# Each lock-screen accessibility binary, mapped to the OriginalFilename values
# Microsoft ships it under. Several tools carry an internal name that differs
# from their file name (utilman2.exe, ScreenMagnifier.exe, SR.exe), so the file
# name alone is not the identity a replacement has to be compared against.
_ACCESSIBILITY_TOOLS: dict[str, frozenset[str]] = {
    r"Windows\System32\sethc.exe": frozenset({"sethc.exe"}),
    r"Windows\System32\osk.exe": frozenset({"osk.exe"}),
    r"Windows\System32\Narrator.exe": frozenset({"narrator.exe", "sr.exe"}),
    r"Windows\System32\Magnify.exe": frozenset({"magnify.exe", "screenmagnifier.exe"}),
    r"Windows\System32\utilman.exe": frozenset({"utilman.exe", "utilman2.exe"}),
    r"Windows\System32\AtBroker.exe": frozenset({"atbroker.exe"}),
    r"Windows\System32\DisplaySwitch.exe": frozenset({"displayswitch.exe"}),
}

# Binaries Windows signs through the catalog store rather than with an embedded
# Authenticode signature, which is how the accessibility tools are signed too. A
# reference carrying an embedded signature (kernel32.dll) resolves even when the
# collection omitted CatRoot, so it would prove nothing about the lookup these
# tools depend on.
_SIGNATURE_REFERENCES: tuple[str, ...] = (
    r"Windows\System32\winlogon.exe",
    r"Windows\System32\cmd.exe",
    r"Windows\System32\notepad.exe",
)

_MICROSOFT_SIGNER_PREFIX = "microsoft"
_ORIGINAL_FILENAME_KEY = "originalfilename"


def _is_microsoft_signed(signer: str) -> bool:
    """Report whether an Authenticode signer name is one of Microsoft's."""
    return signer.strip().casefold().startswith(_MICROSOFT_SIGNER_PREFIX)


def _original_filename(host_path: Path) -> str:
    """Return the OriginalFilename a PE records in its version resource."""
    try:
        binary = lief.PE.parse(str(host_path))
        if binary is None:
            return ""
        manager = binary.resources_manager
        if not isinstance(manager, lief.PE.ResourcesManager):
            return ""
        for version in manager.version:
            string_file_info = version.string_file_info
            if string_file_info is None:
                continue
            for string_table in string_file_info.children:
                for entry in string_table.entries:
                    if entry.key.casefold() == _ORIGINAL_FILENAME_KEY:
                        return entry.value.strip()
    except Exception:
        logger.debug("Version resource unreadable: %s", host_path, exc_info=True)
    return ""


@register_plugin
class AccessibilityTools(PersistencePlugin):
    """Detects Accessibility Features Backdoor persistence entries."""

    definition = CheckDefinition(
        id="accessibility_tools",
        technique="Accessibility Features Backdoor",
        mitre_id="T1546.008",
        description=(
            "Accessibility tools such as sethc.exe, osk.exe and utilman.exe run at the "
            "lock screen before authentication, as SYSTEM. A binary that is not the "
            "Microsoft-signed original, or that is signed but identifies itself as a "
            "different program, has been replaced."
        ),
    )

    def run(self) -> list[Finding]:
        """Report accessibility binaries that are not the originals Microsoft ships."""
        findings: list[Finding] = []
        collected_tools = {
            tool_path: original_names
            for tool_path, original_names in _ACCESSIBILITY_TOOLS.items()
            if self.filesystem.exists(tool_path)
        }
        if not collected_tools:
            return findings

        signer_extractor = SignerExtractor(self.filesystem)
        if not self._signatures_are_provable(signer_extractor):
            logger.debug(
                "No catalog signature resolves on this image, so a replaced "
                "accessibility binary cannot be told apart from a collection "
                "that carries no signature data"
            )
            return findings

        for tool_path, original_names in collected_tools.items():
            evidence = self._replacement_evidence(
                tool_path, original_names, signer_extractor
            )
            if evidence:
                findings.append(
                    self._make_finding(
                        path=tool_path,
                        value=evidence,
                        access=AccessLevel.SYSTEM,
                        resolve_target=tool_path,
                    )
                )

        return findings

    def _signatures_are_provable(self, signer_extractor: SignerExtractor) -> bool:
        """Report whether catalog signatures resolve at all on this image."""
        # Without the catalog store every accessibility binary resolves to no
        # signer, so all seven would be reported on any collection that omitted
        # it. Losing the check there costs less than seven false positives.
        return any(
            _is_microsoft_signed(signer_extractor.extract(reference))
            for reference in _SIGNATURE_REFERENCES
        )

    def _replacement_evidence(
        self,
        tool_path: str,
        original_names: frozenset[str],
        signer_extractor: SignerExtractor,
    ) -> str:
        """Describe why a binary is not the original, or empty when it is."""
        signer = signer_extractor.extract(tool_path)
        if not _is_microsoft_signed(signer):
            return f"Not the Microsoft-signed original (signer: {signer or 'none'})"

        original_name = _original_filename(self.filesystem.resolve(tool_path))
        if original_name and original_name.casefold() not in original_names:
            return (
                "Microsoft-signed binary planted under another name "
                f"(original filename: {original_name})"
            )
        return ""
