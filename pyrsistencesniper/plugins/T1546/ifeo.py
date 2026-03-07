from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.models.finding import AccessLevel
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import CheckDefinition, PersistencePlugin

if TYPE_CHECKING:
    from pyrsistencesniper.models.finding import Finding

_IFEO_PATH = r"Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
_SPE_PATH = r"Microsoft\Windows NT\CurrentVersion\SilentProcessExit"


class _IfeoMixin:
    """Mixin providing IFEO subkey enumeration for debugger-style persistence checks."""

    def _scan_ifeo(self: PersistencePlugin, value_name: str) -> list[Finding]:  # type: ignore[misc]  # mixin
        """Return findings for any IFEO subkey containing the given value name."""
        findings: list[Finding] = []

        tree = self._load_subtree("SOFTWARE", _IFEO_PATH)
        if tree is None:
            return findings

        for subkey_name, node in tree.children():
            value_str = self._to_str(node.get(value_name))
            if value_str is None:
                continue

            findings.append(
                self._make_finding(
                    path=f"HKLM\\SOFTWARE\\{_IFEO_PATH}\\{subkey_name}\\{value_name}",
                    value=value_str,
                    access=AccessLevel.SYSTEM,
                )
            )

        return findings


@register_plugin
class IfeoDebugger(_IfeoMixin, PersistencePlugin):
    definition = CheckDefinition(
        id="ifeo_debugger",
        technique="Image File Execution Options Debugger",
        mitre_id="T1546.012",
        description=(
            "An IFEO Debugger value causes Windows to launch the specified "
            "debugger instead of the target executable. Attackers set this "
            "to redirect execution of common tools to malicious binaries."
        ),
        references=("https://attack.mitre.org/techniques/T1546/012/",),
    )

    def run(self) -> list[Finding]:
        return self._scan_ifeo("Debugger")


@register_plugin
class IfeoSilentProcessExit(_IfeoMixin, PersistencePlugin):
    definition = CheckDefinition(
        id="ifeo_silent_process_exit",
        technique="Silent Process Exit Monitor",
        mitre_id="T1546.012",
        description=(
            "SilentProcessExit MonitorProcess is invoked when a target "
            "process terminates. Configuring this triggers attacker code "
            "execution on process exit, providing event-driven persistence."
        ),
        references=("https://attack.mitre.org/techniques/T1546/012/",),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        tree = self._load_subtree("SOFTWARE", _SPE_PATH)
        if tree is None:
            return findings

        for subkey_name, node in tree.children():
            value_str = self._to_str(node.get("MonitorProcess"))
            if value_str is None:
                continue

            findings.append(
                self._make_finding(
                    path=f"HKLM\\SOFTWARE\\{_SPE_PATH}\\{subkey_name}\\MonitorProcess",
                    value=value_str,
                    access=AccessLevel.SYSTEM,
                )
            )

        return findings


@register_plugin
class IfeoDelegatedNtdll(_IfeoMixin, PersistencePlugin):
    definition = CheckDefinition(
        id="ifeo_delegated_ntdll",
        technique="IFEO Delegated NTDLL",
        mitre_id="T1546.012",
        description=(
            "VerifierDlls under IFEO with GlobalFlag 0x100 (Application "
            "Verifier) causes a custom DLL to be loaded into the target "
            "process at startup, providing reliable DLL injection persistence."
        ),
        references=("https://attack.mitre.org/techniques/T1546/012/",),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        tree = self._load_subtree("SOFTWARE", _IFEO_PATH)
        if tree is None:
            return findings
        for subkey_name, node in tree.children():
            value_str = self._to_str(node.get("VerifierDlls"))
            if value_str is None:
                continue
            global_flag = node.get("GlobalFlag")
            if not isinstance(global_flag, int) or not (global_flag & 0x100):
                continue
            findings.append(
                self._make_finding(
                    path=f"HKLM\\SOFTWARE\\{_IFEO_PATH}\\{subkey_name}\\VerifierDlls",
                    value=value_str,
                    access=AccessLevel.SYSTEM,
                )
            )
        return findings
