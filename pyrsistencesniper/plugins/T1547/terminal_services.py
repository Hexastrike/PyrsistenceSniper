"""Detections for the Terminal Services and RDP autostart registrations."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
    HiveScope,
    RegistryTarget,
)
from pyrsistencesniper.core.registry import (
    commands_below,
    stores_commands_in_sections,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin


def _decoded_addin_value(raw_value: object) -> str:
    """Return an AddIns value as text; pyregf hands these back as UTF-16 bytes."""
    if isinstance(raw_value, bytes):
        text = raw_value.strip(b"\x00").decode("utf-16-le", errors="replace")
        return text.strip("\x00")
    return str(raw_value)


@register_plugin
class TsInitialProgram(PersistencePlugin):
    """Detects Terminal Services Initial Program persistence entries."""

    definition = CheckDefinition(
        id="ts_initial_program",
        technique="Terminal Services Initial Program",
        mitre_id="T1547.001",
        description=(
            "The Terminal Services InitialProgram value replaces the default shell for "
            "every incoming RDP session. The Terminal Server Install key holds a "
            "shadow copy of the Run, RunOnce and RunOnceEx keys."
        ),
        references=("https://attack.mitre.org/techniques/T1547/001/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
                values="InitialProgram",
                scope=HiveScope.HKLM,
            ),
            RegistryTarget(
                path=(
                    r"SOFTWARE\Microsoft\Windows NT"
                    r"\CurrentVersion\Terminal Server\Install"
                    r"\Software\Microsoft\Windows"
                    r"\CurrentVersion\Run"
                ),
                scope=HiveScope.HKLM,
            ),
            RegistryTarget(
                path=(
                    r"SOFTWARE\Microsoft\Windows NT"
                    r"\CurrentVersion\Terminal Server\Install"
                    r"\Software\Microsoft\Windows"
                    r"\CurrentVersion\Runonce"
                ),
                scope=HiveScope.HKLM,
            ),
            RegistryTarget(
                path=(
                    r"SOFTWARE\Microsoft\Windows NT"
                    r"\CurrentVersion\Terminal Server\Install"
                    r"\Software\Microsoft\Windows"
                    r"\CurrentVersion\RunOnceEx"
                ),
                scope=HiveScope.HKLM,
            ),
        ),
    )

    def run(self) -> list[Finding]:
        """Read the flat values, then descend the RunOnceEx section subkeys."""
        findings = super().run()
        for target in self.definition.targets:
            if stores_commands_in_sections(target.path):
                findings.extend(self._section_findings(target))
        return findings

    def _section_findings(self, target: RegistryTarget) -> list[Finding]:
        """Collect the commands stored below one machine key's section subkeys."""
        hive_name, _, key_path = target.path.partition("\\")
        return [
            self._make_finding(path=path, value=command, access=AccessLevel.SYSTEM)
            for path, command in commands_below(
                self.context.load_subtree(hive_name, key_path),
                f"HKLM\\{target.path}",
            )
        ]


@register_plugin
class RdpWdsStartupPrograms(PersistencePlugin):
    """Detects RDP WDS Startup Programs persistence entries."""

    definition = CheckDefinition(
        id="rdp_wds_startup",
        technique="RDP WDS Startup Programs",
        mitre_id="T1547.001",
        description=(
            "The WDS StartupPrograms value lists programs started in every RDP "
            "session. The default is 'rdpclip'."
        ),
        references=("https://attack.mitre.org/techniques/T1547/001/",),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Control\Terminal Server\Wds\rdpwd",
                values="StartupPrograms",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class RdpClxDll(PersistencePlugin):
    """Detects RDP Client Extension DLL persistence entries."""

    definition = CheckDefinition(
        id="rdp_clx_dll",
        technique="RDP Client Extension DLL",
        mitre_id="T1547.001",
        description=(
            "The ClxDllPath value under Terminal Server "
            "DefaultUserConfiguration specifies a DLL loaded during RDP "
            "connection initialization."
        ),
        references=("https://attack.mitre.org/techniques/T1547/001/",),
        targets=(
            RegistryTarget(
                path=(
                    r"SYSTEM\{controlset}\Control"
                    r"\Terminal Server"
                    r"\DefaultUserConfiguration"
                ),
                values="ClxDllPath",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class RdpVirtualChannel(PersistencePlugin):
    """Detects RDP Virtual Channel DLL persistence entries."""

    definition = CheckDefinition(
        id="rdp_virtual_channel",
        technique="RDP Virtual Channel DLL",
        mitre_id="T1547.001",
        description=(
            "RDP virtual channel add-in DLLs are loaded by the Remote Desktop client "
            "during a session."
        ),
        references=("https://attack.mitre.org/techniques/T1547/001/",),
    )

    def run(self) -> list[Finding]:
        """Report every add-in DLL registered for the RDP client's virtual channels."""
        findings: list[Finding] = []
        addins_path = r"Microsoft\Terminal Server Client\Default\AddIns"
        tree = self.context.load_subtree("SOFTWARE", addins_path)
        if tree is None:
            return findings
        for subkey_name, node in tree.children():
            for value_name, raw_value in node.values():
                addin_dll = _decoded_addin_value(raw_value)
                if not addin_dll.strip():
                    continue
                findings.append(
                    self._make_finding(
                        path=(
                            f"HKLM\\SOFTWARE\\{addins_path}"
                            f"\\{subkey_name}\\{value_name}"
                        ),
                        value=addin_dll,
                        access=AccessLevel.SYSTEM,
                    )
                )
        return findings
