from __future__ import annotations

from pyrsistencesniper.models.finding import AccessLevel, FilterRule, Finding
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import (
    CheckDefinition,
    HiveScope,
    PersistencePlugin,
    RegistryTarget,
)


@register_plugin
class TsInitialProgram(PersistencePlugin):
    definition = CheckDefinition(
        id="ts_initial_program",
        technique="Terminal Services Initial Program",
        mitre_id="T1547.001",
        description=(
            "The Terminal Services InitialProgram value replaces the "
            "default shell for RDP sessions. Setting it to a malicious "
            "binary provides persistence for all incoming RDP connections."
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


@register_plugin
class RdpWdsStartupPrograms(PersistencePlugin):
    definition = CheckDefinition(
        id="rdp_wds_startup",
        technique="RDP WDS Startup Programs",
        mitre_id="T1547.001",
        description=(
            "The WDS StartupPrograms value specifies programs launched in "
            "RDP sessions. The default is 'rdpclip'; any other value "
            "warrants investigation."
        ),
        references=("https://attack.mitre.org/techniques/T1547/001/",),
        allow=(
            FilterRule(
                reason="Default RDP startup program", value_matches=r"^rdpclip$"
            ),
        ),
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
    definition = CheckDefinition(
        id="rdp_virtual_channel",
        technique="RDP Virtual Channel DLL",
        mitre_id="T1547.001",
        description=(
            "RDP Virtual Channel add-in DLLs are loaded during RDP "
            "sessions, providing DLL-based persistence for remote "
            "connections."
        ),
        references=("https://attack.mitre.org/techniques/T1547/001/",),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        addins_path = r"Microsoft\Terminal Server Client\Default\AddIns"
        tree = self._load_subtree("SOFTWARE", addins_path)
        if tree is None:
            return findings
        for subkey_name, node in tree.children():
            for val_name, val in node.values():
                if not val or (isinstance(val, str) and not val.strip()):
                    continue
                findings.append(
                    self._make_finding(
                        path=f"HKLM\\SOFTWARE\\{addins_path}\\{subkey_name}\\{val_name}",
                        value=str(val),
                        access=AccessLevel.SYSTEM,
                    )
                )
        return findings
