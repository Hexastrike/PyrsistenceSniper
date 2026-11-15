"""Detections for registry keys that name a DLL the Windows loader will load."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
    HiveScope,
    RegistryTarget,
)
from pyrsistencesniper.core.registry import registry_value_to_str
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin


@register_plugin
class NaturalLanguageDevelopmentPlatform(PersistencePlugin):
    """Detects NLDP DLL Override persistence entries."""

    definition = CheckDefinition(
        id="nldp_dll",
        technique="NLDP DLL Override",
        mitre_id="T1574.001",
        description=(
            "The NlsData DllOverridePath value names a custom DLL the natural language "
            "processing subsystem loads."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NlsData",
                values="DllOverridePath",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class ChmHelper(PersistencePlugin):
    """Detects CHM Helper DLL persistence entries."""

    definition = CheckDefinition(
        id="chm_helper_dll",
        technique="CHM Helper DLL",
        mitre_id="T1574.001",
        description=(
            "The HtmlHelp Author Location value names a DLL loaded when a compiled "
            "HTML help (.chm) file is opened."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\HtmlHelp Author",
                values="Location",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class HhctrlOcx(PersistencePlugin):
    """Detects hhctrl.ocx DLL Override persistence entries."""

    definition = CheckDefinition(
        id="hhctrl_ocx_dll",
        technique="hhctrl.ocx DLL Override",
        mitre_id="T1574.001",
        description=(
            "The InprocServer32 of the hhctrl.ocx CLSID names the DLL loaded whenever "
            "HTML Help content is rendered."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        targets=(
            RegistryTarget(
                path=(
                    r"SOFTWARE\Classes\CLSID"
                    r"\{adb880a6-d8ff-11cf-9377-00aa003b7a11}\InprocServer32"
                ),
                values="(Default)",
                scope=HiveScope.BOTH,
                include_wow64=True,
            ),
        ),
    )


@register_plugin
class AutodialDll(PersistencePlugin):
    """Detects AutodialDLL Override persistence entries."""

    definition = CheckDefinition(
        id="autodial_dll",
        technique="AutodialDLL Override",
        mitre_id="T1574.001",
        description=(
            "The AutodialDLL value names a DLL the WinSock auto-dial feature loads "
            "into any process that uses WinSock."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Services\WinSock2\Parameters",
                values="AutodialDLL",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class LsaExtensions(PersistencePlugin):
    """Detects LSA Extensions DLL persistence entries."""

    definition = CheckDefinition(
        id="lsa_extensions",
        technique="LSA Extensions DLL",
        mitre_id="T1574.001",
        description=(
            "LSA Extensions are DLLs the Local Security Authority loads into lsass.exe "
            "during system startup."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Control\LsaExtensionConfig\LsaSrv",
                values="Extensions",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class ServerLevelPluginDll(PersistencePlugin):
    """Detects DNS Server Level Plugin DLL persistence entries."""

    definition = CheckDefinition(
        id="server_level_plugin_dll",
        technique="DNS Server Level Plugin DLL",
        mitre_id="T1574.001",
        description=(
            "The DNS Server ServerLevelPluginDll value names a DLL the DNS service "
            "loads at startup, as SYSTEM, typically on a domain controller."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Services\DNS\Parameters",
                values="ServerLevelPluginDll",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class CryptoExpoOffload(PersistencePlugin):
    """Detects Crypto ExpoOffload DLL persistence entries."""

    definition = CheckDefinition(
        id="crypto_expo_offload",
        technique="Crypto ExpoOffload DLL",
        mitre_id="T1574.001",
        description=(
            "The ExpoOffload value names a DLL the cryptography subsystem loads for "
            "exponentiation offloading."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Cryptography\Offload",
                values="ExpoOffload",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class Direct3dDll(PersistencePlugin):
    """Detects Direct3D Software Rasterizer DLL persistence entries."""

    definition = CheckDefinition(
        id="direct3d_dll",
        technique="Direct3D Software Rasterizer DLL",
        mitre_id="T1574.001",
        description=(
            "The Direct3D SoftwareRasterizer value names the DLL loaded as the "
            "software rasterizer by any process that initializes Direct3D."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Direct3D\Drivers",
                values="SoftwareRasterizer",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class MsdtcXaDll(PersistencePlugin):
    """Detects MSDTC XA DLL persistence entries."""

    definition = CheckDefinition(
        id="msdtc_xa_dll",
        technique="MSDTC XA DLL",
        mitre_id="T1574.001",
        description=(
            "The OracleXaLib and OracleOciLib values name the XA DLLs the Distributed "
            "Transaction Coordinator loads into the MSDTC service, which runs as "
            "Network Service by default."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\MSDTC\MTxOCI",
                values="OracleXaLib",
                scope=HiveScope.HKLM,
            ),
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\MSDTC\MTxOCI",
                values="OracleOciLib",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class DiagTrackDll(PersistencePlugin):
    """Detects DiagTrack Service ImagePath persistence entries."""

    definition = CheckDefinition(
        id="diagtrack_dll",
        technique="DiagTrack Service ImagePath",
        mitre_id="T1574.001",
        description=(
            "The DiagTrack service ImagePath names the binary the service control "
            "manager starts for the telemetry service, as SYSTEM."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Services\DiagTrack",
                values="ImagePath",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class DiagTrackListenerDll(PersistencePlugin):
    """Detects DiagTrack Listener DLL persistence entries."""

    definition = CheckDefinition(
        id="diagtrack_listener_dll",
        technique="DiagTrack Listener DLL",
        mitre_id="T1574.001",
        description=(
            "The DiagTrack-Listener Autologger FileName value names the DLL loaded for "
            "telemetry collection at boot, as SYSTEM."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Control\WMI\Autologger\DiagTrack-Listener",
                values="FileName",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class RdpTestDvcPlugin(PersistencePlugin):
    """Detects RDP TestDVCPlugin DLL persistence entries."""

    definition = CheckDefinition(
        id="rdp_test_dvc_plugin",
        technique="RDP TestDVCPlugin DLL",
        mitre_id="T1574.001",
        description=(
            "The TestDVCPlugin value names a DLL the RDP client loads for Dynamic "
            "Virtual Channel testing."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Terminal Server Client",
                values="TestDVCPlugin",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class SearchIndexerDll(PersistencePlugin):
    """Detects Search Indexer DLL Override persistence entries."""

    definition = CheckDefinition(
        id="search_indexer_dll",
        technique="Search Indexer DLL Override",
        mitre_id="T1574.001",
        description=(
            "The Windows Search DllPath value names a DLL the search indexer loads "
            "during indexing, as SYSTEM."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Windows Search",
                values="DllPath",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class WuServiceStartupDll(PersistencePlugin):
    """Detects Windows Update Service Startup DLL persistence entries."""

    definition = CheckDefinition(
        id="wu_service_startup_dll",
        technique="Windows Update Service Startup DLL",
        mitre_id="T1574.001",
        description=(
            "The Windows Update ServiceDll value names the DLL the wuauserv service "
            "loads when it starts, as SYSTEM."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Services\wuauserv\Parameters",
                values="ServiceDll",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class KnownManagedDebuggingDlls(PersistencePlugin):
    """Detects Known Managed Debugging DLLs persistence entries."""

    definition = CheckDefinition(
        id="known_managed_debugging_dlls",
        technique="Known Managed Debugging DLLs",
        mitre_id="T1574.001",
        description=(
            "KnownManagedDebuggingDlls lists DLLs loaded whenever .NET managed "
            "debugging is started."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\.NETFramework",
                values="KnownManagedDebuggingDlls",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class MiniDumpAuxiliaryDlls(PersistencePlugin):
    """Detects MiniDump Auxiliary DLLs persistence entries."""

    definition = CheckDefinition(
        id="minidump_auxiliary_dlls",
        technique="MiniDump Auxiliary DLLs",
        mitre_id="T1574.001",
        description=(
            "MiniDumpAuxiliaryDlls entries name a trigger module and the "
            "auxiliary DLL dbghelp loads into the dumping process when that "
            "module is present. The auxiliary DLL runs during every crash "
            "dump, so registering one here provides code execution."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
    )

    def run(self) -> list[Finding]:
        """Report the auxiliary DLL each MiniDumpAuxiliaryDlls entry loads."""
        findings: list[Finding] = []

        key_path = r"Microsoft\Windows NT\CurrentVersion\MiniDumpAuxiliaryDlls"
        tree = self.context.load_subtree("SOFTWARE", key_path)
        if tree is None:
            return findings

        for trigger_module, auxiliary_dll in tree.values():
            if not trigger_module.strip():
                continue
            auxiliary_dll_path = registry_value_to_str(auxiliary_dll)
            if auxiliary_dll_path is None:
                continue
            findings.append(
                self._make_finding(
                    path=f"HKLM\\SOFTWARE\\{key_path}\\{trigger_module}",
                    value=auxiliary_dll_path,
                    access=AccessLevel.SYSTEM,
                    description=(
                        f"{self.definition.description} "
                        f"(trigger module: {trigger_module})"
                    ),
                )
            )

        return findings


@register_plugin
class Mapi32DllPath(PersistencePlugin):
    """Detects MAPI32 DLL Path Override persistence entries."""

    definition = CheckDefinition(
        id="mapi32_dll_path",
        technique="MAPI32 DLL Path Override",
        mitre_id="T1574.001",
        description=(
            "Every mail client registers its MAPI provider in a subkey of "
            "Clients\\Mail, where DLLPathEx (or the legacy DLLPath) names the DLL "
            "loaded by every process that initializes MAPI, such as Outlook or any "
            "application that sends mail."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Clients\Mail",
                values="DLLPathEx",
                scope=HiveScope.HKLM,
                recurse=True,
                include_wow64=True,
            ),
            RegistryTarget(
                path=r"SOFTWARE\Clients\Mail",
                values="DLLPath",
                scope=HiveScope.HKLM,
                recurse=True,
                include_wow64=True,
            ),
        ),
    )


@register_plugin
class GpExtensionDlls(PersistencePlugin):
    """Detects Group Policy Extension DLLs persistence entries."""

    definition = CheckDefinition(
        id="gp_extension_dlls",
        technique="Group Policy Extension DLLs",
        mitre_id="T1574.001",
        description=(
            "Group Policy extension DLLs are loaded by the Group Policy engine at "
            "every policy refresh, as SYSTEM."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        targets=(
            RegistryTarget(
                path=(
                    r"SOFTWARE\Microsoft\Windows NT"
                    r"\CurrentVersion\Winlogon\GPExtensions"
                ),
                values="DllName",
                scope=HiveScope.HKLM,
                recurse=True,
            ),
        ),
    )


@register_plugin
class WinsockAutoProxy(PersistencePlugin):
    """Detects Winsock AutoProxy DLL persistence entries."""

    definition = CheckDefinition(
        id="winsock_auto_proxy",
        technique="Winsock AutoProxy DLL",
        mitre_id="T1574.001",
        description=(
            "Winsock NameSpace_Catalog5 provider DLLs, in the 32-bit and the 64-bit "
            "catalog, are loaded for name resolution into any process that uses the "
            "network."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        targets=(
            RegistryTarget(
                path=(
                    r"SYSTEM\{controlset}\Services\WinSock2\Parameters"
                    r"\NameSpace_Catalog5\Catalog_Entries"
                ),
                values="LibraryPath",
                scope=HiveScope.HKLM,
                recurse=True,
            ),
            RegistryTarget(
                path=(
                    r"SYSTEM\{controlset}\Services\WinSock2\Parameters"
                    r"\NameSpace_Catalog5\Catalog_Entries64"
                ),
                values="LibraryPath",
                scope=HiveScope.HKLM,
                recurse=True,
            ),
        ),
    )
