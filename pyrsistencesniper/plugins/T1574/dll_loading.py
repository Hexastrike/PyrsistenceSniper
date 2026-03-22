"""T1574 DLL hijacking persistence plugins.

Detects DLL search-order hijacking and side-loading via registry keys that
specify loadable DLL paths.  Covers 16 declarative checks for known DLL
override locations and 3 custom-scan plugins that walk subtrees for
GP extensions, Winsock providers, and minidump auxiliary DLLs.
"""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    FilterRule,
    Finding,
    HiveScope,
    RegistryTarget,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin


@register_plugin
class NaturalLanguageDevelopmentPlatform(PersistencePlugin):
    definition = CheckDefinition(
        id="nldp_dll",
        technique="NLDP DLL Override",
        mitre_id="T1574.001",
        description=(
            "The NlsData DllOverridePath specifies a custom DLL loaded by "
            "the Natural Language Processing subsystem. Any value present "
            "indicates DLL hijacking persistence."
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
    definition = CheckDefinition(
        id="chm_helper_dll",
        technique="CHM Helper DLL",
        mitre_id="T1574.001",
        description=(
            "The CHM helper DLL Location value specifies a DLL loaded when "
            "rendering compiled HTML help files. Hijacking this provides "
            "code execution when .chm files are opened."
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
    definition = CheckDefinition(
        id="hhctrl_ocx_dll",
        technique="hhctrl.ocx DLL Override",
        mitre_id="T1574.001",
        description=(
            "The hhctrl.ocx CLSID InprocServer32 points to the DLL loaded "
            "for HTML Help controls. Hijacking this COM registration "
            "provides code execution when any HTML Help content is rendered."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        allow=(
            FilterRule(
                reason="Default HTML Help control",
                value_matches=r"hhctrl\.ocx$",
                signer="Microsoft",
            ),
        ),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Classes\CLSID\{adb880a6-d8ff-11cf-9377-00aa003b7a11}\InprocServer32",
                values="(Default)",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class AutodialDll(PersistencePlugin):
    definition = CheckDefinition(
        id="autodial_dll",
        technique="AutodialDLL Override",
        mitre_id="T1574.001",
        description=(
            "The AutodialDLL value specifies a DLL loaded by the WinSock "
            "auto-dial feature. A non-OS DLL provides persistent code "
            "execution in any process that uses WinSock."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        allow=(
            FilterRule(
                reason="Default autodial DLL",
                value_matches=r"rasadhlp\.dll$",
                signer="Microsoft",
            ),
        ),
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
    definition = CheckDefinition(
        id="lsa_extensions",
        technique="LSA Extensions DLL",
        mitre_id="T1574.001",
        description=(
            "LSA Extensions are DLLs loaded by the Local Security Authority "
            "during system startup. A malicious extension can intercept "
            "credentials and provide SYSTEM-level persistence."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        allow=(
            FilterRule(
                reason="Default LSA extension",
                value_matches=r"^lsasrv\.dll$",
                signer="Microsoft",
            ),
        ),
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
    definition = CheckDefinition(
        id="server_level_plugin_dll",
        technique="DNS Server Level Plugin DLL",
        mitre_id="T1574.001",
        description=(
            "The DNS Server ServerLevelPluginDll value specifies a DLL "
            "loaded by the DNS service at startup. Abuse provides "
            "SYSTEM-level persistence on domain controllers."
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
    definition = CheckDefinition(
        id="crypto_expo_offload",
        technique="Crypto ExpoOffload DLL",
        mitre_id="T1574.001",
        description=(
            "The ExpoOffload value specifies a DLL loaded by the "
            "cryptography subsystem for exponentiation offloading. Any "
            "value present indicates potential DLL hijacking persistence."
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
    definition = CheckDefinition(
        id="direct3d_dll",
        technique="Direct3D Software Rasterizer DLL",
        mitre_id="T1574.001",
        description=(
            "The D3D SoftwareRasterizer value specifies the DLL loaded as "
            "the Direct3D software rasterizer. Hijacking provides code "
            "execution in any process that initializes Direct3D."
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
    definition = CheckDefinition(
        id="msdtc_xa_dll",
        technique="MSDTC XA DLL",
        mitre_id="T1574.001",
        description=(
            "MSDTC XA DLLs (OracleXaLib, OracleOciLib) are loaded by the "
            "Distributed Transaction Coordinator. A malicious DLL executes "
            "in the SYSTEM context of the MSDTC service."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        allow=(
            FilterRule(
                reason="Default MSDTC XA/OCI DLL", value_matches=r"^(xa80|oci)\.dll$"
            ),
        ),
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
    definition = CheckDefinition(
        id="diagtrack_dll",
        technique="DiagTrack DLL",
        mitre_id="T1574.001",
        description=(
            "The DiagTrack service ImagePath specifies the service binary. "
            "Replacing it with a non-OS executable provides SYSTEM-level "
            "persistence triggered by the telemetry service."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        allow=(
            FilterRule(
                reason="Default DiagTrack service",
                value_matches=r"svchost\.exe",
                signer="Microsoft",
            ),
        ),
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
    definition = CheckDefinition(
        id="diagtrack_listener_dll",
        technique="DiagTrack Listener DLL",
        mitre_id="T1574.001",
        description=(
            "The DiagTrack Autologger listener FileName specifies the DLL "
            "loaded for telemetry collection. Hijacking this value provides "
            "SYSTEM-level persistence at boot."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        allow=(
            FilterRule(
                reason="Default DiagTrack listener",
                value_matches=r"Diagtrack-Listener\.etl",
                signer="Microsoft",
            ),
        ),
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
    definition = CheckDefinition(
        id="rdp_test_dvc_plugin",
        technique="RDP TestDVCPlugin DLL",
        mitre_id="T1574.001",
        description=(
            "The TestDVCPlugin value specifies a DLL loaded by the RDP "
            "client for Dynamic Virtual Channel testing. Any value present "
            "indicates potential DLL-based persistence via RDP sessions."
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
    definition = CheckDefinition(
        id="search_indexer_dll",
        technique="Search Indexer DLL Override",
        mitre_id="T1574.001",
        description=(
            "The Windows Search Indexer DllPath value can be overridden to "
            "load a malicious DLL during indexing operations, providing "
            "SYSTEM-level persistence."
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
    definition = CheckDefinition(
        id="wu_service_startup_dll",
        technique="Windows Update Service Startup DLL",
        mitre_id="T1574.001",
        description=(
            "The Windows Update ServiceDll value specifies the DLL loaded "
            "by the wuauserv service. A non-OS DLL provides SYSTEM-level "
            "persistence triggered by Windows Update operations."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        allow=(
            FilterRule(
                reason="Default Windows Update DLL",
                value_matches=r"wuaueng\.dll$",
                signer="Microsoft",
            ),
        ),
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
    definition = CheckDefinition(
        id="known_managed_debugging_dlls",
        technique="Known Managed Debugging DLLs",
        mitre_id="T1574.001",
        description=(
            "KnownManagedDebuggingDlls specifies DLLs loaded by .NET "
            "managed debuggers. Registering a malicious DLL provides "
            "code execution whenever managed debugging is initiated."
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
    definition = CheckDefinition(
        id="minidump_auxiliary_dlls",
        technique="MiniDump Auxiliary DLLs",
        mitre_id="T1574.001",
        description=(
            "MiniDumpAuxiliaryDlls are loaded during crash dump generation. "
            "Registering a DLL here provides code execution whenever a "
            "process crash dump is created."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        allow=(
            FilterRule(
                reason="Default minidump auxiliary DLL",
                value_matches=r"(clr|mscorwks|Chakra|jscript9|mrt100)\.dll$",
                signer="Microsoft",
            ),
        ),
    )

    def run(self) -> list[Finding]:
        """Report DLL paths registered as value names under MiniDumpAuxiliaryDlls."""
        findings: list[Finding] = []

        key_path = (
            r"Microsoft\Windows NT"
            r"\CurrentVersion\MiniDumpAuxiliaryDlls"
        )
        tree = self.hive_ops.load_subtree("SOFTWARE", key_path)
        if tree is None:
            return findings

        for name, _val in tree.values():
            if not name.strip():
                continue
            findings.append(
                self._make_finding(
                    path=f"HKLM\\SOFTWARE\\{key_path}\\{name}",
                    value=name,
                    access=AccessLevel.SYSTEM,
                )
            )

        return findings


@register_plugin
class Mapi32DllPath(PersistencePlugin):
    definition = CheckDefinition(
        id="mapi32_dll_path",
        technique="MAPI32 DLL Path Override",
        mitre_id="T1574.001",
        description=(
            "The MAPI32 DLLPath value specifies the DLL loaded by the "
            "Messaging API. Hijacking this provides code execution in any "
            "process that uses MAPI for email operations."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Clients\Mail",
                values="DLLPath",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class GpExtensionDlls(PersistencePlugin):
    definition = CheckDefinition(
        id="gp_extension_dlls",
        technique="Group Policy Extension DLLs",
        mitre_id="T1574.001",
        description=(
            "Group Policy Extension DLLs are loaded by the GP engine "
            "during policy refresh. A non-OS DLL registered here provides "
            "SYSTEM-level persistence triggered at every gpupdate cycle."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        allow=(
            FilterRule(
                reason="Built-in GP extension",
                value_matches=r"\\system32\\",
                signer="Microsoft",
                not_lolbin=True,
            ),
            FilterRule(
                reason="Built-in GP extension DLL",
                value_matches=(
                    r"^(gptext|scecli|appmgmts|fdeploy|auditcse"
                    r"|dmenrollengine|pwlauncher|dggpext|dot3gpclnt"
                    r"|wlgpclnt|AppManagementConfiguration"
                    r"|WorkFoldersGPExt)\.dll$"
                ),
                signer="Microsoft",
            ),
        ),
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
    definition = CheckDefinition(
        id="winsock_auto_proxy",
        technique="Winsock AutoProxy DLL",
        mitre_id="T1574.001",
        description=(
            "Winsock NameSpace_Catalog5 provider DLLs are loaded for "
            "network name resolution. A non-OS library in the catalog "
            "provides persistent DLL loading in any networking process."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        allow=(
            FilterRule(
                reason="Default Winsock provider",
                value_matches=r"(mswsock|napinsp|nlansp_c|winrnr|wshbth)\.dll$",
                signer="Microsoft",
            ),
        ),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries",
                values="LibraryPath",
                scope=HiveScope.HKLM,
                recurse=True,
            ),
        ),
    )
