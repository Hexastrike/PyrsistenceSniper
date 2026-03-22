from __future__ import annotations

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    FilterRule,
    Finding,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_KNOWN_DLLS_PATH_TEMPLATE = r"{controlset}\Control\Session Manager\KnownDLLs"


@register_plugin
class KnownDlls(PersistencePlugin):
    definition = CheckDefinition(
        id="known_dlls",
        technique="Known DLLs",
        mitre_id="T1574.001",
        description=(
            "The KnownDLLs key forces Windows to load specific DLLs from "
            "System32. Adding entries causes a malicious DLL to be loaded "
            "by any process that imports the specified DLL name. Changes "
            "to DllDirectory values are also flagged."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
        allow=(
            FilterRule(
                reason="Default Windows KnownDLL entry",
                value_matches=(
                    r"^(advapi32|clbcatq|combase|COMDLG32|COML2"
                    r"|CoreMessaging|CoreUIComponents|CRYPT32"
                    r"|difxapi|gdi32|gdiplus|GDI32Full"
                    r"|IMAGEHLP|IMM32|kernel32|KERNELBASE"
                    r"|MFC42u|MSCTF|MSVCP_WIN|MSVCRT"
                    r"|NORMALIZ|NSI|ntdll|OLEAUT32|OLE32"
                    r"|RPCRT4|sechost|Setupapi|SHCORE|SHELL32"
                    r"|shlwapi|TextShaping|ucrtbase|USER32"
                    r"|win32u|WINTRUST|WS2_32|WLDAP32)\.dll$"
                ),
                signer="Microsoft",
            ),
            FilterRule(
                reason="Standard Windows KnownDLL entry",
                signer="Microsoft",
                not_lolbin=True,
            ),
        ),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        kd_path = _KNOWN_DLLS_PATH_TEMPLATE.replace(
            "{controlset}", self.context.active_controlset
        )
        tree = self.hive_ops.load_subtree("SYSTEM", kd_path)
        if tree is None:
            return findings

        for name, raw_value in tree.values():
            if not name.strip():
                continue
            findings.append(
                self._make_finding(
                    path=f"HKLM\\SYSTEM\\{kd_path}\\{name}",
                    value=str(raw_value),
                    access=AccessLevel.SYSTEM,
                )
            )

        return findings
