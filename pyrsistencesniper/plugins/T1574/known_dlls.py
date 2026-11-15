"""Detection for Known DLLs and the settings that weaken the DLL search order."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_SESSION_MANAGER_PATH_TEMPLATE = r"{controlset}\Control\Session Manager"
_KNOWN_DLLS_PATH_TEMPLATE = _SESSION_MANAGER_PATH_TEMPLATE + r"\KnownDLLs"
_EXCLUDE_FROM_KNOWN_DLLS = "ExcludeFromKnownDlls"

_SEARCH_ORDER_FLAGS: tuple[tuple[str, int], ...] = (
    ("SafeDllSearchMode", 0),
    ("CWDIllegalInDllSearch", 0),
)


def _multi_string_entries(raw_value: object) -> list[str]:
    """Return the non-blank strings a REG_MULTI_SZ value holds."""
    if raw_value is None:
        return []
    if isinstance(raw_value, list):
        return [str(entry).strip() for entry in raw_value if str(entry).strip()]
    text = str(raw_value).strip()
    return [text] if text else []


def _flag_value(raw_value: object) -> int | None:
    """Return a registry flag as an integer, or None when it does not hold one."""
    if raw_value is None:
        return None
    if isinstance(raw_value, int):
        return raw_value
    text = str(raw_value).strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


@register_plugin
class KnownDlls(PersistencePlugin):
    """Detects Known DLLs persistence entries."""

    definition = CheckDefinition(
        id="known_dlls",
        technique="Known DLLs",
        mitre_id="T1574.001",
        description=(
            "The KnownDLLs key makes Windows load the listed DLLs from System32 for "
            "every process that imports them, and its DllDirectory values name that "
            "directory."
        ),
        references=("https://attack.mitre.org/techniques/T1574/001/",),
    )

    def run(self) -> list[Finding]:
        """Report every DLL name the KnownDLLs key pins for the whole system."""
        findings: list[Finding] = []

        known_dlls_path = _KNOWN_DLLS_PATH_TEMPLATE.replace(
            "{controlset}", self.context.active_controlset
        )
        tree = self.context.load_subtree("SYSTEM", known_dlls_path)
        if tree is None:
            return findings

        for name, raw_value in tree.values():
            if not name.strip():
                continue
            findings.append(
                self._make_finding(
                    path=f"HKLM\\SYSTEM\\{known_dlls_path}\\{name}",
                    value=str(raw_value),
                    access=AccessLevel.SYSTEM,
                )
            )

        return findings


@register_plugin
class ExcludeFromKnownDlls(PersistencePlugin):
    """Detects DLLs removed from the KnownDLLs protection namespace."""

    definition = CheckDefinition(
        id="exclude_from_known_dlls",
        technique="KnownDLLs Exclusion",
        mitre_id="T1574.001",
        description=(
            "ExcludeFromKnownDlls drops a DLL out of the KnownDLLs section "
            "namespace, so the loader searches the application directory for "
            "it instead of mapping the System32 copy. Every name listed here "
            "is a DLL that search-order hijacking has been re-enabled for. "
            "Windows ships the value empty."
        ),
        references=(
            "https://attack.mitre.org/techniques/T1574/001/",
            "https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order",
        ),
    )

    def run(self) -> list[Finding]:
        """Report every DLL name excluded from the KnownDLLs section namespace."""
        session_manager_path = _SESSION_MANAGER_PATH_TEMPLATE.replace(
            "{controlset}", self.context.active_controlset
        )
        node = self.context.load_subtree("SYSTEM", session_manager_path)
        if node is None:
            return []

        value_path = f"HKLM\\SYSTEM\\{session_manager_path}\\{_EXCLUDE_FROM_KNOWN_DLLS}"
        return [
            self._make_finding(
                path=value_path,
                value=dll_name,
                access=AccessLevel.SYSTEM,
            )
            for dll_name in _multi_string_entries(node.get(_EXCLUDE_FROM_KNOWN_DLLS))
        ]


@register_plugin
class DllSearchMode(PersistencePlugin):
    """Detects Session Manager flags that widen the DLL search order."""

    definition = CheckDefinition(
        id="dll_search_mode",
        technique="DLL Search Order Weakening",
        mitre_id="T1574.001",
        description=(
            "SafeDllSearchMode set to 0 moves the current directory ahead of "
            "System32 in the DLL search order, and CWDIllegalInDllSearch set "
            "to 0 restores the current directory as a search location. Both "
            "are the enabling half of search-order hijacking and leave no "
            "other registry trace. Windows ships neither value set."
        ),
        references=(
            "https://attack.mitre.org/techniques/T1574/001/",
            "https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-security",
        ),
    )

    def run(self) -> list[Finding]:
        """Report each search-order flag that carries its weakening value."""
        session_manager_path = _SESSION_MANAGER_PATH_TEMPLATE.replace(
            "{controlset}", self.context.active_controlset
        )
        node = self.context.load_subtree("SYSTEM", session_manager_path)
        if node is None:
            return []

        findings: list[Finding] = []
        for flag_name, weakening_value in _SEARCH_ORDER_FLAGS:
            current = _flag_value(node.get(flag_name))
            if current != weakening_value:
                continue
            findings.append(
                self._make_finding(
                    path=f"HKLM\\SYSTEM\\{session_manager_path}\\{flag_name}",
                    value=str(current),
                    access=AccessLevel.SYSTEM,
                )
            )
        return findings
