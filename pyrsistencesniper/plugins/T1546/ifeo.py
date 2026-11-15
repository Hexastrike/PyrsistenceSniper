"""Detection for Image File Execution Options and Silent Process Exit abuse."""

from __future__ import annotations

from pyrsistencesniper.core.context import AnalysisContext
from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
)
from pyrsistencesniper.core.registry import RegistryNode, registry_value_to_str
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

# The Wow6432Node IFEO key is a volatile symbolic link onto the native key, so a
# collected hive normally carries no separate 32-bit store and this second path
# matches nothing. It stays: it costs one lookup, and an image that did capture
# the key would otherwise go unread. SilentProcessExit below is a real 32-bit
# store, not a link.
_IFEO_PATHS = (
    r"Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    r"Wow6432Node\Microsoft\Windows NT\CurrentVersion"
    r"\Image File Execution Options",
)

_SPE_PATHS = (
    r"Microsoft\Windows NT\CurrentVersion\SilentProcessExit",
    r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\SilentProcessExit",
)


def _collect_subtree_values(
    tree: RegistryNode,
    value_name: str,
    relative_path: str = "",
) -> list[tuple[str, str]]:
    """Return (key path relative to the subtree root, value) at any depth."""
    results: list[tuple[str, str]] = []
    for subkey_name, node in tree.children():
        subkey_path = (
            f"{relative_path}\\{subkey_name}" if relative_path else subkey_name
        )
        value_str = registry_value_to_str(node.get(value_name))
        if value_str is not None:
            results.append((subkey_path, value_str))
        results.extend(_collect_subtree_values(node, value_name, subkey_path))
    return results


def _collect_view_values(
    context: AnalysisContext,
    key_paths: tuple[str, ...],
    value_name: str,
) -> list[tuple[str, str]]:
    """Return (reportable HKLM path, value) for a value in every registry view."""
    results: list[tuple[str, str]] = []
    for key_path in key_paths:
        tree = context.load_subtree("SOFTWARE", key_path)
        if tree is None:
            continue
        results.extend(
            (f"HKLM\\SOFTWARE\\{key_path}\\{subkey_path}\\{value_name}", value_str)
            for subkey_path, value_str in _collect_subtree_values(tree, value_name)
        )
    return results


@register_plugin
class IfeoDebugger(PersistencePlugin):
    """Detects Image File Execution Options Debugger persistence entries."""

    definition = CheckDefinition(
        id="ifeo_debugger",
        technique="Image File Execution Options Debugger",
        mitre_id="T1546.012",
        description=(
            "An IFEO Debugger value makes Windows start the named debugger in place of "
            "the target executable. With UseFilter set, the Debugger sits in a named "
            "filter subkey below the image key."
        ),
        references=("https://attack.mitre.org/techniques/T1546/012/",),
    )

    def run(self) -> list[Finding]:
        """Report every Debugger value anywhere below an IFEO image key."""
        return [
            self._make_finding(path=path, value=value, access=AccessLevel.SYSTEM)
            for path, value in _collect_view_values(
                self.context, _IFEO_PATHS, "Debugger"
            )
        ]


@register_plugin
class IfeoSilentProcessExit(PersistencePlugin):
    """Detects Silent Process Exit Monitor persistence entries."""

    definition = CheckDefinition(
        id="ifeo_silent_process_exit",
        technique="Silent Process Exit Monitor",
        mitre_id="T1546.012",
        description=(
            "A SilentProcessExit MonitorProcess value names a program started when the "
            "monitored process exits. A 32-bit process is configured through the "
            "Wow6432Node view."
        ),
        references=("https://attack.mitre.org/techniques/T1546/012/",),
    )

    def run(self) -> list[Finding]:
        """Report every MonitorProcess registered under SilentProcessExit."""
        return [
            self._make_finding(path=path, value=value, access=AccessLevel.SYSTEM)
            for path, value in _collect_view_values(
                self.context, _SPE_PATHS, "MonitorProcess"
            )
        ]


@register_plugin
class IfeoDelegatedNtdll(PersistencePlugin):
    """Detects IFEO Verifier DLLs persistence entries."""

    definition = CheckDefinition(
        id="ifeo_delegated_ntdll",
        technique="IFEO Verifier DLLs",
        mitre_id="T1546.012",
        description=(
            "VerifierDlls under an IFEO image key names DLLs loaded into that process "
            "at startup. It is armed by GlobalFlag 0x100 (Application Verifier), which "
            "the loader accepts as either a DWORD or a string."
        ),
        references=("https://attack.mitre.org/techniques/T1546/012/",),
    )

    def run(self) -> list[Finding]:
        """Report every VerifierDlls list anywhere below an IFEO image key."""
        return [
            self._make_finding(path=path, value=value, access=AccessLevel.SYSTEM)
            for path, value in _collect_view_values(
                self.context, _IFEO_PATHS, "VerifierDlls"
            )
        ]
