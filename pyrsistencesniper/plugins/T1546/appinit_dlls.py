from __future__ import annotations

import re

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
)
from pyrsistencesniper.core.registry import RegistryNode
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_KEY_PATHS: tuple[str, str] = (
    r"Microsoft\Windows NT\CurrentVersion\Windows",
    r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
)
_SPLIT_RE = re.compile(r"[,\s]+")


@register_plugin
class AppInitDlls(PersistencePlugin):
    definition = CheckDefinition(
        id="appinit_dlls",
        technique="AppInit DLLs",
        mitre_id="T1546.010",
        description=(
            "AppInit_DLLs are injected into every process that loads "
            "user32.dll. Both native and WoW64 paths are checked. "
            "The mechanism is only active when LoadAppInit_DLLs is set "
            "to 1 and is disabled by default on Windows 8+ with Secure "
            "Boot enabled."
        ),
        references=("https://attack.mitre.org/techniques/T1546/010/",),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        hive = self.hive_ops.open_hive("SOFTWARE")
        if hive is None:
            return findings

        for key_path in _KEY_PATHS:
            node = self.registry.load_subtree(hive, key_path)
            if node is None:
                continue
            raw_value = node.get("AppInit_DLLs")
            if raw_value is None:
                continue
            value_str = str(raw_value).strip()
            if not value_str:
                continue

            context = self._read_context(node)

            for raw_dll in _SPLIT_RE.split(value_str):
                dll_path = raw_dll.strip()
                if not dll_path:
                    continue

                display = f"{dll_path} [{context}]" if context else dll_path

                findings.append(
                    self._make_finding(
                        path=f"HKLM\\SOFTWARE\\{key_path}\\AppInit_DLLs",
                        value=display,
                        access=AccessLevel.SYSTEM,
                    )
                )

        return findings

    @staticmethod
    def _read_context(node: object) -> str:
        assert isinstance(node, RegistryNode)
        parts: list[str] = []
        load = node.get("LoadAppInit_DLLs")
        if isinstance(load, int):
            label = f"LoadAppInit_DLLs={load}"
            if load == 0:
                label += " (INACTIVE)"
            parts.append(label)
        signed = node.get("RequireSignedAppInit_DLLs")
        if isinstance(signed, int):
            parts.append(f"RequireSignedAppInit_DLLs={signed}")
        return ", ".join(parts)
