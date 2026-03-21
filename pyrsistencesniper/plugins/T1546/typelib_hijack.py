from __future__ import annotations

import re

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    FilterRule,
    Finding,
)
from pyrsistencesniper.core.registry import registry_value_to_str
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_SCRIPT_MONIKER_RE = re.compile(r"^script:", re.IGNORECASE)
_SAFE_PATH_RE = re.compile(
    r"(\\system32\\|\\syswow64\\|\\program files\\|\\program files \(x86\)\\)",
    re.IGNORECASE,
)


@register_plugin
class TypeLibHijack(PersistencePlugin):
    definition = CheckDefinition(
        id="typelib_hijack",
        technique="TypeLib COM Hijacking",
        mitre_id="T1546.015",
        description=(
            "TypeLib entries in per-user hives (HKCU\\Software\\Classes\\"
            "TypeLib) are checked for suspicious paths. HKCU TypeLib "
            "entries override HKLM, allowing user-level persistence. "
            "Entries using script: monikers or pointing to user-writable "
            "locations are flagged."
        ),
        references=("https://attack.mitre.org/techniques/T1546/015/",),
        allow=(
            FilterRule(
                reason="Standard system type library",
                path_matches=r"\\(system32|syswow64|Program Files)",
                signer="microsoft",
            ),
        ),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        for profile, hive in self.hive_ops.iter_usrclass_hives():
            typelib_tree = self.registry.load_subtree(hive, r"Software\Classes\TypeLib")
            if typelib_tree is None:
                continue

            for guid, guid_node in typelib_tree.children():
                for version, ver_node in guid_node.children():
                    for platform in ("win32", "win64"):
                        zero_node = ver_node.child("0")
                        if zero_node is None:
                            continue
                        plat_node = zero_node.child(platform)
                        if plat_node is None:
                            continue
                        path_val = registry_value_to_str(plat_node.get("(Default)"))
                        if path_val is None:
                            continue
                        if _SCRIPT_MONIKER_RE.match(
                            path_val
                        ) or not _SAFE_PATH_RE.search(path_val):
                            findings.append(
                                self._make_finding(
                                    path=(
                                        f"HKU\\{profile.username}"
                                        f"\\Software\\Classes\\TypeLib"
                                        f"\\{guid}\\{version}\\0"
                                        f"\\{platform}"
                                    ),
                                    value=path_val,
                                    access=AccessLevel.USER,
                                )
                            )

        return findings
