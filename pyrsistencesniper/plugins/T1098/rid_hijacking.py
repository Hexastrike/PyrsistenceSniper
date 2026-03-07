from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from pyrsistencesniper.models.finding import AccessLevel
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import CheckDefinition, PersistencePlugin

if TYPE_CHECKING:
    from pyrsistencesniper.models.finding import Finding

_USERS_PATH = r"SAM\Domains\Account\Users"


@register_plugin
class RidHijacking(PersistencePlugin):
    definition = CheckDefinition(
        id="rid_hijacking",
        technique="RID Hijacking",
        mitre_id="T1098",
        description=(
            "RID Hijacking modifies the binary F value in the SAM hive to "
            "change a user account's effective RID. A mismatch between the "
            "registry subkey RID and the F-value RID (typically changed to "
            "500/Administrator) grants admin privileges to a low-privilege "
            "account."
        ),
        references=("https://attack.mitre.org/techniques/T1098/",),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        tree = self._load_subtree("SAM", _USERS_PATH)
        if tree is None:
            return findings

        for rid_hex, node in tree.children():
            if rid_hex == "Names":
                continue

            try:
                actual_rid = int(rid_hex, 16)
            except ValueError:
                continue

            f_value = node.get("F")
            if f_value is None or not isinstance(f_value, bytes):
                continue
            if len(f_value) < 52:
                continue

            try:
                f_rid = struct.unpack_from("<I", f_value, 0x30)[0]
            except struct.error:
                continue

            if f_rid != actual_rid:
                findings.append(
                    self._make_finding(
                        path=f"HKLM\\{_USERS_PATH}\\{rid_hex}\\F",
                        value=(
                            f"RID mismatch: subkey=0x{actual_rid:X} "
                            f"({actual_rid}), F value=0x{f_rid:X} ({f_rid})"
                        ),
                        access=AccessLevel.SYSTEM,
                    )
                )

        return findings


@register_plugin
class RidSuborner(PersistencePlugin):
    definition = CheckDefinition(
        id="rid_suborner",
        technique="RID Suborner (Hidden Admin Account)",
        mitre_id="T1098",
        description=(
            "The Suborner technique creates a hidden account with RID 500 "
            "by directly manipulating SAM hive entries, bypassing standard "
            "account-creation APIs. Accounts whose F-value RID is 500 but "
            "whose subkey RID differs are flagged."
        ),
        references=("https://attack.mitre.org/techniques/T1098/",),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        tree = self._load_subtree("SAM", _USERS_PATH)
        if tree is None:
            return findings

        for rid_hex, node in tree.children():
            if rid_hex == "Names":
                continue

            f_value = node.get("F")
            if f_value is None or not isinstance(f_value, bytes):
                continue
            if len(f_value) < 52:
                continue

            try:
                f_rid = struct.unpack_from("<I", f_value, 0x30)[0]
            except struct.error:
                continue

            try:
                actual_rid = int(rid_hex, 16)
            except ValueError:
                continue

            if f_rid == 500 and actual_rid != 500:
                findings.append(
                    self._make_finding(
                        path=f"HKLM\\{_USERS_PATH}\\{rid_hex}\\F",
                        value=(
                            f"Potential Suborner: account 0x{actual_rid:X} "
                            f"has F-value RID=500"
                        ),
                        access=AccessLevel.SYSTEM,
                    )
                )

        return findings
