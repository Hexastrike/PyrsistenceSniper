"""Detect RID hijacking and RID suborner persistence in the SAM hive (T1098).

RID Hijacking modifies the binary F value in the SAM hive to change a
user account's effective RID.  A mismatch between the registry subkey
RID and the F-value RID (typically changed to 500/Administrator) grants
admin privileges to a low-privilege account.  The Suborner variant
specifically detects hidden accounts whose F-value RID has been set to
500.
"""

from __future__ import annotations

import logging
import struct

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
)
from pyrsistencesniper.core.registry import RegistryNode
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

logger = logging.getLogger(__name__)

_USERS_PATH = r"SAM\Domains\Account\Users"
_MIN_F_VALUE_LENGTH = 52
_ADMIN_RID = 500


def _parse_f_value_rid(f_value: bytes) -> int | None:
    """Extract the RID from a SAM F-value at offset 0x30.

    Returns None if the F-value is too short or unpacking fails.
    """
    if len(f_value) < _MIN_F_VALUE_LENGTH:
        return None
    try:
        rid: int = struct.unpack_from("<I", f_value, 0x30)[0]
        return rid
    except struct.error:
        return None


def _iter_user_rid_nodes(
    tree: RegistryNode,
) -> list[tuple[str, int, RegistryNode]]:
    """Yield (rid_hex, actual_rid, node) for each valid user subkey."""
    results: list[tuple[str, int, RegistryNode]] = []
    for rid_hex_name, child_node in tree.children():
        if rid_hex_name == "Names":
            continue
        try:
            actual_rid = int(rid_hex_name, 16)
        except ValueError:
            logger.debug("Invalid RID hex value: %s", rid_hex_name, exc_info=True)
            continue
        results.append((rid_hex_name, actual_rid, child_node))
    return results


@register_plugin
class RidHijacking(PersistencePlugin):
    """Detect RID mismatch between SAM subkey name and binary F-value RID."""

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
        """Scan SAM user subkeys for RID mismatches."""
        findings: list[Finding] = []

        users_tree = self.hive_ops.load_subtree("SAM", _USERS_PATH)
        if users_tree is None:
            return findings

        for rid_hex_name, actual_rid, child_node in _iter_user_rid_nodes(users_tree):
            f_value_raw = child_node.get("F")
            if f_value_raw is None or not isinstance(f_value_raw, bytes):
                continue

            f_value_rid = _parse_f_value_rid(f_value_raw)
            if f_value_rid is None:
                continue

            if f_value_rid != actual_rid:
                findings.append(
                    self._make_finding(
                        path=f"HKLM\\{_USERS_PATH}\\{rid_hex_name}\\F",
                        value=(
                            f"RID mismatch: subkey=0x{actual_rid:X} "
                            f"({actual_rid}), F value=0x{f_value_rid:X} ({f_value_rid})"
                        ),
                        access=AccessLevel.SYSTEM,
                    )
                )

        return findings


@register_plugin
class RidSuborner(PersistencePlugin):
    """Detect hidden admin accounts with F-value RID set to 500."""

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
        """Scan SAM user subkeys for hidden admin (RID 500) accounts."""
        findings: list[Finding] = []

        users_tree = self.hive_ops.load_subtree("SAM", _USERS_PATH)
        if users_tree is None:
            return findings

        for rid_hex_name, actual_rid, child_node in _iter_user_rid_nodes(users_tree):
            f_value_raw = child_node.get("F")
            if f_value_raw is None or not isinstance(f_value_raw, bytes):
                continue

            f_value_rid = _parse_f_value_rid(f_value_raw)
            if f_value_rid is None:
                continue

            if f_value_rid == _ADMIN_RID and actual_rid != _ADMIN_RID:
                findings.append(
                    self._make_finding(
                        path=f"HKLM\\{_USERS_PATH}\\{rid_hex_name}\\F",
                        value=(
                            f"Potential Suborner: account 0x{actual_rid:X} "
                            f"has F-value RID=500"
                        ),
                        access=AccessLevel.SYSTEM,
                    )
                )

        return findings
