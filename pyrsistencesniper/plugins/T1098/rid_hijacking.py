"""Detect RID hijacking and RID suborner persistence in the SAM hive (T1098)."""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
)
from pyrsistencesniper.core.sam import USERS_PATH, iter_user_rid_nodes
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

if TYPE_CHECKING:
    from collections.abc import Iterator

    from pyrsistencesniper.core.registry import RegistryNode

_MIN_F_VALUE_LENGTH = 52
_ADMIN_RID = 500


def _parse_f_value_rid(f_value: bytes) -> int | None:
    """Return the RID a SAM F value carries at offset 0x30, or None when unreadable."""
    if len(f_value) < _MIN_F_VALUE_LENGTH:
        return None
    try:
        rid: int = struct.unpack_from("<I", f_value, 0x30)[0]
        return rid
    except struct.error:
        return None


def _iter_account_rids(users_tree: RegistryNode) -> Iterator[tuple[str, int, int]]:
    """Yield (subkey name, subkey RID, F value RID) for every readable user key."""
    for rid_hex_name, subkey_rid, user_node in iter_user_rid_nodes(users_tree):
        f_value = user_node.get("F")
        if not isinstance(f_value, bytes):
            continue
        f_value_rid = _parse_f_value_rid(f_value)
        if f_value_rid is None:
            continue
        yield rid_hex_name, subkey_rid, f_value_rid


@register_plugin
class RidHijacking(PersistencePlugin):
    """Detect RID mismatch between SAM subkey name and binary F-value RID."""

    definition = CheckDefinition(
        id="rid_hijacking",
        technique="RID Hijacking",
        mitre_id="T1098",
        description=(
            "RID Hijacking rewrites the binary F value in the SAM hive to "
            "change an account's effective RID. A subkey RID that disagrees "
            "with the F value RID (usually set to 500, Administrator) grants "
            "admin privileges to a low-privilege account."
        ),
    )

    def run(self) -> list[Finding]:
        """Report every account whose F value RID differs from its subkey RID."""
        users_tree = self.context.load_subtree("SAM", USERS_PATH)
        if users_tree is None:
            return []

        return [
            self._make_finding(
                path=f"HKLM\\{USERS_PATH}\\{rid_hex_name}\\F",
                value=(
                    f"RID mismatch: subkey=0x{subkey_rid:X} "
                    f"({subkey_rid}), F value=0x{f_value_rid:X} ({f_value_rid})"
                ),
                access=AccessLevel.SYSTEM,
            )
            for rid_hex_name, subkey_rid, f_value_rid in _iter_account_rids(users_tree)
            if f_value_rid != subkey_rid
        ]


@register_plugin
class RidSuborner(PersistencePlugin):
    """Detect hidden admin accounts with F-value RID set to 500."""

    definition = CheckDefinition(
        id="rid_suborner",
        technique="RID Suborner (Hidden Admin Account)",
        mitre_id="T1098",
        description=(
            "The Suborner technique writes SAM hive entries directly, bypassing the "
            "account-creation APIs, to leave a hidden account whose F value carries "
            "RID 500 while its subkey RID does not."
        ),
    )

    def run(self) -> list[Finding]:
        """Report every non-Administrator account whose F value claims RID 500."""
        users_tree = self.context.load_subtree("SAM", USERS_PATH)
        if users_tree is None:
            return []

        return [
            self._make_finding(
                path=f"HKLM\\{USERS_PATH}\\{rid_hex_name}\\F",
                value=(
                    f"Potential Suborner: account 0x{subkey_rid:X} has F-value RID=500"
                ),
                access=AccessLevel.SYSTEM,
            )
            for rid_hex_name, subkey_rid, f_value_rid in _iter_account_rids(users_tree)
            if f_value_rid == _ADMIN_RID and subkey_rid != _ADMIN_RID
        ]
