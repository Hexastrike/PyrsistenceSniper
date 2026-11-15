"""Detect anomalous membership of the local Administrators group (T1098)."""

from __future__ import annotations

import struct

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
)
from pyrsistencesniper.core.sam import (
    USERS_PATH,
    hidden_account_names,
    iter_user_rid_nodes,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_ACCOUNT_KEY = r"SAM\Domains\Account"
_ADMINISTRATORS_KEY = r"SAM\Domains\Builtin\Aliases\00000220"
_ADMINISTRATORS_REPORT_KEY = rf"HKLM\{_ADMINISTRATORS_KEY}\C"
_LOCAL_GROUP_CONTAINERS = ("Aliases", "Groups")

# The alias C value opens with a fixed header whose offsets are relative to its
# end; only the member list is read here.
_ALIAS_HEADER_SIZE = 0x34
_ALIAS_MEMBER_OFFSET_FIELD = 0x28
_ALIAS_MEMBER_LENGTH_FIELD = 0x2C

# The user V value opens with a table of (offset, length) pairs relative to 0xCC;
# the account name is the second entry.
_V_DATA_BASE = 0xCC
_V_NAME_OFFSET_FIELD = 0x0C
_V_NAME_LENGTH_FIELD = 0x10

_SID_HEADER_SIZE = 8
_SID_SUBAUTHORITY_SIZE = 4
_SID_MAX_SUBAUTHORITIES = 15
_MACHINE_SID_SUBAUTHORITIES = 4
_MACHINE_SID_SIZE = _SID_HEADER_SIZE + (
    _MACHINE_SID_SUBAUTHORITIES * _SID_SUBAUTHORITY_SIZE
)


def _dword_at(blob: bytes, offset: int) -> int | None:
    """Read a little-endian DWORD, or None when the structure is too short."""
    if len(blob) < offset + 4:
        return None
    value: int = struct.unpack_from("<I", blob, offset)[0]
    return value


def _parse_sid(blob: bytes, offset: int) -> tuple[str, int] | None:
    """Render the binary SID at an offset and report where the next one starts."""
    if len(blob) < offset + _SID_HEADER_SIZE:
        return None
    revision = blob[offset]
    subauthority_count = blob[offset + 1]
    if subauthority_count == 0 or subauthority_count > _SID_MAX_SUBAUTHORITIES:
        return None
    end = offset + _SID_HEADER_SIZE + subauthority_count * _SID_SUBAUTHORITY_SIZE
    if len(blob) < end:
        return None
    authority = int.from_bytes(blob[offset + 2 : offset + _SID_HEADER_SIZE], "big")
    subauthorities = struct.unpack_from(
        f"<{subauthority_count}I", blob, offset + _SID_HEADER_SIZE
    )
    parts = "-".join(str(subauthority) for subauthority in subauthorities)
    return f"S-{revision}-{authority}-{parts}", end


def _alias_member_sids(alias_value: bytes) -> list[str]:
    """Return the SIDs the Administrators alias C value lists as members."""
    member_offset = _dword_at(alias_value, _ALIAS_MEMBER_OFFSET_FIELD)
    member_length = _dword_at(alias_value, _ALIAS_MEMBER_LENGTH_FIELD)
    if member_offset is None or member_length is None:
        return []
    start = _ALIAS_HEADER_SIZE + member_offset
    members = alias_value[start : start + member_length]
    sids: list[str] = []
    position = 0
    while position < len(members):
        parsed = _parse_sid(members, position)
        if parsed is None:
            break
        sid, position = parsed
        sids.append(sid)
    return sids


def _account_name(user_value: bytes) -> str:
    """Return the account name held in a SAM user V value."""
    name_offset = _dword_at(user_value, _V_NAME_OFFSET_FIELD)
    name_length = _dword_at(user_value, _V_NAME_LENGTH_FIELD)
    if name_offset is None or not name_length:
        return ""
    start = _V_DATA_BASE + name_offset
    return user_value[start : start + name_length].decode("utf-16-le", "replace")


def _relative_id(sid: str, domain_sid: str) -> int | None:
    """Return the RID a SID carries within a domain, or None when it is foreign."""
    prefix = f"{domain_sid}-"
    if not sid.startswith(prefix):
        return None
    try:
        return int(sid[len(prefix) :])
    except ValueError:
        return None


def _hex_relative_id(subkey_name: str) -> int | None:
    """Return the RID a SAM subkey name spells in hex, or None when it is not one."""
    try:
        return int(subkey_name, 16)
    except ValueError:
        return None


@register_plugin
class AdministratorsGroupMembership(PersistencePlugin):
    """Detects Administrators members that no ordinary administrator explains."""

    definition = CheckDefinition(
        id="admin_group_membership",
        technique="Administrators Group Membership",
        mitre_id="T1098",
        description=(
            "Adding a SID to the Builtin\\Administrators alias grants administrator "
            "rights without touching any account's own SAM record. Membership alone is "
            "normal, so only a member hidden from the sign-in screen, or a SID naming "
            "no account or group in the SAM, appears here."
        ),
        references=("https://attack.mitre.org/techniques/T1098/",),
    )

    def run(self) -> list[Finding]:
        """Report the Administrators members a legitimate promotion cannot explain."""
        domain_sid = self._machine_domain_sid()
        if not domain_sid:
            return []

        account_names = self._local_account_names()
        group_ids = self._local_group_ids()
        hidden_names = hidden_account_names(self.context)

        findings: list[Finding] = []
        for member_sid in self._administrator_sids():
            relative_id = _relative_id(member_sid, domain_sid)
            if relative_id is None:
                continue
            anomaly = self._anomaly(
                member_sid, relative_id, account_names, group_ids, hidden_names
            )
            if anomaly:
                findings.append(
                    self._make_finding(
                        path=_ADMINISTRATORS_REPORT_KEY,
                        value=anomaly,
                        access=AccessLevel.SYSTEM,
                    )
                )
        return findings

    @staticmethod
    def _anomaly(
        member_sid: str,
        relative_id: int,
        account_names: dict[int, str],
        group_ids: set[int],
        hidden_names: set[str],
    ) -> str:
        """Describe why a member is anomalous, or return empty for an ordinary one."""
        account_name = account_names.get(relative_id)
        if account_name is None:
            if relative_id in group_ids:
                return ""
            return (
                f"{member_sid} is a member of Administrators but names no "
                f"account or group in the SAM"
            )
        if account_name.casefold() in hidden_names:
            return (
                f"{account_name} ({member_sid}) is a member of Administrators "
                f"and is hidden from the sign-in screen"
            )
        return ""

    def _administrator_sids(self) -> list[str]:
        """Return the SIDs listed as members of the Builtin Administrators alias."""
        alias = self.context.load_subtree("SAM", _ADMINISTRATORS_KEY)
        if alias is None:
            return []
        alias_value = alias.get("C")
        if not isinstance(alias_value, bytes):
            return []
        return _alias_member_sids(alias_value)

    def _machine_domain_sid(self) -> str:
        """Return the machine's own domain SID, stored at the end of the Account V."""
        account = self.context.load_subtree("SAM", _ACCOUNT_KEY)
        if account is None:
            return ""
        account_value = account.get("V")
        if not isinstance(account_value, bytes):
            return ""
        if len(account_value) < _MACHINE_SID_SIZE:
            return ""
        parsed = _parse_sid(account_value[-_MACHINE_SID_SIZE:], 0)
        return parsed[0] if parsed else ""

    def _local_account_names(self) -> dict[int, str]:
        """Map each local account's RID to the name held in its SAM V value."""
        users = self.context.load_subtree("SAM", USERS_PATH)
        if users is None:
            return {}
        names: dict[int, str] = {}
        for _rid_hex_name, relative_id, user_node in iter_user_rid_nodes(users):
            user_value = user_node.get("V")
            if isinstance(user_value, bytes):
                names[relative_id] = _account_name(user_value)
        return names

    # A local group nested inside Administrators is ordinary and its RID is not
    # in the user list, so without these a custom group would be reported as a
    # member naming nothing.
    def _local_group_ids(self) -> set[int]:
        """Return the RIDs of the local groups and aliases the SAM defines."""
        group_ids: set[int] = set()
        for container in _LOCAL_GROUP_CONTAINERS:
            node = self.context.load_subtree("SAM", rf"{_ACCOUNT_KEY}\{container}")
            if node is None:
                continue
            group_ids.update(
                relative_id
                for child_name, _child_node in node.children()
                if (relative_id := _hex_relative_id(child_name)) is not None
            )
        return group_ids
