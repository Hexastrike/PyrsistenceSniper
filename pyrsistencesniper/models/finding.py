from __future__ import annotations

import enum
from collections.abc import Mapping
from dataclasses import dataclass, field


class AccessLevel(enum.Enum):
    """Privilege level associated with a persistence finding."""

    USER = "USER"
    SYSTEM = "SYSTEM"


@dataclass(frozen=True, slots=True)
class Finding:
    """Immutable record representing one detected persistence mechanism."""

    path: str = ""
    value: str = ""
    technique: str = ""
    mitre_id: str = ""
    description: str = ""
    access_gained: AccessLevel = AccessLevel.USER
    is_lolbin: bool | None = None
    exists: bool | None = None
    sha256: str = ""
    is_builtin: bool | None = None
    is_in_os_directory: bool | None = None
    signer: str = ""
    hostname: str = ""
    check_id: str = ""
    references: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class Enrichment:
    """Key-value data attached to a finding by an enrichment plugin."""

    provider: str = ""
    data: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AllowRule:
    """Allowlist rule that suppresses matching findings during policy evaluation."""

    reason: str = ""
    value_equals: str = ""
    value_contains: str = ""
    path_equals: str = ""
    path_contains: str = ""
    signer: str = ""
    hash: str = ""
    not_lolbin: bool = False

    def matches(self, finding: Finding) -> bool:
        """Return True if all non-empty rule fields match the finding (AND logic)."""
        matched_any = False

        if self.not_lolbin:
            if finding.is_lolbin or finding.is_lolbin is None:
                return False
            matched_any = True

        if self.value_equals:
            if finding.value.lower() != self.value_equals.lower():
                return False
            matched_any = True

        if self.value_contains:
            if self.value_contains.lower() not in finding.value.lower():
                return False
            matched_any = True

        if self.path_equals:
            if finding.path.lower() != self.path_equals.lower():
                return False
            matched_any = True

        if self.path_contains:
            if self.path_contains.lower() not in finding.path.lower():
                return False
            matched_any = True

        if self.signer:
            if not finding.signer:
                return False
            if self.signer.lower() not in finding.signer.lower():
                return False
            matched_any = True

        if self.hash:
            if finding.sha256.lower() != self.hash.lower():
                return False
            matched_any = True

        return matched_any


AnnotatedResult = tuple[Finding, tuple[Enrichment, ...]]
