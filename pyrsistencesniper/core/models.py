"""Domain models: findings, check definitions, filter rules, and supporting types."""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar, Protocol, TypeAlias


@dataclass(frozen=True, slots=True)
class UserProfile:
    """User profile location within a forensic image."""

    username: str
    profile_path: Path
    ntuser_path: Path | None = None


class AccessLevel(enum.Enum):
    """Privilege level associated with a persistence finding."""

    USER = "USER"
    SYSTEM = "SYSTEM"


class Severity(enum.Enum):
    """Classification of a finding based on allow/block rule matching."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    def __ge__(self, other: Severity) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return _SEVERITY_RANK[self] >= _SEVERITY_RANK[other]

    def __gt__(self, other: Severity) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return _SEVERITY_RANK[self] > _SEVERITY_RANK[other]

    def __le__(self, other: Severity) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return _SEVERITY_RANK[self] <= _SEVERITY_RANK[other]

    def __lt__(self, other: Severity) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return _SEVERITY_RANK[self] < _SEVERITY_RANK[other]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
}


@dataclass(frozen=True, slots=True)
class Finding:
    """Immutable record representing one detected persistence mechanism."""

    FIELDS: ClassVar[dict[str, str]] = {
        "path": "Path",
        "value": "Value",
        "technique": "Technique",
        "mitre_id": "MITRE ID",
        "description": "Description",
        "access_gained": "Access Gained",
        "severity": "Severity",
        "is_lolbin": "LOLBin",
        "exists": "Exists",
        "sha256": "SHA256",
        "is_builtin": "Builtin",
        "is_in_os_directory": "OS Directory",
        "signer": "Signer",
        "hostname": "Hostname",
        "check_id": "Check ID",
        "references": "References",
    }

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
    severity: Severity = Severity.MEDIUM


@dataclass(frozen=True, slots=True)
class Enrichment:
    """Key-value data attached to a finding by an enrichment plugin."""

    provider: str = ""
    data: dict[str, str] = field(default_factory=dict)


class MatchResult(enum.Enum):
    """How well a FilterRule matches a Finding."""

    NONE = "NONE"
    PARTIAL = "PARTIAL"
    FULL = "FULL"


MATCH_TO_SEVERITY: dict[MatchResult, Severity] = {
    MatchResult.NONE: Severity.MEDIUM,
    MatchResult.PARTIAL: Severity.LOW,
    MatchResult.FULL: Severity.INFO,
}


@dataclass(frozen=True, slots=True)
class FilterRule:
    """Allowlist rule that suppresses matching findings during policy evaluation."""

    reason: str = ""
    value_matches: str = ""
    path_matches: str = ""
    signer: str = ""
    hash: str = ""
    not_lolbin: bool = False

    def match_result(self, finding: Finding) -> MatchResult:
        """Classify how well this rule matches the finding.

        Fields are evaluated in two tiers:

        - **Core** (``value_matches``, ``path_matches``, ``hash``,
          ``not_lolbin``): every specified core field must pass or the
          result is ``NONE``.
        - **Signer** is a *soft* condition: when all core fields pass but
          the signer check fails the result degrades to ``PARTIAL``
          instead of ``NONE``.  This avoids penalising a finding just
          because a legitimate binary happens to be unsigned.

        Returns ``NONE`` when no conditions are specified.
        """
        core_pass: list[bool] = []

        if self.not_lolbin:
            core_pass.append(
                not finding.is_lolbin and finding.is_lolbin is not None,
            )
        if self.value_matches:
            core_pass.append(
                bool(re.search(self.value_matches, finding.value, re.IGNORECASE)),
            )
        if self.path_matches:
            core_pass.append(
                bool(re.search(self.path_matches, finding.path, re.IGNORECASE)),
            )
        if self.hash:
            core_pass.append(finding.sha256.lower() == self.hash.lower())

        signer_ok = not self.signer or (
            bool(finding.signer) and self.signer.lower() in finding.signer.lower()
        )

        if not core_pass and not self.signer:
            return MatchResult.NONE
        if not all(core_pass):
            return MatchResult.NONE
        if signer_ok:
            return MatchResult.FULL
        return MatchResult.PARTIAL if core_pass else MatchResult.NONE

    def matches(self, finding: Finding) -> bool:
        """Return True if all non-empty rule fields match the finding (AND logic)."""
        return self.match_result(finding) == MatchResult.FULL


AnnotatedResult: TypeAlias = tuple[Finding, tuple[Enrichment, ...]]


class KeyProtocol(Protocol):
    """Structural type for registry key objects (pyregf.key)."""

    def get_name(self) -> str: ...
    def get_number_of_sub_keys(self) -> int: ...
    def get_sub_key(self, index: int) -> KeyProtocol: ...
    def get_number_of_values(self) -> int: ...
    def get_value(self, index: int) -> KeyProtocol: ...


class HiveProtocol(Protocol):
    """Structural type for registry hive file handles.

    Matches the interface of pyregf.file that the codebase actually uses,
    without coupling to the C extension at import time.
    """

    def get_key_by_path(self, path: str) -> KeyProtocol | None:
        """Resolve a registry key by its backslash-delimited path."""
        ...


class HiveScope(enum.Enum):
    """Specifies whether a registry target uses HKLM, HKU, or both."""

    HKLM = "HKLM"
    HKU = "HKU"
    BOTH = "BOTH"


@dataclass(frozen=True, slots=True)
class RegistryTarget:
    """Describes a single registry path and value selector to scan."""

    path: str = ""
    values: str = "*"
    scope: HiveScope = HiveScope.BOTH
    recurse: bool = False


@dataclass(frozen=True, slots=True)
class CheckDefinition:
    """Immutable specification of a persistence check's metadata and targets."""

    id: str = ""
    technique: str = ""
    mitre_id: str = ""
    description: str = ""
    targets: tuple[RegistryTarget, ...] = field(default_factory=tuple)
    references: tuple[str, ...] = field(default_factory=tuple)
    allow: tuple[FilterRule, ...] = field(default_factory=tuple)
    block: tuple[FilterRule, ...] = field(default_factory=tuple)
