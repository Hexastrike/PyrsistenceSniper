"""Domain models: findings, check definitions, filter rules, and supporting types."""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field
from functools import total_ordering
from pathlib import Path
from typing import ClassVar, Protocol, TypeAlias


@dataclass(frozen=True, slots=True)
class UserProfile:
    """User profile location within a forensic image."""

    username: str
    profile_path: Path
    ntuser_path: Path | None = None
    usrclass_path: Path | None = None


class AccessLevel(enum.Enum):
    """Privilege level associated with a persistence finding."""

    USER = "USER"
    SYSTEM = "SYSTEM"


class HiveStatus(enum.Enum):
    """Outcome of an attempt to open a registry hive."""

    OPENED = "OPENED"
    REPAIRED = "REPAIRED"
    OPEN_FAILED = "OPEN_FAILED"
    NOT_READ = "NOT_READ"
    NOT_COLLECTED = "NOT_COLLECTED"


ESSENTIAL_HIVES: frozenset[str] = frozenset({"SOFTWARE", "SYSTEM"})


@dataclass(frozen=True, slots=True)
class HiveRecord:
    """One hive the scan expected, and what became of it."""

    name: str = ""
    owner: str = ""
    path: str = ""
    status: HiveStatus = HiveStatus.NOT_COLLECTED
    dirty: bool = False
    error: str = ""

    @property
    def cost_checks(self) -> bool:
        """Report whether this hive's state removed checks from the scan."""
        # SAM, SECURITY, DEFAULT and AMCACHE are absent from most collections by
        # design, so a missing one costs nothing unless a check depends on it.
        if self.status is HiveStatus.OPEN_FAILED:
            return True
        return self.status is HiveStatus.NOT_COLLECTED and self.name in ESSENTIAL_HIVES

    @property
    def label(self) -> str:
        """Name the hive, with its owner when it belongs to a user."""
        return f"{self.name} [{self.owner}]" if self.owner else self.name

    @property
    def outcome(self) -> str:
        """State what became of the hive, with the reason when one was recorded."""
        return f"{self.status.value}: {self.error}" if self.error else self.status.value


@dataclass(frozen=True, slots=True)
class CheckFailure:
    """One check, registry key or artifact that failed and contributed nothing."""

    check_id: str = ""
    error: str = ""
    # The key or file that was lost, empty when the whole check produced nothing
    artifact: str = ""

    @property
    def label(self) -> str:
        """Name what was lost on one line, the check, the artifact, or both."""
        if not self.artifact:
            return self.check_id
        if not self.check_id:
            return self.artifact
        return f"{self.check_id} artifact {self.artifact}"


class ChangeEvidence(enum.Enum):
    """Why a finding's last-change column holds what it holds."""

    NOT_RUN = "NOT_RUN"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NO_ARTIFACT = "NO_ARTIFACT"
    NO_MATCH = "NO_MATCH"
    REJECTED = "REJECTED"
    RESOLVED = "RESOLVED"


@total_ordering
class Severity(enum.Enum):
    """Finding classification, ordered by declaration: INFO < LOW < MEDIUM < HIGH."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    def __lt__(self, other: Severity) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        members = list(Severity)
        return members.index(self) < members.index(other)


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
        "last_change": "Last Change",
        "change_source": "Change Source",
        "change_evidence": "Change Evidence",
        "is_lolbin": "LOLBin",
        "launcher": "Launcher",
        "exists": "Exists",
        "sha256": "SHA256",
        "is_builtin": "Builtin",
        "is_in_os_directory": "OS Directory",
        "signer": "Signer",
        "hostname": "Hostname",
        "check_id": "Check ID",
        "references": "References",
        "triage_notes": "Triage Notes",
    }

    path: str = ""
    value: str = ""
    technique: str = ""
    mitre_id: str = ""
    description: str = ""
    access_gained: AccessLevel = AccessLevel.USER
    is_lolbin: bool | None = None
    # The launcher the value proxies through, empty when it runs its image directly
    launcher: str = ""
    exists: bool | None = None
    sha256: str = ""
    is_builtin: bool | None = None
    is_in_os_directory: bool | None = None
    signer: str = ""
    hostname: str = ""
    check_id: str = ""
    references: tuple[str, ...] = field(default_factory=tuple)
    # Why the resolved target deserves a second look, empty when nothing does
    triage_notes: str = ""
    severity: Severity = Severity.MEDIUM
    last_change: str = ""
    change_source: str = ""
    change_evidence: ChangeEvidence = ChangeEvidence.NOT_RUN
    # Not in FIELDS: names the file resolution inspects, never a report column
    resolve_target: str = ""
    # Not in FIELDS: evidence descriptors the timeline stage resolves
    time_evidence: tuple[TimeEvidence, ...] = field(default_factory=tuple)
    # Not in FIELDS: every candidate considered, HTML tooltip only
    change_candidates: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class ScanReport:
    """Everything one scan hands a renderer: findings and what the scan lost."""

    findings: list[Finding] = field(default_factory=list)
    inventory: tuple[HiveRecord, ...] = ()
    failures: tuple[CheckFailure, ...] = ()
    hostname: str = ""


class MatchResult(enum.Enum):
    """How well a FilterRule matches a Finding."""

    NONE = "NONE"
    PARTIAL = "PARTIAL"
    FULL = "FULL"


# A PARTIAL allow match lands on LOW, below the default --min-severity of
# medium, so the finding is filtered out of the report. That is deliberate: an
# allow rule whose only failing condition is the signer still suppresses by
# default, while --min-severity low brings the finding back for review.
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
        """Classify how well this rule matches the finding."""
        # NONE when the rule states no conditions. Signer is a soft condition:
        # it degrades the result to PARTIAL rather than NONE, so an unsigned but
        # otherwise legitimate binary keeps its allowlist match.
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


class KeyProtocol(Protocol):
    """Structural type for registry key objects (pyregf.key)."""

    def get_name(self) -> str: ...
    def get_number_of_sub_keys(self) -> int: ...
    def get_sub_key(self, index: int) -> KeyProtocol: ...
    def get_number_of_values(self) -> int: ...
    def get_value(self, index: int) -> KeyProtocol: ...


class HiveProtocol(Protocol):
    """Structural type for registry hive file handles (pyregf.file)."""

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
    include_wow64: bool = False


@dataclass(frozen=True, slots=True)
class FileWriteTime:
    """Time evidence: the $MFT record of a file inside the image."""

    path: str = ""
    weak: bool = False


@dataclass(frozen=True, slots=True)
class EventLogTime:
    """Time evidence: matching records in an event log channel."""

    channel: str = ""
    event_ids: tuple[int, ...] = field(default_factory=tuple)
    match_field: str = ""
    match_value: str = ""


TimeEvidence: TypeAlias = FileWriteTime | EventLogTime


@dataclass(frozen=True, slots=True)
class CheckDefinition:
    """Immutable specification of a persistence check's metadata and targets."""

    id: str = ""
    technique: str = ""
    mitre_id: str = ""
    description: str = ""
    targets: tuple[RegistryTarget, ...] = field(default_factory=tuple)
    references: tuple[str, ...] = field(default_factory=tuple)

    @property
    def reference_links(self) -> tuple[str, ...]:
        """Return the MITRE page of the technique, then any further reading."""
        technique, _, sub_technique = self.mitre_id.partition(".")
        page = f"https://attack.mitre.org/techniques/{technique}/"
        if sub_technique:
            page += f"{sub_technique}/"
        return (page, *self.references)
