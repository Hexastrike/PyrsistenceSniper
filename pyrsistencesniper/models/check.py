from __future__ import annotations

import enum
from dataclasses import dataclass, field

from pyrsistencesniper.models.finding import FilterRule


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


@dataclass(frozen=True, slots=True)
class CheckDefinition:
    """Immutable specification of a persistence check's metadata and targets."""

    id: str = ""
    technique: str = ""
    mitre_id: str = ""
    description: str = ""
    targets: tuple[RegistryTarget, ...] = field(default_factory=tuple)
    references: tuple[str, ...] = field(default_factory=tuple)
    # Policy-level suppression — filters valid-but-expected findings.
    # Bypassed by --raw.  For rejecting invalid data, filter in run().
    allow: tuple[FilterRule, ...] = field(default_factory=tuple)
    block: tuple[FilterRule, ...] = field(default_factory=tuple)
