"""Check definitions, registry targets, and the HiveProtocol structural type."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Protocol

from pyrsistencesniper.models.finding import FilterRule


class HiveProtocol(Protocol):
    """Structural type for registry hive file handles.

    Matches the interface of pyregf.file that the codebase actually uses,
    without coupling to the C extension at import time.
    """

    def get_key_by_path(self, path: str) -> object | None:
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
