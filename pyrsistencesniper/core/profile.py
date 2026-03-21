"""YAML-driven detection profiles with global and per-check allow/block rules."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from pyrsistencesniper.core.models import FilterRule

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class CheckOverride:
    """Enable/disable state and allow/block rules scoped to a single check."""

    enabled: bool = True
    allow: tuple[FilterRule, ...] = field(default_factory=tuple)
    block: tuple[FilterRule, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class DetectionProfile:
    """YAML-driven detection profile with global and per-check allow/block rules."""

    allow: tuple[FilterRule, ...] = field(default_factory=tuple)
    block: tuple[FilterRule, ...] = field(default_factory=tuple)
    checks: dict[str, CheckOverride] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path | None) -> DetectionProfile:
        """Parse a YAML profile file into a DetectionProfile.

        Returns an empty profile when *path* is None.
        """
        if path is None:
            return cls()
        data = _read_yaml(path)
        if data is None:
            return cls()
        return cls(
            allow=_parse_rules(data.get("allow", [])),
            block=_parse_rules(data.get("block", [])),
            checks=_parse_checks(data.get("checks", {})),
        )

    def effective_rules(self, check_id: str) -> CheckOverride:
        """Return rules for a check (global + check-specific, merged)."""
        override = self.checks.get(check_id)
        if override is None:
            return CheckOverride(allow=self.allow, block=self.block)
        return CheckOverride(
            enabled=override.enabled,
            allow=(*self.allow, *override.allow),
            block=(*self.block, *override.block),
        )


def _read_yaml(path: Path) -> dict[str, object] | None:
    """Read and validate a YAML profile file.

    Returns the parsed dict, or None if the file does not exist.
    Raises ValueError on parse errors and TypeError on invalid structure.
    """
    try:
        with path.open("r", encoding="utf-8") as profile_file:
            data = yaml.safe_load(profile_file)
    except FileNotFoundError:
        logger.warning("Profile not found: %s, using defaults", path)
        return None
    except (yaml.YAMLError, OSError) as exc:
        raise ValueError(f"Failed to parse detection profile {path}") from exc

    if not isinstance(data, dict):
        raise TypeError(
            f"Detection profile {path} must be a YAML mapping,"
            f" got {type(data).__name__}"
        )
    return data


def _parse_checks(raw: object) -> dict[str, CheckOverride]:
    """Convert a raw checks mapping into a dict of CheckOverride instances."""
    if not isinstance(raw, dict):
        return {}
    checks: dict[str, CheckOverride] = {}
    for check_id, check_data in raw.items():
        if not isinstance(check_data, dict):
            continue
        checks[check_id] = CheckOverride(
            enabled=check_data.get("enabled", True),
            allow=_parse_rules(check_data.get("allow", [])),
            block=_parse_rules(check_data.get("block", [])),
        )
    return checks


def _parse_rules(raw: object) -> tuple[FilterRule, ...]:
    """Convert a list of rule dictionaries into a tuple of FilterRule instances."""
    if not isinstance(raw, list):
        return ()
    rules: list[FilterRule] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        rules.append(
            FilterRule(
                reason=item.get("reason", ""),
                value_matches=item.get("value_matches", ""),
                path_matches=item.get("path_matches", ""),
                signer=item.get("signer", ""),
                hash=item.get("hash", ""),
                not_lolbin=bool(item.get("not_lolbin", False)),
            )
        )
    return tuple(rules)
