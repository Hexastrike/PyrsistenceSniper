from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from pyrsistencesniper.models.finding import FilterRule, Finding

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class CheckOverride:
    """Enable/disable state and allow/block rules scoped to a single check."""

    enabled: bool = True
    allow: tuple[FilterRule, ...] = field(default_factory=tuple)
    block: tuple[FilterRule, ...] = field(default_factory=tuple)


_DEFAULT_TRUSTED_SIGNERS: frozenset[str] = frozenset(
    {
        "microsoft windows",
        "microsoft corporation",
        "microsoft windows publisher",
    }
)


@dataclass(frozen=True, slots=True)
class DetectionProfile:
    """YAML-driven detection profile with global and per-check allow/block rules."""

    allow: tuple[FilterRule, ...] = field(default_factory=tuple)
    block: tuple[FilterRule, ...] = field(default_factory=tuple)
    checks: dict[str, CheckOverride] = field(default_factory=dict)
    trusted_signers: frozenset[str] = field(
        default_factory=lambda: _DEFAULT_TRUSTED_SIGNERS
    )

    @classmethod
    def load(cls, path: Path) -> DetectionProfile:
        """Parse a YAML profile file into a DetectionProfile."""
        try:
            with path.open("r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except FileNotFoundError:
            logger.warning("Profile not found: %s, using defaults", path)
            return cls.default()
        except (yaml.YAMLError, OSError) as exc:
            raise ValueError(f"Failed to parse detection profile {path}") from exc

        if not isinstance(data, dict):
            raise TypeError(
                f"Detection profile {path} must be a YAML mapping,"
                f" got {type(data).__name__}"
            )

        global_allow = _parse_rules(data.get("allow", []))
        global_block = _parse_rules(data.get("block", []))
        checks: dict[str, CheckOverride] = {}
        checks_raw = data.get("checks", {})
        if not isinstance(checks_raw, dict):
            checks_raw = {}
        for check_id, check_data in checks_raw.items():
            if not isinstance(check_data, dict):
                continue
            checks[check_id] = CheckOverride(
                enabled=check_data.get("enabled", True),
                allow=_parse_rules(check_data.get("allow", [])),
                block=_parse_rules(check_data.get("block", [])),
            )
        trusted_signers_raw = data.get("trusted_signers")
        if isinstance(trusted_signers_raw, list):
            trusted_signers = frozenset(
                str(s).lower() for s in trusted_signers_raw if s
            )
        else:
            trusted_signers = _DEFAULT_TRUSTED_SIGNERS

        return cls(
            allow=global_allow,
            block=global_block,
            checks=checks,
            trusted_signers=trusted_signers,
        )

    @classmethod
    def default(cls) -> DetectionProfile:
        """Return a profile with no rules and default trusted signers."""
        return cls()

    def is_enabled(self, check_id: str) -> bool:
        """Return True if the check is enabled (default) or not explicitly disabled."""
        override = self.checks.get(check_id)
        if override is not None:
            return override.enabled
        return True

    def matches_allow(self, check_id: str, finding: Finding) -> bool:
        """Return True if any allow rule matches the finding."""
        return self._any_rule_matches(check_id, finding, self.allow, "allow")

    def matches_block(self, check_id: str, finding: Finding) -> bool:
        """Return True if any block rule matches the finding."""
        return self._any_rule_matches(check_id, finding, self.block, "block")

    def _any_rule_matches(
        self,
        check_id: str,
        finding: Finding,
        global_rules: tuple[FilterRule, ...],
        override_attr: str,
    ) -> bool:
        """Test global rules then check-specific rules for a match."""
        for rule in global_rules:
            if rule.matches(finding):
                return True
        override = self.checks.get(check_id)
        if override:
            for rule in getattr(override, override_attr):
                if rule.matches(finding):
                    return True
        return False


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
                value_equals=item.get("value_equals", ""),
                value_contains=item.get("value_contains", ""),
                path_equals=item.get("path_equals", ""),
                path_contains=item.get("path_contains", ""),
                signer=item.get("signer", ""),
                hash=item.get("hash", ""),
                not_lolbin=bool(item.get("not_lolbin", False)),
            )
        )
    return tuple(rules)
