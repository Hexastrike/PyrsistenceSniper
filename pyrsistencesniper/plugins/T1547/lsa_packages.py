"""Detections for the LSA package registrations and protection flags."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    CheckDefinition,
    HiveScope,
    RegistryTarget,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin


@register_plugin
class AuthenticationPackages(PersistencePlugin):
    """Detects Authentication Packages persistence entries."""

    definition = CheckDefinition(
        id="authentication_packages",
        technique="Authentication Packages",
        mitre_id="T1547.002",
        description=(
            "Authentication Packages are DLLs LSA loads at system start. The default "
            "is 'msv1_0'."
        ),
        references=("https://attack.mitre.org/techniques/T1547/002/",),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Control\Lsa",
                values="Authentication Packages",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class SecurityPackages(PersistencePlugin):
    """Detects Security Packages persistence entries."""

    definition = CheckDefinition(
        id="security_packages",
        technique="Security Packages",
        mitre_id="T1547.005",
        description=(
            "Security Support Providers (SSPs) are DLLs LSA loads into lsass.exe, "
            "where an SSP sees the plaintext credentials of every interactive logon."
        ),
        references=("https://attack.mitre.org/techniques/T1547/005/",),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Control\Lsa",
                values="Security Packages",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class LsaRunAsPPL(PersistencePlugin):
    """Detects LSASS PPL Protection Status persistence entries."""

    definition = CheckDefinition(
        id="lsa_run_as_ppl",
        technique="LSASS PPL Protection Status",
        mitre_id="T1547.008",
        description=(
            "RunAsPPL controls whether LSASS runs as a Protected Process "
            "Light. When set to 0 or absent, LSA protection is disabled, "
            "weakening credential protection. Value 1 enables protection."
        ),
        references=("https://attack.mitre.org/techniques/T1547/008/",),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Control\Lsa",
                values="RunAsPPL",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class LsaCfgFlags(PersistencePlugin):
    """Detects Credential Guard Configuration persistence entries."""

    definition = CheckDefinition(
        id="lsa_cfg_flags",
        technique="Credential Guard Configuration",
        mitre_id="T1547.008",
        description=(
            "LsaCfgFlags controls Credential Guard. Value 0 disables it, "
            "1 enables with UEFI lock, 2 enables without lock. Disabling "
            "Credential Guard weakens credential isolation."
        ),
        references=("https://attack.mitre.org/techniques/T1547/008/",),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Control\Lsa",
                values="LsaCfgFlags",
                scope=HiveScope.HKLM,
            ),
        ),
    )
