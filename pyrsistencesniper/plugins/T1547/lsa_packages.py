from __future__ import annotations

from pyrsistencesniper.core.models import (
    CheckDefinition,
    FilterRule,
    HiveScope,
    RegistryTarget,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin


@register_plugin
class AuthenticationPackages(PersistencePlugin):
    definition = CheckDefinition(
        id="authentication_packages",
        technique="Authentication Packages",
        mitre_id="T1547.002",
        description=(
            "Authentication Packages are DLLs loaded by LSA at system "
            "start. A non-default package (beyond 'msv1_0') may intercept "
            "credentials or provide boot-level persistence."
        ),
        references=("https://attack.mitre.org/techniques/T1547/002/",),
        allow=(FilterRule(reason="Default auth package", value_matches=r"^msv1_0$"),),
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
    definition = CheckDefinition(
        id="security_packages",
        technique="Security Packages",
        mitre_id="T1547.005",
        description=(
            "Security Support Providers (SSPs) are DLLs loaded by LSA "
            "into lsass.exe. A malicious SSP captures plaintext "
            "credentials for every interactive logon."
        ),
        references=("https://attack.mitre.org/techniques/T1547/005/",),
        allow=(
            FilterRule(
                reason="Default Windows SSP",
                value_matches=r"^(kerberos|msv1_0|schannel|wdigest|tspkg|pku2u|cloudap)$",
            ),
        ),
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
        allow=(
            FilterRule(
                reason="LSA protection enabled",
                value_matches=r"^[12]$",
            ),
        ),
    )


@register_plugin
class LsaCfgFlags(PersistencePlugin):
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
        allow=(
            FilterRule(
                reason="Credential Guard enabled",
                value_matches=r"^[12]$",
            ),
        ),
    )
