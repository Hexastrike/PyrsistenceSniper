from __future__ import annotations

from pyrsistencesniper.models.finding import AllowRule
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import (
    CheckDefinition,
    HiveScope,
    PersistencePlugin,
    RegistryTarget,
)


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
        allow=(AllowRule(reason="Default auth package", value_contains="msv1_0"),),
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
            AllowRule(reason="Default Windows SSP", value_contains="kerberos"),
            AllowRule(reason="Default Windows SSP", value_contains="msv1_0"),
            AllowRule(reason="Default Windows SSP", value_contains="schannel"),
            AllowRule(reason="Default Windows SSP", value_contains="wdigest"),
            AllowRule(reason="Default Windows SSP", value_contains="tspkg"),
            AllowRule(reason="Default Windows SSP", value_contains="pku2u"),
            AllowRule(reason="Default Windows SSP", value_contains="cloudap"),
        ),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Control\Lsa",
                values="Security Packages",
                scope=HiveScope.HKLM,
            ),
        ),
    )
