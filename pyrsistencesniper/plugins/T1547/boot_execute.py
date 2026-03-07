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
class BootExecute(PersistencePlugin):
    definition = CheckDefinition(
        id="boot_execute",
        technique="Boot Execute",
        mitre_id="T1547.001",
        description=(
            "Session Manager BootExecute programs run before the Windows "
            "subsystem starts. The legitimate default is 'autocheck "
            "autochk *'; any other entry indicates persistence or "
            "tampering."
        ),
        references=("https://attack.mitre.org/techniques/T1547/001/",),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Control\Session Manager",
                values="BootExecute",
                scope=HiveScope.HKLM,
            ),
        ),
        allow=(
            AllowRule(
                reason="Default Windows boot-time disk check",
                value_contains="autocheck autochk",
            ),
        ),
    )


@register_plugin
class SetupExecute(PersistencePlugin):
    definition = CheckDefinition(
        id="setup_execute",
        technique="Setup Execute",
        mitre_id="T1547.001",
        description=(
            "SetupExecute programs run during early system setup, before "
            "the graphical shell. Any value present is suspicious outside "
            "fresh OS installs."
        ),
        references=("https://attack.mitre.org/techniques/T1547/001/",),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Control\Session Manager",
                values="SetupExecute",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class PlatformExecute(PersistencePlugin):
    definition = CheckDefinition(
        id="platform_execute",
        technique="Platform Execute",
        mitre_id="T1547.001",
        description=(
            "PlatformExecute programs run during early boot for "
            "hardware-specific initialization. Values here are uncommon "
            "and may indicate boot-level persistence."
        ),
        references=("https://attack.mitre.org/techniques/T1547/001/",),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Control\Session Manager",
                values="PlatformExecute",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class SessionManagerExecute(PersistencePlugin):
    definition = CheckDefinition(
        id="session_manager_execute",
        technique="Session Manager Execute",
        mitre_id="T1547.001",
        description=(
            "The Session Manager Execute value runs programs during session "
            "initialization, before user logon. Any value present warrants "
            "investigation."
        ),
        references=("https://attack.mitre.org/techniques/T1547/001/",),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Control\Session Manager",
                values="Execute",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class S0InitialCommand(PersistencePlugin):
    definition = CheckDefinition(
        id="s0_initial_command",
        technique="S0 Initial Command",
        mitre_id="T1547.001",
        description=(
            "S0InitialCommand runs a program during Session 0 "
            "initialization, before interactive logon. Presence of this "
            "value is unusual and suggests persistence."
        ),
        references=("https://attack.mitre.org/techniques/T1547/001/",),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Control\Session Manager",
                values="S0InitialCommand",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class ServiceControlManagerExtension(PersistencePlugin):
    definition = CheckDefinition(
        id="scm_extension",
        technique="Service Control Manager Extension",
        mitre_id="T1547.001",
        description=(
            "ServiceControlManagerExtension values specify DLLs loaded by "
            "the SCM during boot, executing in a highly privileged context."
        ),
        references=("https://attack.mitre.org/techniques/T1547/001/",),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Control\ServiceControlManagerExtension",
                scope=HiveScope.HKLM,
            ),
        ),
    )
