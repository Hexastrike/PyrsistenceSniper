"""Detections for the programs and DLLs Windows runs before user logon."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    CheckDefinition,
    HiveScope,
    RegistryTarget,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin


@register_plugin
class BootExecute(PersistencePlugin):
    """Detects Boot Execute persistence entries."""

    definition = CheckDefinition(
        id="boot_execute",
        technique="Boot Execute",
        mitre_id="T1547.001",
        description=(
            "Session Manager BootExecute programs run before the Windows subsystem "
            "starts. The default is 'autocheck autochk *'."
        ),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Control\Session Manager",
                values="BootExecute",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class SetupExecute(PersistencePlugin):
    """Detects Setup Execute persistence entries."""

    definition = CheckDefinition(
        id="setup_execute",
        technique="Setup Execute",
        mitre_id="T1547.001",
        description=(
            "SetupExecute programs run during early system setup, before the graphical "
            "shell. The value is normally set only while Windows is being installed."
        ),
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
    """Detects Platform Execute persistence entries."""

    definition = CheckDefinition(
        id="platform_execute",
        technique="Platform Execute",
        mitre_id="T1547.001",
        description=(
            "PlatformExecute programs run during early boot for hardware-specific "
            "initialization. The value is rarely set."
        ),
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
    """Detects Session Manager Execute persistence entries."""

    definition = CheckDefinition(
        id="session_manager_execute",
        technique="Session Manager Execute",
        mitre_id="T1547.001",
        description=(
            "The Session Manager Execute value lists programs run during session "
            "initialization, before user logon."
        ),
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
    """Detects S0 Initial Command persistence entries."""

    definition = CheckDefinition(
        id="s0_initial_command",
        technique="S0 Initial Command",
        mitre_id="T1547.001",
        description=(
            "S0InitialCommand names a program run during Session 0 initialization, "
            "before interactive logon. The value is rarely set."
        ),
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
    """Detects Service Control Manager Extension persistence entries."""

    definition = CheckDefinition(
        id="scm_extension",
        technique="Service Control Manager Extension",
        mitre_id="T1547.001",
        description=(
            "ServiceControlManagerExtension values name DLLs the service control "
            "manager loads during boot, inside its own SYSTEM process."
        ),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Control\ServiceControlManagerExtension",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class SessionManagerSubSystems(PersistencePlugin):
    """Detects Session Manager SubSystems persistence entries."""

    definition = CheckDefinition(
        id="session_manager_subsystems",
        technique="Session Manager SubSystems",
        mitre_id="T1547",
        description=(
            "The SubSystems\\Windows value names the Windows subsystem server the "
            "Session Manager starts during boot. The default references csrss.exe."
        ),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Control\Session Manager\SubSystems",
                values="Windows",
                scope=HiveScope.HKLM,
            ),
        ),
    )
