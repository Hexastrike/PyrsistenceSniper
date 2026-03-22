from __future__ import annotations

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    FilterRule,
    Finding,
    HiveScope,
    RegistryTarget,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin


@register_plugin
class AeDebug(PersistencePlugin):
    definition = CheckDefinition(
        id="ae_debug",
        technique="AeDebug Debugger Hijack",
        mitre_id="T1546.012",
        description=(
            "The AeDebug Debugger value specifies the Just-In-Time "
            "debugger launched on application crashes. Replacing it with "
            "a malicious binary provides persistence triggered by any "
            "user-mode crash."
        ),
        references=("https://attack.mitre.org/techniques/T1546/012/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug",
                values="Debugger",
                scope=HiveScope.HKLM,
            ),
        ),
        allow=(
            FilterRule(
                reason="Known JIT debugger", value_matches=r"(vsjitdebugger|drwtsn32)"
            ),
        ),
    )


@register_plugin
class AeDebugProtected(PersistencePlugin):
    definition = CheckDefinition(
        id="ae_debug_protected",
        technique="AeDebug Protected Process Debugger",
        mitre_id="T1546.012",
        description=(
            "The AeDebugProtected Debugger value targets protected-process "
            "crash debugging and can be abused identically to AeDebug for "
            "crash-triggered persistence."
        ),
        references=("https://attack.mitre.org/techniques/T1546/012/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebugProtected",
                values="Debugger",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class WerDebugger(PersistencePlugin):
    definition = CheckDefinition(
        id="wer_debugger",
        technique="WER Debugger Hijack",
        mitre_id="T1546",
        description=(
            "The Windows Error Reporting Debugger value is invoked when "
            "WER processes an application crash, providing an alternative "
            "crash-handler persistence vector."
        ),
        references=("https://attack.mitre.org/techniques/T1546/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Windows\Windows Error Reporting",
                values="Debugger",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class WerReflectDebugger(PersistencePlugin):
    definition = CheckDefinition(
        id="wer_reflect_debugger",
        technique="WER ReflectDebugger Hijack",
        mitre_id="T1546",
        description=(
            "The WER ReflectDebugger value is invoked for reflection-based "
            "crash analysis and can be hijacked for persistence via "
            "application failures."
        ),
        references=("https://attack.mitre.org/techniques/T1546/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Windows\Windows Error Reporting",
                values="ReflectDebugger",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class WerHangs(PersistencePlugin):
    definition = CheckDefinition(
        id="wer_hangs",
        technique="WER Hangs Debugger Hijack",
        mitre_id="T1546",
        description=(
            "The WER Hangs Debugger value is invoked when Windows detects "
            "an application hang (not responding), providing persistence "
            "triggered by UI freezes."
        ),
        references=("https://attack.mitre.org/techniques/T1546/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs",
                values="Debugger",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class WerRuntimeExceptionHelperModules(PersistencePlugin):
    definition = CheckDefinition(
        id="wer_runtime_exception",
        technique="WER Runtime Exception Modules",
        mitre_id="T1546",
        description=(
            "RuntimeExceptionHelperModules are DLLs loaded by WER when "
            "handling unhandled exceptions. Registering a malicious module "
            "provides DLL-based persistence via application crashes."
        ),
        references=("https://attack.mitre.org/techniques/T1546/",),
        allow=(
            FilterRule(
                reason="Known WER helper module",
                value_matches=r"(mscordacwks|iertutil|msiwer|wbiosrvc|msedge_wer)\.dll",
                signer="Microsoft",
            ),
            FilterRule(
                reason="Google Chrome WER helper",
                value_matches=r"chrome_wer\.dll",
                signer="Google",
            ),
        ),
    )

    def run(self) -> list[Finding]:
        """Report RuntimeExceptionHelperModules DLL paths."""
        findings: list[Finding] = []

        key_path = (
            r"Microsoft\Windows"
            r"\Windows Error Reporting"
            r"\RuntimeExceptionHelperModules"
        )
        tree = self.hive_ops.load_subtree("SOFTWARE", key_path)
        if tree is None:
            return findings

        for name, _val in tree.values():
            if not name.strip():
                continue
            findings.append(
                self._make_finding(
                    path=f"HKLM\\SOFTWARE\\{key_path}\\{name}",
                    value=name,
                    access=AccessLevel.SYSTEM,
                )
            )

        return findings


@register_plugin
class DotNetDbgManagedDebugger(PersistencePlugin):
    definition = CheckDefinition(
        id="dotnet_dbg_managed_debugger",
        technique=".NET DbgManagedDebugger Hijack",
        mitre_id="T1546",
        description=(
            "DbgManagedDebugger specifies the debugger for managed (.NET) "
            "application crashes. Both native and WoW64 paths are checked. "
            "Abuse provides persistence when any .NET application faults."
        ),
        references=("https://attack.mitre.org/techniques/T1546/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Microsoft\.NETFramework",
                values="DbgManagedDebugger",
                scope=HiveScope.BOTH,
            ),
            RegistryTarget(
                path=r"SOFTWARE\Wow6432Node\Microsoft\.NETFramework",
                values="DbgManagedDebugger",
                scope=HiveScope.HKLM,
            ),
        ),
    )


@register_plugin
class LsmDebugger(PersistencePlugin):
    definition = CheckDefinition(
        id="lsm_debugger",
        technique="LSM Debugger Hijack",
        mitre_id="T1546.012",
        description=(
            "The SilentProcessExit MonitorProcess for lsm.exe is invoked "
            "when the Local Session Manager terminates, providing "
            "persistence tied to session management events."
        ),
        references=("https://attack.mitre.org/techniques/T1546/012/",),
        targets=(
            RegistryTarget(
                path=(
                    r"SOFTWARE\Microsoft\Windows NT"
                    r"\CurrentVersion\SilentProcessExit"
                    r"\lsm.exe"
                ),
                values="MonitorProcess",
                scope=HiveScope.HKLM,
            ),
        ),
    )
