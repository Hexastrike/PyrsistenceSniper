"""Detect Office add-in persistence across machine, per-user and ClickToRun hives."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
    HiveProtocol,
)
from pyrsistencesniper.core.registry import RegistryNode, registry_key_join
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_OFFICE_APPS: tuple[str, ...] = (
    "Word",
    "Excel",
    "PowerPoint",
    "Outlook",
    "Access",
)

_OFFICE_VERSIONS: tuple[str, ...] = ("", "14.0", "15.0", "16.0")

_REGISTRATION_VALUES: tuple[str, ...] = ("Manifest", "FileName", "Path")

_CLICK_TO_RUN_MACHINE = "Microsoft\\Office\\ClickToRun\\REGISTRY\\MACHINE"

_MACHINE_ADDIN_ROOTS: tuple[str, ...] = (
    "Microsoft\\Office",
    f"{_CLICK_TO_RUN_MACHINE}\\Software\\Microsoft\\Office",
)

_MACHINE_CLASS_ROOTS: tuple[str, ...] = (
    "Classes",
    "Classes\\Wow6432Node",
    f"{_CLICK_TO_RUN_MACHINE}\\Software\\Classes",
    f"{_CLICK_TO_RUN_MACHINE}\\Software\\Classes\\Wow6432Node",
)

_NTUSER_CLASS_ROOTS: tuple[str, ...] = (
    "Software\\Classes",
    "Software\\Classes\\Wow6432Node",
)

_USRCLASS_CLASS_ROOTS: tuple[str, ...] = ("", "Wow6432Node")

_LOAD_BEHAVIORS: dict[int, str] = {
    0: "registered but not loaded",
    1: "loaded, no startup load",
    2: "loads at application startup, currently disconnected",
    3: "loads automatically at application startup",
    8: "loads on demand, currently disconnected",
    9: "loads on demand",
    16: "loads once on first use, then on demand",
}


def _describe_load_behavior(raw_value: object) -> str:
    """Render a LoadBehavior value as the load state Office reads it as."""
    if raw_value is None:
        return "absent"
    try:
        behavior = int(str(raw_value).strip(), 0)
    except ValueError:
        return f"{raw_value} (unrecognized)"
    return f"{behavior} ({_LOAD_BEHAVIORS.get(behavior, 'undocumented load state')})"


@register_plugin
class OfficeAddins(PersistencePlugin):
    """Detects Office Add-in Registration persistence entries."""

    definition = CheckDefinition(
        id="office_addins",
        technique="Office Add-in Registration",
        mitre_id="T1137.006",
        description=(
            "Office add-in registrations under per-application Addins keys load code "
            "at application startup, either directly through a Manifest, FileName or "
            "Path value or, for a classic COM add-in, through the ProgID to CLSID to "
            "InprocServer32 chain in Software\\Classes. LoadBehavior records whether "
            "the add-in loads automatically."
        ),
    )

    def run(self) -> list[Finding]:
        """Report every Office add-in registration across the scanned hives."""
        findings: list[Finding] = []

        machine_hive = self.context.open_hive_by_name("SOFTWARE")
        machine_class_roots: list[tuple[HiveProtocol, str]] = []
        if machine_hive is not None:
            machine_class_roots = [
                (machine_hive, class_root) for class_root in _MACHINE_CLASS_ROOTS
            ]
            for addin_root in _MACHINE_ADDIN_ROOTS:
                self._scan_addins_hive(
                    machine_hive,
                    addin_root,
                    "HKLM\\SOFTWARE",
                    AccessLevel.SYSTEM,
                    machine_class_roots,
                    findings,
                )

        usrclass_hives = {
            profile.username: hive
            for profile, hive in self.context.iter_usrclass_hives()
        }

        for profile, user_hive in self.context.iter_user_hives():
            class_roots: list[tuple[HiveProtocol, str]] = [
                (user_hive, class_root) for class_root in _NTUSER_CLASS_ROOTS
            ]
            usrclass_hive = usrclass_hives.get(profile.username)
            if usrclass_hive is not None:
                class_roots.extend(
                    (usrclass_hive, class_root) for class_root in _USRCLASS_CLASS_ROOTS
                )
            class_roots.extend(machine_class_roots)
            self._scan_addins_hive(
                user_hive,
                "Software\\Microsoft\\Office",
                f"HKU\\{profile.username}",
                AccessLevel.USER,
                class_roots,
                findings,
            )

        return findings

    def _scan_addins_hive(
        self,
        hive: HiveProtocol,
        base_path: str,
        path_prefix: str,
        access: AccessLevel,
        class_roots: list[tuple[HiveProtocol, str]],
        findings: list[Finding],
    ) -> None:
        """Scan one hive's Addins keys for every Office application and version."""
        for app in _OFFICE_APPS:
            for version in _OFFICE_VERSIONS:
                version_segment = f"{version}\\" if version else ""
                addins_path = f"{base_path}\\{version_segment}{app}\\Addins"
                tree = self.registry.load_subtree(hive, addins_path)
                if tree is None:
                    continue
                for addin, node in tree.children():
                    self._scan_addin(
                        node,
                        addin,
                        f"{path_prefix}\\{addins_path}\\{addin}",
                        access,
                        class_roots,
                        findings,
                    )

    def _scan_addin(
        self,
        node: RegistryNode,
        addin: str,
        addin_path: str,
        access: AccessLevel,
        class_roots: list[tuple[HiveProtocol, str]],
        findings: list[Finding],
    ) -> None:
        """Emit a finding for every load point one add-in registration declares."""
        raw_behavior = node.get("LoadBehavior")
        load_behavior = _describe_load_behavior(raw_behavior)
        declared_image = False
        for value_name in _REGISTRATION_VALUES:
            raw_value = node.get(value_name)
            if raw_value is None:
                continue
            declared_image = True
            findings.append(
                self._make_finding(
                    path=f"{addin_path}\\{value_name}",
                    value=str(raw_value),
                    access=access,
                    description=self._addin_description(load_behavior, ""),
                )
            )
        if declared_image or raw_behavior is None:
            return
        clsid, image = self._com_server_image(addin, class_roots)
        if not image:
            return
        findings.append(
            self._make_finding(
                path=addin_path,
                value=image,
                access=access,
                description=self._addin_description(load_behavior, clsid),
            )
        )

    def _addin_description(self, load_behavior: str, clsid: str) -> str:
        """Render the per-finding description carrying load state and COM class."""
        details = f"LoadBehavior: {load_behavior}"
        if clsid:
            details = f"{details}; COM server {clsid}"
        return f"{self.definition.description} ({details})"

    def _com_server_image(
        self, addin: str, class_roots: list[tuple[HiveProtocol, str]]
    ) -> tuple[str, str]:
        """Follow ProgID to CLSID to InprocServer32, returning the CLSID and DLL."""
        clsid = (
            addin if addin.startswith("{") else self._progid_clsid(addin, class_roots)
        )
        if not clsid:
            return "", ""
        for hive, class_root in class_roots:
            image = self.context.resolve_clsid_default(
                hive, registry_key_join(class_root, "CLSID", clsid, "InprocServer32")
            )
            if image.strip():
                return clsid, image.strip()
        return clsid, ""

    def _progid_clsid(
        self, progid: str, class_roots: list[tuple[HiveProtocol, str]]
    ) -> str:
        """Return the CLSID an add-in ProgID maps to, or empty when unregistered."""
        for hive, class_root in class_roots:
            clsid = self.context.resolve_clsid_default(
                hive, registry_key_join(class_root, progid, "CLSID")
            )
            if clsid.startswith("{"):
                return clsid
        return ""


@register_plugin
class OfficeAiHijack(PersistencePlugin):
    """Detects Office AI Add-in Hijack persistence entries."""

    definition = CheckDefinition(
        id="office_ai_hijack",
        technique="Office AI Add-in Hijack",
        mitre_id="T1137.006",
        description=(
            "Values under the ClickToRun Common\\AI key register the COM DLLs Office "
            "loads when its AI features are invoked."
        ),
    )

    def run(self) -> list[Finding]:
        """Report every value under the ClickToRun Office AI key."""
        findings: list[Finding] = []

        ai_path = (
            r"Microsoft\Office\ClickToRun\REGISTRY\MACHINE"
            r"\Software\Microsoft\Office\16.0\Common\AI"
        )
        tree = self.context.load_subtree("SOFTWARE", ai_path)
        if tree is None:
            return findings

        for value_name, raw_value in tree.values():
            if raw_value is not None:
                findings.append(
                    self._make_finding(
                        path=f"HKLM\\SOFTWARE\\{ai_path}\\{value_name}",
                        value=str(raw_value),
                        access=AccessLevel.SYSTEM,
                    )
                )

        return findings
