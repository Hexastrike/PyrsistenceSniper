from __future__ import annotations

from pyrsistencesniper.models.finding import AccessLevel, Finding
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import CheckDefinition, PersistencePlugin

_DSRM_NETWORK_LOGON = 2


@register_plugin
class DsrmBackdoor(PersistencePlugin):
    definition = CheckDefinition(
        id="dsrm_backdoor",
        technique="DSRM Admin Logon Behavior",
        mitre_id="T1547.001",
        description=(
            "Setting DsrmAdminLogonBehavior to 2 on a domain controller "
            "enables network logon with the DSRM password, creating a "
            "persistent backdoor that survives password resets."
        ),
        references=("https://attack.mitre.org/techniques/T1547/001/",),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        key_path = r"Control\Lsa"
        for cs in ("ControlSet001", "ControlSet002", "CurrentControlSet"):
            full_path = f"{cs}\\{key_path}"
            tree = self._load_subtree("SYSTEM", full_path)
            if tree is None:
                continue
            val = tree.get("DsrmAdminLogonBehavior")
            if isinstance(val, int) and val == _DSRM_NETWORK_LOGON:
                findings.append(
                    self._make_finding(
                        path=f"HKLM\\SYSTEM\\{full_path}\\DsrmAdminLogonBehavior",
                        value=str(val),
                        access=AccessLevel.SYSTEM,
                    )
                )
        return findings
