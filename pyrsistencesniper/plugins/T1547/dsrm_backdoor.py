"""Detection for DSRM Admin Logon Behavior."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_DSRM_NETWORK_LOGON = 2


@register_plugin
class DsrmBackdoor(PersistencePlugin):
    """Detects DSRM Admin Logon Behavior persistence entries."""

    definition = CheckDefinition(
        id="dsrm_backdoor",
        technique="DSRM Admin Logon Behavior",
        mitre_id="T1547.001",
        description=(
            "Setting DsrmAdminLogonBehavior to 2 on a domain controller "
            "enables network logon with the DSRM password, creating a "
            "persistent backdoor that survives password resets."
        ),
    )

    def run(self) -> list[Finding]:
        """Report DsrmAdminLogonBehavior set to network logon in any control set."""
        findings: list[Finding] = []
        key_path = r"Control\Lsa"
        for controlset_name in ("ControlSet001", "ControlSet002", "CurrentControlSet"):
            full_path = f"{controlset_name}\\{key_path}"
            tree = self.context.load_subtree("SYSTEM", full_path)
            if tree is None:
                continue
            behavior = tree.get("DsrmAdminLogonBehavior")
            if isinstance(behavior, int) and behavior == _DSRM_NETWORK_LOGON:
                findings.append(
                    self._make_finding(
                        path=f"HKLM\\SYSTEM\\{full_path}\\DsrmAdminLogonBehavior",
                        value=str(behavior),
                        access=AccessLevel.SYSTEM,
                    )
                )
        return findings
