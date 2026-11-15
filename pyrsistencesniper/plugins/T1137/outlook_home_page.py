"""Detect Outlook folder Home Page URL persistence (T1137.004)."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
)
from pyrsistencesniper.core.registry import registry_value_to_str
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_OFFICE_VERSIONS: tuple[str, ...] = ("14.0", "15.0", "16.0")


@register_plugin
class OutlookHomePage(PersistencePlugin):
    """Detects Outlook Home Page Attack persistence entries."""

    definition = CheckDefinition(
        id="outlook_home_page",
        technique="Outlook Home Page Attack",
        mitre_id="T1137.004",
        description=(
            "An Outlook folder Home Page URL loads as an embedded web page inside the "
            "folder view and runs arbitrary HTML, JavaScript and ActiveX. The feature "
            "is deprecated and unset in standard deployments."
        ),
    )

    def run(self) -> list[Finding]:
        """Report every Outlook WebView folder that carries a Home Page URL."""
        findings: list[Finding] = []

        for profile, hive in self.context.iter_user_hives():
            for version in _OFFICE_VERSIONS:
                webview_path = (
                    f"Software\\Microsoft\\Office\\{version}\\Outlook\\WebView"
                )
                webview_node = self.registry.load_subtree(hive, webview_path)
                if webview_node is None:
                    continue
                for folder, folder_node in webview_node.children():
                    url_value = registry_value_to_str(folder_node.get("URL"))
                    if url_value is None:
                        continue
                    findings.append(
                        self._make_finding(
                            path=(
                                f"HKU\\{profile.username}"
                                f"\\{webview_path}\\{folder}\\URL"
                            ),
                            value=url_value,
                            access=AccessLevel.USER,
                        )
                    )

        return findings
