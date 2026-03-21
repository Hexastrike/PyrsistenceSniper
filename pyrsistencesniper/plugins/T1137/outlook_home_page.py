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
_OUTLOOK_FOLDERS: tuple[str, ...] = (
    "Inbox",
    "Calendar",
    "Contacts",
    "Drafts",
    "Journal",
    "Notes",
    "Tasks",
    "Deleted Items",
    "Sent Items",
    "Outbox",
)


@register_plugin
class OutlookHomePage(PersistencePlugin):
    definition = CheckDefinition(
        id="outlook_home_page",
        technique="Outlook Home Page Attack",
        mitre_id="T1137.004",
        description=(
            "Outlook Folder Home Page URLs are loaded as embedded web "
            "pages inside Outlook folder views, allowing execution of "
            "arbitrary HTML/JavaScript/ActiveX content. This feature is "
            "deprecated and never configured in standard deployments."
        ),
        references=("https://attack.mitre.org/techniques/T1137/004/",),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        for profile, hive in self.hive_ops.iter_user_hives():
            for version in _OFFICE_VERSIONS:
                for folder in _OUTLOOK_FOLDERS:
                    webview_path = (
                        f"Software\\Microsoft\\Office\\{version}"
                        f"\\Outlook\\WebView\\{folder}"
                    )
                    node = self.registry.load_subtree(hive, webview_path)
                    if node is None:
                        continue
                    url_val = registry_value_to_str(node.get("URL"))
                    if url_val is None:
                        continue
                    findings.append(
                        self._make_finding(
                            path=(f"HKU\\{profile.username}\\{webview_path}\\URL"),
                            value=url_val,
                            access=AccessLevel.USER,
                        )
                    )

        return findings
