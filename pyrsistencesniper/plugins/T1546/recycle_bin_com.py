from __future__ import annotations

from pyrsistencesniper.core.models import (
    CheckDefinition,
    HiveScope,
    RegistryTarget,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_RECYCLE_BIN_CLSID = r"{645FF040-5081-101B-9F08-00AA002F954E}"


@register_plugin
class RecycleBinComExtension(PersistencePlugin):
    definition = CheckDefinition(
        id="recycle_bin_com_extension",
        technique="Recycle Bin COM Extension Handler",
        mitre_id="T1546.015",
        description=(
            "Shell verb commands and shell extension handlers on the "
            "Recycle Bin CLSID ({645FF040-...}) are checked for "
            "non-standard values, including ContextMenuHandlers and "
            "DragDropHandlers."
        ),
        references=("https://attack.mitre.org/techniques/T1546/015/",),
        targets=(
            RegistryTarget(
                path=f"SOFTWARE\\Classes\\CLSID\\{_RECYCLE_BIN_CLSID}\\shell\\open\\command",
                values="(Default)",
                scope=HiveScope.HKLM,
            ),
            RegistryTarget(
                path=f"SOFTWARE\\Classes\\CLSID\\{_RECYCLE_BIN_CLSID}\\shell\\empty\\command",
                values="(Default)",
                scope=HiveScope.HKLM,
            ),
            RegistryTarget(
                path=f"SOFTWARE\\Classes\\CLSID\\{_RECYCLE_BIN_CLSID}\\shell\\explore\\command",
                values="(Default)",
                scope=HiveScope.HKLM,
            ),
            RegistryTarget(
                path=f"SOFTWARE\\Classes\\CLSID\\{_RECYCLE_BIN_CLSID}\\shellex\\ContextMenuHandlers",
                values="(Default)",
                recurse=True,
                scope=HiveScope.HKLM,
            ),
            RegistryTarget(
                path=f"SOFTWARE\\Classes\\CLSID\\{_RECYCLE_BIN_CLSID}\\shellex\\DragDropHandlers",
                values="(Default)",
                recurse=True,
                scope=HiveScope.HKLM,
            ),
        ),
    )
