"""Detection for Recycle Bin COM Extension Handler."""

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
    """Detects Recycle Bin COM Extension Handler persistence entries."""

    definition = CheckDefinition(
        id="recycle_bin_com_extension",
        technique="Recycle Bin COM Extension Handler",
        mitre_id="T1546.015",
        description=(
            "Shell verb commands and shell extension handlers registered on the "
            "Recycle Bin's CLSID run in Explorer when a user opens, empties or "
            "right-clicks the Recycle Bin."
        ),
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
