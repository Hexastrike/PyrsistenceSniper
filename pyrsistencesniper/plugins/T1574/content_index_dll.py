"""Detection for NL6 ContentIndex DLL Override."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    CheckDefinition,
    HiveScope,
    RegistryTarget,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin


@register_plugin
class ContentIndexDll(PersistencePlugin):
    """Detects NL6 ContentIndex DLL Override persistence entries."""

    definition = CheckDefinition(
        id="content_index_dll",
        technique="NL6 ContentIndex DLL Override",
        mitre_id="T1574",
        description=(
            "DLLOverridePath under a ContentIndex\\Language subkey names a DLL the "
            "Windows Search indexer loads in place of the default NL6 content indexing "
            "DLL. The value is normally absent."
        ),
        targets=(
            RegistryTarget(
                path=r"SYSTEM\{controlset}\Control\ContentIndex\Language",
                values="DLLOverridePath",
                recurse=True,
                scope=HiveScope.HKLM,
            ),
        ),
    )
