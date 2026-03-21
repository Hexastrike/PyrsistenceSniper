from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, PropertyMock, create_autospec

from pyrsistencesniper.core.context import AnalysisContext
from pyrsistencesniper.core.filesystem import FilesystemHelper
from pyrsistencesniper.core.profile import DetectionProfile
from pyrsistencesniper.core.registry import RegistryHelper, RegistryNode

if TYPE_CHECKING:
    from pyrsistencesniper.core.models import UserProfile


def make_node(
    name: str = "test",
    values: dict[str, object] | None = None,
    children: dict[str, RegistryNode] | None = None,
) -> RegistryNode:
    """Build a RegistryNode stub with the given values and children."""
    vals = values or {}
    val_dict = {}
    for k, v in vals.items():
        key = k.lower()
        if key == "(default)":
            key = ""
        val_dict[key] = (k, v)
    child_dict = {}
    if children:
        for cname, cnode in children.items():
            child_dict[cname.lower()] = cnode
    return RegistryNode(name, val_dict, child_dict)


def make_deps(
    tmp_path: Path,
    user_profiles: list[UserProfile] | None = None,
) -> tuple[MagicMock, MagicMock, FilesystemHelper, DetectionProfile]:
    """Create a mock AnalysisContext and its dependencies for plugin testing."""
    registry = create_autospec(RegistryHelper, instance=True)
    filesystem = FilesystemHelper(image_root=tmp_path)
    profile = DetectionProfile()

    context = create_autospec(AnalysisContext, instance=True)
    type(context).hostname = PropertyMock(return_value="TESTHOST")
    type(context).active_controlset = PropertyMock(return_value="ControlSet001")
    type(context).user_profiles = PropertyMock(return_value=user_profiles or [])
    context.registry = registry
    context.filesystem = filesystem
    context.profile = profile

    return context, registry, filesystem, profile


def make_plugin(
    cls: type,
    tmp_path: Path,
    *,
    user_profiles: list[UserProfile] | None = None,
) -> object:
    """Instantiate a plugin class with a mocked AnalysisContext."""
    context, registry, _filesystem, _profile = make_deps(
        tmp_path, user_profiles=user_profiles
    )
    context.registry = registry
    return cls(context=context)


def setup_hklm(
    plugin: object,
    tree_node: object,
    *,
    hive_path: str = "/fake/SOFTWARE",
) -> None:
    """Wire a mock HKLM hive so the plugin reads *tree_node* as its subtree."""
    plugin.context.hive_path.return_value = Path(hive_path)  # type: ignore[union-attr]
    plugin.registry.open_hive.return_value = MagicMock()  # type: ignore[union-attr]
    plugin.registry.load_subtree.return_value = tree_node  # type: ignore[union-attr]


def setup_filesystem(
    plugin: object,
    files: dict[str, bytes | str],
) -> None:
    """Create test files under the plugin's filesystem image_root.

    Counterpart to setup_hklm for filesystem-based plugins.

    Args:
        plugin: Plugin instance created by make_plugin (has .filesystem attribute
                via .context.filesystem which is a real FilesystemHelper).
        files: Mapping of relative paths (from image_root) to file content.
    """
    root = plugin.filesystem.image_root  # type: ignore[union-attr]
    for rel_path, content in files.items():
        target = root / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content)
