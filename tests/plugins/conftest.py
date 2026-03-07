from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, PropertyMock

from pyrsistencesniper.core.filesystem import FilesystemHelper
from pyrsistencesniper.core.image import ForensicImage, UserProfile
from pyrsistencesniper.core.profile import DetectionProfile
from pyrsistencesniper.core.registry import RegistryHelper, RegistryNode


def make_node(
    name: str = "test",
    values: dict[str, object] | None = None,
    children: dict[str, RegistryNode] | None = None,
) -> RegistryNode:
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
    image = MagicMock(spec=ForensicImage)
    type(image).hostname = PropertyMock(return_value="TESTHOST")
    type(image).active_controlset = PropertyMock(return_value="ControlSet001")
    type(image).user_profiles = PropertyMock(return_value=user_profiles or [])

    registry = MagicMock(spec=RegistryHelper)
    filesystem = FilesystemHelper(image_root=tmp_path)
    profile = DetectionProfile.default()
    return image, registry, filesystem, profile
