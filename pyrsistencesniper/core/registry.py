from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pyregf

logger = logging.getLogger(__name__)


def _pyregf_extract_data(val: Any) -> object:  # noqa: ANN401
    """Convert a pyregf value to a native Python type (str, int, list, or bytes)."""
    vtype = val.get_type()
    try:
        if vtype in (pyregf.value_types.STRING, pyregf.value_types.EXPANDABLE_STRING):
            return val.get_data_as_string()
        if vtype in (
            pyregf.value_types.INTEGER_32BIT_LITTLE_ENDIAN,
            pyregf.value_types.INTEGER_64BIT_LITTLE_ENDIAN,
            pyregf.value_types.INTEGER_32BIT_BIG_ENDIAN,
        ):
            return val.get_data_as_integer()
        if vtype == pyregf.value_types.MULTI_VALUE_STRING:
            return list(val.get_data_as_multi_string())
    except Exception:
        logger.debug(
            "Failed to extract typed data for value type %s",
            vtype,
            exc_info=True,
        )
    data = val.get_data()
    return data if data is not None else b""


class RegistryNode:
    """In-memory registry key with dict-based value and child lookups."""

    __slots__ = ("_children", "_values", "name")

    def __init__(
        self,
        name: str,
        values: dict[str, tuple[str, object]],
        children: dict[str, RegistryNode],
    ) -> None:
        self.name = name
        self._values = values
        self._children = children

    def get(self, value_name: str) -> object | None:
        """Return a value by name (case-insensitive)."""
        key = value_name.lower()
        if key == "(default)":
            key = ""
        entry = self._values.get(key)
        return entry[1] if entry is not None else None

    def child(self, name: str) -> RegistryNode | None:
        """Return a child subkey by name (case-insensitive), or None."""
        return self._children.get(name.lower())

    def children(self) -> Iterator[tuple[str, RegistryNode]]:
        """Yield (name, node) pairs for all child subkeys."""
        for node in self._children.values():
            yield (node.name, node)

    def values(self) -> Iterator[tuple[str, object]]:
        """Yield (name, data) pairs for all values in this key."""
        yield from self._values.values()


class RegistryHelper:
    """Offline registry hive parser built on pyregf with caching."""

    def __init__(self) -> None:
        self._hive_cache: dict[str, object | None] = {}
        self._subtree_cache: dict[tuple[int, str], RegistryNode | None] = {}

    def open_hive(self, path: Path) -> object | None:
        """Open a registry hive file, caching by resolved path."""
        key = str(path.resolve())
        if key in self._hive_cache:
            return self._hive_cache[key]
        try:
            reg_file = pyregf.file()
            reg_file.open(str(path))
            hive: object | None = reg_file
        except Exception:
            logger.warning("Failed to open hive: %s", path, exc_info=True)
            hive = None
        self._hive_cache[key] = hive
        return hive

    @staticmethod
    def _normalize_key_path(key_path: str) -> str:
        """Strip leading backslash for pyregf compatibility."""
        return key_path.lstrip("\\")

    def load_subtree(self, hive: object, key_path: str) -> RegistryNode | None:
        """Build and cache a RegistryNode tree for the given key path via DFS."""
        norm = self._normalize_key_path(key_path)
        cache_key = (id(hive), norm.lower())
        if cache_key in self._subtree_cache:
            return self._subtree_cache[cache_key]

        pyregf_key = self._resolve_key(hive, key_path)
        if pyregf_key is None:
            self._subtree_cache[cache_key] = None
            return None

        node = _materialize(pyregf_key)
        self._subtree_cache[cache_key] = node
        return node

    @staticmethod
    def _resolve_key(hive: object, key_path: str) -> object | None:
        """Resolve a key path to a pyregf key object, or None."""
        try:
            norm = RegistryHelper._normalize_key_path(key_path)
            return hive.get_key_by_path(norm)  # type: ignore[attr-defined, no-any-return]
        except Exception:
            logger.debug("Could not resolve key %s", key_path, exc_info=True)
            return None


def _materialize(key: Any) -> RegistryNode:  # noqa: ANN401
    """Recursively convert a pyregf key and its children into a RegistryNode tree."""
    name: str = key.get_name()

    values: dict[str, tuple[str, object]] = {}
    for i in range(key.get_number_of_values()):
        val = key.get_value(i)
        val_name: str = val.get_name() or ""
        values[val_name.lower()] = (val_name, _pyregf_extract_data(val))

    children: dict[str, RegistryNode] = {}
    for i in range(key.get_number_of_sub_keys()):
        sk = key.get_sub_key(i)
        child_node = _materialize(sk)
        children[child_node.name.lower()] = child_node

    return RegistryNode(name, values, children)
