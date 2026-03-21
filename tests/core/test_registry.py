"""Tests for core/registry.py — RegistryHelper, HiveOps, registry_value_to_str."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, PropertyMock, create_autospec, patch

import pyregf
from pyrsistencesniper.core.context import AnalysisContext
from pyrsistencesniper.core.registry import (
    HiveOps,
    RegistryHelper,
    RegistryNode,
    registry_value_to_str,
)

if TYPE_CHECKING:
    from pathlib import Path


# -- helpers to build fake pyregf objects ------------------------------------


def _make_value(
    name: str,
    data: object,
    vtype: int = pyregf.value_types.STRING,
) -> MagicMock:
    """Return a mock pyregf value object."""
    val = MagicMock()
    val.get_name.return_value = name
    val.get_type.return_value = vtype
    if vtype in (pyregf.value_types.STRING, pyregf.value_types.EXPANDABLE_STRING):
        val.get_data_as_string.return_value = data
    elif vtype in (
        pyregf.value_types.INTEGER_32BIT_LITTLE_ENDIAN,
        pyregf.value_types.INTEGER_64BIT_LITTLE_ENDIAN,
        pyregf.value_types.INTEGER_32BIT_BIG_ENDIAN,
    ):
        val.get_data_as_integer.return_value = data
    elif vtype == pyregf.value_types.MULTI_VALUE_STRING:
        val.get_data_as_multi_string.return_value = data
    else:
        val.get_data.return_value = data
    return val


def _make_key(
    values: list[MagicMock] | None = None,
    subkeys: list[MagicMock] | None = None,
) -> MagicMock:
    """Return a mock pyregf key object."""
    key = MagicMock()
    vals = values or []
    sks = subkeys or []
    key.get_number_of_values.return_value = len(vals)
    key.get_value.side_effect = lambda i: vals[i]
    key.get_number_of_sub_keys.return_value = len(sks)
    key.get_sub_key.side_effect = lambda i: sks[i]
    return key


def _make_subkey(name: str) -> MagicMock:
    sk = MagicMock()
    sk.get_name.return_value = name
    return sk


def _make_hive(keys: dict[str, MagicMock | None] | None = None) -> MagicMock:
    """Return a mock pyregf file (hive) object.

    *keys* maps normalised key paths to mock key objects (or None for
    missing keys).
    """
    hive = MagicMock()
    mapping = keys or {}

    def lookup(path: str) -> MagicMock | None:
        return mapping.get(path)

    hive.get_key_by_path.side_effect = lookup
    return hive


# -- RegistryHelper.open_hive ------------------------------------------------


@patch("pyrsistencesniper.core.registry.pyregf")
def test_open_hive_success(mock_pyregf: MagicMock, tmp_path: Path) -> None:
    fake_hive = MagicMock()
    mock_pyregf.file.return_value = fake_hive

    reg = RegistryHelper()
    hive_path = tmp_path / "SOFTWARE"
    hive_path.touch()

    result = reg.open_hive(hive_path)
    assert result is fake_hive
    fake_hive.open.assert_called_once_with(str(hive_path))


@patch("pyrsistencesniper.core.registry.pyregf")
def test_open_hive_failure(mock_pyregf: MagicMock, tmp_path: Path) -> None:
    fake_hive = MagicMock()
    fake_hive.open.side_effect = OSError("bad hive")
    mock_pyregf.file.return_value = fake_hive

    reg = RegistryHelper()
    result = reg.open_hive(tmp_path / "BAD_HIVE")
    assert result is None


@patch("pyrsistencesniper.core.registry.pyregf")
def test_open_hive_caches(mock_pyregf: MagicMock, tmp_path: Path) -> None:
    fake_hive = MagicMock()
    mock_pyregf.file.return_value = fake_hive

    reg = RegistryHelper()
    hive_path = tmp_path / "SOFTWARE"
    hive_path.touch()

    result1 = reg.open_hive(hive_path)
    result2 = reg.open_hive(hive_path)

    assert result1 is result2
    # pyregf.file() should only be called once
    assert mock_pyregf.file.call_count == 1


# -- HiveOps helpers ---------------------------------------------------------


def _make_hive_ops() -> HiveOps:
    context = create_autospec(AnalysisContext, instance=True)
    type(context).hostname = PropertyMock(return_value="TESTHOST")
    context.registry = MagicMock()
    context.profile = MagicMock()
    return HiveOps(context)


def _make_node(values: dict[str, object]) -> RegistryNode:
    """Build a RegistryNode from {name: data} pairs."""
    val_dict = {k.lower(): (k, v) for k, v in values.items()}
    return RegistryNode("test", val_dict, {})


# -- registry_value_to_str ----------------------------------------------------


def test_registry_value_to_str_string() -> None:
    assert registry_value_to_str("hello") == "hello"


def test_registry_value_to_str_none() -> None:
    assert registry_value_to_str(None) is None


def test_registry_value_to_str_blank() -> None:
    assert registry_value_to_str("   ") is None


def test_registry_value_to_str_integer() -> None:
    assert registry_value_to_str(42) == "42"


def test_registry_value_to_str_strips_whitespace() -> None:
    assert registry_value_to_str("  foo  ") == "foo"


# -- HiveOps.open_hive --------------------------------------------------------


def test_hive_ops_open_hive_returns_hive() -> None:
    hive_ops = _make_hive_ops()
    sentinel = object()
    hive_ops._context.hive_path.return_value = Path("/fake/SYSTEM")
    hive_ops._registry.open_hive.return_value = sentinel

    result = hive_ops.open_hive("SYSTEM")
    assert result is sentinel
    hive_ops._context.hive_path.assert_called_once_with("SYSTEM")
    hive_ops._registry.open_hive.assert_called_once_with(Path("/fake/SYSTEM"))


def test_hive_ops_open_hive_returns_none_when_no_path() -> None:
    hive_ops = _make_hive_ops()
    hive_ops._context.hive_path.return_value = None

    result = hive_ops.open_hive("SOFTWARE")
    assert result is None
    hive_ops._registry.open_hive.assert_not_called()


def test_hive_ops_open_hive_returns_none_when_open_fails() -> None:
    hive_ops = _make_hive_ops()
    hive_ops._context.hive_path.return_value = Path("/fake/SYSTEM")
    hive_ops._registry.open_hive.return_value = None

    result = hive_ops.open_hive("SYSTEM")
    assert result is None


# -- HiveOps.resolve_clsid_default -------------------------------------------


def test_resolve_clsid_default_found() -> None:
    hive_ops = _make_hive_ops()
    hive = MagicMock()
    hive_ops._registry.load_subtree.return_value = _make_node(
        {"": "C:\\Windows\\evil.dll", "ThreadingModel": "Both"}
    )

    subpath = "Classes\\CLSID\\{abc}\\InprocServer32"
    result = hive_ops.resolve_clsid_default(hive, subpath)
    assert result == "C:\\Windows\\evil.dll"


def test_resolve_clsid_default_not_found() -> None:
    hive_ops = _make_hive_ops()
    hive = MagicMock()
    hive_ops._registry.load_subtree.return_value = _make_node(
        {"ThreadingModel": "Both"}
    )

    subpath = "Classes\\CLSID\\{abc}\\InprocServer32"
    result = hive_ops.resolve_clsid_default(hive, subpath)
    assert result == ""


def test_resolve_clsid_default_empty_value() -> None:
    hive_ops = _make_hive_ops()
    hive = MagicMock()
    hive_ops._registry.load_subtree.return_value = _make_node({"(Default)": ""})

    subpath = "Classes\\CLSID\\{abc}\\InprocServer32"
    result = hive_ops.resolve_clsid_default(hive, subpath)
    assert result == ""
