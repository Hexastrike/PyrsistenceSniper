"""Tests for core/registry.py: RegistryHelper, RegistryNode, value coercion."""

from __future__ import annotations

import struct
from pathlib import Path
from unittest.mock import MagicMock, patch

from pyrsistencesniper.core import registry
from pyrsistencesniper.core.context import AnalysisContext
from pyrsistencesniper.core.models import HiveRecord, HiveStatus
from pyrsistencesniper.core.registry import (
    _MAX_REGISTRY_DEPTH,
    RegistryHelper,
    _base_block_checksum,
    _clamp_bin_list,
    _materialize,
    hive_key,
    partial_reads,
    read_hive_header,
    registry_key_join,
    registry_value_to_str,
    reset_partial_reads,
)


@patch("pyrsistencesniper.core.registry.pyregf")
def test_open_hive_success(mock_pyregf: MagicMock, tmp_path: Path) -> None:
    """The hive is handed to libregf as a string path, the only form it accepts."""
    fake_hive = MagicMock()
    mock_pyregf.file.return_value = fake_hive

    registry_helper = RegistryHelper()
    hive_path = tmp_path / "SOFTWARE"
    hive_path.touch()

    result = registry_helper.open_hive(hive_path)
    assert result is fake_hive
    fake_hive.open.assert_called_once_with(str(hive_path))


@patch("pyrsistencesniper.core.registry.pyregf")
def test_open_hive_failure(mock_pyregf: MagicMock, tmp_path: Path) -> None:
    """One unreadable hive degrades to None rather than aborting the scan."""
    fake_hive = MagicMock()
    fake_hive.open.side_effect = OSError("bad hive")
    mock_pyregf.file.return_value = fake_hive

    registry_helper = RegistryHelper()
    result = registry_helper.open_hive(tmp_path / "BAD_HIVE")
    assert result is None


@patch("pyrsistencesniper.core.registry.pyregf")
def test_open_hive_caches(mock_pyregf: MagicMock, tmp_path: Path) -> None:
    """Plugins share hives, so a second open reuses the handle instead of reparsing."""
    fake_hive = MagicMock()
    mock_pyregf.file.return_value = fake_hive

    registry_helper = RegistryHelper()
    hive_path = tmp_path / "SOFTWARE"
    hive_path.touch()

    result1 = registry_helper.open_hive(hive_path)
    result2 = registry_helper.open_hive(hive_path)

    assert result1 is result2
    assert mock_pyregf.file.call_count == 1


def test_registry_value_to_str_string() -> None:
    """Coercion leaves an already-usable string untouched."""
    assert registry_value_to_str("hello") == "hello"


def test_registry_value_to_str_none() -> None:
    """A missing value stays absent instead of becoming the text 'None'."""
    assert registry_value_to_str(None) is None


def test_registry_value_to_str_blank() -> None:
    """Whitespace-only data names no executable, so it reads as absent."""
    assert registry_value_to_str("   ") is None


def test_registry_value_to_str_integer() -> None:
    """A DWORD renders as digits rather than being dropped as a non-string."""
    assert registry_value_to_str(42) == "42"


def test_registry_value_to_str_strips_whitespace() -> None:
    """Padding around a path must not defeat later exact-match filtering."""
    assert registry_value_to_str("  foo  ") == "foo"


def test_materialize_depth_limit() -> None:
    """Materialize stops recursing at the depth limit to prevent RecursionError."""

    def make_key_chain(depth_remaining: int) -> MagicMock:
        """Build a single-child key chain of the requested depth."""
        key = MagicMock()
        key.get_name.return_value = f"key_{depth_remaining}"
        key.get_number_of_values.return_value = 0
        if depth_remaining == 0:
            key.get_number_of_sub_keys.return_value = 0
            key.get_sub_key.side_effect = IndexError
        else:
            child = make_key_chain(depth_remaining - 1)
            key.get_number_of_sub_keys.return_value = 1
            key.get_sub_key.return_value = child
        return key

    root = make_key_chain(_MAX_REGISTRY_DEPTH + 10)
    node = _materialize(root)

    depth = 0
    current = node
    while current._children:
        depth += 1
        current = next(iter(current._children.values()))
    assert depth == _MAX_REGISTRY_DEPTH


def _base_block(
    primary: int = 7, secondary: int = 7, bins_size: int = 4096
) -> bytearray:
    """Build a REGF base block with a correct checksum."""
    block = bytearray(512)
    block[0:4] = b"regf"
    struct.pack_into("<II", block, 4, primary, secondary)
    struct.pack_into("<I", block, 40, bins_size)
    struct.pack_into("<I", block, 508, _base_block_checksum(bytes(block)))
    return block


def _hive_bytes(bin_count: int, declared_bins_size: int) -> bytearray:
    """Build a hive whose declared bin extent may disagree with the bins present."""
    data = _base_block(bins_size=declared_bins_size)
    data.extend(bytearray(4096 - len(data)))
    for index in range(bin_count):
        hive_bin = bytearray(4096)
        hive_bin[0:4] = b"hbin"
        struct.pack_into("<I", hive_bin, 4, index * 4096)
        struct.pack_into("<I", hive_bin, 8, 4096)
        data.extend(hive_bin)
    return data


def test_read_hive_header_parses_a_base_block(tmp_path: Path) -> None:
    """Sequence numbers, bin extent and checksum are read from the base block."""
    hive_path = tmp_path / "SOFTWARE"
    hive_path.write_bytes(bytes(_base_block(primary=9, secondary=9, bins_size=8192)))

    header = read_hive_header(hive_path)

    assert header is not None
    assert header.primary_sequence == 9
    assert header.secondary_sequence == 9
    assert header.hive_bins_size == 8192
    assert header.checksum_valid is True
    assert header.dirty is False


def test_read_hive_header_reports_a_dirty_hive(tmp_path: Path) -> None:
    """Mismatched sequence numbers mean uncommitted transactions."""
    hive_path = tmp_path / "SYSTEM"
    hive_path.write_bytes(bytes(_base_block(primary=12, secondary=11)))

    header = read_hive_header(hive_path)

    assert header is not None
    assert header.dirty is True


def test_read_hive_header_detects_a_bad_checksum(tmp_path: Path) -> None:
    """A base block whose stored checksum does not match its bytes is reported."""
    block = _base_block()
    struct.pack_into("<I", block, 508, 0x1234)
    hive_path = tmp_path / "SAM"
    hive_path.write_bytes(bytes(block))

    header = read_hive_header(hive_path)

    assert header is not None
    assert header.checksum_valid is False


def test_read_hive_header_rejects_a_short_file(tmp_path: Path) -> None:
    """An empty or truncated file is not a hive header."""
    hive_path = tmp_path / "SOFTWARE"
    hive_path.touch()
    assert read_hive_header(hive_path) is None


def test_read_hive_header_rejects_a_foreign_signature(tmp_path: Path) -> None:
    """A file without the regf signature is not a hive."""
    hive_path = tmp_path / "notes.txt"
    hive_path.write_bytes(b"MZ" + bytes(600))
    assert read_hive_header(hive_path) is None


def test_read_hive_header_tolerates_a_missing_file(tmp_path: Path) -> None:
    """A path that does not exist returns None instead of raising."""
    assert read_hive_header(tmp_path / "absent") is None


def test_clamp_bin_list_shrinks_an_overstated_extent() -> None:
    """A declared extent longer than the bins present is clamped to what is there."""
    data = _hive_bytes(bin_count=2, declared_bins_size=4096 * 9)

    assert _clamp_bin_list(data) is True
    assert struct.unpack_from("<I", data, 40)[0] == 4096 * 2


def test_clamp_bin_list_levels_the_sequence_numbers() -> None:
    """The repaired block reads as clean so libregf will accept it."""
    data = _hive_bytes(bin_count=1, declared_bins_size=4096 * 5)
    struct.pack_into("<II", data, 4, 20, 19)

    assert _clamp_bin_list(data) is True
    assert struct.unpack_from("<I", data, 4)[0] == struct.unpack_from("<I", data, 8)[0]
    assert struct.unpack_from("<I", data, 508)[0] == _base_block_checksum(
        bytes(data[:512])
    )


def test_oversized_hive_is_not_copied_for_repair(tmp_path: Path) -> None:
    """Repair holds a hive in memory, so one past the cap is left unopened."""
    hive_path = tmp_path / "SOFTWARE"
    hive_path.write_bytes(bytes(_hive_bytes(2, 3 * 4096)))

    with patch.object(registry, "_MAX_REPAIR_BYTES", 16):
        assert RegistryHelper._reopen_repaired(hive_path) is None


def test_clamp_bin_list_refuses_a_hive_with_no_intact_bins() -> None:
    """Nothing is claimed to be recoverable when the first bin is already damaged."""
    data = _hive_bytes(bin_count=0, declared_bins_size=4096 * 3)
    data.extend(b"junk" + bytes(4092))

    assert _clamp_bin_list(data) is False


def test_open_attempts_records_a_successful_open(tmp_path: Path) -> None:
    """A hive that opens is recorded so the report can say it was read."""
    hive_path = tmp_path / "SOFTWARE"
    hive_path.write_bytes(bytes(_hive_bytes(bin_count=1, declared_bins_size=4096)))

    registry_helper = RegistryHelper()
    with patch("pyrsistencesniper.core.registry.pyregf") as mock_pyregf:
        mock_pyregf.file.return_value = MagicMock()
        registry_helper.open_hive(hive_path)

    record = registry_helper.open_attempts()[str(hive_path.resolve())]
    assert record.status is HiveStatus.OPENED
    assert record.error == ""


def test_open_attempts_records_a_failure_with_its_reason(tmp_path: Path) -> None:
    """A hive that will not open is recorded with the reason it refused."""
    registry_helper = RegistryHelper()
    with patch("pyrsistencesniper.core.registry.pyregf") as mock_pyregf:
        mock_pyregf.file.return_value.open.side_effect = OSError("bad hive")
        assert registry_helper.open_hive(tmp_path / "BAD_HIVE") is None

    record = registry_helper.open_attempts()[str((tmp_path / "BAD_HIVE").resolve())]
    assert record.status is HiveStatus.OPEN_FAILED
    assert "bad hive" in record.error


def test_open_attempts_records_dirtiness(tmp_path: Path) -> None:
    """Dirtiness travels with the record even when the hive opens normally."""
    hive_path = tmp_path / "SYSTEM"
    data = _hive_bytes(bin_count=1, declared_bins_size=4096)
    struct.pack_into("<II", data, 4, 31, 30)
    hive_path.write_bytes(bytes(data))

    registry_helper = RegistryHelper()
    with patch("pyrsistencesniper.core.registry.pyregf") as mock_pyregf:
        mock_pyregf.file.return_value = MagicMock()
        registry_helper.open_hive(hive_path)

    assert registry_helper.open_attempts()[str(hive_path.resolve())].dirty is True


def _detoured_path(root: Path, name: str) -> Path:
    """Return a path reaching `name` under `root` by a redundant "sub/.." step."""
    # The detour keeps the resolved spelling different from the literal one, so a
    # caller that derived its key without resolving cannot agree by coincidence.
    (root / "sub").mkdir(exist_ok=True)
    return root / "sub" / ".." / name


def _path_of_length(root: Path, length: int) -> Path:
    """Build a hive path of exactly the requested length under a real root."""
    # The padding goes into one leaf name, so the length matches on Windows and on
    # the POSIX CI runners, whose temporary roots differ in length.
    padding = length - len(str(_detoured_path(root, "h")))
    assert padding >= 0, "temporary root is already longer than the target length"
    return _detoured_path(root, "h" * (padding + 1))


def test_hive_key_is_the_resolved_path(tmp_path: Path) -> None:
    """A hive's identity is its resolved path, so every caller derives one key."""
    hive_path = tmp_path / "SOFTWARE"
    hive_path.touch()

    assert hive_key(hive_path) == str(hive_path.resolve())


def test_hive_key_collapses_two_spellings_of_one_hive(tmp_path: Path) -> None:
    """Resolution is what stops the same hive being inventoried twice."""
    (tmp_path / "config").mkdir()
    hive_path = tmp_path / "config" / "SOFTWARE"
    hive_path.touch()
    detoured_path = tmp_path / "config" / "sub" / ".." / "SOFTWARE"

    assert hive_key(detoured_path) == hive_key(hive_path)


def test_hive_key_falls_back_to_the_unresolved_path_when_resolve_fails(
    tmp_path: Path,
) -> None:
    """A path the volume refuses to resolve still gets an identity, not an OSError."""
    hive_path = tmp_path / "SOFTWARE"

    with patch.object(Path, "resolve", side_effect=OSError(22, "corrupted")):
        assert hive_key(hive_path) == str(hive_path)


def test_cache_key_is_the_hive_key(tmp_path: Path) -> None:
    """The cache key is the inventory identity, not a second derivation of it."""
    hive_path = tmp_path / "SYSTEM"

    assert RegistryHelper._cache_key(hive_path) == hive_key(hive_path)


def test_cache_key_and_hive_record_agree_when_resolve_fails(tmp_path: Path) -> None:
    """An unresolvable hive is still found by the report that has to name it."""
    hive_path = tmp_path / "SOFTWARE"

    with patch.object(Path, "resolve", side_effect=OSError(22, "corrupted")):
        attempts = {
            RegistryHelper._cache_key(hive_path): HiveRecord(
                path=str(hive_path), status=HiveStatus.OPENED
            )
        }
        record = AnalysisContext._hive_record(attempts, "SOFTWARE", "", hive_path)

    assert record.status is HiveStatus.OPENED
    assert record.name == "SOFTWARE"
    assert record.owner == ""


def test_cache_key_and_hive_record_agree_on_a_250_character_path(
    tmp_path: Path,
) -> None:
    """A long hive path must not be recorded one way and looked up another."""
    # Divergence reports a fully parsed hive as NOT_READ in the same report that
    # carries its findings, and NOT_READ does not trip cost_checks.
    hive_path = _path_of_length(tmp_path, 250)
    assert len(str(hive_path)) == 250
    assert hive_key(hive_path) != str(hive_path), "the key must not be the literal path"

    attempts = {
        RegistryHelper._cache_key(hive_path): HiveRecord(
            path=str(hive_path), status=HiveStatus.REPAIRED, dirty=True
        )
    }
    record = AnalysisContext._hive_record(attempts, "NTUSER.DAT", "alice", hive_path)

    assert record.status is HiveStatus.REPAIRED
    assert record.dirty is True
    assert record.name == "NTUSER.DAT"
    assert record.owner == "alice"


def test_hive_record_reports_not_read_when_no_attempt_matches(tmp_path: Path) -> None:
    """The placeholder is real, so a key that misses genuinely fails the tests above."""
    hive_path = _path_of_length(tmp_path, 250)
    attempts = {
        hive_key(tmp_path / "OTHER"): HiveRecord(status=HiveStatus.OPENED),
    }

    record = AnalysisContext._hive_record(attempts, "NTUSER.DAT", "alice", hive_path)

    assert record.status is HiveStatus.NOT_READ
    assert record.path == str(hive_path)


def test_open_hive_records_under_the_key_the_inventory_looks_up(
    tmp_path: Path,
) -> None:
    """End to end: what open_hive stored is what the hive inventory finds."""
    hive_path = _detoured_path(tmp_path, "SOFTWARE")
    hive_path.write_bytes(bytes(_hive_bytes(bin_count=1, declared_bins_size=4096)))

    registry_helper = RegistryHelper()
    with patch("pyrsistencesniper.core.registry.pyregf") as mock_pyregf:
        mock_pyregf.file.return_value = MagicMock()
        registry_helper.open_hive(hive_path)

    record = AnalysisContext._hive_record(
        registry_helper.open_attempts(), "SOFTWARE", "", hive_path
    )

    assert record.status is HiveStatus.OPENED
    assert record.name == "SOFTWARE"


def test_registry_key_join_skips_empty_segments() -> None:
    """A hive whose root is the key of interest contributes an empty segment."""
    assert registry_key_join(r"HKLM\SOFTWARE", "") == r"HKLM\SOFTWARE"
    assert registry_key_join("", "Classes") == "Classes"
    assert registry_key_join("", "") == ""
    assert registry_key_join("Software", "", "Run") == r"Software\Run"


def test_hive_key_is_exported() -> None:
    """Callers outside the module derive the identity, so it is part of the API."""
    assert "hive_key" in registry.__all__
    assert registry.hive_key is hive_key


class _FlakyKey:
    """Fake pyregf key whose subkey at a chosen index raises, as a damaged cell does."""

    def __init__(
        self,
        name: str,
        values: dict[str, object] | None = None,
        children: list[_FlakyKey] | None = None,
        bad_child_index: int | None = None,
        bad_value_index: int | None = None,
    ) -> None:
        """Record the key's shape and which index should raise on access."""
        self._name = name
        self._values = values or {}
        self._children = children or []
        self._bad_child_index = bad_child_index
        self._bad_value_index = bad_value_index

    def get_name(self) -> str:
        """Return the key name."""
        return self._name

    def get_number_of_values(self) -> int:
        """Return how many values this key claims to hold."""
        return len(self._values)

    def get_value(self, index: int) -> object:
        """Return the value at the index, raising for the cell marked damaged."""
        if index == self._bad_value_index:
            raise OSError("pyregf_key_get_value_by_index: unable to retrieve value")
        name = list(self._values)[index]
        return _FlakyValue(name, self._values[name])

    def get_number_of_sub_keys(self) -> int:
        """Return how many subkeys this key claims to hold."""
        return len(self._children)

    def get_sub_key(self, index: int) -> _FlakyKey:
        """Return the subkey at the index, raising for the cell marked damaged."""
        if index == self._bad_child_index:
            raise OSError("pyregf_key_get_sub_key_by_index: unable to retrieve sub key")
        return self._children[index]


class _FlakyValue:
    """Fake pyregf value carrying a name and string data."""

    def __init__(self, name: str, data: object) -> None:
        """Record the value name and its data."""
        self._name = name
        self._data = data

    def get_name(self) -> str:
        """Return the value name."""
        return self._name

    def get_type(self) -> int:
        """Report the value as REG_SZ."""
        return 1

    def get_data_as_string(self) -> str:
        """Return the value data as a string."""
        return str(self._data)


def test_damaged_subkey_does_not_discard_its_siblings() -> None:
    """A subkey libregf cannot follow costs only itself, not the whole subtree."""
    reset_partial_reads()
    key = _FlakyKey(
        "Run",
        children=[
            _FlakyKey("Good", values={"A": "a.exe"}),
            _FlakyKey("Damaged"),
            _FlakyKey("AlsoGood", values={"B": "b.exe"}),
        ],
        bad_child_index=1,
    )

    node = _materialize(key)

    assert sorted(name for name, _child in node.children()) == ["AlsoGood", "Good"]


def test_damaged_value_does_not_discard_its_siblings() -> None:
    """An unreadable value cell leaves the key's other values intact."""
    reset_partial_reads()
    key = _FlakyKey("Run", values={"A": "a.exe", "B": "b.exe"}, bad_value_index=0)

    node = _materialize(key)

    assert node.get("B") == "b.exe"


def test_damaged_cell_is_recorded_as_a_partial_read() -> None:
    """The gap is recorded so an incomplete read never passes as a complete one."""
    reset_partial_reads()
    key = _FlakyKey("Run", children=[_FlakyKey("Damaged")], bad_child_index=0)

    _materialize(key)

    assert "Run" in partial_reads()
    assert "unable to retrieve sub key" in partial_reads()["Run"]


def test_intact_key_records_no_partial_read() -> None:
    """A key that reads cleanly leaves the partial-read record empty."""
    reset_partial_reads()
    key = _FlakyKey("Run", values={"A": "a.exe"})

    _materialize(key)

    assert partial_reads() == {}
