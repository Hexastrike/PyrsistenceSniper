"""Tests for core/signer.py: SignerExtractor, catalog parsing, signer index."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

from pyrsistencesniper.core.filesystem import FilesystemHelper
from pyrsistencesniper.core.signer import (
    SignerExtractor,
    _iter_der,
    _parse_ctl_entries,
)

if TYPE_CHECKING:
    from pathlib import Path


class TestExtract:
    """Cases for reading a publisher from a PE, and the fallbacks when it has none."""

    def test_extract_returns_empty_for_nonexistent_file(self, tmp_path: Path) -> None:
        """A file the image never held has no publisher to read."""
        extractor = SignerExtractor(FilesystemHelper(image_root=tmp_path))
        assert extractor.extract("C:\\nonexistent\\file.exe") == ""

    def test_extract_returns_program_name_from_signature(self, tmp_path: Path) -> None:
        """A signed PE carries its publisher inline, so no catalog lookup is needed."""
        pe_file = tmp_path / "Windows" / "System32" / "cmd.exe"
        pe_file.parent.mkdir(parents=True, exist_ok=True)
        pe_file.write_bytes(b"MZ fake PE content")

        extractor = SignerExtractor(FilesystemHelper(image_root=tmp_path))

        mock_opus = MagicMock()
        mock_opus.program_name = "Microsoft Windows"

        mock_signer = MagicMock()
        mock_signer.get_auth_attribute.return_value = mock_opus

        mock_sig = MagicMock()
        mock_sig.signers = [mock_signer]

        mock_pe = MagicMock()
        mock_pe.signatures = [mock_sig]

        with patch(
            "pyrsistencesniper.core.signer.lief.PE.parse",
            return_value=mock_pe,
        ):
            result = extractor.extract("C:\\Windows\\System32\\cmd.exe")
        assert result == "Microsoft Windows"

    def test_extract_falls_through_to_catalog_lookup(self, tmp_path: Path) -> None:
        """Most Windows binaries are signed by catalog, so the fallback path matters."""
        pe_file = tmp_path / "Windows" / "System32" / "notepad.exe"
        pe_file.parent.mkdir(parents=True, exist_ok=True)
        pe_file.write_bytes(b"MZ fake PE")

        extractor = SignerExtractor(FilesystemHelper(image_root=tmp_path))

        mock_pe = MagicMock()
        mock_pe.signatures = []

        with (
            patch(
                "pyrsistencesniper.core.signer.lief.PE.parse",
                return_value=mock_pe,
            ),
            patch.object(
                extractor,
                "_lookup_in_catalogs",
                return_value="Catalog Signer",
            ) as mock_lookup,
        ):
            result = extractor.extract("C:\\Windows\\System32\\notepad.exe")
        mock_lookup.assert_called_once_with(mock_pe)
        assert result == "Catalog Signer"

    def test_extract_returns_empty_on_exception(self, tmp_path: Path) -> None:
        """A PE that will not parse costs its signer, not the whole scan."""
        pe_file = tmp_path / "Windows" / "bad.exe"
        pe_file.parent.mkdir(parents=True, exist_ok=True)
        pe_file.write_bytes(b"MZ corrupt")

        extractor = SignerExtractor(FilesystemHelper(image_root=tmp_path))

        with patch(
            "pyrsistencesniper.core.signer.lief.PE.parse",
            side_effect=RuntimeError("parse failed"),
        ):
            assert extractor.extract("C:\\Windows\\bad.exe") == ""


class TestSignerIndex:
    """Cases for building the catalog index once and reusing it across the scan."""

    def test_signer_index_empty_for_missing_dir(self, tmp_path: Path) -> None:
        """An image with no CatRoot yields an empty index rather than an error."""
        extractor = SignerExtractor(FilesystemHelper(image_root=tmp_path))
        assert extractor._load_signer_index() == {}

    def test_signer_index_skips_corrupt_catalogs(self, tmp_path: Path) -> None:
        """Non-parseable .cat files are silently skipped; others contribute."""
        cat_dir = (
            tmp_path
            / "Windows"
            / "System32"
            / "CatRoot"
            / "{F750E6C3-38EE-11D1-85E5-00C04FC295EE}"
        )
        cat_dir.mkdir(parents=True)
        (cat_dir / "bad.cat").write_bytes(b"garbage-not-a-valid-cms-blob")
        (cat_dir / "empty.cat").write_bytes(b"")

        extractor = SignerExtractor(FilesystemHelper(image_root=tmp_path))
        assert extractor._load_signer_index() == {}

    def test_signer_index_cached_on_second_call(self, tmp_path: Path) -> None:
        """CatRoot is parsed once; every later lookup reuses that index."""
        extractor = SignerExtractor(FilesystemHelper(image_root=tmp_path))

        first = extractor._get_signer_index()
        second = extractor._get_signer_index()

        assert first is second


class TestCtlParsing:
    """Cases for walking a Microsoft CertTrustList out of a catalog body."""

    @staticmethod
    def _der(tag: int, body: bytes) -> bytes:
        """Wrap a body in a DER header, using the long form when it is needed."""
        if len(body) < 0x80:
            return bytes([tag, len(body)]) + body
        length = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
        return bytes([tag, 0x80 | len(length)]) + length + body

    def _subject(self, identifier: bytes) -> bytes:
        """Build one trusted-subject SEQUENCE with an identifier and attribute."""
        return self._der(0x30, self._der(0x04, identifier) + self._der(0x31, b""))

    def _ctl_body(self, identifiers: list[bytes]) -> bytes:
        """Build a CTL body whose last SEQUENCE is the trusted-subject list."""
        subjects = b"".join(self._subject(identifier) for identifier in identifiers)
        return (
            self._der(0x30, self._der(0x06, bytes([0x2B, 0x06, 0x01, 0x04])))
            + self._der(0x04, b"listid")
            + self._der(0x30, subjects)
        )

    def test_sha1_and_sha256_identifiers_are_both_recovered(self) -> None:
        """Catalogs carry a mix of hash widths and both must reach the index."""
        sha1 = bytes([0xAA]) * 20
        sha256 = bytes([0xBB]) * 32

        assert _parse_ctl_entries(self._ctl_body([sha1, sha256])) == [sha1, sha256]

    def test_identifiers_of_other_widths_are_ignored(self) -> None:
        """A field that is not a hash width is not mistaken for a member hash."""
        assert _parse_ctl_entries(self._ctl_body([bytes([0xCC]) * 8])) == []

    def test_truncated_catalog_body_yields_no_hashes(self) -> None:
        """A body cut mid-element stops the walk instead of raising."""
        body = self._ctl_body([bytes([0xAA]) * 32])

        assert _parse_ctl_entries(body[: len(body) // 2]) == []

    def test_empty_body_yields_no_hashes(self) -> None:
        """An empty CTL body is not an error."""
        assert _parse_ctl_entries(b"") == []

    def test_der_walk_stops_on_a_declared_length_past_the_buffer(self) -> None:
        """A length longer than the buffer ends the walk rather than over-reading."""
        assert list(_iter_der(bytes([0x04, 0x40]) + b"short")) == []

    def test_der_walk_reads_consecutive_elements(self) -> None:
        """Sibling elements are all yielded in order."""
        buf = self._der(0x04, b"aa") + self._der(0x04, b"bb")

        assert [body for _tag, body in _iter_der(buf)] == [b"aa", b"bb"]

    def test_largest_subject_sequence_wins(self) -> None:
        """The trusted-subject list is the richest SEQUENCE, not merely the first."""
        decoy = self._der(0x30, self._subject(bytes([0xDD]) * 20))
        real = self._der(
            0x30, b"".join(self._subject(bytes([index]) * 32) for index in range(4))
        )

        assert len(_parse_ctl_entries(decoy + real)) == 4
