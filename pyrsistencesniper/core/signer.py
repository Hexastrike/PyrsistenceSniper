"""Authenticode signer extraction and Windows catalog (.cat) parsing."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from typing import Any

import lief
from asn1crypto import cms, core

from pyrsistencesniper.core.filesystem import (
    FilesystemHelper,
    safe_is_dir,
    safe_is_file,
)
from pyrsistencesniper.core.windows import _io_path

logger = logging.getLogger(__name__)

_CATROOT_SUBDIR = "Windows/System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}"

_SPC_SP_OPUS_INFO_OID = "1.3.6.1.4.1.311.2.1.12"


def _extract_program_name_from_signed_data(signed_data: Any) -> str:  # noqa: ANN401
    """Extract the SpcSpOpusInfo program name from a parsed SignedData."""
    for signer_info in signed_data["signer_infos"]:
        for attribute in signer_info["signed_attrs"]:
            if attribute["type"].dotted == _SPC_SP_OPUS_INFO_OID:
                # SpcSpOpusInfo: SEQUENCE { [0] EXPLICIT SpcString, ... }
                # SpcString: CHOICE { [0] BMPString, [1] IA5String }
                sequence = core.Sequence.load(attribute["values"][0].contents)
                for child in sequence:
                    child_bytes = child.contents
                    if child_bytes:
                        try:
                            return str(child_bytes.decode("utf-16-be").strip("\x00"))
                        except UnicodeDecodeError:
                            return str(child_bytes.decode("ascii", errors="replace"))
    return ""


_HASH_LENGTHS = frozenset({20, 32})
_DER_SEQUENCE = 0x30
_DER_OCTET_STRING = 0x04
_DER_LONG_FORM = 0x80
_DER_LENGTH_MASK = 0x7F


def _iter_der(data: bytes) -> Iterator[tuple[int, bytes]]:
    """Yield (tag, body) for each DER element, stopping at malformed data."""
    offset = 0
    while offset < len(data):
        tag = data[offset]
        cursor = offset + 1
        if cursor >= len(data):
            return
        length = data[cursor]
        cursor += 1
        if length & _DER_LONG_FORM:
            count = length & _DER_LENGTH_MASK
            if count == 0 or cursor + count > len(data):
                return
            length = int.from_bytes(data[cursor : cursor + count], "big")
            cursor += count
        if cursor + length > len(data):
            return
        yield tag, data[cursor : cursor + length]
        offset = cursor + length


def _subject_hashes(trusted_subjects: bytes) -> list[bytes]:
    """Return the member hash of every trusted subject in a CTL subject list."""
    hashes: list[bytes] = []
    for tag, entry in _iter_der(trusted_subjects):
        if tag != _DER_SEQUENCE:
            continue
        for field_tag, field in _iter_der(entry):
            if field_tag == _DER_OCTET_STRING and len(field) in _HASH_LENGTHS:
                hashes.append(field)
            break
    return hashes


def _parse_ctl_entries(ctl_body: bytes) -> list[bytes]:
    """Walk a Microsoft CertTrustList body and return all member identifier hashes."""
    # Parsed by hand rather than with a schema: asn1crypto cannot walk
    # Microsoft's structure generically, and a catalog that fails to parse must
    # cost only its own hashes rather than the whole index.
    best: list[bytes] = []
    for tag, body in _iter_der(ctl_body):
        if tag != _DER_SEQUENCE:
            continue
        hashes = _subject_hashes(body)
        if len(hashes) > len(best):
            best = hashes
    return best


def _signer_from_certificates(signed_data: Any) -> str:  # noqa: ANN401
    """Return the leaf certificate subject, used when a catalog has no opus info."""
    # Skipping a common name containing PCA or Root picks the leaf out of a
    # Microsoft catalog chain, where those name the intermediate and the root.
    # The heuristic is specific to those chains, not to Authenticode generally.
    best = ""
    for cert in signed_data["certificates"]:
        try:
            subject = cert.chosen["tbs_certificate"]["subject"].native
        except Exception:
            logger.debug("Certificate subject unreadable", exc_info=True)
            continue
        common_name = subject.get("common_name") or ""
        if common_name and "PCA" not in common_name and "Root" not in common_name:
            return str(common_name)
        if not best:
            best = str(subject.get("organization_name") or "")
    return best


def _parse_catalog(data: bytes) -> tuple[str, list[bytes]]:
    """Return (signer_name, member_hashes) for a .cat blob. Empty on failure."""
    try:
        content_info = cms.ContentInfo.load(data)
        signed_data = content_info["content"]
    except Exception:
        logger.debug("Catalog outer parse failed", exc_info=True)
        return "", []
    try:
        signer = _extract_program_name_from_signed_data(signed_data)
    except Exception:
        logger.debug("Signer name parse failed", exc_info=True)
        signer = ""
    if not signer:
        try:
            signer = _signer_from_certificates(signed_data)
        except Exception:
            logger.debug("Certificate subject parse failed", exc_info=True)
    hashes: list[bytes] = []
    try:
        econtent = signed_data["encap_content_info"]["content"]
        hashes = _parse_ctl_entries(econtent.contents)
    except Exception:
        logger.debug("Catalog CTL parse failed", exc_info=True)
    return signer, hashes


class SignerExtractor:
    """Extracts Authenticode signer names from PE files."""

    def __init__(self, filesystem: FilesystemHelper) -> None:
        self._fs = filesystem
        self._signer_index: dict[bytes, str] | None = None

    def extract(self, resolved_path: str) -> str:
        """Return the signer program name, or empty string if unavailable."""
        host_path = self._fs.resolve(resolved_path)
        if not safe_is_file(host_path):
            return ""
        try:
            pe = lief.PE.parse(str(host_path))
            if pe is None:
                return ""
            # Embedded Authenticode first, catalog index second: a file
            # carrying its own signature names its publisher, while the catalog
            # only names whatever package vouches for the hash.
            for signature in pe.signatures:
                for signer in signature.signers:
                    opus = signer.get_auth_attribute(
                        lief.PE.Attribute.TYPE.SPC_SP_OPUS_INFO
                    )
                    if opus is not None and opus.program_name:  # type: ignore[attr-defined]
                        return str(opus.program_name)  # type: ignore[attr-defined]
            return self._lookup_in_catalogs(pe)
        except Exception:
            logger.debug(
                "Signer extraction failed for %s",
                host_path,
                exc_info=True,
            )
        return ""

    def _lookup_in_catalogs(self, pe: Any) -> str:  # noqa: ANN401
        """Look up a PE's authentihash in the signer index."""
        index = self._get_signer_index()
        for authentihash in (pe.authentihash_sha256, pe.authentihash_sha1):
            signer = index.get(bytes(authentihash))
            if signer:
                return signer
        return ""

    def _get_signer_index(self) -> dict[bytes, str]:
        """Return the cached {hash: signer_name} index, building on first call."""
        if self._signer_index is None:
            self._signer_index = self._load_signer_index()
        return self._signer_index

    def _load_signer_index(self) -> dict[bytes, str]:
        """Parse all .cat files and return {member_hash: signer_name}."""
        # Memory holds one entry per unique hash, not the catalogs themselves.
        index: dict[bytes, str] = {}
        cat_dir = self._fs.image_root / _CATROOT_SUBDIR
        if not safe_is_dir(cat_dir):
            return index
        try:
            cat_files = list(cat_dir.glob("*.cat"))
        except OSError:
            logger.debug("Cannot glob catalog directory: %s", cat_dir, exc_info=True)
            return index
        if not cat_files:
            return index
        logger.info("Building signer index from %d catalogs ...", len(cat_files))
        for cat_path in cat_files:
            try:
                data = _io_path(cat_path).read_bytes()
            except OSError:
                logger.debug("Cannot read catalog: %s", cat_path, exc_info=True)
                continue
            signer, hashes = _parse_catalog(data)
            if not signer or not hashes:
                continue
            for member_hash in hashes:
                index.setdefault(member_hash, signer)
        logger.info("Signer index contains %d hashes", len(index))
        return index
