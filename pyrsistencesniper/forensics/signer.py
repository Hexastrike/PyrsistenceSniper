"""Authenticode signer extraction from PE files and catalog lookups."""

from __future__ import annotations

import contextlib
import hashlib
import logging

from pyrsistencesniper.forensics.filesystem import FilesystemHelper

try:
    from signify.authenticode.signed_file import SignedPEFile

    _HAS_SIGNIFY = True
except ImportError:
    _HAS_SIGNIFY = False

try:
    from signify.authenticode import CertificateTrustList

    _HAS_SIGNIFY_CTL = True
except ImportError:
    _HAS_SIGNIFY_CTL = False

logger = logging.getLogger(__name__)

_CATROOT_SUBDIR = "Windows/System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}"


class SignerExtractor:
    """Extracts Authenticode signer names from PE files."""

    def __init__(self, filesystem: FilesystemHelper) -> None:
        self._fs = filesystem
        self._catalog_data: list[bytes] | None = None

    def extract(self, resolved_path: str) -> str:
        """Return the signer program name, or empty string if unavailable."""
        if not _HAS_SIGNIFY:
            return ""
        host_path = self._fs.resolve(resolved_path)
        if not host_path.is_file():
            return ""
        try:
            with host_path.open("rb") as pe_file_handle:
                pe_signed = SignedPEFile(pe_file_handle)
                for signature in pe_signed.iter_signatures():
                    signer_info = signature.signer_info
                    if signer_info is not None and signer_info.program_name:  # type: ignore[attr-defined]
                        return str(signer_info.program_name)  # type: ignore[attr-defined]
                return self._lookup_in_catalogs(pe_signed)
        except Exception:
            logger.debug(
                "Signer extraction failed for %s",
                host_path,
                exc_info=True,
            )
        return ""

    def _lookup_in_catalogs(self, pe_signed: SignedPEFile) -> str:
        """Search catalog files for a matching hash and return the signer name."""
        if not _HAS_SIGNIFY_CTL:
            return ""
        catalog_data = self._get_catalog_data()
        for algo in (hashlib.sha256, hashlib.sha1):
            fingerprint_bytes = pe_signed.get_fingerprint(algo)
            for data in catalog_data:
                if fingerprint_bytes not in data:
                    continue
                try:
                    ctl = CertificateTrustList.from_envelope(data)
                    signer_info = ctl.signer_info
                    if signer_info is not None and signer_info.program_name:  # type: ignore[attr-defined]
                        return str(signer_info.program_name)  # type: ignore[attr-defined]
                except Exception:
                    logger.debug("Catalog parse failed", exc_info=True)
        return ""

    def _get_catalog_data(self) -> list[bytes]:
        """Return cached catalog file contents, loading on first call."""
        if self._catalog_data is None:
            self._catalog_data = self._load_catalog_data()
        return self._catalog_data

    def _load_catalog_data(self) -> list[bytes]:
        """Read all .cat files from the CatRoot directory into memory."""
        cat_dir = self._fs.image_root / _CATROOT_SUBDIR
        if not cat_dir.is_dir():
            return []
        cat_files = list(cat_dir.glob("*.cat"))
        if not cat_files:
            return []
        logger.info("Loading %d catalog files into memory ...", len(cat_files))
        result: list[bytes] = []
        for cat_path in cat_files:
            with contextlib.suppress(OSError):
                result.append(cat_path.read_bytes())
        total_mb = sum(len(entry) for entry in result) / 1_048_576
        logger.info("Loaded %d catalog files (%.1f MB)", len(result), total_mb)
        return result
