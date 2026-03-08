from __future__ import annotations

import contextlib
import hashlib
import logging
from pathlib import Path

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

from pyrsistencesniper.forensics.filesystem import FilesystemHelper

logger = logging.getLogger(__name__)

_CATROOT_SUBDIR = "Windows/System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}"


class SignerExtractor:
    """Extracts Authenticode signer names from PE files."""

    def __init__(self, filesystem: FilesystemHelper) -> None:
        self._fs = filesystem
        self._catalog_data: list[tuple[Path, bytes]] | None = None

    def extract(self, resolved_path: str) -> str:
        """Return the signer program name, or empty string if unavailable."""
        if not _HAS_SIGNIFY:
            return ""
        host_path = self._fs.resolve(resolved_path)
        if not host_path.is_file():
            return ""
        try:
            with host_path.open("rb") as f:
                pe = SignedPEFile(f)
                for sig in pe.iter_signatures():
                    signer_info = sig.signer_info
                    if signer_info and signer_info.program_name:  # type: ignore[attr-defined]
                        return str(signer_info.program_name)  # type: ignore[attr-defined]
                if _HAS_SIGNIFY_CTL:
                    catalog_data = self._get_catalog_data()
                    if catalog_data:
                        for algo in (hashlib.sha256, hashlib.sha1):
                            fp_bytes = pe.get_fingerprint(algo)
                            for _cat_path, data in catalog_data:
                                if fp_bytes in data:
                                    try:
                                        ctl = CertificateTrustList.from_envelope(data)
                                        si = ctl.signer_info
                                        if si and si.program_name:  # type: ignore[attr-defined]
                                            return str(si.program_name)  # type: ignore[attr-defined]
                                    except Exception:
                                        pass
        except Exception:
            logger.debug("Signer extraction failed for %s", host_path, exc_info=True)
        return ""

    def _get_catalog_data(self) -> list[tuple[Path, bytes]]:
        """Return cached catalog file contents, loading on first call."""
        if self._catalog_data is None:
            self._catalog_data = self._load_catalog_data()
        return self._catalog_data

    def _load_catalog_data(self) -> list[tuple[Path, bytes]]:
        """Read all .cat files from the CatRoot directory into memory."""
        cat_dir = self._fs.image_root / _CATROOT_SUBDIR
        if not cat_dir.is_dir():
            return []
        cat_files = list(cat_dir.glob("*.cat"))
        if not cat_files:
            return []
        logger.info("Loading %d catalog files into memory …", len(cat_files))
        result: list[tuple[Path, bytes]] = []
        for cat_path in cat_files:
            with contextlib.suppress(OSError):
                result.append((cat_path, cat_path.read_bytes()))
        total_mb = sum(len(d) for _, d in result) / 1_048_576
        logger.info("Loaded %d catalog files (%.1f MB)", len(result), total_mb)
        return result
