"""Post-detection resolution: file existence, hashing, signer, and classification."""

from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import logging
from typing import Any, TypedDict

from pyrsistencesniper.core.filesystem import FilesystemHelper
from pyrsistencesniper.core.models import Finding
from pyrsistencesniper.core.winutil import (
    canonicalize_windows_path,
    expand_env_vars,
    extract_executable_from_cmdline,
    is_builtin,
    is_in_os_directory,
    is_lolbin,
)

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


class _CacheEntry(TypedDict):
    exists: bool
    sha256: str
    is_lolbin: bool
    is_builtin: bool
    signer: str
    is_in_os_directory: bool


class ResolutionPipeline:
    """Post-detection enrichment of findings."""

    def __init__(self, filesystem: FilesystemHelper) -> None:
        self._fs = filesystem
        self._cache: dict[str, _CacheEntry] = {}
        self._signer = SignerExtractor(filesystem)

    def resolve(self, finding: Finding) -> Finding:
        """Populate resolution fields on a finding, caching results by resolved path."""
        exe_path = extract_executable_from_cmdline(finding.value)
        if not exe_path:
            exe_path = finding.value
        exe_path = expand_env_vars(exe_path)
        exe_path = canonicalize_windows_path(exe_path)

        # Bare filenames (e.g. "ifmon.dll") fall back to System32
        resolve_path = exe_path
        if "\\" not in exe_path and "." in exe_path:
            sys32_path = f"Windows\\System32\\{exe_path}"
            sys32_key = sys32_path.lower()
            if sys32_key in self._cache or self._fs.exists(sys32_path):
                resolve_path = sys32_path

        cache_key = resolve_path.lower()
        if cache_key not in self._cache:
            exists = self._fs.exists(resolve_path)
            self._cache[cache_key] = {
                "exists": exists,
                "sha256": self._fs.sha256(resolve_path) if exists else "",
                "is_lolbin": is_lolbin(resolve_path),
                "is_builtin": is_builtin(resolve_path),
                "signer": (self._signer.extract(resolve_path) if exists else ""),
                "is_in_os_directory": is_in_os_directory(resolve_path),
            }

        cached = self._cache[cache_key]
        replacements: dict[str, Any] = {}

        if finding.exists is None:
            replacements["exists"] = cached["exists"]
        if not finding.sha256:
            replacements["sha256"] = cached["sha256"]
        if finding.is_lolbin is None:
            replacements["is_lolbin"] = cached["is_lolbin"]
        if finding.is_builtin is None:
            replacements["is_builtin"] = cached["is_builtin"]
        if finding.is_in_os_directory is None:
            replacements["is_in_os_directory"] = cached["is_in_os_directory"]
        if not finding.signer:
            replacements["signer"] = cached["signer"]

        if replacements:
            return dataclasses.replace(finding, **replacements)
        return finding
