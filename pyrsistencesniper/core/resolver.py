"""Post-detection resolution: file existence, hashing, signer, and classification."""

from __future__ import annotations

import contextlib
import dataclasses
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
    import lief

    _HAS_LIEF = True
except ImportError:
    _HAS_LIEF = False

try:
    from asn1crypto import cms

    _HAS_ASN1 = True
except ImportError:
    _HAS_ASN1 = False

logger = logging.getLogger(__name__)

_CATROOT_SUBDIR = "Windows/System32/CatRoot/{F750E6C3-38EE-11D1-85E5-00C04FC295EE}"

_SPC_SP_OPUS_INFO_OID = "1.3.6.1.4.1.311.2.1.12"


def _extract_program_name_from_cms(data: bytes) -> str:
    """Parse a CMS SignedData blob (.cat file) and extract the signer program name."""
    content_info = cms.ContentInfo.load(data)
    signed_data = content_info["content"]
    for signer_info in signed_data["signer_infos"]:
        for attr in signer_info["signed_attrs"]:
            if attr["type"].dotted == _SPC_SP_OPUS_INFO_OID:
                raw = attr["values"][0].contents
                # SpcSpOpusInfo: SEQUENCE { [0] EXPLICIT SpcString, ... }
                # SpcString: CHOICE { [0] BMPString, [1] IA5String }
                # Quick parse: find the BMPString (tag 0x1e) or IA5String (tag 0x16)
                from asn1crypto import core

                seq = core.Sequence.load(raw)
                for child in seq:
                    child_bytes = child.contents
                    if child_bytes:
                        try:
                            return str(child_bytes.decode("utf-16-be").strip("\x00"))
                        except UnicodeDecodeError:
                            return str(child_bytes.decode("ascii", errors="replace"))
    return ""


class SignerExtractor:
    """Extracts Authenticode signer names from PE files."""

    def __init__(self, filesystem: FilesystemHelper) -> None:
        self._fs = filesystem
        self._catalog_data: list[bytes] | None = None

    def extract(self, resolved_path: str) -> str:
        """Return the signer program name, or empty string if unavailable."""
        if not _HAS_LIEF:
            return ""
        host_path = self._fs.resolve(resolved_path)
        if not host_path.is_file():
            return ""
        try:
            pe = lief.PE.parse(str(host_path))
            if pe is None:
                return ""
            for sig in pe.signatures:
                for signer in sig.signers:
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
        """Search catalog files for a matching hash and return the signer name."""
        if not _HAS_ASN1:
            return ""
        catalog_data = self._get_catalog_data()
        for authentihash in (pe.authentihash_sha256, pe.authentihash_sha1):
            fingerprint = bytes(authentihash)
            for data in catalog_data:
                if fingerprint not in data:
                    continue
                try:
                    return _extract_program_name_from_cms(data)
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
