"""Detection for PowerShell Profile."""

from __future__ import annotations

import logging
from pathlib import Path

from pyrsistencesniper.core.filesystem import safe_is_dir, safe_is_file, safe_iterdir
from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
    HiveProtocol,
    UserProfile,
)
from pyrsistencesniper.core.windows import expand_env_vars
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

logger = logging.getLogger(__name__)

# Every host loads profile.ps1 plus its own Microsoft.<Host>_profile.ps1, so the
# directories are enumerated by suffix rather than by a list of host names that
# would silently miss the ISE and VSCode profiles.
_PROFILE_FILE_SUFFIX = "profile.ps1"

_WINDOWS_POWERSHELL_HOMES: tuple[str, ...] = (
    r"Windows\System32\WindowsPowerShell\v1.0",
    r"Windows\SysWOW64\WindowsPowerShell\v1.0",
)

# $PSHOME for PowerShell Core is versioned (7, 7-preview, 6), so the install
# roots are walked instead of named.
_POWERSHELL_CORE_INSTALL_ROOTS: tuple[str, ...] = (
    r"Program Files\PowerShell",
    r"Program Files (x86)\PowerShell",
)

_USER_PROFILE_DIRECTORIES: tuple[str, ...] = ("WindowsPowerShell", "PowerShell")

_DEFAULT_DOCUMENTS = "Documents"

_SHELL_FOLDERS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
_USER_SHELL_FOLDERS_KEY = (
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
)
_DOCUMENTS_VALUE = "Personal"

_ONEDRIVE_PREFIX = "onedrive"


@register_plugin
class PowerShellProfiles(PersistencePlugin):
    """Detects PowerShell Profile persistence entries."""

    definition = CheckDefinition(
        id="powershell_profiles",
        technique="PowerShell Profile",
        mitre_id="T1546.013",
        description=(
            "PowerShell profile scripts (profile.ps1, "
            "Microsoft.PowerShell_profile.ps1) run at the start of every PowerShell "
            "session, system-wide or per user, for both Windows PowerShell and "
            "PowerShell Core."
        ),
    )

    def run(self) -> list[Finding]:
        """Report every PowerShell profile script a session would auto-load."""
        findings: list[Finding] = []
        reported: set[str] = set()

        for directory in self._machine_profile_directories():
            self._scan_directory(directory, AccessLevel.SYSTEM, findings, reported)

        hives = {
            profile.username: hive for profile, hive in self.context.iter_user_hives()
        }
        for profile in self.context.user_profiles:
            for documents in self._documents_directories(
                profile, hives.get(profile.username)
            ):
                for directory_name in _USER_PROFILE_DIRECTORIES:
                    self._scan_directory(
                        documents / directory_name,
                        AccessLevel.USER,
                        findings,
                        reported,
                    )

        return findings

    def _machine_profile_directories(self) -> list[Path]:
        """Return every $PSHOME on the image, for Windows PowerShell and Core alike."""
        directories = [
            self.filesystem.resolve(home) for home in _WINDOWS_POWERSHELL_HOMES
        ]
        for install_root in _POWERSHELL_CORE_INSTALL_ROOTS:
            base = self.filesystem.resolve(install_root)
            if not safe_is_dir(base):
                continue
            directories.extend(
                version_directory
                for version_directory in safe_iterdir(base)
                if safe_is_dir(version_directory)
            )
        return directories

    def _documents_directories(
        self, profile: UserProfile, hive: HiveProtocol | None
    ) -> list[Path]:
        """Return every Documents folder this user's profile scripts could sit in."""
        # $PROFILE follows the MyDocuments shell folder, which OneDrive Known
        # Folder Move repoints out of the profile root, so the recorded
        # redirection is authoritative and the default path only a fallback.
        candidates = [
            self.filesystem.resolve(f"Users\\{profile.username}\\{_DEFAULT_DOCUMENTS}")
        ]
        redirected = self._redirected_documents(profile, hive)
        if redirected is not None:
            candidates.append(redirected)
        candidates.extend(self._onedrive_documents(profile))

        directories: list[Path] = []
        seen: set[str] = set()
        for candidate in candidates:
            key = str(candidate).casefold()
            if key not in seen:
                seen.add(key)
                directories.append(candidate)
        return directories

    def _redirected_documents(
        self, profile: UserProfile, hive: HiveProtocol | None
    ) -> Path | None:
        """Read the user's MyDocuments location out of their own NTUSER.DAT."""
        if hive is None:
            return None
        for key_path in (_USER_SHELL_FOLDERS_KEY, _SHELL_FOLDERS_KEY):
            node = self.registry.load_subtree(hive, key_path)
            if node is None:
                continue
            documents = node.get(_DOCUMENTS_VALUE)
            if documents and str(documents).strip():
                expanded = expand_env_vars(str(documents), profile.username)
                return self.filesystem.resolve(expanded)
        return None

    def _onedrive_documents(self, profile: UserProfile) -> list[Path]:
        """Return the Documents folder inside every OneDrive root in the profile."""
        # An image whose NTUSER.DAT was never collected still shows the sync root
        # on disk, so the redirected profile scripts stay reachable without it.
        profile_root = self.filesystem.resolve(f"Users\\{profile.username}")
        return [
            entry / _DEFAULT_DOCUMENTS
            for entry in safe_iterdir(profile_root)
            if entry.name.casefold().startswith(_ONEDRIVE_PREFIX) and safe_is_dir(entry)
        ]

    def _scan_directory(
        self,
        directory: Path,
        access: AccessLevel,
        findings: list[Finding],
        reported: set[str],
    ) -> None:
        """Report every profile script in a directory PowerShell auto-loads from."""
        if not safe_is_dir(directory):
            return
        for entry in sorted(
            safe_iterdir(directory), key=lambda item: item.name.lower()
        ):
            if not entry.name.casefold().endswith(_PROFILE_FILE_SUFFIX):
                continue
            if not safe_is_file(entry):
                continue
            self._add(self.filesystem.image_relative(entry), access, findings, reported)

    def _add(
        self,
        artifact: str,
        access: AccessLevel,
        findings: list[Finding],
        reported: set[str],
    ) -> None:
        """Record one profile script, skipping a file two candidate paths both reach."""
        # A redirected Documents folder frequently resolves onto the default one,
        # and Users\Default User is a junction onto Users\Default, so the same
        # script is reachable by more than one route.
        key = artifact.casefold()
        if key in reported:
            return
        reported.add(key)
        findings.append(
            self._make_finding(
                path=artifact,
                value=artifact,
                access=access,
                resolve_target=artifact,
            )
        )
