"""Detection for Windows Terminal Custom Profiles."""

from __future__ import annotations

import json

from pyrsistencesniper.core.filesystem import safe_is_file
from pyrsistencesniper.core.ledger import record_artifact_failure
from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
)
from pyrsistencesniper.core.windows import read_bounded
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_SETTINGS_LOCATIONS = (
    r"AppData\Local\Packages"
    r"\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json",
    r"AppData\Local\Packages"
    r"\Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe\LocalState\settings.json",
    r"AppData\Local\Microsoft\Windows Terminal\settings.json",
)

_CLOSING_BRACKETS = ("}", "]")

# A settings file is kilobytes; the cap keeps a planted one from being read whole.
_MAX_SETTINGS_BYTES = 4 << 20


def _next_significant(text: str, start: int) -> str:
    """Return the next character that is neither whitespace nor a comment."""
    index = start
    length = len(text)
    while index < length:
        character = text[index]
        if character.isspace():
            index += 1
        elif text.startswith("//", index):
            line_end = text.find("\n", index)
            if line_end == -1:
                return ""
            index = line_end + 1
        elif text.startswith("/*", index):
            comment_end = text.find("*/", index + 2)
            if comment_end == -1:
                return ""
            index = comment_end + 2
        else:
            return character
    return ""


def strip_jsonc(text: str) -> str:
    """Drop JSONC comments and trailing commas without touching string literals."""
    cleaned: list[str] = []
    index = 0
    length = len(text)
    inside_string = False
    while index < length:
        character = text[index]
        if inside_string:
            cleaned.append(character)
            if character == "\\" and index + 1 < length:
                cleaned.append(text[index + 1])
                index += 2
                continue
            if character == '"':
                inside_string = False
            index += 1
        elif character == '"':
            inside_string = True
            cleaned.append(character)
            index += 1
        elif text.startswith("//", index):
            line_end = text.find("\n", index)
            index = length if line_end == -1 else line_end
        elif text.startswith("/*", index):
            comment_end = text.find("*/", index + 2)
            index = length if comment_end == -1 else comment_end + 2
        elif (
            character == "," and _next_significant(text, index + 1) in _CLOSING_BRACKETS
        ):
            index += 1
        else:
            cleaned.append(character)
            index += 1
    return "".join(cleaned)


def _profile_entries(data: object) -> tuple[object, list[object]]:
    """Split a settings document into its profile defaults and its profile list."""
    if not isinstance(data, dict):
        return {}, []
    section = data.get("profiles")
    if isinstance(section, list):
        return {}, list(section)
    if not isinstance(section, dict):
        return {}, []
    entries = section.get("list")
    return section.get("defaults"), list(entries) if isinstance(entries, list) else []


def _commandline(entry: object) -> str:
    """Return the command line a profile entry declares, or an empty string."""
    if not isinstance(entry, dict):
        return ""
    commandline = entry.get("commandline", "")
    return commandline if isinstance(commandline, str) else ""


@register_plugin
class WindowsTerminal(PersistencePlugin):
    """Detects Windows Terminal Custom Profiles persistence entries."""

    definition = CheckDefinition(
        id="windows_terminal",
        technique="Windows Terminal Custom Profiles",
        mitre_id="T1546",
        description=(
            "A Windows Terminal settings.json profile carries a command line that runs "
            "each time a tab is opened with that profile."
        ),
    )

    def run(self) -> list[Finding]:
        """Report every command line declared in a user's Windows Terminal settings."""
        findings: list[Finding] = []

        for profile in self.context.user_profiles:
            for location in _SETTINGS_LOCATIONS:
                settings_path = f"Users\\{profile.username}\\{location}"
                findings.extend(self._scan_settings(settings_path))

        return findings

    def _scan_settings(self, settings_path: str) -> list[Finding]:
        """Read one settings.json and report every command line it declares."""
        host_path = self.filesystem.resolve(settings_path)
        if not safe_is_file(host_path):
            return []

        try:
            raw_bytes = read_bounded(host_path, _MAX_SETTINGS_BYTES)
            data = json.loads(strip_jsonc(raw_bytes.decode("utf-8-sig")))
        except (OSError, UnicodeDecodeError, ValueError) as error:
            record_artifact_failure(self.definition.id, host_path, error)
            return []

        defaults, entries = _profile_entries(data)
        findings: list[Finding] = []
        for entry in (defaults, *entries):
            commandline = _commandline(entry)
            if not commandline:
                continue
            findings.append(
                self._make_finding(
                    path=settings_path,
                    value=commandline,
                    access=AccessLevel.USER,
                )
            )
        return findings
