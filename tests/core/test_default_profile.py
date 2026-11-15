"""Behavioural tests for the rules shipped in config/default_profile.yaml."""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

import pyrsistencesniper
import pytest
from pyrsistencesniper.core.models import AccessLevel, Finding, Severity
from pyrsistencesniper.core.profile import CheckPolicy, DetectionProfile
from pyrsistencesniper.plugins import PLUGIN_REGISTRY, discover_plugins

_OFFICE_EXCEL_SOURCE = "{00020810-0000-0000-C000-000000000046}"
_OFFICE_EXCEL_TARGET = "{00020820-0000-0000-C000-000000000046}"
_PACKAGER_SOURCE = "{00020C01-0000-0000-C000-000000000046}"
_PACKAGER_TARGET = "{F20DA720-C02F-11CE-927B-0800095AE340}"
_UNKNOWN_CLSID = "{DEADBEEF-1111-2222-3333-444444444444}"
_TASKCACHE_TREE = (
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree"
)
_KNOWN_DLLS_KEY = "HKLM\\SYSTEM\\ControlSet001\\Control\\Session Manager\\KnownDLLs"
_TELEMETRY_COMMAND = (
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT"
    "\\CurrentVersion\\AppCompatFlags\\TelemetryController"
    "\\Updater\\Command"
)


@pytest.fixture
def treat_as_policy() -> CheckPolicy:
    """Return the shipped policy for the com_treat_as check."""
    return DetectionProfile.load(None).policy_for("com_treat_as")


def test_no_check_is_configured_twice() -> None:
    """Every check appears once; YAML silently keeps the last of two duplicate keys."""
    profile_path = (
        Path(pyrsistencesniper.__file__).parent / "config" / "default_profile.yaml"
    )
    check_ids = re.findall(
        r"^  ([a-z0-9_]+):$", profile_path.read_text(encoding="utf-8"), re.MULTILINE
    )
    duplicates = [name for name, count in Counter(check_ids).items() if count > 1]

    assert not duplicates, (
        f"duplicate check blocks in default_profile.yaml: {duplicates}"
    )


def test_every_configured_check_exists() -> None:
    """No profile block names a check that no longer exists."""
    discover_plugins()
    configured = set(DetectionProfile.load(None).checks)
    unknown = configured - set(PLUGIN_REGISTRY)

    assert not unknown, (
        f"profile configures checks that do not exist: {sorted(unknown)}"
    )


def _treat_as_finding(source_clsid: str, target_clsid: str) -> Finding:
    """Build a com_treat_as finding for a source CLSID forwarding to a target."""
    return Finding(
        path=f"HKLM\\SOFTWARE\\Classes\\CLSID\\{source_clsid}\\TreatAs",
        value=target_clsid,
        check_id="com_treat_as",
        access_gained=AccessLevel.SYSTEM,
        is_lolbin=False,
    )


class TestComTreatAsAllowlist:
    """The shipped TreatAs rules pin both ends of every forwarding they suppress."""

    @pytest.mark.parametrize(
        ("source_clsid", "target_clsid"),
        [
            (_OFFICE_EXCEL_SOURCE, _OFFICE_EXCEL_TARGET),
            (_PACKAGER_SOURCE, _PACKAGER_TARGET),
        ],
    )
    def test_shipped_pair_is_suppressed(
        self, treat_as_policy: CheckPolicy, source_clsid: str, target_clsid: str
    ) -> None:
        """A known Microsoft source and target pair drops to INFO."""
        finding = _treat_as_finding(source_clsid, target_clsid)
        assert treat_as_policy.classify(finding) is Severity.INFO

    # The rules pin source and target together: matching on the target alone
    # would hide a shipped Office CLSID repointed at attacker code.
    def test_repointed_office_source_survives(
        self, treat_as_policy: CheckPolicy
    ) -> None:
        """An allowlisted source forwarding somewhere else is still reported."""
        finding = _treat_as_finding(_OFFICE_EXCEL_SOURCE, _UNKNOWN_CLSID)
        assert treat_as_policy.classify(finding) is Severity.MEDIUM

    def test_unknown_source_at_office_target_survives(
        self, treat_as_policy: CheckPolicy
    ) -> None:
        """An unlisted CLSID forwarding to a shipped Office class is reported."""
        finding = _treat_as_finding(_UNKNOWN_CLSID, _OFFICE_EXCEL_TARGET)
        assert treat_as_policy.classify(finding) is Severity.MEDIUM

    def test_path_must_end_at_treatas(self, treat_as_policy: CheckPolicy) -> None:
        """A path continuing past TreatAs does not match the anchored rule."""
        finding = _treat_as_finding(_OFFICE_EXCEL_SOURCE, _OFFICE_EXCEL_TARGET)
        extended = Finding(
            path=f"{finding.path}\\Extra",
            value=finding.value,
            check_id=finding.check_id,
            is_lolbin=False,
        )
        assert treat_as_policy.classify(extended) is Severity.MEDIUM

    def test_value_must_match_whole_target(self, treat_as_policy: CheckPolicy) -> None:
        """An unanchored target substring does not earn the allowlist match."""
        finding = _treat_as_finding(
            _PACKAGER_SOURCE, f"{_PACKAGER_TARGET} {_UNKNOWN_CLSID}"
        )
        assert treat_as_policy.classify(finding) is Severity.MEDIUM


class TestGhostTaskAllowlist:
    """The shipped ghost_task rule keeps built-in Windows task folders quiet."""

    @staticmethod
    def _ghost(tree_path: str) -> Finding:
        """Build a ghost_task finding registered at the given TaskCache Tree path."""
        return Finding(
            path=tree_path,
            value="{11111111-2222-3333-4444-555555555555}",
            check_id="ghost_task",
            access_gained=AccessLevel.SYSTEM,
            is_lolbin=False,
        )

    def test_builtin_task_folder_is_suppressed(self) -> None:
        """A task under the Microsoft folder is a default, not a finding."""
        policy = DetectionProfile.load(None).policy_for("ghost_task")
        finding = self._ghost(f"{_TASKCACHE_TREE}\\Microsoft\\Windows\\AppID\\Task")

        assert policy.classify(finding) is Severity.INFO

    def test_task_outside_the_builtin_folders_is_reported(self) -> None:
        """A ghost task registered outside the Microsoft tree reaches the report."""
        policy = DetectionProfile.load(None).policy_for("ghost_task")
        finding = self._ghost(f"{_TASKCACHE_TREE}\\EvilGhost")

        assert policy.classify(finding) >= Severity.MEDIUM


class TestKnownDllsAllowlist:
    """The shipped known_dlls rules keep signed defaults quiet."""

    @staticmethod
    def _known_dll(value: str, signer: str) -> Finding:
        """Build a known_dlls finding naming the DLL a KnownDLLs entry points at."""
        return Finding(
            path=_KNOWN_DLLS_KEY,
            value=value,
            check_id="known_dlls",
            access_gained=AccessLevel.SYSTEM,
            signer=signer,
            is_lolbin=False,
        )

    def test_signed_known_dll_is_suppressed(self) -> None:
        """A signed KnownDLL entry stays out of the report."""
        policy = DetectionProfile.load(None).policy_for("known_dlls")

        assert policy.classify(self._known_dll("ntdll.dll", "Microsoft Windows")) is (
            Severity.INFO
        )

    def test_unsigned_planted_known_dll_is_not_fully_allowed(self) -> None:
        """An unsigned DLL added to KnownDLLs never reaches a full allowlist match."""
        policy = DetectionProfile.load(None).policy_for("known_dlls")

        assert policy.classify(self._known_dll("evil.dll", "")) is not Severity.INFO


class TestTelemetryControllerAllowlist:
    """Only the genuine appraiser command is suppressed under TelemetryController."""

    @staticmethod
    def _telemetry(value: str, signer: str) -> Finding:
        """Build a telemetry_controller finding for a registered command."""
        return Finding(
            path=_TELEMETRY_COMMAND,
            value=value,
            check_id="telemetry_controller",
            access_gained=AccessLevel.SYSTEM,
            signer=signer,
            is_lolbin=False,
        )

    def test_builtin_appraiser_command_is_suppressed(self) -> None:
        """The shipped CompatTelRunner command is not reported as persistence."""
        policy = DetectionProfile.load(None).policy_for("telemetry_controller")
        finding = self._telemetry(
            "%windir%\\system32\\CompatTelRunner.exe -m:appraiser.dll",
            "Microsoft Windows",
        )

        assert policy.classify(finding) is Severity.INFO

    def test_planted_command_is_reported(self) -> None:
        """An attacker command under TelemetryController reaches the report."""
        policy = DetectionProfile.load(None).policy_for("telemetry_controller")
        finding = self._telemetry("C:\\ProgramData\\upd.exe", "")

        assert policy.classify(finding) >= Severity.MEDIUM


class TestLolbinAllowlistInteraction:
    """A shipped rule must still fire for a default that is itself a LOLBin."""

    @staticmethod
    def _run_key(value: str, signer: str, is_lolbin: bool) -> Finding:
        """Build a Run key finding as the resolver would populate it."""
        return Finding(
            path=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WindowsMail",
            value=value,
            check_id="run_keys",
            signer=signer,
            is_lolbin=is_lolbin,
        )

    def test_windows_mail_default_is_suppressed_though_it_is_a_lolbin(self) -> None:
        """wab.exe is in the LOLBin list, so not_lolbin made this rule unfireable."""
        policy = DetectionProfile.load(None).policy_for("run_keys")
        finding = self._run_key(
            r"C:\Program Files\Windows Mail\wab.exe",
            "Microsoft Windows",
            is_lolbin=True,
        )

        assert policy.classify(finding) is Severity.INFO

    def test_planted_binary_named_like_the_default_is_still_reported(self) -> None:
        """The rule names a product directory, so a payload elsewhere survives it."""
        policy = DetectionProfile.load(None).policy_for("run_keys")
        finding = self._run_key(r"C:\Users\Public\wab.exe", "", is_lolbin=True)

        assert policy.classify(finding) >= Severity.MEDIUM
