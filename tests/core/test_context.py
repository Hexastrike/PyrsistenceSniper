from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

from pyrsistencesniper.core.context import (
    AnalysisContext,
    ArtifactKind,
    _build_evtx_context,
    _build_hive_context,
    _classify_input,
    _discover_hives,
    _discover_profiles,
    build_context,
)


def _make_context(root: Path, *, hostname: str = "") -> AnalysisContext:
    return build_context(root, hostname=hostname)


# -- hive_path ----------------------------------------------------------------


def test_hive_path_software(tmp_path: Path) -> None:
    config = tmp_path / "Windows" / "System32" / "config"
    config.mkdir(parents=True)
    (config / "SOFTWARE").write_bytes(b"\x00" * 16)
    ctx = _make_context(tmp_path)
    path = ctx.hive_path("SOFTWARE")
    assert path is not None
    assert path.name == "SOFTWARE"
    assert path.is_file()


def test_hive_path_system(tmp_path: Path) -> None:
    config = tmp_path / "Windows" / "System32" / "config"
    config.mkdir(parents=True)
    (config / "SYSTEM").write_bytes(b"\x00" * 16)
    ctx = _make_context(tmp_path)
    path = ctx.hive_path("SYSTEM")
    assert path is not None
    assert path.name == "SYSTEM"


def test_hive_path_ntuser_requires_username(tmp_path: Path) -> None:
    ctx = _make_context(tmp_path)
    assert ctx.hive_path("NTUSER.DAT") is None


def test_hive_path_ntuser_with_username(tmp_path: Path) -> None:
    user_dir = tmp_path / "Users" / "John Doe"
    user_dir.mkdir(parents=True)
    (user_dir / "NTUSER.DAT").write_bytes(b"\x00" * 16)
    ctx = _make_context(tmp_path)
    path = ctx.hive_path("NTUSER.DAT", "John Doe")
    assert path is not None
    assert path.is_file()


def test_hive_path_nonexistent(tmp_path: Path) -> None:
    ctx = _make_context(tmp_path)
    assert ctx.hive_path("BOGUS_HIVE") is None


# -- user_profiles ------------------------------------------------------------


def _setup_user_dirs(tmp_path: Path) -> AnalysisContext:
    """Create a typical Users/ layout and return the built context."""
    users = tmp_path / "Users"
    for name in ("John Doe", "Jane Doe", "Default", "Public"):
        d = users / name
        d.mkdir(parents=True)
        if name != "Public":
            (d / "NTUSER.DAT").write_bytes(b"\x00" * 16)
    return _make_context(tmp_path)


def test_user_profiles_discovers_users(tmp_path: Path) -> None:
    ctx = _setup_user_dirs(tmp_path)
    usernames = [p.username for p in ctx.user_profiles]
    assert "John Doe" in usernames
    assert "Jane Doe" in usernames
    assert "Default" in usernames
    assert "Public" in usernames


def test_user_profiles_ntuser_presence(tmp_path: Path) -> None:
    ctx = _setup_user_dirs(tmp_path)
    by_name = {p.username: p for p in ctx.user_profiles}
    assert by_name["John Doe"].ntuser_path is not None
    assert by_name["Jane Doe"].ntuser_path is not None
    assert by_name["Default"].ntuser_path is not None
    assert by_name["Public"].ntuser_path is None


# -- hostname -----------------------------------------------------------------


def test_hostname_missing_system_hive(tmp_path: Path) -> None:
    ctx = _make_context(tmp_path)
    assert ctx.hostname == ""


def test_hostname_override(tmp_path: Path) -> None:
    ctx = _make_context(tmp_path, hostname="MY-HOST")
    assert ctx.hostname == "MY-HOST"


# -- hive_path UsrClass.dat ---------------------------------------------------


def test_hive_path_usrclass_deep_path(tmp_path: Path) -> None:
    """UsrClass.dat should be found at the correct deep path."""
    user_dir = (
        tmp_path / "Users" / "Alice" / "AppData" / "Local" / "Microsoft" / "Windows"
    )
    user_dir.mkdir(parents=True)
    hive = user_dir / "UsrClass.dat"
    hive.write_bytes(b"fake hive")

    ctx = _make_context(tmp_path)
    result = ctx.hive_path("UsrClass.dat", "Alice")
    assert result is not None
    assert result == hive


def test_hive_path_usrclass_shallow_fallback(tmp_path: Path) -> None:
    """UsrClass.dat at shallow path should work as fallback."""
    user_dir = tmp_path / "Users" / "Bob"
    user_dir.mkdir(parents=True)
    hive = user_dir / "UsrClass.dat"
    hive.write_bytes(b"fake hive")

    ctx = _make_context(tmp_path)
    result = ctx.hive_path("UsrClass.dat", "Bob")
    assert result is not None
    assert result == hive


def test_hive_path_usrclass_requires_username(tmp_path: Path) -> None:
    ctx = _make_context(tmp_path)
    assert ctx.hive_path("UsrClass.dat") is None


# -- build_context standalone -------------------------------------------------


def test_build_context_standalone_software(tmp_path: Path) -> None:
    """build_context with a standalone SOFTWARE file should set hives correctly."""
    hive_file = tmp_path / "SOFTWARE"
    hive_file.write_bytes(b"\x00" * 16)
    ctx = build_context(hive_file)
    assert ctx.root == tmp_path
    assert ctx.hive_path("SOFTWARE") is not None
    assert ctx.user_profiles == []


def test_build_context_standalone_ntuser(tmp_path: Path) -> None:
    """build_context with NTUSER.DAT should create a standalone user profile."""
    hive_file = tmp_path / "NTUSER.DAT"
    hive_file.write_bytes(b"\x00" * 16)
    ctx = build_context(hive_file)
    assert len(ctx.user_profiles) == 1
    assert ctx.user_profiles[0].username == "standalone_user"
    assert ctx.user_profiles[0].ntuser_path == hive_file


def test_build_context_standalone_evtx(tmp_path: Path) -> None:
    """build_context with an .evtx file should enter standalone mode."""
    evtx_file = tmp_path / "Security.evtx"
    evtx_file.write_bytes(b"\x00" * 16)
    ctx = build_context(evtx_file)
    assert ctx.root == tmp_path
    assert ctx.user_profiles == []
    assert ctx.hive_path("SOFTWARE") is None


# -- _classify_input ----------------------------------------------------------


class TestClassifyInput:
    """Tests for _classify_input classification logic."""

    def test_classify_input_directory_returns_image_root(self, tmp_path: Path) -> None:
        """A directory path classifies as IMAGE_ROOT."""
        result = _classify_input(tmp_path)
        assert result == ArtifactKind.IMAGE_ROOT, (
            "Directory should classify as IMAGE_ROOT"
        )

    def test_classify_input_hive_file_returns_hive_file(self, tmp_path: Path) -> None:
        """Known hive names classify as HIVE_FILE."""
        for hive_name in ("SOFTWARE", "SYSTEM", "SAM", "NTUSER.DAT", "usrclass.dat"):
            hive_file = tmp_path / hive_name
            hive_file.write_bytes(b"regf")
            result = _classify_input(hive_file)
            assert result == ArtifactKind.HIVE_FILE, (
                f"{hive_name} should classify as HIVE_FILE"
            )

    def test_classify_input_evtx_returns_evtx_file(self, tmp_path: Path) -> None:
        """A .evtx file classifies as EVTX_FILE."""
        evtx_file = tmp_path / "Security.evtx"
        evtx_file.write_bytes(b"ElfFile")
        result = _classify_input(evtx_file)
        assert result == ArtifactKind.EVTX_FILE, (
            ".evtx file should classify as EVTX_FILE"
        )

    def test_classify_input_unknown_file_returns_image_root(
        self, tmp_path: Path
    ) -> None:
        """An unknown file type classifies as IMAGE_ROOT (fallback)."""
        unknown = tmp_path / "readme.txt"
        unknown.write_text("just a text file")
        result = _classify_input(unknown)
        assert result == ArtifactKind.IMAGE_ROOT, (
            "Unknown file type should fall back to IMAGE_ROOT"
        )

    def test_classify_input_nonexistent_returns_image_root(
        self, tmp_path: Path
    ) -> None:
        """A nonexistent path classifies as IMAGE_ROOT (not a file)."""
        result = _classify_input(tmp_path / "nonexistent")
        assert result == ArtifactKind.IMAGE_ROOT, (
            "Nonexistent path should classify as IMAGE_ROOT"
        )


# -- _build_hive_context -------------------------------------------------------


class TestBuildHiveContext:
    """Tests for _build_hive_context standalone hive setup."""

    def test_build_hive_context_ntuser(self, tmp_path: Path) -> None:
        """NTUSER.DAT creates a UserProfile with ntuser_path set."""
        ntuser = tmp_path / "NTUSER.DAT"
        ntuser.write_bytes(b"regf")
        root, hives, profiles = _build_hive_context(ntuser)
        assert root == tmp_path, "Root should be parent of hive file"
        assert hives == {}, "No system hives for user hive"
        assert len(profiles) == 1, "Should create exactly one profile"
        assert profiles[0].username == "standalone_user", (
            "Profile username should be 'standalone_user'"
        )
        assert profiles[0].ntuser_path == ntuser, (
            "ntuser_path should point to the NTUSER.DAT file"
        )

    def test_build_hive_context_usrclass(self, tmp_path: Path) -> None:
        """usrclass.dat creates a UserProfile without ntuser_path."""
        usrclass = tmp_path / "usrclass.dat"
        usrclass.write_bytes(b"regf")
        root, hives, profiles = _build_hive_context(usrclass)
        assert root == tmp_path, "Root should be parent of hive file"
        assert hives == {}, "No system hives for user hive"
        assert len(profiles) == 1, "Should create exactly one profile"
        assert profiles[0].ntuser_path is None, (
            "usrclass.dat should not set ntuser_path"
        )

    def test_build_hive_context_system_hive(self, tmp_path: Path) -> None:
        """A system hive (e.g., software) adds to hives dict, no profiles."""
        software = tmp_path / "SOFTWARE"
        software.write_bytes(b"regf")
        root, hives, profiles = _build_hive_context(software)
        assert root == tmp_path, "Root should be parent of hive file"
        assert "software" in hives, "Hive name (lowered) should be in dict"
        assert hives["software"] == software, "Hive path should match"
        assert profiles == [], "System hive should not create profiles"


# -- _build_evtx_context -------------------------------------------------------


class TestBuildEvtxContext:
    """Tests for _build_evtx_context standalone evtx setup."""

    def test_build_evtx_context(self, tmp_path: Path) -> None:
        """Returns parent dir, empty hives, empty profiles."""
        evtx = tmp_path / "Security.evtx"
        evtx.write_bytes(b"ElfFile")
        root, hives, profiles = _build_evtx_context(evtx)
        assert root == tmp_path, "Root should be parent directory"
        assert hives == {}, "Should have no hives"
        assert profiles == [], "Should have no profiles"


# -- _discover_hives -----------------------------------------------------------


class TestDiscoverHives:
    """Tests for _discover_hives hive file search."""

    def test_discover_hives_from_config_dir(self, tmp_path: Path) -> None:
        """Finds hives in Windows/System32/config/."""
        config_dir = tmp_path / "Windows" / "System32" / "config"
        config_dir.mkdir(parents=True)
        (config_dir / "SOFTWARE").write_bytes(b"regf")
        (config_dir / "SYSTEM").write_bytes(b"regf")

        hives = _discover_hives(tmp_path)
        assert "software" in hives, "Should find SOFTWARE hive in config dir"
        assert "system" in hives, "Should find SYSTEM hive in config dir"
        assert hives["software"] == config_dir / "SOFTWARE", (
            "Path should point to config dir file"
        )

    def test_discover_hives_root_fallback(self, tmp_path: Path) -> None:
        """Finds hives at root level when config/ is absent."""
        (tmp_path / "SAM").write_bytes(b"regf")
        hives = _discover_hives(tmp_path)
        assert "sam" in hives, "Should find SAM at root level via fallback"
        assert hives["sam"] == tmp_path / "SAM", "Path should point to root-level file"

    def test_discover_hives_empty_when_no_matches(self, tmp_path: Path) -> None:
        """Returns empty dict when no known hive files exist."""
        (tmp_path / "readme.txt").write_text("not a hive")
        hives = _discover_hives(tmp_path)
        assert hives == {}, "Should return empty dict for non-hive files"

    def test_discover_hives_config_takes_precedence(self, tmp_path: Path) -> None:
        """Hive in config/ takes precedence over same-named hive at root."""
        config_dir = tmp_path / "Windows" / "System32" / "config"
        config_dir.mkdir(parents=True)
        (config_dir / "SOFTWARE").write_bytes(b"config-version")
        (tmp_path / "SOFTWARE").write_bytes(b"root-version")

        hives = _discover_hives(tmp_path)
        assert hives["software"] == config_dir / "SOFTWARE", (
            "Config dir hive should take precedence over root-level hive"
        )


# -- _discover_profiles --------------------------------------------------------


class TestDiscoverProfiles:
    """Tests for _discover_profiles user enumeration."""

    def test_discover_profiles_enumerates_users(self, tmp_path: Path) -> None:
        """Finds user directories under Users/ with NTUSER.DAT."""
        users_dir = tmp_path / "Users"
        alice_dir = users_dir / "alice"
        alice_dir.mkdir(parents=True)
        (alice_dir / "NTUSER.DAT").write_bytes(b"regf")

        profiles = _discover_profiles(tmp_path)
        assert len(profiles) == 1, "Should find one user profile"
        assert profiles[0].username == "alice", "Username should be 'alice'"
        assert profiles[0].profile_path == alice_dir, (
            "Profile path should be the user directory"
        )
        assert profiles[0].ntuser_path == alice_dir / "NTUSER.DAT", (
            "ntuser_path should point to NTUSER.DAT"
        )

    def test_discover_profiles_skips_files(self, tmp_path: Path) -> None:
        """Ignores non-directory entries in Users/."""
        users_dir = tmp_path / "Users"
        users_dir.mkdir()
        (users_dir / "desktop.ini").write_text("not a user")
        profiles = _discover_profiles(tmp_path)
        assert profiles == [], "Should skip non-directory entries"

    def test_discover_profiles_empty_when_no_users_dir(self, tmp_path: Path) -> None:
        """Returns empty list when Users/ does not exist."""
        profiles = _discover_profiles(tmp_path)
        assert profiles == [], "Should return empty when Users/ dir absent"

    def test_discover_profiles_handles_missing_ntuser(self, tmp_path: Path) -> None:
        """Profile created with ntuser_path=None when NTUSER.DAT absent."""
        users_dir = tmp_path / "Users"
        bob_dir = users_dir / "bob"
        bob_dir.mkdir(parents=True)
        # No NTUSER.DAT created

        profiles = _discover_profiles(tmp_path)
        assert len(profiles) == 1, "Should create profile even without NTUSER.DAT"
        assert profiles[0].username == "bob", "Username should be 'bob'"
        assert profiles[0].ntuser_path is None, (
            "ntuser_path should be None when NTUSER.DAT is absent"
        )

    def test_discover_profiles_multiple_users_sorted(self, tmp_path: Path) -> None:
        """Multiple user directories are discovered and sorted."""
        users_dir = tmp_path / "Users"
        for name in ("charlie", "alice", "bob"):
            user_dir = users_dir / name
            user_dir.mkdir(parents=True)
            (user_dir / "NTUSER.DAT").write_bytes(b"regf")

        profiles = _discover_profiles(tmp_path)
        assert len(profiles) == 3, "Should find all three users"
        usernames = [p.username for p in profiles]
        assert usernames == ["alice", "bob", "charlie"], (
            "Profiles should be sorted alphabetically"
        )
