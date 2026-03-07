from __future__ import annotations

from pathlib import Path

from pyrsistencesniper.core.image import ForensicImage

# -- hive_path ----------------------------------------------------------------


def test_hive_path_software(tmp_path: Path) -> None:
    config = tmp_path / "Windows" / "System32" / "config"
    config.mkdir(parents=True)
    (config / "SOFTWARE").write_bytes(b"\x00" * 16)
    img = ForensicImage(tmp_path)
    path = img.hive_path("SOFTWARE")
    assert path is not None
    assert path.name == "SOFTWARE"
    assert path.is_file()


def test_hive_path_system(tmp_path: Path) -> None:
    config = tmp_path / "Windows" / "System32" / "config"
    config.mkdir(parents=True)
    (config / "SYSTEM").write_bytes(b"\x00" * 16)
    img = ForensicImage(tmp_path)
    path = img.hive_path("SYSTEM")
    assert path is not None
    assert path.name == "SYSTEM"


def test_hive_path_ntuser_requires_username(tmp_path: Path) -> None:
    img = ForensicImage(tmp_path)
    assert img.hive_path("NTUSER.DAT") is None


def test_hive_path_ntuser_with_username(tmp_path: Path) -> None:
    user_dir = tmp_path / "Users" / "John Doe"
    user_dir.mkdir(parents=True)
    (user_dir / "NTUSER.DAT").write_bytes(b"\x00" * 16)
    img = ForensicImage(tmp_path)
    path = img.hive_path("NTUSER.DAT", "John Doe")
    assert path is not None
    assert path.is_file()


def test_hive_path_nonexistent(tmp_path: Path) -> None:
    img = ForensicImage(tmp_path)
    assert img.hive_path("BOGUS_HIVE") is None


# -- user_profiles ------------------------------------------------------------


def test_user_profiles_discovers_users(tmp_path: Path) -> None:
    users = tmp_path / "Users"
    for name in ("John Doe", "Jane Doe", "Default", "Public"):
        d = users / name
        d.mkdir(parents=True)
        if name != "Public":
            (d / "NTUSER.DAT").write_bytes(b"\x00" * 16)
    img = ForensicImage(tmp_path)
    usernames = [p.username for p in img.user_profiles]
    assert "John Doe" in usernames
    assert "Jane Doe" in usernames
    assert "Default" in usernames
    assert "Public" in usernames


def test_user_profiles_ntuser_presence(tmp_path: Path) -> None:
    users = tmp_path / "Users"
    for name in ("John Doe", "Jane Doe", "Default", "Public"):
        d = users / name
        d.mkdir(parents=True)
        if name != "Public":
            (d / "NTUSER.DAT").write_bytes(b"\x00" * 16)
    img = ForensicImage(tmp_path)
    by_name = {p.username: p for p in img.user_profiles}
    assert by_name["John Doe"].ntuser_path is not None
    assert by_name["Jane Doe"].ntuser_path is not None
    assert by_name["Default"].ntuser_path is not None
    assert by_name["Public"].ntuser_path is None


# -- hostname -----------------------------------------------------------------


def test_hostname_missing_system_hive(tmp_path: Path) -> None:
    img = ForensicImage(tmp_path)
    assert img.hostname == ""


def test_hostname_override(tmp_path: Path) -> None:
    img = ForensicImage(tmp_path, hostname_override="MY-HOST")
    assert img.hostname == "MY-HOST"


# -- is_standalone_artifact ---------------------------------------------------


def test_is_standalone_artifact_software() -> None:
    assert ForensicImage.is_standalone_artifact("SOFTWARE") is True


def test_is_standalone_artifact_ntuser() -> None:
    assert ForensicImage.is_standalone_artifact("NTUSER.DAT") is True


def test_is_standalone_artifact_case_insensitive() -> None:
    assert ForensicImage.is_standalone_artifact("system") is True


def test_is_standalone_artifact_random_file() -> None:
    assert ForensicImage.is_standalone_artifact("readme.txt") is False


# -- hive_path UsrClass.dat ---------------------------------------------------


def test_hive_path_usrclass_deep_path(tmp_path: Path) -> None:
    """UsrClass.dat should be found at the correct deep path."""
    user_dir = (
        tmp_path / "Users" / "Alice" / "AppData" / "Local" / "Microsoft" / "Windows"
    )
    user_dir.mkdir(parents=True)
    hive = user_dir / "UsrClass.dat"
    hive.write_bytes(b"fake hive")

    img = ForensicImage(tmp_path)
    result = img.hive_path("UsrClass.dat", "Alice")
    assert result is not None
    assert result == hive


def test_hive_path_usrclass_shallow_fallback(tmp_path: Path) -> None:
    """UsrClass.dat at shallow path should work as fallback."""
    user_dir = tmp_path / "Users" / "Bob"
    user_dir.mkdir(parents=True)
    hive = user_dir / "UsrClass.dat"
    hive.write_bytes(b"fake hive")

    img = ForensicImage(tmp_path)
    result = img.hive_path("UsrClass.dat", "Bob")
    assert result is not None
    assert result == hive


def test_hive_path_usrclass_requires_username(tmp_path: Path) -> None:
    img = ForensicImage(tmp_path)
    assert img.hive_path("UsrClass.dat") is None


# -- user_profiles caching ----------------------------------------------------


def test_user_profiles_is_cached(tmp_path: Path) -> None:
    """user_profiles should return the same object on repeated access."""
    (tmp_path / "Users" / "TestUser").mkdir(parents=True)
    img = ForensicImage(tmp_path)
    first = img.user_profiles
    second = img.user_profiles
    assert first is second
