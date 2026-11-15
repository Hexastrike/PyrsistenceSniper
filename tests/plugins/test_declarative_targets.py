"""Every declarative check must read the registry location its definition declares."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from pyrsistencesniper.core.models import (
    CheckDefinition,
    HiveScope,
    RegistryTarget,
    UserProfile,
)
from pyrsistencesniper.core.windows import normalize_windows_path
from pyrsistencesniper.plugins import PLUGIN_REGISTRY, discover_plugins
from pyrsistencesniper.plugins.base import PersistencePlugin

from .conftest import make_node, make_plugin, setup_keys, setup_usrclass_only

if TYPE_CHECKING:
    from pyrsistencesniper.core.models import Finding

_CONTROLSET = "ControlSet001"
_DECOY_KEY = r"Decoy\Path\No\Check\Declares"
_SENTINEL = r"C:\sentinel\payload.exe"
_USERNAME = "sentinel"
_USER_CLASSES_PREFIX = "software\\classes\\"
_MACHINE_CLASSES_ROOT = "Classes"
_WOW64_KEY = "Wow6432Node"
_REDIRECTED_HIVE = "SOFTWARE"


def _declarative_checks() -> list[tuple[str, type[PersistencePlugin]]]:
    """Return every registered check that relies on the declarative engine."""
    discover_plugins()
    return sorted(
        (check_id, cls)
        for check_id, cls in PLUGIN_REGISTRY.items()
        if cls.run is PersistencePlugin.run and cls.definition.targets
    )


def _hklm_key_path(target: RegistryTarget) -> str:
    """Return the key path the engine asks for under HKLM, hive name removed."""
    normalized = normalize_windows_path(target.path).strip("\\") if target.path else ""
    parts = normalized.split("\\", 1) if normalized else [""]
    key_path = parts[1] if len(parts) > 1 else ""
    return key_path.replace("{controlset}", _CONTROLSET)


def _hklm_hive_name(target: RegistryTarget) -> str:
    """Return the machine hive file a target's path names."""
    normalized = normalize_windows_path(target.path).strip("\\") if target.path else ""
    return normalized.split("\\", 1)[0] if normalized else ""


def _declared_key_paths(definition: CheckDefinition) -> list[str]:
    """Return every key path the engine will request for this check's targets."""
    paths: list[str] = []
    for target in definition.targets:
        if target.scope in (HiveScope.HKLM, HiveScope.BOTH):
            paths.append(_hklm_key_path(target))
        if target.scope in (HiveScope.HKU, HiveScope.BOTH):
            paths.append(target.path)
    return paths


def _satisfying_node(target: RegistryTarget) -> object:
    """Build a node shaped so the target yields at least one finding."""
    value_name = "SentinelValue" if target.values == "*" else target.values
    if target.recurse:
        child = make_node(name="SentinelChild", values={value_name: _SENTINEL})
        return make_node(children={"SentinelChild": child})
    return make_node(values={value_name: _SENTINEL})


def _wiring(definition: CheckDefinition) -> dict[str, object]:
    """Map every declared key path to a node that satisfies its target."""
    wiring: dict[str, object] = {}
    for target in definition.targets:
        node = _satisfying_node(target)
        if target.scope in (HiveScope.HKLM, HiveScope.BOTH):
            wiring[_hklm_key_path(target)] = node
        if target.scope in (HiveScope.HKU, HiveScope.BOTH):
            wiring[target.path] = node
    return wiring


def _profiles() -> list[UserProfile]:
    """Return one user profile carrying both per-user hives, as discovery sets them."""
    return [
        UserProfile(
            username=_USERNAME,
            profile_path=Path(f"/img/Users/{_USERNAME}"),
            ntuser_path=Path(f"/img/Users/{_USERNAME}/NTUSER.DAT"),
            usrclass_path=Path(f"/img/Users/{_USERNAME}/UsrClass.dat"),
        )
    ]


def _run(
    cls: type[PersistencePlugin], tmp_path: Path, keys: dict[str, object]
) -> list[Finding]:
    """Run a declarative check against a hive answering only the given key paths."""
    plugin = make_plugin(cls, tmp_path, user_profiles=_profiles())
    plugin.context.active_controlset = _CONTROLSET
    setup_keys(plugin, keys)
    return plugin.run()


_CHECKS = _declarative_checks()
_IDS = [check_id for check_id, _cls in _CHECKS]


@pytest.mark.parametrize(("check_id", "cls"), _CHECKS, ids=_IDS)
def test_declared_target_produces_findings(
    check_id: str, cls: type[PersistencePlugin], tmp_path: Path
) -> None:
    """A hive answering only the declared key paths yields findings for the check."""
    findings = _run(cls, tmp_path, _wiring(cls.definition))

    assert findings, (
        f"{check_id} produced nothing from the key paths its own definition declares: "
        f"{_declared_key_paths(cls.definition)}"
    )


@pytest.mark.parametrize(("check_id", "cls"), _CHECKS, ids=_IDS)
def test_undeclared_key_produces_nothing(
    check_id: str, cls: type[PersistencePlugin], tmp_path: Path
) -> None:
    """A hive answering only an undeclared key yields nothing, pinning the read."""
    target = cls.definition.targets[0]
    findings = _run(cls, tmp_path, {_DECOY_KEY: _satisfying_node(target)})

    assert not findings, (
        f"{check_id} produced findings from {_DECOY_KEY}, which it never declares; "
        "the check reads whatever key it is handed"
    )


def _handwritten_checks() -> list[tuple[str, type[PersistencePlugin]]]:
    """Return every registered check that implements its own run()."""
    discover_plugins()
    return sorted(
        (check_id, cls)
        for check_id, cls in PLUGIN_REGISTRY.items()
        if cls.run is not PersistencePlugin.run
    )


_HANDWRITTEN = _handwritten_checks()
_HANDWRITTEN_IDS = [check_id for check_id, _cls in _HANDWRITTEN]


@pytest.mark.parametrize(("check_id", "cls"), _HANDWRITTEN, ids=_HANDWRITTEN_IDS)
def test_handwritten_check_ignores_an_undeclared_key(
    check_id: str, cls: type[PersistencePlugin], tmp_path: Path
) -> None:
    """A hand-written check reads a key it chose, not whatever the hive hands it."""
    node = make_node(
        values={"SentinelValue": _SENTINEL},
        children={
            "SentinelChild": make_node(
                name="SentinelChild", values={"SentinelValue": _SENTINEL}
            )
        },
    )
    findings = _run(cls, tmp_path, {_DECOY_KEY: node})

    assert not findings, (
        f"{check_id} produced findings from {_DECOY_KEY}, a key it never reads; "
        "the check accepts whatever subtree it is given"
    )


def test_every_declarative_check_is_covered() -> None:
    """The sweep above must actually cover the declarative checks in the registry."""
    discover_plugins()
    declarative = {
        check_id
        for check_id, cls in PLUGIN_REGISTRY.items()
        if cls.run is PersistencePlugin.run and cls.definition.targets
    }

    assert declarative == set(_IDS)
    assert len(declarative) > 50


def _usrclass_key_path(target: RegistryTarget) -> str | None:
    """Return the UsrClass.dat key path of a per-user class target, else None."""
    if target.scope not in (HiveScope.HKU, HiveScope.BOTH):
        return None
    path = target.path.strip("\\")
    if not path.lower().startswith(_USER_CLASSES_PREFIX):
        return None
    return path[len(_USER_CLASSES_PREFIX) :]


def _canonical_user_prefix(target: RegistryTarget) -> str:
    """Return the HKCU-shaped path a per-user class finding must be reported under."""
    return "HKU\\" + _USERNAME + "\\" + target.path.strip("\\")


def _machine_wow64_key_path(key_path: str) -> str:
    """Return where a 32-bit writer's copy of a SOFTWARE-hive key path lives."""
    lowered = key_path.lower()
    root = _MACHINE_CLASSES_ROOT
    if lowered == root.lower():
        return root + "\\" + _WOW64_KEY
    if lowered.startswith(root.lower() + "\\"):
        return root + "\\" + _WOW64_KEY + key_path[len(root) :]
    return _WOW64_KEY + "\\" + key_path


def _user_wow64_key_path(key_path: str) -> str | None:
    """Return where a 32-bit writer's copy of a per-user key path lives, else None."""
    path = key_path.strip("\\")
    prefix = _USER_CLASSES_PREFIX.rstrip("\\")
    if not path.lower().startswith(prefix + "\\"):
        return None
    return path[: len(prefix)] + "\\" + _WOW64_KEY + path[len(prefix) :]


def _redirected_key_paths(target: RegistryTarget) -> set[str]:
    """Return every 32-bit-view key path the engine must read for this target."""
    paths: set[str] = set()
    if target.scope in (HiveScope.HKLM, HiveScope.BOTH) and (
        _hklm_hive_name(target).upper() == _REDIRECTED_HIVE
    ):
        paths.add(_machine_wow64_key_path(_hklm_key_path(target)))
    if target.scope in (HiveScope.HKU, HiveScope.BOTH):
        user_path = _user_wow64_key_path(target.path)
        if user_path is not None:
            paths.add(user_path)
    return paths


def _run_against_usrclass(
    cls: type[PersistencePlugin], tmp_path: Path, keys: dict[str, object]
) -> list[Finding]:
    """Run a check against an image where only UsrClass.dat answers any key."""
    plugin = make_plugin(cls, tmp_path, user_profiles=_profiles())
    plugin.context.active_controlset = _CONTROLSET
    setup_usrclass_only(plugin, keys)
    return plugin.run()


_PER_USER_CLASS_CHECKS = [
    (check_id, cls)
    for check_id, cls in _CHECKS
    if any(_usrclass_key_path(target) is not None for target in cls.definition.targets)
]
_PER_USER_CLASS_IDS = [check_id for check_id, _cls in _PER_USER_CLASS_CHECKS]


@pytest.mark.parametrize(
    ("check_id", "cls"), _PER_USER_CLASS_CHECKS, ids=_PER_USER_CLASS_IDS
)
def test_per_user_class_target_is_read_from_usrclass(
    check_id: str, cls: type[PersistencePlugin], tmp_path: Path
) -> None:
    """Per-user class registrations live in UsrClass.dat, never in NTUSER.DAT."""
    keys = {
        usrclass_path: _satisfying_node(target)
        for target in cls.definition.targets
        if (usrclass_path := _usrclass_key_path(target)) is not None
    }

    findings = _run_against_usrclass(cls, tmp_path, keys)

    assert findings, (
        f"{check_id} read nothing out of UsrClass.dat at {sorted(keys)}, where the "
        "per-user class registrations it declares are actually stored"
    )
    prefixes = tuple(
        _canonical_user_prefix(target)
        for target in cls.definition.targets
        if _usrclass_key_path(target) is not None
    )
    assert all(finding.path.startswith(prefixes) for finding in findings), (
        f"{check_id} reported a UsrClass.dat finding under a path an analyst cannot "
        f"match to the NTUSER.DAT half; expected one of {sorted(prefixes)}"
    )


def test_per_user_class_sweep_covers_the_checks_that_need_it() -> None:
    """The per-user class sweep is worthless if it matches no check at all."""
    assert _PER_USER_CLASS_IDS


def test_wow64_targets_are_read_from_the_redirected_key(tmp_path: Path) -> None:
    """Every target opting into the 32-bit view is read at its redirected key path."""
    for check_id, cls in _CHECKS:
        for target in cls.definition.targets:
            if not target.include_wow64:
                continue
            redirected = _redirected_key_paths(target)
            if not redirected:
                continue
            keys = {key_path: _satisfying_node(target) for key_path in redirected}
            assert _run(cls, tmp_path, keys), (
                f"{check_id} opted into the 32-bit registry view but read nothing "
                f"from {sorted(redirected)}"
            )
