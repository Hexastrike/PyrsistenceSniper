"""Detection for COM object hijacking via TreatAs and per-user server registrations."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
)
from pyrsistencesniper.core.registry import RegistryNode, registry_value_to_str
from pyrsistencesniper.core.windows import (
    expand_env_vars,
    extract_executable_from_cmdline,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin

_TREAT_AS_KEY = "TreatAs"
_SERVER_KEYS: tuple[str, ...] = ("InprocServer32", "LocalServer32")

_MACHINE_CLSID_PATHS: tuple[str, ...] = (
    r"Classes\CLSID",
    r"Classes\Wow6432Node\CLSID",
)
_USRCLASS_CLSID_VIEWS: tuple[tuple[str, str], ...] = (
    ("CLSID", r"SOFTWARE\Classes\CLSID"),
    (r"Wow6432Node\CLSID", r"SOFTWARE\Classes\Wow6432Node\CLSID"),
)
_NTUSER_CLSID_VIEWS: tuple[tuple[str, str], ...] = (
    (r"SOFTWARE\Classes\CLSID", r"SOFTWARE\Classes\CLSID"),
    (r"SOFTWARE\Classes\Wow6432Node\CLSID", r"SOFTWARE\Classes\Wow6432Node\CLSID"),
)

_SHADOW_DESCRIPTION = (
    "A per-user CLSID registers a COM server for a class that is also "
    "registered machine-wide. Activation resolves the user hive first, so "
    "every process using the class loads this server instead of the machine "
    "one, and writing it requires no administrator rights."
)


@dataclass(frozen=True, slots=True)
class _ClsidView:
    """One materialised CLSID tree, the path it reports under, and who may write it."""

    tree: RegistryNode
    canonical_path: str
    access: AccessLevel


def _server_image(clsid_node: RegistryNode) -> str:
    """Return the COM server image a CLSID registers, in-process server first."""
    for server_key in _SERVER_KEYS:
        server_node = clsid_node.child(server_key)
        if server_node is None:
            continue
        server_value = registry_value_to_str(server_node.get("(Default)"))
        if server_value is None:
            continue
        executable = extract_executable_from_cmdline(server_value) or server_value
        return expand_env_vars(executable)
    return ""


def _forwarded_server(views: list[_ClsidView], target_clsid: str) -> str:
    """Return the COM server image that a TreatAs target ultimately loads."""
    # A bare CLSID matches nothing on disk: left unresolved, the signer stays
    # empty and every allowlist rule naming a signer degrades to a partial match.
    # All views are searched because a TreatAs forwards across the machine/user
    # boundary in both directions.
    for view in views:
        target_node = view.tree.child(target_clsid)
        if target_node is None:
            continue
        server_image = _server_image(target_node)
        if server_image:
            return server_image
    return ""


def _hijack_values(
    clsid_node: RegistryNode, *, shadows_machine_class: bool
) -> Iterator[tuple[str, str]]:
    """Yield the subkey and value pairs on one CLSID that constitute a hijack."""
    # TreatAs is always reported: it exists only to redirect activation and stays
    # rare -- 17 entries across all four CLSID views of a live Windows 11 profile.
    # A server key is reported only when a per-user CLSID shadows a machine class,
    # because the override is what makes it the technique. Reporting every
    # per-user server key instead surfaced 69 stock OneDrive, Paint and shell
    # registrations at MEDIUM on that same host.
    treat_as_node = clsid_node.child(_TREAT_AS_KEY)
    if treat_as_node is not None:
        treat_as_value = registry_value_to_str(treat_as_node.get("(Default)"))
        if treat_as_value is not None:
            yield _TREAT_AS_KEY, treat_as_value
    if not shadows_machine_class:
        return
    for server_key in _SERVER_KEYS:
        server_node = clsid_node.child(server_key)
        if server_node is None:
            continue
        server_value = registry_value_to_str(server_node.get("(Default)"))
        if server_value is not None:
            yield server_key, server_value


@register_plugin
class ComTreatAs(PersistencePlugin):
    """Detects COM class hijacks registered through TreatAs or per-user servers."""

    definition = CheckDefinition(
        id="com_treat_as",
        technique="COM Object Hijack",
        mitre_id="T1546.015",
        description=(
            "A TreatAs subkey under a CLSID redirects activation of that COM class to "
            "a different one, so the substitute's server runs whenever the original "
            "CLSID is activated."
        ),
        references=("https://attack.mitre.org/techniques/T1546/015/",),
    )

    def run(self) -> list[Finding]:
        """Report every CLSID hijack across the machine and per-user views."""
        views = self._clsid_views()
        machine_clsids = frozenset(
            clsid.casefold()
            for view in views
            if view.access is AccessLevel.SYSTEM
            for clsid, _clsid_node in view.tree.children()
        )
        findings: list[Finding] = []
        emitted: set[tuple[str, str]] = set()
        for view in views:
            for finding in self._view_findings(view, views, machine_clsids):
                identity = (finding.path, finding.value)
                if identity in emitted:
                    continue
                emitted.add(identity)
                findings.append(finding)
        return findings

    def _view_findings(
        self,
        view: _ClsidView,
        views: list[_ClsidView],
        machine_clsids: frozenset[str],
    ) -> Iterator[Finding]:
        """Yield every hijack recorded in one materialised CLSID tree."""
        for clsid, clsid_node in view.tree.children():
            shadows_machine_class = (
                view.access is AccessLevel.USER and clsid.casefold() in machine_clsids
            )
            for key_name, value in _hijack_values(
                clsid_node, shadows_machine_class=shadows_machine_class
            ):
                is_treat_as = key_name == _TREAT_AS_KEY
                yield self._make_finding(
                    path=f"{view.canonical_path}\\{clsid}\\{key_name}",
                    value=value,
                    access=view.access,
                    description="" if is_treat_as else _SHADOW_DESCRIPTION,
                    resolve_target=(
                        _forwarded_server(views, value) if is_treat_as else ""
                    ),
                )

    def _clsid_views(self) -> list[_ClsidView]:
        """Materialise every CLSID tree this scan can read, machine views first."""
        views: list[_ClsidView] = []
        for key_path in _MACHINE_CLSID_PATHS:
            tree = self.context.load_subtree("SOFTWARE", key_path)
            if tree is not None:
                views.append(
                    _ClsidView(tree, f"HKLM\\SOFTWARE\\{key_path}", AccessLevel.SYSTEM)
                )
        views.extend(self._user_clsid_views())
        return views

    def _user_clsid_views(self) -> Iterator[_ClsidView]:
        """Yield the per-user CLSID trees, UsrClass.dat before NTUSER.DAT."""
        for hives, view_paths in (
            (self.context.iter_usrclass_hives(), _USRCLASS_CLSID_VIEWS),
            (self.context.iter_user_hives(), _NTUSER_CLSID_VIEWS),
        ):
            for user_profile, hive in hives:
                for key_path, canonical_suffix in view_paths:
                    tree = self.registry.load_subtree(hive, key_path)
                    if tree is None:
                        continue
                    yield _ClsidView(
                        tree,
                        f"HKU\\{user_profile.username}\\{canonical_suffix}",
                        AccessLevel.USER,
                    )
