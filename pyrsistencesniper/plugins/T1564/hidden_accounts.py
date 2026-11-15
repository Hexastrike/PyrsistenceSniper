"""Detect local accounts hidden from the sign-in screen (T1564.002)."""

from __future__ import annotations

from pyrsistencesniper.core.models import (
    AccessLevel,
    CheckDefinition,
    Finding,
)
from pyrsistencesniper.core.sam import (
    USER_LIST_REPORT_KEY,
    iter_hidden_accounts,
)
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import PersistencePlugin


@register_plugin
class HiddenLocalAccount(PersistencePlugin):
    """Detects local accounts hidden from the sign-in screen by SpecialAccounts."""

    definition = CheckDefinition(
        id="hidden_account",
        technique="Hidden Local Account",
        mitre_id="T1564.002",
        description=(
            "A SpecialAccounts\\UserList entry set to 0 removes the named "
            "account from the sign-in screen and from the Settings user list. "
            "Windows creates no entry here by default, so a zero is a "
            "deliberate decision to keep an account out of sight and is the "
            "standard companion to a backdoor local account."
        ),
    )

    def run(self) -> list[Finding]:
        """Report every account SpecialAccounts hides from the sign-in screen."""
        return [
            self._make_finding(
                path=f"{USER_LIST_REPORT_KEY}\\{account_name}",
                value=f"{account_name} is hidden from the sign-in screen",
                access=AccessLevel.SYSTEM,
            )
            for account_name in iter_hidden_accounts(self.context)
        ]
