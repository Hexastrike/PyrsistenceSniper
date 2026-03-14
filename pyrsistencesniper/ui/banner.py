# ruff: noqa: E501
from __future__ import annotations

import sys

from rich.console import Console

from pyrsistencesniper import __version__

_BANNER = r"""
[deep_pink2]
    ██████╗ ██╗   ██╗██████╗ ███████╗██╗███████╗████████╗███████╗███╗   ██╗ ██████╗███████╗
    ██╔══██╗╚██╗ ██╔╝██╔══██╗██╔════╝██║██╔════╝╚══██╔══╝██╔════╝████╗  ██║██╔════╝██╔════╝
    ██████╔╝ ╚████╔╝ ██████╔╝███████╗██║███████╗   ██║   █████╗  ██╔██╗ ██║██║     █████╗
    ██╔═══╝   ╚██╔╝  ██╔══██╗╚════██║██║╚════██║   ██║   ██╔══╝  ██║╚██╗██║██║     ██╔══╝
    ██║        ██║   ██║  ██║███████║██║███████║   ██║   ███████╗██║ ╚████║╚██████╗███████╗
    ╚═╝        ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═══╝ ╚═════╝╚══════╝
[/deep_pink2]
[deep_pink2]
    ███████╗███╗   ██╗██╗██████╗ ███████╗██████╗
    ██╔════╝████╗  ██║██║██╔══██╗██╔════╝██╔══██╗
    ███████╗██╔██╗ ██║██║██████╔╝█████╗  ██████╔╝
    ╚════██║██║╚██╗██║██║██╔═══╝ ██╔══╝  ██╔══██╗
    ███████║██║ ╚████║██║██║     ███████╗██║  ██║
    ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
[/deep_pink2]
    by Maurice Fielenbach (Hexastrike Cybersecurity)
    Version {version}
"""


def print_banner() -> None:
    """Print the ASCII art banner to stderr if running in a terminal."""
    if not sys.stderr.isatty():
        return
    console = Console(stderr=True)
    console.print(_BANNER.replace("{version}", __version__), highlight=False)
