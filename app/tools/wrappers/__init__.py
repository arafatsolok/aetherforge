"""Concrete tool wrappers.

Each submodule here contributes exactly one ``ToolWrapper`` subclass.
The registry loader auto-discovers them at boot — no manual registration
needed. Adding a new tool:

    1. Create ``app/tools/wrappers/<name>.py`` with a subclass of
       ``ToolWrapper``.
    2. Build the Dockerfile under ``docker/tools/<name>/``.
    3. Add a per-tool row in ``configs/tools.yaml`` with image +
       overrides.
    4. Author rule YAMLs in ``rules/*/``.
"""

from __future__ import annotations

from app.tools.wrappers.amass import AmassWrapper
from app.tools.wrappers.ffuf import FfufWrapper
from app.tools.wrappers.httpx import HttpxWrapper
from app.tools.wrappers.masscan import MasscanWrapper
from app.tools.wrappers.metasploit import MetasploitWrapper
from app.tools.wrappers.nettacker import NettackerWrapper
from app.tools.wrappers.nikto import NiktoWrapper
from app.tools.wrappers.nmap import NmapWrapper
from app.tools.wrappers.nuclei import NucleiWrapper
from app.tools.wrappers.openvas import OpenvasWrapper
from app.tools.wrappers.sqlmap import SqlmapWrapper
from app.tools.wrappers.subfinder import SubfinderWrapper
from app.tools.wrappers.wapiti import WapitiWrapper

__all__ = [
    "AmassWrapper",
    "FfufWrapper",
    "HttpxWrapper",
    "MasscanWrapper",
    "MetasploitWrapper",
    "NettackerWrapper",
    "NiktoWrapper",
    "NmapWrapper",
    "NucleiWrapper",
    "OpenvasWrapper",
    "SqlmapWrapper",
    "SubfinderWrapper",
    "WapitiWrapper",
]
