"""Tool management: install, verify, upgrade and roll back scanner tools.

``specs``    what each tool is and how it installs (the extension point)
``manager``  reconcile with the server's manifest; verified, atomic installs
``locks``    readers–writer lock so scans never see a half-swapped tool
"""

from .manager import InstallError, ToolManager
from .specs import SPECS, ToolSpec

__all__ = ["InstallError", "SPECS", "ToolManager", "ToolSpec"]
