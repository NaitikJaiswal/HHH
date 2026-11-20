"""LOGN Platform and Application Log Adapters

Provides an extensible adapter architecture to extract log records from Windows,
Linux, and Application log sources with graceful fallbacks and availability checks.
"""

from __future__ import annotations

import sys
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class BaseLogAdapter(ABC):
    """Abstract base class for all LOGN log adapters."""

    def __init__(self, name: str) -> None:
        self.name = name

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the source or underlying OS mechanism is available on this host."""
        raise NotImplementedError

    @abstractmethod
    def collect(self) -> List[Dict[str, Any]]:
        """Collect and return raw log records.

        Each record is a dictionary containing at least:
        - 'event_type': str
        - 'severity': str
        - 'message': str
        - 'metadata': dict
        """
        raise NotImplementedError


from .windows_adapter import WindowsEventLogAdapter
from .linux_adapter import LinuxLogAdapter
from .application_adapter import ApplicationLogAdapter

__all__ = [
    "BaseLogAdapter",
    "WindowsEventLogAdapter",
    "LinuxLogAdapter",
    "ApplicationLogAdapter",
    "get_system_adapter",
]


def get_system_adapter() -> BaseLogAdapter:
    """Return the appropriate OS system log adapter based on the host platform."""
    if sys.platform.startswith("win"):
        return WindowsEventLogAdapter()
    if sys.platform.startswith("linux"):
        return LinuxLogAdapter()
    # Default to an application adapter as universal fallback
    return ApplicationLogAdapter()
