"""Endpoint collection module (read-only)."""
from __future__ import annotations

from .base import EndpointCollector, CollectionResult, CollectionError
from .commands import COMMANDS, CommandSpec, read_only_catalog
from .files import FilePolicy, FileSample, FilePolicyError
from .local_collector import LocalCollector
from .ssh_collector import SSHCollector
from .winrm_collector import WinRMCollector

__all__ = [
    "EndpointCollector", "CollectionResult", "CollectionError",
    "COMMANDS", "CommandSpec", "read_only_catalog",
    "FilePolicy", "FileSample", "FilePolicyError",
    "LocalCollector", "SSHCollector", "WinRMCollector",
]
