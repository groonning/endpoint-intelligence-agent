"""Local collector — runs the read-only catalog against the host the agent runs
on (localhost / 127.0.0.1). Useful for self-audit of the Kali box and as a
dependency-free backend for the test suite (no SSH/WinRM server needed).
"""
from __future__ import annotations

import subprocess

from .base import EndpointCollector


class LocalCollector(EndpointCollector):
    transport = "local"

    def _connect(self, host: str, **kw) -> None:
        # Only localhost makes sense here; scope gate already ran in collect().
        self._host = host

    def _exec_raw(self, argv: list[str], timeout: int) -> tuple[int, str, str]:
        try:
            p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
            return p.returncode, p.stdout, p.stderr
        except FileNotFoundError:
            return 127, "", f"{argv[0]} not found"
        except subprocess.TimeoutExpired:
            return 124, "", f"timeout after {timeout}s"

    def _close(self) -> None:
        pass
