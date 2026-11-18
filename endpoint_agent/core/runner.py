"""Uniform, logged subprocess execution — sync and async.

Mirrors Agent 1's `wifi_agent.runner` (same RunResult shape and no-shell policy)
and adds an async variant for the discovery/collection fan-out. Commands are
always passed as argument lists — never a shell string — so target-derived values
cannot inject commands.
"""
from __future__ import annotations

import asyncio
import shutil
import subprocess
import time
from dataclasses import dataclass, field


@dataclass
class RunResult:
    cmd: list[str]
    returncode: int
    stdout: str
    stderr: str
    seconds: float
    started_at: float = field(default_factory=time.time)

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def tool_available(binary: str) -> bool:
    return shutil.which(binary) is not None


def run(cmd: list[str], timeout: int | None = None, dry_run: bool = False) -> RunResult:
    """Run a command synchronously. dry_run returns the command un-executed."""
    start = time.time()
    if dry_run:
        return RunResult(cmd=cmd, returncode=0,
                         stdout=f"[dry-run] {' '.join(cmd)}", stderr="", seconds=0.0)
    if not tool_available(cmd[0]):
        return RunResult(cmd=cmd, returncode=127, stdout="",
                         stderr=f"{cmd[0]} not installed on this host", seconds=0.0)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return RunResult(cmd=cmd, returncode=proc.returncode, stdout=proc.stdout,
                         stderr=proc.stderr, seconds=time.time() - start)
    except subprocess.TimeoutExpired as e:
        return RunResult(cmd=cmd, returncode=124, stdout=e.stdout or "",
                         stderr=f"timeout after {timeout}s", seconds=time.time() - start)


async def arun(cmd: list[str], timeout: int | None = None,
               dry_run: bool = False) -> RunResult:
    """Async variant for concurrent host operations."""
    start = time.time()
    if dry_run:
        return RunResult(cmd=cmd, returncode=0,
                         stdout=f"[dry-run] {' '.join(cmd)}", stderr="", seconds=0.0)
    if not tool_available(cmd[0]):
        return RunResult(cmd=cmd, returncode=127, stdout="",
                         stderr=f"{cmd[0]} not installed on this host", seconds=0.0)
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return RunResult(cmd=cmd, returncode=124, stdout="",
                             stderr=f"timeout after {timeout}s",
                             seconds=time.time() - start)
        return RunResult(cmd=cmd, returncode=proc.returncode or 0,
                         stdout=out.decode(errors="ignore"),
                         stderr=err.decode(errors="ignore"),
                         seconds=time.time() - start)
    except Exception as e:  # pragma: no cover
        return RunResult(cmd=cmd, returncode=1, stdout="", stderr=str(e),
                         seconds=time.time() - start)
