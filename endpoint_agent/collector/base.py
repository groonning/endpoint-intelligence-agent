"""Collector base class + result types.

A collector connects to one authorised endpoint and runs the read-only command
catalog for that OS, returning a structured CollectionResult. Concrete backends
(SSH, WinRM, local) implement only `_connect`, `_exec_raw`, and `_close`.

Safety invariants enforced here, for every backend:
  * The target is re-checked against the Scope gate on every collect().
  * RBAC must permit `collect.read` for the actor.
  * Only CommandSpecs from the catalog are ever executed — callers choose keys,
    never raw command strings.
  * Rate limiter + kill switch are honoured between commands.
  * Each command execution is audit-logged (by key, never with output secrets).
"""
from __future__ import annotations

import abc
import time
from dataclasses import dataclass, field, asdict
from typing import Any

from ..core.scope import Scope
from ..core.rbac import RBAC
from ..core.audit import AuditLog
from ..core.ratelimit import RateLimiter
from ..core.killswitch import KillSwitch
from .commands import CommandSpec, read_only_catalog
from .files import FilePolicy, FileSample, FilePolicyError, decode_content, sha256


class CollectionError(Exception):
    pass


@dataclass
class CommandOutput:
    key: str
    category: str
    returncode: int
    stdout: str
    stderr: str
    seconds: float
    redactable: bool = False

    def dict(self) -> dict:
        return asdict(self)


@dataclass
class CollectionResult:
    host: str
    os_name: str
    transport: str
    started_at: str
    finished_at: str = ""
    outputs: dict[str, CommandOutput] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    files: list[FileSample] = field(default_factory=list)
    # Raw file contents, kept in memory for hashing + YARA only. Deliberately
    # left out of dict(): contents are never written to reports or baselines.
    file_bytes: dict[str, bytes] = field(default_factory=dict, repr=False)

    def dict(self) -> dict:
        return {"host": self.host, "os_name": self.os_name,
                "transport": self.transport, "started_at": self.started_at,
                "finished_at": self.finished_at,
                "outputs": {k: v.dict() for k, v in self.outputs.items()},
                "files": [f.dict() for f in self.files],
                "errors": list(self.errors)}

    def get(self, key: str) -> str:
        o = self.outputs.get(key)
        return o.stdout if o else ""


class EndpointCollector(abc.ABC):
    transport = "base"

    def __init__(self, scope: Scope, rbac: RBAC | None = None,
                 audit: AuditLog | None = None, rate: RateLimiter | None = None,
                 kill: KillSwitch | None = None, actor: str = "agent2",
                 role: str = "operator", command_timeout: int = 60,
                 include_logs: bool = True, extras: list[str] | None = None,
                 file_policy: FilePolicy | None = None):
        self.include_logs = include_logs
        self.extras = extras or []
        self.file_policy = file_policy
        self.scope = scope
        self.rbac = rbac
        self.audit = audit
        self.rate = rate or RateLimiter(5, 10)
        self.kill = kill or KillSwitch()
        self.actor = actor
        self.role = role
        self.command_timeout = command_timeout

    # ---- backend hooks ------------------------------------------------
    @abc.abstractmethod
    def _connect(self, host: str, **kw) -> None: ...

    @abc.abstractmethod
    def _exec_raw(self, argv: list[str], timeout: int) -> tuple[int, str, str]:
        """Run one argv on the endpoint, return (rc, stdout, stderr)."""

    @abc.abstractmethod
    def _close(self) -> None: ...

    # ---- orchestration ------------------------------------------------
    def collect(self, host: str, os_name: str, only: list[str] | None = None,
                **connect_kw) -> CollectionResult:
        # 1) hard scope gate
        self.scope.require(host)
        # 2) RBAC
        if self.rbac is not None:
            self.rbac.check(self.role, "collect.read")
        catalog = read_only_catalog(os_name, self.include_logs, self.extras)
        if not catalog:
            raise CollectionError(f"no command catalog for os {os_name!r}")
        if only:
            catalog = [c for c in catalog if c.key in set(only)]

        res = CollectionResult(host=host, os_name=os_name,
                               transport=self.transport, started_at=_iso())
        if self.audit:
            self.audit.record(self.actor, f"collect.{self.transport}", host,
                              "start", {"os": os_name, "keys": [c.key for c in catalog]})
        try:
            self._connect(host, **connect_kw)
        except Exception as e:
            res.errors.append(f"connect failed: {e}")
            res.finished_at = _iso()
            if self.audit:
                self.audit.record(self.actor, f"collect.{self.transport}", host,
                                  "error", {"stage": "connect", "error": str(e)})
            raise CollectionError(f"connect failed: {e}") from e
        try:
            for spec in catalog:
                self.kill.check()
                self.rate.acquire()
                out = self._run_spec(spec)
                res.outputs[spec.key] = out
            if self.file_policy is not None and not only:
                self._collect_files(res)
        finally:
            try:
                self._close()
            except Exception:
                pass
            res.finished_at = _iso()
        if self.audit:
            self.audit.record(self.actor, f"collect.{self.transport}", host, "ok",
                              {"collected": list(res.outputs)})
        return res

    def _collect_files(self, res: CollectionResult) -> None:
        """Read file contents, but only inside the approved directories."""
        pol = self.file_policy
        budget = pol.max_files
        for directory in pol.paths(res.os_name):
            if budget <= 0:
                break
            self.kill.check()
            self.rate.acquire()
            rc, out, err = self._exec_raw(pol.list_argv(res.os_name, directory),
                                          self.command_timeout)
            samples = pol.parse_listing(res.os_name, directory, out)[:budget]
            budget -= len(samples)
            if self.audit:
                self.audit.record(self.actor, "collect.files", res.host, "ok",
                                  {"directory": directory, "files": len(samples)})
            for sample in samples:
                self.kill.check()
                self.rate.acquire()
                try:
                    rc, out, err = self._exec_raw(
                        pol.read_argv(res.os_name, sample.path), self.command_timeout)
                    if rc != 0:
                        raise FilePolicyError(err.strip() or f"exit {rc}")
                    data = decode_content(out)
                    if len(data) > pol.max_file_bytes:
                        raise FilePolicyError("file grew past the size limit")
                    sample.sha256 = sha256(data)
                    sample.size = len(data)
                    res.file_bytes[sample.path] = data
                except Exception as e:
                    sample.error = str(e)[:200]
                res.files.append(sample)

    def _run_spec(self, spec: CommandSpec) -> CommandOutput:
        t0 = time.time()
        try:
            rc, out, err = self._exec_raw(spec.argv, self.command_timeout)
        except Exception as e:
            rc, out, err = 1, "", str(e)
        return CommandOutput(key=spec.key, category=spec.category, returncode=rc,
                             stdout=out, stderr=err, seconds=time.time() - t0,
                             redactable=spec.redactable)


def _iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
