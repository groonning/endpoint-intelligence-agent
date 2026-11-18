"""Append-only, hash-chained audit log.

Every action the agent takes that touches a remote host — discovery sweep,
connection, command execution, scan, model call, report write — is recorded as
one JSON line. Each record embeds the SHA-256 of the previous record, so the log
is tamper-evident: altering or deleting any line breaks the chain, and
`verify()` reports the first break.

The log is intentionally simple (JSONL, one file) so it is trivial to ship to
the Security Orchestrator or an external SIEM. It never records secrets — the
credential vault passes only a credential *reference* (an id), never the secret.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any, Iterator

_GENESIS = "0" * 64


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@dataclass
class AuditEvent:
    ts: str
    actor: str                    # role / operator / "agent2"
    action: str                   # e.g. "collect.ssh", "discovery.sweep"
    target: str                   # host or range the action touched
    outcome: str                  # "ok" | "denied" | "error" | "start"
    detail: dict[str, Any] = field(default_factory=dict)
    prev_hash: str = _GENESIS
    hash: str = ""

    def compute_hash(self) -> str:
        body = {k: getattr(self, k) for k in
                ("ts", "actor", "action", "target", "outcome", "detail", "prev_hash")}
        blob = json.dumps(body, sort_keys=True, ensure_ascii=False).encode()
        return hashlib.sha256(blob).hexdigest()

    def dict(self) -> dict:
        return asdict(self)


class AuditLog:
    """Thread-safe, append-only audit log backed by a JSONL file."""

    def __init__(self, path: str | Path = "audit/agent2-audit.jsonl"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._last_hash = self._read_last_hash()

    def _read_last_hash(self) -> str:
        if not self.path.exists():
            return _GENESIS
        last = _GENESIS
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    last = json.loads(line).get("hash", last)
                except json.JSONDecodeError:
                    continue
        return last

    def record(self, actor: str, action: str, target: str, outcome: str,
               detail: dict[str, Any] | None = None) -> AuditEvent:
        with self._lock:
            ev = AuditEvent(ts=_now_iso(), actor=actor, action=action,
                            target=target, outcome=outcome, detail=detail or {},
                            prev_hash=self._last_hash)
            ev.hash = ev.compute_hash()
            # Open-append-flush-fsync so a crash can't lose a committed record.
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(ev.dict(), ensure_ascii=False) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self._last_hash = ev.hash
            return ev

    def events(self) -> Iterator[AuditEvent]:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                d = json.loads(line)
                yield AuditEvent(**d)

    def verify(self) -> tuple[bool, str]:
        """Walk the chain. Returns (ok, message). On failure, message names the
        first broken record."""
        prev = _GENESIS
        n = 0
        for ev in self.events():
            n += 1
            if ev.prev_hash != prev:
                return False, f"chain break at record #{n}: prev_hash mismatch"
            if ev.compute_hash() != ev.hash:
                return False, f"chain break at record #{n}: content hash mismatch"
            prev = ev.hash
        return True, f"audit chain intact ({n} records)"

    def tail(self, n: int = 20) -> list[dict]:
        evs = list(self.events())
        return [e.dict() for e in evs[-n:]]
