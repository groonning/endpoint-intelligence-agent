"""Approval queue: nothing widens the agent's access without a human saying yes.

Anything that would extend authority (today: adding an endpoint or range to the
scope) is filed here as a *request*. A request does nothing by itself. It only
takes effect when someone holding the `approval.grant` capability approves it.
Automated callers (the orchestrator bus, the Agent 1 bridge) can only ever file
requests; they cannot approve them.
"""
from __future__ import annotations

import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, asdict, field
from pathlib import Path


@dataclass
class ApprovalRequest:
    id: str
    action: str                 # e.g. "scope.add"
    target: str                 # e.g. "192.168.56.20"
    requested_by: str
    reason: str = ""
    params: dict = field(default_factory=dict)
    status: str = "pending"     # pending | approved | denied
    created_at: float = field(default_factory=time.time)
    decided_by: str = ""
    decided_at: float | None = None

    def dict(self) -> dict:
        return asdict(self)


class ApprovalQueue:
    def __init__(self, path: str | Path = ".run/approvals.json"):
        self.path = Path(path)
        self._lock = threading.Lock()

    def _load(self) -> list[ApprovalRequest]:
        if not self.path.exists():
            return []
        return [ApprovalRequest(**d) for d in json.loads(self.path.read_text() or "[]")]

    def _save(self, items: list[ApprovalRequest]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps([i.dict() for i in items], indent=2))
        os.replace(tmp, self.path)

    def request(self, action: str, target: str, requested_by: str,
                reason: str = "", params: dict | None = None) -> ApprovalRequest:
        with self._lock:
            items = self._load()
            for i in items:      # one open request per (action, target)
                if i.status == "pending" and i.action == action and i.target == target:
                    return i
            req = ApprovalRequest(id=uuid.uuid4().hex[:10], action=action,
                                  target=target, requested_by=requested_by,
                                  reason=reason, params=params or {})
            items.append(req)
            self._save(items)
            return req

    def pending(self) -> list[ApprovalRequest]:
        return [i for i in self._load() if i.status == "pending"]

    def all(self) -> list[ApprovalRequest]:
        return self._load()

    def decide(self, req_id: str, approve: bool, decided_by: str) -> ApprovalRequest:
        with self._lock:
            items = self._load()
            for i in items:
                if i.id == req_id:
                    if i.status != "pending":
                        raise ValueError(f"request {req_id} is already {i.status}")
                    i.status = "approved" if approve else "denied"
                    i.decided_by = decided_by
                    i.decided_at = time.time()
                    self._save(items)
                    return i
        raise ValueError(f"no approval request with id {req_id!r}")
