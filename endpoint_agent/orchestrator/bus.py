"""Security Orchestrator bus — the clean interface between Agent 2 and the rest
of the system (Agent 1, and a future Security Orchestrator).

Design goals:
  * Explicit, serialisable contract (Task / TaskResult as plain dicts) so the
    transport can be a file drop, an HTTP call, or an in-process call without
    changing callers.
  * Agent 2 never reaches into Agent 1's internals. They exchange Tasks and
    TaskResults only. This keeps Agent 2 modular and separable, as required.

Two concrete transports ship here:
  * InProcessBus — direct function hand-off (used by tests and single-box runs).
  * FileBus      — a watched directory of JSON tasks/results, matching Agent 1's
    file-based `.run/` convention (e.g. `.run/orchestrator/inbox`,
    `.run/orchestrator/outbox`). An external orchestrator drops a task JSON in
    the inbox; Agent 2 writes the result JSON to the outbox.

A Task that references endpoints is still fully re-validated by Agent 2's scope
gate before any work — the bus carries intent, never authority.
"""
from __future__ import annotations

import abc
import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable


@dataclass
class Task:
    kind: str                       # "discover" | "collect" | "analyze" | "report" | "full_sweep"
    params: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    origin: str = "orchestrator"
    created_at: float = field(default_factory=time.time)

    def dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Task":
        return cls(kind=d["kind"], params=d.get("params", {}),
                   id=d.get("id", uuid.uuid4().hex),
                   origin=d.get("origin", "orchestrator"),
                   created_at=d.get("created_at", time.time()))


@dataclass
class TaskResult:
    task_id: str
    agent: str
    ok: bool
    kind: str
    data: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    finished_at: float = field(default_factory=time.time)

    def dict(self) -> dict:
        return asdict(self)


class OrchestratorBus(abc.ABC):
    @abc.abstractmethod
    def submit(self, task: Task) -> None: ...

    @abc.abstractmethod
    def poll(self) -> list[Task]: ...

    @abc.abstractmethod
    def publish(self, result: TaskResult) -> None: ...


class InProcessBus(OrchestratorBus):
    """Direct, in-memory bus. handler(Task) -> TaskResult runs on submit."""

    def __init__(self, handler: Callable[[Task], TaskResult] | None = None):
        self.handler = handler
        self.inbox: list[Task] = []
        self.results: list[TaskResult] = []

    def submit(self, task: Task) -> None:
        self.inbox.append(task)
        if self.handler is not None:
            self.results.append(self.handler(task))

    def poll(self) -> list[Task]:
        tasks, self.inbox = self.inbox, []
        return tasks

    def publish(self, result: TaskResult) -> None:
        self.results.append(result)


class FileBus(OrchestratorBus):
    """Directory-based bus matching Agent 1's `.run/` file convention."""

    def __init__(self, root: str | Path = ".run/orchestrator", agent: str = "agent2"):
        self.root = Path(root)
        self.inbox = self.root / "inbox"
        self.outbox = self.root / "outbox"
        self.done = self.root / "done"
        for d in (self.inbox, self.outbox, self.done):
            d.mkdir(parents=True, exist_ok=True)
        self.agent = agent

    def submit(self, task: Task) -> None:
        (self.inbox / f"{task.id}.json").write_text(
            json.dumps(task.dict(), indent=2))

    def poll(self) -> list[Task]:
        tasks = []
        for p in sorted(self.inbox.glob("*.json")):
            try:
                tasks.append(Task.from_dict(json.loads(p.read_text())))
            except Exception:
                continue
            p.rename(self.done / p.name)
        return tasks

    def publish(self, result: TaskResult) -> None:
        (self.outbox / f"{result.task_id}.json").write_text(
            json.dumps(result.dict(), indent=2, ensure_ascii=False))

    def read_results(self) -> list[TaskResult]:
        out = []
        for p in sorted(self.outbox.glob("*.json")):
            d = json.loads(p.read_text())
            out.append(TaskResult(**d))
        return out
