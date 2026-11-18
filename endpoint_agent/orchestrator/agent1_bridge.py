"""Bridge from Agent 1 (the WiFi agent) to Agent 2.

Agent 1 learns which devices are on an authorised network: its dashboard API
(`GET /api/traffic`) returns a MAC -> IP map. This bridge reads that map and
turns it into work for Agent 2, without importing or changing Agent 1:

  * device already in Agent 2's scope, credential known -> an `assess` task
  * device in scope, no credential mapped              -> listed as needing one
  * device NOT in scope                                -> an approval request

A device seen by Agent 1 is never authorised automatically. Being on the WiFi
is not permission to log in to a machine; a person approves each new target.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import urllib.request
from typing import Callable

from .bus import OrchestratorBus, Task


def _http_get(url: str, timeout: int = 10) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read())


class Agent1Bridge:
    def __init__(self, agent, bus: OrchestratorBus,
                 fetch: Callable[[str], dict] | None = None):
        self.agent = agent
        self.bus = bus
        self._fetch = fetch or _http_get

    def devices(self) -> dict[str, str]:
        """MAC -> IP for private addresses Agent 1 currently knows about."""
        url = self.agent.cfg.agent1.url.rstrip("/") + "/api/traffic"
        data = self._fetch(url)
        out = {}
        for mac, ip in (data.get("mac_ip") or {}).items():
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if addr.is_private and not addr.is_loopback and not addr.is_link_local:
                out[mac] = ip
        return out

    def _os_for(self, ip: str) -> str:
        hint = self.agent.scope.require(ip).os_hint
        if hint:
            return hint
        try:
            host = asyncio.run(self.agent.discovery._probe_tcp(ip))
            return host.os_guess
        except Exception:
            return ""

    def sync(self, with_ai: bool = True) -> dict:
        """Read Agent 1's devices and queue work. Returns a summary."""
        self.agent.kill.check()
        summary = {"queued": [], "needs_credential": [], "unknown_os": [],
                   "approval_requested": []}
        for mac, ip in sorted(self.devices().items(), key=lambda kv: kv[1]):
            if not self.agent.scope.is_authorised(ip):
                req = self.agent.request_scope_add(
                    ip, "agent1-bridge", f"seen on the network by Agent 1 (MAC {mac})")
                summary["approval_requested"].append({"ip": ip, "mac": mac, "id": req.id})
                continue
            cred = self.agent.credential_for(ip)
            if not cred:
                summary["needs_credential"].append({"ip": ip, "mac": mac})
                continue
            os_name = self._os_for(ip)
            if os_name not in ("linux", "windows"):
                summary["unknown_os"].append({"ip": ip, "mac": mac})
                continue
            task = Task(kind="assess", origin="agent1-bridge",
                        params={"host": ip, "os_name": os_name, "cred_id": cred,
                                "with_ai": with_ai, "mac": mac})
            self.bus.submit(task)
            summary["queued"].append({"ip": ip, "mac": mac, "task": task.id})
        self.agent.audit.record("agent1-bridge", "bridge.sync", "agent1", "ok",
                                {k: len(v) for k, v in summary.items()})
        return summary
