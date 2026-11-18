"""Endpoint Discovery.

Finds live hosts inside the *authorised* ranges only, identifies the likely OS,
and reports which management interfaces (SSH / WinRM / RDP) are reachable. It is
a thin, auditable orchestration layer over nmap when present, with a pure-Python
TCP-connect fallback so the module works (and is testable) without nmap.

Hard rules:
  * Every candidate host is checked against the Scope gate before it is probed.
    A host discovered inside a CIDR is still re-validated individually.
  * The sweep honours the rate limiter and the kill switch between hosts.
  * Discovery is passive-ish reconnaissance (ping + TCP connect / nmap -sn -sV);
    it never authenticates and never touches a host outside scope.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
from dataclasses import dataclass, field, asdict

from ..core.scope import Scope, ScopeError
from ..core.ratelimit import RateLimiter
from ..core.killswitch import KillSwitch
from ..core.audit import AuditLog
from ..core.runner import arun, tool_available

# Management ports we care about for endpoint collection.
MGMT_PORTS = {
    22: "ssh",
    5985: "winrm-http",
    5986: "winrm-https",
    3389: "rdp",
    445: "smb",
}


@dataclass
class DiscoveredHost:
    ip: str
    hostname: str = ""
    alive: bool = False
    os_guess: str = ""                      # "linux" | "windows" | ""
    open_mgmt_ports: list[int] = field(default_factory=list)
    services: dict[int, str] = field(default_factory=dict)
    source: str = "tcp"                     # "nmap" | "tcp"

    def dict(self) -> dict:
        d = asdict(self)
        d["open_mgmt_ports"] = list(self.open_mgmt_ports)
        return d

    @property
    def mgmt_interface(self) -> str:
        if 22 in self.open_mgmt_ports:
            return "ssh"
        if 5985 in self.open_mgmt_ports or 5986 in self.open_mgmt_ports:
            return "winrm"
        return ""


class EndpointDiscovery:
    def __init__(self, scope: Scope, rate: RateLimiter | None = None,
                 kill: KillSwitch | None = None, audit: AuditLog | None = None,
                 actor: str = "agent2", connect_timeout: float = 2.0):
        self.scope = scope
        self.rate = rate or RateLimiter(10, 20)
        self.kill = kill or KillSwitch()
        self.audit = audit
        self.actor = actor
        self.connect_timeout = connect_timeout

    # ----------------------------------------------------------------- public
    async def sweep(self, concurrency: int = 16,
                    use_nmap: bool | None = None) -> list[DiscoveredHost]:
        """Discover live authorised hosts across every range in scope."""
        if self.audit:
            self.audit.record(self.actor, "discovery.sweep", "scope",
                              "start", {"ranges": self.scope.networks()})
        use_nmap = tool_available("nmap") if use_nmap is None else use_nmap
        targets = self._expand_targets()
        sem = asyncio.Semaphore(concurrency)
        results: list[DiscoveredHost] = []

        async def _one(ip: str):
            async with sem:
                self.kill.check()
                await self.rate.aacquire()
                host = (await self._probe_nmap(ip) if use_nmap
                        else await self._probe_tcp(ip))
                if host.alive:
                    results.append(host)

        await asyncio.gather(*(_one(ip) for ip in targets))
        results.sort(key=lambda h: ipaddress.ip_address(h.ip))
        if self.audit:
            self.audit.record(self.actor, "discovery.sweep", "scope", "ok",
                              {"candidates": len(targets), "alive": len(results)})
        return results

    # ----------------------------------------------------------- target expand
    def _expand_targets(self, max_hosts: int = 4096) -> list[str]:
        ips: list[str] = []
        for ident in self.scope.networks():
            try:
                net = ipaddress.ip_network(ident, strict=False)
            except ValueError:
                # hostname — resolve lazily at probe time; keep as-is
                ips.append(ident)
                continue
            if net.num_addresses == 1:
                ips.append(str(net.network_address))
            else:
                hosts = list(net.hosts())
                if len(hosts) > max_hosts:
                    raise ScopeError(
                        f"range {ident} expands to {len(hosts)} hosts (> {max_hosts}); "
                        "narrow the scope.")
                ips.extend(str(h) for h in hosts)
        # de-dup, preserve order
        seen, out = set(), []
        for ip in ips:
            if ip not in seen:
                seen.add(ip)
                out.append(ip)
        return out

    # -------------------------------------------------------------- probing
    async def _probe_tcp(self, ip: str) -> DiscoveredHost:
        # Re-validate the individual host against the gate.
        self.scope.require(ip)
        host = DiscoveredHost(ip=ip, source="tcp")
        for port in MGMT_PORTS:
            if await self._tcp_open(ip, port):
                host.alive = True
                host.open_mgmt_ports.append(port)
                host.services[port] = MGMT_PORTS[port]
        host.os_guess = self._os_from_ports(host.open_mgmt_ports)
        return host

    async def _tcp_open(self, ip: str, port: int) -> bool:
        try:
            fut = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(fut, timeout=self.connect_timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except (asyncio.TimeoutError, OSError):
            return False

    async def _probe_nmap(self, ip: str) -> DiscoveredHost:
        self.scope.require(ip)
        ports = ",".join(str(p) for p in MGMT_PORTS)
        res = await arun(["nmap", "-Pn", "-sV", "--open", "-p", ports, ip],
                         timeout=120)
        host = DiscoveredHost(ip=ip, source="nmap")
        if not res.ok and res.returncode == 127:
            return await self._probe_tcp(ip)
        host.services = self._parse_nmap_ports(res.stdout)
        host.open_mgmt_ports = sorted(host.services)
        host.alive = bool(host.open_mgmt_ports) or "Host is up" in res.stdout
        m = re.search(r"OS details?:\s*(.+)", res.stdout)
        if m and "windows" in m.group(1).lower():
            host.os_guess = "windows"
        elif m and ("linux" in m.group(1).lower() or "unix" in m.group(1).lower()):
            host.os_guess = "linux"
        host.os_guess = host.os_guess or self._os_from_ports(host.open_mgmt_ports)
        hm = re.search(r"Nmap scan report for ([^\s(]+)", res.stdout)
        if hm and not _is_ip(hm.group(1)):
            host.hostname = hm.group(1)
        return host

    @staticmethod
    def _parse_nmap_ports(out: str) -> dict[int, str]:
        svc: dict[int, str] = {}
        for m in re.finditer(r"^(\d+)/tcp\s+open\s+(\S+)", out, re.M):
            svc[int(m.group(1))] = m.group(2)
        return svc

    @staticmethod
    def _os_from_ports(ports: list[int]) -> str:
        if 5985 in ports or 5986 in ports or 3389 in ports:
            return "windows"
        if 22 in ports:
            return "linux"
        return ""


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False
