"""Authorisation gate for endpoints — the hard block before any active work.

This is the Agent-2 analogue of Agent 1's `wifi_agent.scope`, generalised from a
single BSSID to IP addresses, CIDR ranges and hostnames. Adding an endpoint (or
range) to the allowlist IS the authorisation step: you assert you own the host
or hold written permission to test it. Every discovery/collection/scan call
re-checks this list before a single packet is sent.

The gate is deliberately strict:
  * An IP is authorised only if it is explicitly listed or falls inside an
    explicitly listed CIDR range.
  * A hostname is authorised only if listed verbatim (case-insensitive).
  * There is no "allow all" wildcard. `0.0.0.0/0` is rejected on load.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import yaml

_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9\-\.]{0,253}[A-Za-z0-9])?$")
# CIDR ranges this broad are never acceptable as an "authorised scope".
_FORBIDDEN_NETS = [
    ipaddress.ip_network("0.0.0.0/0"),
    ipaddress.ip_network("::/0"),
]


class ScopeError(Exception):
    """Raised when an action targets a host outside the authorised scope."""


@dataclass(frozen=True)
class Endpoint:
    """One authorised endpoint or range.

    Exactly one of (ip, cidr, hostname) is the canonical identifier, but a host
    may carry a hostname alongside its ip for readability.
    """
    identifier: str          # ip, cidr or hostname as written
    note: str = ""           # why you're authorised (free text, for the audit trail)
    os_hint: str = ""        # optional "linux" | "windows" hint for the collector

    def __post_init__(self) -> None:
        if not self._valid(self.identifier):
            raise ValueError(f"invalid endpoint identifier: {self.identifier!r}")

    @staticmethod
    def _valid(ident: str) -> bool:
        """Accept a valid IP, CIDR range, or RFC-1123 hostname."""
        try:
            ipaddress.ip_network(ident, strict=False)
            return True
        except ValueError:
            return bool(_HOST_RE.match(ident))

    @property
    def is_network(self) -> bool:
        try:
            ipaddress.ip_network(self.identifier, strict=False)
            return True
        except ValueError:
            return False


def _forbidden_nets_for(net) -> list:
    return [f for f in _FORBIDDEN_NETS if f.version == net.version]


class Scope:
    """Authorised-endpoint allowlist. Thread-safe enough for read-heavy use."""

    def __init__(self, endpoints: Iterable[Endpoint], path: Path | None = None):
        self._endpoints: list[Endpoint] = []
        self._networks: list[tuple[ipaddress._BaseNetwork, Endpoint]] = []
        self._hosts: dict[str, Endpoint] = {}
        self._path = path
        for ep in endpoints:
            self._index(ep)

    # ------------------------------------------------------------------ load
    @classmethod
    def load(cls, path: str | Path, create: bool = True) -> "Scope":
        path = Path(path)
        if not path.exists():
            if create:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("endpoints: []\n")
                return cls([], path=path)
            raise ScopeError(f"no authorised-endpoints file at {path}")
        data = yaml.safe_load(path.read_text()) or {}
        raw = data.get("endpoints") or []
        eps = []
        for e in raw:
            if isinstance(e, str):
                eps.append(Endpoint(identifier=e))
            else:
                eps.append(Endpoint(identifier=e["identifier"],
                                    note=e.get("note", ""),
                                    os_hint=e.get("os_hint", "")))
        return cls(eps, path=path)

    def _index(self, ep: Endpoint) -> None:
        # Reject dangerously broad ranges at index time, not just construction.
        if ep.is_network:
            net = ipaddress.ip_network(ep.identifier, strict=False)
            for f in _forbidden_nets_for(net):
                if net == f:
                    raise ScopeError(
                        f"refusing to authorise an all-addresses range: {ep.identifier}")
            self._networks.append((net, ep))
        else:
            self._hosts[ep.identifier.lower()] = ep
        self._endpoints.append(ep)

    # ------------------------------------------------------------- queries
    def is_authorised(self, target: str) -> bool:
        try:
            return self.require(target) is not None
        except ScopeError:
            return False

    def require(self, target: str) -> Endpoint:
        """Return the matching Endpoint or raise ScopeError. `target` may be an
        IP or a hostname."""
        h = self._hosts.get(target.lower())
        if h is not None:
            return h
        try:
            ip = ipaddress.ip_address(target)
        except ValueError:
            raise ScopeError(
                f"{target!r} is NOT an authorised endpoint — refusing to act. "
                "Add it to the scope first (you confirm you have permission).")
        for net, ep in self._networks:
            if ip in net:
                return ep
        raise ScopeError(
            f"{target} is NOT in an authorised range — refusing to act. "
            "Add it to the scope first (you confirm you have permission).")

    def all(self) -> list[Endpoint]:
        return list(self._endpoints)

    def networks(self) -> list[str]:
        """CIDR/host identifiers suitable for the discovery sweep."""
        return [ep.identifier for ep in self._endpoints]

    # -------------------------------------------------------------- mutate
    def add(self, identifier: str, note: str = "authorised at runtime",
            os_hint: str = "") -> Endpoint:
        ep = Endpoint(identifier=identifier, note=note, os_hint=os_hint)
        self._index(ep)
        self._save()
        return ep

    def remove(self, identifier: str) -> None:
        self._endpoints = [e for e in self._endpoints if e.identifier != identifier]
        self._hosts.pop(identifier.lower(), None)
        self._networks = [(n, e) for n, e in self._networks
                          if e.identifier != identifier]
        self._save()

    def _save(self) -> None:
        if not self._path:
            return
        data = {"endpoints": [
            {"identifier": e.identifier, "note": e.note, "os_hint": e.os_hint}
            for e in self._endpoints]}
        self._path.write_text(yaml.safe_dump(data, sort_keys=False))
