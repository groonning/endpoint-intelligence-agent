"""SSH host-key pinning (trust on first use, then verify).

The first time the agent connects to an authorised host it records the SHA-256
fingerprint of the server's host key. Every later connection must present the
same key; a different key aborts the connection *before* any credential is sent,
because a changed key is what an in-path attacker looks like.

In strict mode nothing is pinned automatically: the operator must pin the key
first (`hostkeys pin`), and unknown hosts are refused.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
from pathlib import Path


class HostKeyError(Exception):
    """Unknown host key in strict mode, or a key that differs from the pin."""


def fingerprint(key_bytes: bytes) -> str:
    digest = hashlib.sha256(key_bytes).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


class HostKeyStore:
    def __init__(self, path: str | Path | None = "config/known_hosts.json",
                 strict: bool = False):
        """path=None keeps pins in memory for this process only."""
        self.path = Path(path) if path is not None else None
        self.strict = strict
        self._lock = threading.Lock()
        self._keys: dict[str, dict] = {}
        if self.path is not None and self.path.exists():
            self._keys = json.loads(self.path.read_text() or "{}")

    @staticmethod
    def _id(host: str, port: int) -> str:
        return f"{host.lower()}:{port}"

    def get(self, host: str, port: int = 22) -> dict | None:
        return self._keys.get(self._id(host, port))

    def pin(self, host: str, port: int, key_type: str, fp: str) -> None:
        with self._lock:
            self._keys[self._id(host, port)] = {"type": key_type, "fingerprint": fp}
            self._save()

    def forget(self, host: str, port: int = 22) -> bool:
        with self._lock:
            gone = self._keys.pop(self._id(host, port), None) is not None
            if gone:
                self._save()
            return gone

    def all(self) -> dict[str, dict]:
        return dict(self._keys)

    def check(self, host: str, port: int, key_type: str, fp: str) -> str:
        """Return "match" or "pinned" (first use), or raise HostKeyError."""
        known = self.get(host, port)
        if known is None:
            if self.strict:
                raise HostKeyError(
                    f"no pinned host key for {host}:{port} and strict mode is on "
                    f"(presented {key_type} {fp}). Pin it first if it is correct.")
            self.pin(host, port, key_type, fp)
            return "pinned"
        if known["fingerprint"] != fp:
            raise HostKeyError(
                f"HOST KEY CHANGED for {host}:{port}: pinned {known['fingerprint']}, "
                f"presented {fp}. Refusing to send credentials. If the host was "
                "reinstalled, remove the pin with: hostkeys forget "
                f"{host} --port {port}")
        return "match"

    def _save(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(self._keys, indent=2, sort_keys=True))
        os.replace(tmp, self.path)
