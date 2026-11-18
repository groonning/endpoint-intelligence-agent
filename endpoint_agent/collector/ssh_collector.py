"""SSH collector for Linux endpoints (paramiko).

Connects with a credential from the vault (password or private key), then runs
the read-only Linux catalog. paramiko is an optional dependency: importing this
module without it is fine; constructing an SSHCollector without it raises a clear
error, so the rest of the agent (and the test suite) still works.

Host keys are pinned on first use and verified on every later connection (see
core.hostkeys); a changed key aborts before any credential is sent.

Read-only guarantee: argv come only from the command catalog. We build a safe
shell string with shlex.join (paramiko's exec_command needs a string), but the
tokens are fixed catalog tokens, never caller input.
"""
from __future__ import annotations

import shlex

from .base import EndpointCollector, CollectionError
from ..core.credentials import Credential
from ..core.hostkeys import HostKeyStore, HostKeyError, fingerprint

try:
    import paramiko
    _HAVE_PARAMIKO = True
except Exception:  # pragma: no cover
    _HAVE_PARAMIKO = False


class SSHCollector(EndpointCollector):
    transport = "ssh"

    def __init__(self, *a, port: int = 22, hostkeys: HostKeyStore | None = None,
                 **kw):
        if not _HAVE_PARAMIKO:
            raise CollectionError(
                "paramiko is required for SSHCollector (pip install paramiko)")
        super().__init__(*a, **kw)
        self.port = port
        # Without an explicit store, pin in memory for this process only.
        self.hostkeys = hostkeys
        self._client = None

    def _connect(self, host: str, credential: Credential | None = None,
                 port: int | None = None, **kw) -> None:
        if credential is None:
            raise CollectionError("SSHCollector requires a credential")
        client = paramiko.SSHClient()
        # No system known_hosts is loaded, so paramiko consults our policy on
        # every connection. The policy runs after key exchange and BEFORE
        # authentication: a changed key aborts before the password is sent.
        client.set_missing_host_key_policy(
            _PinnedKeyPolicy(self.hostkeys, self.audit, self.actor))
        connect_kw = dict(hostname=host, port=port or self.port,
                          username=credential.username,
                          timeout=self.command_timeout, allow_agent=False,
                          look_for_keys=False)
        if credential.kind == "ssh_key":
            from io import StringIO
            pkey = _load_key(credential.secret, credential.extra.get("passphrase"))
            connect_kw["pkey"] = pkey
        else:
            connect_kw["password"] = credential.secret
        try:
            client.connect(**connect_kw)
        except HostKeyError:
            client.close()
            raise
        self._client = client

    def _exec_raw(self, argv: list[str], timeout: int) -> tuple[int, str, str]:
        if self._client is None:
            raise CollectionError("not connected")
        cmd = shlex.join(argv)
        stdin, stdout, stderr = self._client.exec_command(cmd, timeout=timeout)
        rc = stdout.channel.recv_exit_status()
        out = stdout.read().decode(errors="ignore")
        err = stderr.read().decode(errors="ignore")
        return rc, out, err

    def _close(self) -> None:
        if self._client:
            self._client.close()
            self._client = None


class _PinnedKeyPolicy(paramiko.MissingHostKeyPolicy if _HAVE_PARAMIKO else object):
    """Trust-on-first-use pinning, enforced against HostKeyStore."""

    def __init__(self, store, audit, actor):
        self.store = store if store is not None else HostKeyStore(None)
        self.audit = audit
        self.actor = actor

    def missing_host_key(self, client, hostname, key):
        # paramiko passes "[host]:port" for non-default ports.
        host, port = hostname, 22
        if hostname.startswith("[") and "]:" in hostname:
            host, _, p = hostname[1:].partition("]:")
            port = int(p)
        fp = fingerprint(key.asbytes())
        try:
            outcome = self.store.check(host, port, key.get_name(), fp)
        except HostKeyError as e:
            if self.audit:
                self.audit.record(self.actor, "hostkey.reject", host, "denied",
                                  {"port": port, "presented": fp, "error": str(e)[:160]})
            raise
        if outcome == "pinned" and self.audit:
            self.audit.record(self.actor, "hostkey.pin", host, "ok",
                              {"port": port, "type": key.get_name(), "fingerprint": fp})


def _load_key(pem: str, passphrase: str | None):  # pragma: no cover - needs paramiko
    from io import StringIO
    for loader in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return loader.from_private_key(StringIO(pem), password=passphrase)
        except Exception:
            continue
    raise CollectionError("unsupported or invalid private key")
