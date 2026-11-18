"""Real SSH round-trips against an in-process paramiko server on localhost:
collection, authentication failure, and host-key pinning."""
import shlex
import socket
import subprocess
import threading
import time

import pytest

paramiko = pytest.importorskip("paramiko")

from endpoint_agent.core.credentials import Credential
from endpoint_agent.core.hostkeys import HostKeyStore, HostKeyError
from endpoint_agent.collector.base import CollectionError
from endpoint_agent.collector.ssh_collector import SSHCollector
from endpoint_agent.analyzer.analyzer import SecurityAnalyzer

PASSWORD = "correct-horse-battery-7731"
FAKE = {"cat /etc/ssh/sshd_config": "PermitRootLogin yes\n",
        "getent passwd": "root:x:0:0::/root:/bin/bash\nevil:x:0:0::/root:/bin/sh\n"}


class _Server:
    """Minimal SSH server. Counts authentication attempts so a test can prove
    that no credential was offered."""

    def __init__(self):
        self.hostkey = paramiko.RSAKey.generate(2048)
        self.auth_attempts = 0
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        outer = self

        class Iface(paramiko.ServerInterface):
            def check_auth_password(self, user, password):
                outer.auth_attempts += 1
                ok = (user, password) == ("kali", PASSWORD)
                return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED

            def get_allowed_auths(self, user):
                return "password"

            def check_channel_request(self, kind, chanid):
                return paramiko.OPEN_SUCCEEDED

            def check_channel_exec_request(self, channel, command):
                cmd = command.decode()

                def run():
                    time.sleep(0.05)      # let the exec request be acknowledged first
                    if cmd in FAKE:
                        out, rc = FAKE[cmd], 0
                    else:
                        try:
                            p = subprocess.run(shlex.split(cmd), capture_output=True,
                                               text=True, timeout=20)
                            out, rc = p.stdout, p.returncode
                        except Exception:
                            out, rc = "", 127
                    channel.sendall(out.encode())
                    channel.send_exit_status(rc)
                    channel.close()
                threading.Thread(target=run, daemon=True).start()
                return True

        while True:
            try:
                client, _ = self.sock.accept()
            except OSError:
                return
            t = paramiko.Transport(client)
            t.add_server_key(self.hostkey)
            try:
                t.start_server(server=Iface())
            except Exception:
                pass

    def close(self):
        self.sock.close()


@pytest.fixture
def server():
    s = _Server()
    yield s
    s.close()


GOOD = Credential("c", "ssh_password", "kali", PASSWORD)
ONLY = ["kernel", "ssh_config", "users"]


def _collector(scope, rbac, audit, rate, kill, port, store):
    return SSHCollector(scope, rbac, audit, rate, kill, role="operator", port=port,
                        hostkeys=store, command_timeout=20)


def test_collect_and_analyze_over_real_ssh(server, scope, rbac, audit, rate, kill, tmp_path):
    store = HostKeyStore(tmp_path / "kh.json")
    res = _collector(scope, rbac, audit, rate, kill, server.port, store).collect(
        "127.0.0.1", "linux", only=ONLY, credential=GOOD)
    assert res.get("kernel").startswith("Linux")
    titles = [f.title for f in SecurityAnalyzer().analyze(res)]
    assert "Ekstra UID 0-konto: evil" in titles and "SSH root-innlogging tillatt" in titles
    assert store.get("127.0.0.1", server.port)["fingerprint"].startswith("SHA256:")
    assert any(e.action == "hostkey.pin" for e in audit.events())
    assert PASSWORD not in open(audit.path).read()


def test_wrong_password_is_a_clean_error(server, scope, rbac, audit, rate, kill, tmp_path):
    with pytest.raises(CollectionError):
        _collector(scope, rbac, audit, rate, kill, server.port,
                   HostKeyStore(tmp_path / "kh.json")).collect(
            "127.0.0.1", "linux", only=ONLY,
            credential=Credential("c", "ssh_password", "kali", "WRONG"))


def test_changed_host_key_aborts_before_the_password_is_sent(scope, rbac, audit, rate, kill, tmp_path):
    store = HostKeyStore(tmp_path / "kh.json")
    first = _Server()
    _collector(scope, rbac, audit, rate, kill, first.port, store).collect(
        "127.0.0.1", "linux", only=["kernel"], credential=GOOD)
    pinned = store.get("127.0.0.1", first.port)
    first.close()

    impostor = _Server()                      # same address, different host key
    store.pin("127.0.0.1", impostor.port, pinned["type"], pinned["fingerprint"])
    with pytest.raises(CollectionError, match="HOST KEY CHANGED"):
        _collector(scope, rbac, audit, rate, kill, impostor.port, store).collect(
            "127.0.0.1", "linux", only=["kernel"], credential=GOOD)
    assert impostor.auth_attempts == 0        # the credential never left
    assert any(e.action == "hostkey.reject" for e in audit.events())
    impostor.close()


def test_strict_mode_refuses_unpinned_host(server, scope, rbac, audit, rate, kill, tmp_path):
    store = HostKeyStore(tmp_path / "kh.json", strict=True)
    with pytest.raises(CollectionError, match="strict"):
        _collector(scope, rbac, audit, rate, kill, server.port, store).collect(
            "127.0.0.1", "linux", only=["kernel"], credential=GOOD)
    assert server.auth_attempts == 0
