"""Collector: scope gate, RBAC, read-only catalog, kill switch, connect errors."""
import pytest

from endpoint_agent.core.scope import ScopeError
from endpoint_agent.core.rbac import AccessDenied
from endpoint_agent.core.killswitch import KillSwitchEngaged
from endpoint_agent.collector.base import CollectionError
from endpoint_agent.collector.commands import read_only_catalog


def test_collect_gathers_facts(sim_linux):
    res = sim_linux.collect("127.0.0.1", "linux")
    assert res.transport == "simulated"
    assert "SSH" in res.get("ssh_config") or "PermitRootLogin" in res.get("ssh_config")
    assert res.outputs["users"].stdout.startswith("root:")


def test_collect_denies_out_of_scope(sim_linux):
    with pytest.raises(ScopeError):
        sim_linux.collect("8.8.8.8", "linux")


def test_collect_rbac_denied(scope, audit, rate, kill):
    from tests.conftest import SimulatedCollector, LINUX_RESPONSES
    from endpoint_agent.core.rbac import RBAC
    c = SimulatedCollector(scope, RBAC(), audit, rate, kill, role="viewer",
                           responses=LINUX_RESPONSES)
    c.set_catalog_map("linux")
    # viewer may collect.read, so this should pass; now test a role w/o it
    c.role = "nobody"
    with pytest.raises(Exception):
        c.collect("127.0.0.1", "linux")


def test_collect_connect_failure(scope, rbac, audit, rate, kill):
    from tests.conftest import SimulatedCollector
    c = SimulatedCollector(scope, rbac, audit, rate, kill, role="operator",
                           fail_connect=True)
    c.set_catalog_map("linux")
    with pytest.raises(CollectionError):
        c.collect("127.0.0.1", "linux")


def test_killswitch_aborts_collection(sim_linux, kill):
    kill.engage("stop")
    with pytest.raises(KillSwitchEngaged):
        sim_linux.collect("127.0.0.1", "linux")


def test_catalog_is_read_only():
    """No catalog command may invoke a mutating program or PowerShell verb.

    We check the *executable* (argv[0]) against a banned program set, and scan
    PowerShell scripts for state-changing cmdlet verbs. Read-only readers like
    `getent passwd` (reads /etc/passwd) are fine — only mutating programs are
    banned.
    """
    banned_programs = {"rm", "mv", "dd", "mkfs", "shutdown", "reboot", "useradd",
                       "userdel", "passwd", "chmod", "chown", "kill", "pkill",
                       "sudo", "su", "runas", "apt", "apt-get", "dpkg-reconfigure"}
    banned_ps_verbs = ("Set-", "Remove-", "Stop-", "Start-", "New-", "Disable-",
                       "Enable-", "Restart-", "Clear-", "Install-", "Uninstall-")
    for os_name in ("linux", "windows"):
        for spec in read_only_catalog(os_name):
            prog = spec.argv[0].lower()
            assert prog not in banned_programs, f"{spec.key} runs {prog!r}"
            if prog == "powershell":
                script = spec.argv[-1]
                for verb in banned_ps_verbs:
                    assert verb not in script, f"{spec.key} uses {verb} in PowerShell"


def test_only_filter(sim_linux):
    res = sim_linux.collect("127.0.0.1", "linux", only=["ssh_config"])
    assert set(res.outputs) == {"ssh_config"}


def test_collection_audited(sim_linux, audit):
    sim_linux.collect("127.0.0.1", "linux")
    actions = [e.action for e in audit.events()]
    assert "collect.simulated" in actions
