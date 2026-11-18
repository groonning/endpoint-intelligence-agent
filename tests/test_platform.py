"""Agent-level behaviour: full assessment pipeline, parallel sweep, Agent 1
bridge, worker loop and the dashboard API."""
import time
import weakref

import pytest

from endpoint_agent.orchestrator.agent1_bridge import Agent1Bridge
from endpoint_agent.orchestrator.bus import FileBus, Task
from tests.conftest import LINUX_RESPONSES, simulated_factory

LAB = ("endpoints:\n  - identifier: '127.0.0.1'\n    os_hint: linux\n"
       "  - identifier: '192.168.56.0/24'\n    note: lab\n    os_hint: linux\n")


def _sim_agent(make_agent, responses, delay=0.0, **kw):
    holder = {}
    agent = make_agent(scope_yaml=LAB,
                       collector_factory=simulated_factory(lambda: holder["a"], responses, delay),
                       **kw)
    holder["a"] = agent
    return agent


# --- pipeline ----------------------------------------------------------------
def test_assess_combines_rules_lynis_osv_and_baseline(make_agent):
    calls = []

    def osv(url, payload):
        calls.append(payload)
        return {"results": [{"vulns": [{"id": "CVE-2025-1"}]} for _ in payload["queries"]]}

    responses = dict(LINUX_RESPONSES)
    responses["os_release"] = (0, 'ID=debian\nVERSION_ID="12"\n', "")
    responses["packages_src"] = (0, "openssl\t3.0.9-1\tlibssl3\n", "")
    responses["lynis"] = (0, "warning[]=AUTH-9308|No password set for single mode|-|-|\n", "")
    agent = _sim_agent(make_agent, {"192.168.56.10": responses},
                       vuln__enabled=True, lynis__enabled=True, osv_post=osv)
    hr = agent.assess_host("192.168.56.10", "linux")
    sources = {f.source for f in hr.findings}
    assert sources == {"rule", "lynis", "osv", "baseline"}
    assert hr.findings[0].severity.label == "critical"
    assert calls and agent.audit.verify()[0]

    responses["users"] = (0, LINUX_RESPONSES["users"][1] + "\nnew:x:1001:1001::/home/new:/bin/sh", "")
    hr2 = agent.assess_host("192.168.56.10", "linux")
    assert "Ny brukerkonto: new" in [f.title for f in hr2.findings]
    assert len(calls) == 1                              # OSV answer came from the cache


def test_credential_map_and_vault_requirement(make_agent):
    from endpoint_agent.collector.base import CollectionError
    agent = make_agent(scope_yaml=LAB, credentials_map={"192.168.56.0/24": "lab-ssh",
                                                         "192.168.56.99": "special"})
    assert agent.credential_for("192.168.56.10") == "lab-ssh"
    assert agent.credential_for("192.168.56.99") == "special"
    assert agent.credential_for("10.9.9.9") is None
    with pytest.raises(CollectionError, match="vault is not open"):
        agent.collect("192.168.56.10", "linux")


# --- parallel sweep ----------------------------------------------------------
def test_sweep_runs_hosts_in_parallel_and_isolates_failures(make_agent):
    hosts = [f"192.168.56.{i}" for i in range(10, 16)]
    agent = _sim_agent(make_agent, {h: LINUX_RESPONSES for h in hosts}, delay=0.4)
    t0 = time.time()
    session = agent.run_sweep(hosts=[(h, "linux", None) for h in hosts] +
                              [("8.8.8.8", "linux", None)], with_ai=False)
    elapsed = time.time() - t0
    assert elapsed < 1.6, f"6 hosts x 0.4s took {elapsed:.1f}s; not parallel"
    by_host = {h["host"]: h for h in session["hosts"]}
    assert [h["host"] for h in session["hosts"]][:6] == hosts          # order kept
    assert all(by_host[h]["findings"] for h in hosts)
    assert "refusing to act" in by_host["8.8.8.8"]["error"]            # one bad host, rest fine
    assert session["audit_verified"] and agent.last_session()["hosts"]


def test_killed_sweep_is_not_reported_as_finished(make_agent):
    from endpoint_agent.core.killswitch import KillSwitchEngaged
    agent = _sim_agent(make_agent, {}, delay=0.3)
    import threading
    threading.Timer(0.1, lambda: agent.kill.engage("stop")).start()
    with pytest.raises(KillSwitchEngaged):
        agent.run_sweep(hosts=[(f"192.168.56.{i}", "linux", None) for i in range(1, 30)],
                        with_ai=False)


# --- Agent 1 bridge + worker -------------------------------------------------
def test_bridge_queues_known_hosts_and_requests_approval_for_new_ones(make_agent, tmp_path):
    agent = _sim_agent(make_agent, {"192.168.56.10": LINUX_RESPONSES},
                       credentials_map={"192.168.56.10": "lab-ssh"})
    agent.vault = type("V", (), {"get": lambda self, i: object()})()
    bus = FileBus(tmp_path / "bus")
    seen_urls = []

    def fetch(url):
        seen_urls.append(url)
        return {"mac_ip": {"aa:aa": "192.168.56.10", "bb:bb": "192.168.56.20",
                           "cc:cc": "192.168.99.5", "dd:dd": "8.8.8.8", "ee:ee": "junk"}}

    summary = Agent1Bridge(agent, bus, fetch=fetch).sync(with_ai=False)
    assert seen_urls == ["http://127.0.0.1:8777/api/traffic"]
    assert [q["ip"] for q in summary["queued"]] == ["192.168.56.10"]
    assert [q["ip"] for q in summary["needs_credential"]] == ["192.168.56.20"]
    assert [q["ip"] for q in summary["approval_requested"]] == ["192.168.99.5"]   # public IP ignored
    assert not agent.scope.is_authorised("192.168.99.5")                          # not auto-authorised

    assert agent.work(bus, once=True) == 1
    results = bus.read_results()
    assert results[0].ok and results[0].data["host_report"]["host"] == "192.168.56.10"


def test_worker_stops_when_killed(make_agent, tmp_path):
    agent = make_agent(role="admin")
    bus = FileBus(tmp_path / "bus")
    bus.submit(Task(kind="status"))
    agent.kill.engage("stop")
    assert agent.work(bus) == 0 and len(list(bus.inbox.glob("*.json"))) == 1


# --- dashboard ---------------------------------------------------------------
flask = pytest.importorskip("flask")


@pytest.fixture
def dash(make_agent):
    from endpoint_agent.server import create_app
    agent = make_agent(role="operator")
    app = create_app(agent, allowed_hosts={"127.0.0.1:8778"}, token="tok")
    client = app.test_client()
    base = {"base_url": "http://127.0.0.1:8778"}

    def call(method, path, token="tok", json=None, host=None):
        headers = {"X-Agent2-Token": token} if token else {}
        return client.open(path, method=method, headers=headers, json=json,
                           base_url=f"http://{host}" if host else base["base_url"])
    return agent, call


def test_dashboard_requires_token_and_expected_host(dash):
    agent, call = dash
    assert call("GET", "/api/status", token=None).status_code == 403
    assert call("GET", "/api/status", token="wrong").status_code == 403
    assert call("GET", "/api/status", host="evil.example:8778").status_code == 403
    assert call("POST", "/api/kill", token=None, json={}).status_code == 403
    assert not agent.kill.engaged
    r = call("GET", "/api/status")
    assert r.status_code == 200 and r.json["role"] == "operator"


def test_dashboard_page_embeds_token_and_csp(dash):
    agent, call = dash
    r = call("GET", "/", token=None)
    assert r.status_code == 200 and b'TOKEN = "tok"' in r.data
    assert "default-src 'none'" in r.headers["Content-Security-Policy"]
    assert b"innerHTML" not in r.data                    # endpoint data is never parsed as HTML


def test_dashboard_kill_blocks_sweep_and_reset_rearms(dash):
    agent, call = dash
    assert call("POST", "/api/kill", json={"reason": "t"}).json["ok"]
    assert agent.kill.engaged
    assert call("POST", "/api/sweep", json={}).status_code == 409
    assert call("POST", "/api/reset-kill", json={}).json["ok"]
    assert not agent.kill.engaged


def test_dashboard_sweep_runs_and_session_is_served(dash):
    agent, call = dash
    assert call("POST", "/api/sweep", json={"with_ai": False}).json["ok"]
    for _ in range(100):
        if not call("GET", "/api/status").json["sweep"]["running"]:
            break
        time.sleep(0.1)
    sess = call("GET", "/api/session").json
    assert [h["host"] for h in sess["hosts"]] == ["127.0.0.1"]
    assert call("GET", "/api/audit?n=5").json


def test_dashboard_operator_cannot_approve(dash):
    agent, call = dash
    req = agent.request_scope_add("10.0.0.9", "bridge")
    r = call("POST", f"/api/approvals/{req.id}", json={"approve": True})
    assert r.status_code == 403 and not agent.scope.is_authorised("10.0.0.9")
    agent.role = "admin"
    assert call("POST", f"/api/approvals/{req.id}", json={"approve": True}).json["ok"]
    assert agent.scope.is_authorised("10.0.0.9")
