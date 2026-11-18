"""Orchestrator bus + Agent 2 façade (Agent 1 integration contract)."""
import json

from endpoint_agent.core.config import AgentConfig, AIConfig, LimitsConfig
from endpoint_agent.orchestrator.agent2 import EndpointIntelligenceAgent
from endpoint_agent.orchestrator.bus import Task, TaskResult, FileBus, InProcessBus


def _agent(tmp_path, scope_file):
    cfg = AgentConfig(
        scope_path=str(scope_file),
        roles_path=str(tmp_path / "roles.yaml"),
        vault_path=str(tmp_path / "v.vault"),
        audit_path=str(tmp_path / "audit.jsonl"),
        killswitch_path=str(tmp_path / "ks"),
        known_hosts_path=str(tmp_path / "known_hosts.json"),
        approvals_path=str(tmp_path / "approvals.json"),
        bus_dir=str(tmp_path / "bus"),
        state_dir=str(tmp_path / "state"),
        reports_dir=str(tmp_path / "reports"),
        sigma_rules_dir=str(tmp_path / "sigma"),
        yara_rules_dir=str(tmp_path / "yara"),
        ai=AIConfig(allow_external=False),
        limits=LimitsConfig(),
    )
    # enable_ai False so no Ollama needed for the orchestration contract test.
    return EndpointIntelligenceAgent(cfg, role="operator", enable_ai=False)


def _scope_file(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text("endpoints:\n  - identifier: '127.0.0.1'\n    note: self\n")
    return p


def test_full_sweep_localhost(tmp_path):
    agent = _agent(tmp_path, _scope_file(tmp_path))
    session = agent.run_sweep(hosts=[("127.0.0.1", "linux", None)],
                              with_ai=False, write_report=True)
    assert session["hosts"][0]["host"] == "127.0.0.1"
    assert session["audit_verified"] is True
    assert "report" in session


def test_handle_task_assess(tmp_path):
    agent = _agent(tmp_path, _scope_file(tmp_path))
    task = Task(kind="assess", params={"host": "127.0.0.1", "os_name": "linux",
                                       "with_ai": False})
    res = agent.handle_task(task)
    assert res.ok and res.kind == "assess"
    assert res.data["host_report"]["host"] == "127.0.0.1"


def test_handle_task_unknown(tmp_path):
    agent = _agent(tmp_path, _scope_file(tmp_path))
    res = agent.handle_task(Task(kind="nonsense"))
    assert not res.ok and "unknown" in res.error


def test_handle_task_out_of_scope(tmp_path):
    agent = _agent(tmp_path, _scope_file(tmp_path))
    res = agent.handle_task(Task(kind="assess",
                                 params={"host": "8.8.8.8", "os_name": "linux"}))
    assert not res.ok and "refusing to act" in res.error


def test_filebus_roundtrip(tmp_path):
    """Simulates the Agent 1 / Orchestrator <-> Agent 2 file handoff."""
    agent = _agent(tmp_path, _scope_file(tmp_path))
    bus = FileBus(tmp_path / "orch")
    # Orchestrator submits a task
    bus.submit(Task(kind="assess", id="task1",
                    params={"host": "127.0.0.1", "os_name": "linux",
                            "with_ai": False}))
    # Agent 2 polls, runs, publishes
    for task in bus.poll():
        bus.publish(agent.handle_task(task))
    results = bus.read_results()
    assert results and results[0].ok
    assert results[0].task_id == "task1"


def test_inprocess_bus_direct():
    seen = {}
    def handler(task: Task) -> TaskResult:
        seen["kind"] = task.kind
        return TaskResult(task.id, "agent2", True, task.kind)
    bus = InProcessBus(handler)
    bus.submit(Task(kind="discover", id="x"))
    assert seen["kind"] == "discover"
    assert bus.results[0].ok


def test_task_serialisable():
    t = Task(kind="collect", params={"host": "127.0.0.1"})
    d = json.loads(json.dumps(t.dict()))
    t2 = Task.from_dict(d)
    assert t2.kind == "collect" and t2.params["host"] == "127.0.0.1"


def test_killswitch_stops_sweep(tmp_path):
    agent = _agent(tmp_path, _scope_file(tmp_path))
    agent.role = "admin"
    agent.engage_kill("halt")
    res = agent.handle_task(Task(kind="full_sweep",
                                 params={"hosts": [("127.0.0.1", "linux", None)],
                                         "with_ai": False}))
    assert not res.ok


def test_default_sweep_self_audits_localhost(tmp_path):
    """Regression: sweep with no hosts must assess localhost in scope, not
    silently produce an empty report."""
    agent = _agent(tmp_path, _scope_file(tmp_path))
    session = agent.run_sweep(with_ai=False, write_report=False)
    assert [h["host"] for h in session["hosts"]] == ["127.0.0.1"]


def test_sweep_with_nothing_to_do_fails_loudly(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text("endpoints:\n  - identifier: '192.168.56.0/24'\n")
    agent = _agent(tmp_path, p)
    res = agent.handle_task(Task(kind="full_sweep", params={"with_ai": False}))
    assert not res.ok and "no hosts to sweep" in res.error


def test_cli_clean_error_out_of_scope(tmp_path, capsys, monkeypatch):
    from endpoint_agent import cli
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "authorized_endpoints.yaml").write_text("endpoints: []\n")
    rc = cli.main(["--no-ai", "assess", "8.8.8.8", "--os", "linux"])
    assert rc == 2 and "refusing to act" in capsys.readouterr().err
