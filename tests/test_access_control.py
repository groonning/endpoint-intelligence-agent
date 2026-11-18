"""Host-key pinning store, approvals, RBAC on scope and AI, token budget, config."""
import pytest

from endpoint_agent.core.hostkeys import HostKeyStore, HostKeyError
from endpoint_agent.core.approvals import ApprovalQueue
from endpoint_agent.core.rbac import RBAC, AccessDenied
from endpoint_agent.core.config import load_config
from endpoint_agent.ai.engine import AIAnalysisEngine
from endpoint_agent.ai.router import ModelRouter, TaskKind
from endpoint_agent.ai.ollama_backend import OllamaBackend


# --- host keys --------------------------------------------------------------
def test_hostkey_first_use_pins_then_matches(tmp_path):
    s = HostKeyStore(tmp_path / "kh.json")
    assert s.check("10.0.0.5", 22, "ssh-ed25519", "SHA256:aaa") == "pinned"
    assert HostKeyStore(tmp_path / "kh.json").check("10.0.0.5", 22, "ssh-ed25519", "SHA256:aaa") == "match"


def test_hostkey_change_is_refused(tmp_path):
    s = HostKeyStore(tmp_path / "kh.json")
    s.check("10.0.0.5", 22, "ssh-ed25519", "SHA256:aaa")
    with pytest.raises(HostKeyError, match="HOST KEY CHANGED"):
        s.check("10.0.0.5", 22, "ssh-ed25519", "SHA256:evil")


def test_hostkey_strict_refuses_unknown(tmp_path):
    s = HostKeyStore(tmp_path / "kh.json", strict=True)
    with pytest.raises(HostKeyError, match="strict"):
        s.check("10.0.0.5", 22, "ssh-ed25519", "SHA256:aaa")
    assert s.get("10.0.0.5") is None            # nothing was pinned


def test_hostkey_forget_allows_repin(tmp_path):
    s = HostKeyStore(tmp_path / "kh.json")
    s.check("h", 22, "t", "SHA256:a")
    assert s.forget("h", 22)
    assert s.check("h", 22, "t", "SHA256:b") == "pinned"


# --- approvals + scope ------------------------------------------------------
def test_approval_queue_dedupes_and_decides_once(tmp_path):
    q = ApprovalQueue(tmp_path / "a.json")
    r1 = q.request("scope.add", "10.0.0.9", "bridge")
    r2 = q.request("scope.add", "10.0.0.9", "bridge")
    assert r1.id == r2.id and len(q.pending()) == 1
    q.decide(r1.id, True, "admin")
    with pytest.raises(ValueError):
        q.decide(r1.id, False, "admin")


def test_scope_add_needs_confirmation(make_agent):
    agent = make_agent()
    with pytest.raises(PermissionError):
        agent.add_scope("10.0.0.9", "lab")
    assert not agent.scope.is_authorised("10.0.0.9")
    agent.add_scope("10.0.0.9", "lab", confirmed=True)
    assert agent.scope.is_authorised("10.0.0.9")


def test_viewer_cannot_add_scope(make_agent):
    agent = make_agent(role="viewer")
    with pytest.raises(AccessDenied):
        agent.add_scope("10.0.0.9", "lab", confirmed=True)


def test_request_only_takes_effect_when_admin_approves(make_agent):
    agent = make_agent(role="operator")
    req = agent.request_scope_add("10.0.0.9", "agent1-bridge", "seen on wifi")
    assert not agent.scope.is_authorised("10.0.0.9")
    with pytest.raises(AccessDenied):                     # operator cannot approve
        agent.decide_request(req.id, True)
    agent.role = "admin"
    agent.decide_request(req.id, True)
    assert agent.scope.is_authorised("10.0.0.9")
    assert any(e.action == "approval.approved" for e in agent.audit.events())


def test_denied_request_changes_nothing(make_agent):
    agent = make_agent(role="admin")
    req = agent.request_scope_add("10.0.0.9", "x")
    agent.decide_request(req.id, False)
    assert not agent.scope.is_authorised("10.0.0.9")


def test_task_cannot_widen_scope_only_request_it(make_agent):
    from endpoint_agent.orchestrator.bus import Task
    agent = make_agent(role="admin")
    res = agent.handle_task(Task(kind="scope_request", origin="agent1",
                                 params={"identifier": "10.0.0.9"}))
    assert res.ok and res.data["approval"]["status"] == "pending"
    assert not agent.scope.is_authorised("10.0.0.9")


def test_cli_scope_add_refused_without_yes(make_agent, monkeypatch, tmp_path, capsys):
    from endpoint_agent import cli
    agent = make_agent()
    monkeypatch.setattr(cli, "_agent", lambda args: agent)
    monkeypatch.setattr("builtins.input", lambda prompt="": "no")
    assert cli.main(["scope", "add", "10.0.0.9"]) == 2
    assert not agent.scope.is_authorised("10.0.0.9")
    assert cli.main(["scope", "add", "10.0.0.9", "--yes"]) == 0
    assert agent.scope.is_authorised("10.0.0.9")


def test_everyone_may_stop_but_viewer_may_not_rearm(make_agent):
    agent = make_agent(role="viewer")
    agent.engage_kill("stop")
    with pytest.raises(AccessDenied):
        agent.reset_kill()


# --- AI gating --------------------------------------------------------------
class _Local(OllamaBackend):
    def chat(self, system, user, as_json=False, timeout=300):
        return "local"


class _Ext:
    calls = 0
    def available(self): return True, "m"
    def chat(self, system, user, **kw):
        _Ext.calls += 1
        return "external"


def _engine(audit, role="admin", budget=None):
    _Ext.calls = 0
    router = ModelRouter("local-m", "sonnet", "opus", allow_external=True,
                         external_available=True)
    return AIAnalysisEngine(router, _Local(), _Ext(), audit=audit, rbac=RBAC(),
                            role=role, max_external_tokens_per_run=budget)


def test_operator_without_ai_external_stays_local(audit):
    out = _engine(audit, role="operator").run(TaskKind.CORRELATE, "x" * 400)
    assert out.text == "local" and out.route.downgraded and _Ext.calls == 0


def test_admin_may_use_external(audit):
    out = _engine(audit, role="admin").run(TaskKind.CORRELATE, "x" * 400)
    assert out.text == "external"


def test_viewer_gets_no_ai_at_all(audit):
    out = _engine(audit, role="viewer").run(TaskKind.SUMMARIZE, "x")
    assert not out.ok and "may not use AI" in out.error


def test_external_budget_is_per_run_not_per_call(audit):
    eng = _engine(audit, budget=5000)          # each call reserves ~100 + 2048
    results = [eng.run(TaskKind.CORRELATE, "x" * 400).text for _ in range(4)]
    assert results == ["external", "external", "local", "local"]
    assert eng.external_tokens_used <= 5000
    eng.reset_budget()
    assert eng.run(TaskKind.CORRELATE, "x" * 400).text == "external"


# --- config -----------------------------------------------------------------
def test_config_rejects_unknown_keys(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("ai:\n  allow_externall: true\n")
    with pytest.raises(ValueError, match="allow_externall"):
        load_config(p)


def test_config_nested_sections(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("files:\n  enabled: true\n  linux_paths: [/opt/app]\nvuln:\n  enabled: true\n")
    cfg = load_config(p)
    assert cfg.files.linux_paths == ["/opt/app"] and cfg.vuln.enabled
