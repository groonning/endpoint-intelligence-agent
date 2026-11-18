"""AI model router + engine routing/redaction (no network)."""
from endpoint_agent.ai.router import ModelRouter, TaskKind
from endpoint_agent.ai.engine import AIAnalysisEngine
from endpoint_agent.ai.ollama_backend import OllamaBackend


def _router(allow_external=True, external_available=True, **kw):
    return ModelRouter("qwen3:30b-a3b", "claude-sonnet-5-5", "claude-opus-5-5",
                       allow_external=allow_external,
                       external_available=external_available, **kw)


def test_simple_task_local():
    r = _router().route(TaskKind.CLASSIFY)
    assert r.backend == "ollama"


def test_complex_task_sonnet():
    r = _router().route(TaskKind.CORRELATE)
    assert r.backend == "claude" and "sonnet" in r.model


def test_critical_task_opus():
    r = _router().route(TaskKind.RISK_JUDGEMENT)
    assert r.backend == "claude" and "opus" in r.model


def test_external_disabled_downgrades():
    r = _router(allow_external=False).route(TaskKind.CORRELATE)
    assert r.backend == "ollama" and r.downgraded


def test_token_budget_downgrades():
    r = _router(max_external_tokens=10).route(TaskKind.CORRELATE, est_tokens=1000)
    assert r.backend == "ollama" and r.downgraded


def test_risk_pushes_summarize_up():
    # SUMMARIZE is below threshold normally, but high risk should push it over.
    low = _router().route(TaskKind.SUMMARIZE, risk=0.0)
    high = _router().route(TaskKind.SUMMARIZE, risk=1.0)
    assert low.backend == "ollama"
    assert high.backend == "claude"


class _FakeOllama(OllamaBackend):
    def __init__(self):
        super().__init__()
        self.last = None
    def chat(self, system, user, as_json=False, timeout=300):
        self.last = user
        return "local-report"


def test_engine_uses_local_and_records_audit(audit):
    eng = AIAnalysisEngine(_router(allow_external=False), _FakeOllama(),
                           claude=None, audit=audit)
    out = eng.run(TaskKind.SUMMARIZE, "finding on 10.1.2.3 host web.lab")
    assert out.ok and out.text == "local-report"
    assert any(e.action == "ai.call" for e in audit.events())


def test_engine_redacts_before_external(audit):
    class _FakeClaude:
        def __init__(self): self.seen = None
        def available(self): return True, "claude-sonnet-5-5"
        def chat(self, system, user, **kw):
            self.seen = user
            return "ext"
    fc = _FakeClaude()
    eng = AIAnalysisEngine(_router(), _FakeOllama(), claude=fc, audit=audit,
                           redact_external=True)
    out = eng.run(TaskKind.CORRELATE, "host web.lab at 10.1.2.3 is bad")
    assert out.ok
    assert "10.1.2.3" not in fc.seen and "web.lab" not in fc.seen
    assert "<ip>" in fc.seen
