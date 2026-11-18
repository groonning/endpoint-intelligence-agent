"""Reporting: JSON + HTML always produced; confirmed vs hypothesis separated."""
import json

from endpoint_agent.analyzer.analyzer import SecurityAnalyzer
from endpoint_agent.reporting.report import ReportBuilder


def _session(sim_linux):
    res = sim_linux.collect("127.0.0.1", "linux")
    findings = SecurityAnalyzer().analyze(res)
    return {
        "generated_at": "2026-11-17T00:00:00Z",
        "scope": ["127.0.0.1"],
        "audit_verified": True,
        "hosts": [{
            "host": "127.0.0.1", "os_name": "linux", "method": "simulated",
            "collected_at": "2026-11-17T00:00:00Z",
            "findings": [f.dict() for f in findings],
            "ai": {"ok": True, "text": "## Sammendrag\nHypotese om risiko.",
                   "hypothesis": True, "route": {"model": "qwen3:30b-a3b"}},
        }],
        "ai_correlation": None,
    }


def test_json_and_html_written(tmp_path, sim_linux):
    rb = ReportBuilder(tmp_path)
    rep = rb.build(_session(sim_linux), basename="t")
    assert rep.json_path and rep.html_path
    data = json.loads(open(rep.json_path).read())
    assert data["hosts"][0]["host"] == "127.0.0.1"


def test_html_contains_findings_and_marks_hypothesis(tmp_path, sim_linux):
    rb = ReportBuilder(tmp_path)
    rep = rb.build(_session(sim_linux), basename="t")
    html = open(rep.html_path, encoding="utf-8").read()
    assert "Ekstra UID 0" in html                      # a confirmed finding
    assert "AI-hypotese" in html                        # AI clearly labelled


def test_pdf_optional_never_fails(tmp_path, sim_linux):
    rb = ReportBuilder(tmp_path)
    rep = rb.build(_session(sim_linux), basename="t")
    # Either a pdf path exists, or a skip reason is recorded — never an exception.
    assert rep.pdf_path or rep.pdf_skipped_reason
