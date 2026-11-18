"""Sigma engine (self-contained matcher) + YARA engine graceful-absence."""
from endpoint_agent.analyzer.sigma_engine import SigmaEngine
from endpoint_agent.analyzer.yara_engine import YaraEngine


SIGMA_RULE = """
title: Netcat reverse shell
id: test-nc-revshell
level: high
logsource:
  category: process_creation
detection:
  selection:
    Image|contains: 'nc'
    CommandLine|contains: '-e'
  condition: selection
"""


def test_sigma_matches_process(tmp_path, sim_linux):
    rules_dir = tmp_path / "sigma"
    rules_dir.mkdir()
    (rules_dir / "nc.yml").write_text(SIGMA_RULE)
    eng = SigmaEngine(str(rules_dir))
    assert eng.rules, "rule should have loaded"
    res = sim_linux.collect("127.0.0.1", "linux")
    findings = eng.match(res)
    assert any("Netcat" in f.title for f in findings)
    assert findings[0].source == "sigma"


def test_sigma_no_rules_dir():
    eng = SigmaEngine("/nonexistent/path")
    assert eng.rules == []


def test_sigma_skips_unsupported_category(tmp_path):
    rules_dir = tmp_path / "sigma"
    rules_dir.mkdir()
    (rules_dir / "x.yml").write_text(
        "title: web\nlevel: low\nlogsource:\n  category: webserver\n"
        "detection:\n  sel:\n    a: b\n  condition: sel\n")
    eng = SigmaEngine(str(rules_dir))
    assert eng.rules == []           # category not evaluatable from endpoint facts


def test_yara_absent_is_graceful(tmp_path, sim_linux):
    eng = YaraEngine(str(tmp_path / "yara"))
    res = sim_linux.collect("127.0.0.1", "linux")
    # Either yara-x isn't installed (available False) or there are no rules;
    # scan must never raise and must return a list.
    assert isinstance(eng.scan(res), list)
