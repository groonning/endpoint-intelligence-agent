"""Security Analyzer: deterministic findings from canned collection."""
from endpoint_agent.analyzer.analyzer import SecurityAnalyzer, Severity


def _titles(findings):
    return [f.title for f in findings]


def test_linux_findings(sim_linux):
    res = sim_linux.collect("127.0.0.1", "linux")
    findings = SecurityAnalyzer().analyze(res)
    titles = " | ".join(_titles(findings))
    assert "root-innlogging" in titles              # PermitRootLogin yes
    assert "passord-autentisering" in titles        # PasswordAuthentication yes
    assert any(f.title.startswith("Ekstra UID 0") for f in findings)  # backdoor
    assert any("port 23" in f.title for f in findings)                # telnet


def test_critical_sorted_first(sim_linux):
    res = sim_linux.collect("127.0.0.1", "linux")
    findings = SecurityAnalyzer().analyze(res)
    assert findings[0].severity == Severity.CRITICAL


def test_windows_findings(sim_windows):
    res = sim_windows.collect("10.10.10.5", "windows")
    findings = SecurityAnalyzer().analyze(res)
    titles = " | ".join(_titles(findings))
    assert "brannmur" in titles.lower()
    assert "sanntidsbeskyttelse" in titles.lower()


def test_findings_are_confirmed(sim_linux):
    res = sim_linux.collect("127.0.0.1", "linux")
    findings = SecurityAnalyzer().analyze(res)
    assert all(f.confirmed for f in findings)
    assert all(f.source == "rule" for f in findings)


def test_finding_dict_has_labels(sim_linux):
    res = sim_linux.collect("127.0.0.1", "linux")
    f = SecurityAnalyzer().analyze(res)[0]
    d = f.dict()
    assert d["severity_label"] in ("critical", "high", "medium", "low", "info")
    assert isinstance(d["severity"], int)
