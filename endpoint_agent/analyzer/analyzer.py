"""Security Analyzer.

Turns a CollectionResult into prioritised, *deterministic* findings. This layer
is rule-based and explainable — it never invents findings and never depends on an
LLM. (The AI layer may later summarise or correlate these findings, but the
ground truth lives here.)

Three sources of findings:
  1. Built-in misconfiguration rules (this file) — fast, offline, high-signal.
  2. Sigma rules applied to process/network/service facts (sigma_engine).
  3. YARA-X rules applied to any collected file content (yara_engine).

Every Finding separates CONFIRMED observations (a fact the collector saw) from
hypotheses. The analyzer only emits confirmed findings; AI hypotheses are tagged
separately by the AI layer and the reporter keeps them apart.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from enum import IntEnum

from ..collector.base import CollectionResult


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass
class Finding:
    host: str
    severity: Severity
    title: str
    detail: str
    category: str = "misconfig"
    source: str = "rule"            # rule | sigma | yara | lynis | osv | baseline
    evidence: str = ""              # short excerpt of the collected fact
    recommendation: str = ""
    refs: list[str] = field(default_factory=list)
    confirmed: bool = True          # False only for approximate matches (see vuln)

    def dict(self) -> dict:
        d = asdict(self)
        d["severity"] = int(self.severity)
        d["severity_label"] = self.severity.label
        return d


class SecurityAnalyzer:
    def __init__(self, sigma=None, yara=None, extra_sources=None):
        self.sigma = sigma          # optional SigmaEngine
        self.yara = yara            # optional YaraEngine
        # Further finding sources: callables taking a CollectionResult and
        # returning list[Finding] (Lynis, OSV lookup, baseline comparison).
        self.extra_sources = list(extra_sources or [])

    # ------------------------------------------------------------- entry
    def analyze(self, result: CollectionResult) -> list[Finding]:
        findings: list[Finding] = []
        if result.os_name == "linux":
            findings += self._linux_rules(result)
        elif result.os_name == "windows":
            findings += self._windows_rules(result)
        if self.sigma is not None:
            findings += self.sigma.match(result)
        if self.yara is not None:
            findings += self.yara.scan(result)
        for source in self.extra_sources:
            findings += source(result)
        findings.sort(key=lambda f: (-int(f.severity), f.category))
        return findings

    # ------------------------------------------------------- linux rules
    def _linux_rules(self, r: CollectionResult) -> list[Finding]:
        f: list[Finding] = []
        host = r.host
        sshd = r.get("ssh_config")
        if sshd:
            if re.search(r"^\s*PermitRootLogin\s+(yes|prohibit-password)",
                         sshd, re.M | re.I):
                f.append(Finding(host, Severity.HIGH, "SSH root-innlogging tillatt",
                    "sshd_config tillater PermitRootLogin.", "ssh", "rule",
                    _grep(sshd, "PermitRootLogin"),
                    "Sett PermitRootLogin no og bruk en vanlig konto + sudo.",
                    ["CIS Benchmark 5.2"]))
            if re.search(r"^\s*PasswordAuthentication\s+yes", sshd, re.M | re.I):
                f.append(Finding(host, Severity.MEDIUM,
                    "SSH passord-autentisering på",
                    "Passord-pålogging er sårbar for brute force.", "ssh", "rule",
                    _grep(sshd, "PasswordAuthentication"),
                    "Bruk nøkkelbasert autentisering og sett PasswordAuthentication no."))
            if re.search(r"^\s*Protocol\s+1", sshd, re.M | re.I):
                f.append(Finding(host, Severity.HIGH, "SSH protokoll 1 aktivert",
                    "SSHv1 er kryptografisk brutt.", "ssh", "rule",
                    _grep(sshd, "Protocol"), "Fjern 'Protocol 1'."))

        listening = r.get("listening")
        if listening:
            for port, (sev, note) in _RISKY_PORTS.items():
                if re.search(rf":{port}\b", listening):
                    f.append(Finding(host, sev, f"Risikabel tjeneste lytter: port {port}",
                        note, "network", "rule", _grep(listening, f":{port}"),
                        f"Steng port {port} om den ikke trengs, eller begrens med brannmur."))

        users = r.get("users")
        if users:
            for line in users.splitlines():
                parts = line.split(":")
                if len(parts) >= 3 and parts[2] == "0" and parts[0] != "root":
                    f.append(Finding(host, Severity.CRITICAL,
                        f"Ekstra UID 0-konto: {parts[0]}",
                        "En konto utenom root har UID 0 (full root-tilgang).",
                        "users", "rule", line,
                        f"Fjern eller endre UID for {parts[0]}."))

        suid = r.get("suid_binaries")
        if suid:
            risky = [ln for ln in suid.splitlines()
                     if re.search(r"/(nmap|vim|find|bash|python|perl|nc|cp|tar)\b", ln)]
            if risky:
                f.append(Finding(host, Severity.HIGH,
                    "SUID på GTFOBins-binær",
                    "SUID-biter på kjente binærer gir enkel privilegie-eskalering.",
                    "security", "rule", "\n".join(risky[:5]),
                    "Fjern SUID (chmod u-s) der det ikke er nødvendig.",
                    ["https://gtfobins.github.io"]))

        ww = r.get("world_writable")
        if ww and ww.strip():
            f.append(Finding(host, Severity.MEDIUM,
                "Verdens-skrivbare filer under /etc",
                "Konfigurasjonsfiler alle kan endre.", "files", "rule",
                _head(ww, 5), "Fjern skrivetilgang: chmod o-w <fil>."))
        return f

    # ----------------------------------------------------- windows rules
    def _windows_rules(self, r: CollectionResult) -> list[Finding]:
        f: list[Finding] = []
        host = r.host
        fw = r.get("firewall")
        if fw and re.search(r'"Enabled"\s*:\s*(0|false|"False")', fw, re.I):
            f.append(Finding(host, Severity.HIGH, "Windows-brannmur av på en profil",
                "Minst én brannmurprofil er deaktivert.", "security", "rule",
                _head(fw, 6), "Slå på brannmuren for alle profiler."))
        defender = r.get("defender")
        if defender and re.search(r'"RealTimeProtectionEnabled"\s*:\s*(false|0)',
                                  defender, re.I):
            f.append(Finding(host, Severity.HIGH, "Defender sanntidsbeskyttelse av",
                "Microsoft Defender sanntidsbeskyttelse er avslått.", "security",
                "rule", _head(defender, 6), "Slå på sanntidsbeskyttelse."))
        shares = r.get("smb_shares")
        if shares:
            for m in re.finditer(r'"Name"\s*:\s*"([^"]+)"', shares):
                name = m.group(1)
                if name.upper() not in ("ADMIN$", "C$", "IPC$"):
                    f.append(Finding(host, Severity.LOW, f"SMB-deling: {name}",
                        "Ikke-standard SMB-deling eksponert.", "security", "rule",
                        name, "Verifiser at delingen og tilgangsrettighetene er tiltenkt."))
        hotfix = r.get("hotfixes")
        if hotfix is not None and hotfix.strip() in ("", "[]"):
            f.append(Finding(host, Severity.MEDIUM, "Ingen patcher rapportert",
                "Get-HotFix returnerte ingen oppdateringer — kan være uoppdatert.",
                "system", "rule", "", "Kontroller Windows Update-status."))
        return f


# port -> (severity, note)
_RISKY_PORTS = {
    23: (Severity.HIGH, "Telnet — klartekst, bør være av."),
    21: (Severity.MEDIUM, "FTP — ofte klartekst-innlogging."),
    3389: (Severity.MEDIUM, "RDP eksponert."),
    5900: (Severity.MEDIUM, "VNC eksponert."),
    445: (Severity.LOW, "SMB — vanlig mål for lateral bevegelse."),
    6379: (Severity.HIGH, "Redis — ofte uten autentisering."),
    9200: (Severity.MEDIUM, "Elasticsearch eksponert."),
    27017: (Severity.HIGH, "MongoDB — ofte uten autentisering."),
}


def _grep(text: str, needle: str) -> str:
    for line in text.splitlines():
        if needle.lower() in line.lower():
            return line.strip()
    return ""


def _head(text: str, n: int) -> str:
    return "\n".join(text.splitlines()[:n])
