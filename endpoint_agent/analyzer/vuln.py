"""Known-vulnerability lookup against OSV (https://osv.dev).

The collector already gathers installed packages. This module asks the OSV API
which of those exact versions have known vulnerabilities, and turns the answer
into findings. Only package names and versions are sent; no host identifiers.
It is off by default (config: vuln.enabled) because it is the one analysis step
that talks to the internet, and every lookup is audit-logged.

Coverage is honest rather than complete:
  * Debian and Ubuntu endpoints are matched against their own OSV ecosystems.
  * Kali has no OSV ecosystem. With vuln.kali_as_debian set, Kali packages are
    checked against that Debian release and the results are marked unconfirmed,
    because Kali versions do not map one-to-one onto Debian's.
  * Windows patch levels are not covered (OSV does not carry Microsoft KBs).
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.request
from pathlib import Path
from typing import Callable

from .analyzer import Finding, Severity
from ..collector.base import CollectionResult

_BATCH = 500


def _http_post(url: str, payload: dict, timeout: int = 60) -> dict:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def ecosystem_for(os_release: str, kali_as_debian: str = "") -> tuple[str | None, bool, str]:
    """Return (osv ecosystem or None, exact_match, distro id)."""
    info = dict(re.findall(r'^([A-Z_]+)="?([^"\n]*)"?$', os_release, re.M))
    distro = info.get("ID", "").lower()
    version = info.get("VERSION_ID", "")
    if distro == "debian" and version:
        return f"Debian:{version.split('.')[0]}", True, distro
    if distro == "ubuntu" and version:
        lts = "LTS" in info.get("VERSION", "")
        return f"Ubuntu:{version}:LTS" if lts else f"Ubuntu:{version}", True, distro
    if distro == "kali" and kali_as_debian:
        return f"Debian:{kali_as_debian}", False, distro
    return None, False, distro or "ukjent"


def parse_packages(packages_src: str) -> list[tuple[str, str]]:
    """(source package, version) pairs from the packages_src command, de-duplicated."""
    seen, out = set(), []
    for line in packages_src.splitlines():
        parts = line.split("\t")
        if len(parts) < 2 or not parts[0] or not parts[1]:
            continue
        pair = (parts[0].strip(), parts[1].strip())
        if pair not in seen:
            seen.add(pair)
            out.append(pair)
    return out


class OSVClient:
    def __init__(self, url: str = "https://api.osv.dev",
                 cache_path: str | Path = "state/osv_cache.json",
                 ttl_hours: int = 24, post: Callable[[str, dict], dict] | None = None):
        self.url = url.rstrip("/")
        self.cache_path = Path(cache_path)
        self.ttl = ttl_hours * 3600
        self._post = post or _http_post
        self._cache: dict[str, dict] = {}
        if self.cache_path.exists():
            try:
                self._cache = json.loads(self.cache_path.read_text())
            except ValueError:
                self._cache = {}

    def query(self, ecosystem: str, pkgs: list[tuple[str, str]]) -> dict[tuple[str, str], list[str]]:
        now = time.time()
        result: dict[tuple[str, str], list[str]] = {}
        todo = []
        for name, version in pkgs:
            hit = self._cache.get(f"{ecosystem}|{name}|{version}")
            if hit and now - hit["ts"] < self.ttl:
                result[(name, version)] = hit["ids"]
            else:
                todo.append((name, version))
        for i in range(0, len(todo), _BATCH):
            chunk = todo[i:i + _BATCH]
            ids: list[list[str]] = [[] for _ in chunk]
            pending = {n: None for n in range(len(chunk))}      # index -> page token
            for _ in range(10):                                  # pagination guard
                idxs = list(pending)
                queries = []
                for n in idxs:
                    q = {"package": {"name": chunk[n][0], "ecosystem": ecosystem},
                         "version": chunk[n][1]}
                    if pending[n]:
                        q["page_token"] = pending[n]
                    queries.append(q)
                data = self._post(self.url + "/v1/querybatch", {"queries": queries})
                pending = {}
                for n, res in zip(idxs, data.get("results", [])):
                    ids[n] += [v["id"] for v in (res or {}).get("vulns", [])]
                    if (res or {}).get("next_page_token"):
                        pending[n] = res["next_page_token"]
                if not pending:
                    break
            for (name, version), found in zip(chunk, ids):
                result[(name, version)] = found
                self._cache[f"{ecosystem}|{name}|{version}"] = {"ts": now, "ids": found}
        if todo:
            self._save()
        return result

    def _save(self) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.cache_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._cache))
        os.replace(tmp, self.cache_path)


def vuln_findings(result: CollectionResult, client: OSVClient, kali_as_debian: str = "",
                  max_findings: int = 25, audit=None, actor: str = "agent2") -> list[Finding]:
    if result.os_name != "linux":
        return []
    host = result.host
    pkgs = parse_packages(result.get("packages_src"))
    if not pkgs:
        return []
    ecosystem, exact, distro = ecosystem_for(result.get("os_release"), kali_as_debian)
    if ecosystem is None:
        hint = (" Sett vuln.kali_as_debian for et omtrentlig oppslag mot Debian."
                if distro == "kali" else "")
        return [Finding(host, Severity.INFO, "Sårbarhetsoppslag ikke utført",
                        f"OSV har ikke pakkedata for distribusjonen «{distro}».{hint}",
                        "vulnerability", "osv")]
    if audit:
        audit.record(actor, "vuln.osv_lookup", host, "start",
                     {"ecosystem": ecosystem, "packages": len(pkgs), "left_box": True})
    try:
        matches = client.query(ecosystem, pkgs)
    except Exception as e:
        if audit:
            audit.record(actor, "vuln.osv_lookup", host, "error", {"error": str(e)[:200]})
        return [Finding(host, Severity.INFO, "Sårbarhetsoppslag feilet",
                        f"Fikk ikke svar fra OSV ({e}). Ingen CVE-funn i denne kjøringen.",
                        "vulnerability", "osv")]
    vulnerable = sorted(((p, ids) for p, ids in matches.items() if ids),
                        key=lambda x: -len(x[1]))
    if audit:
        audit.record(actor, "vuln.osv_lookup", host, "ok",
                     {"ecosystem": ecosystem, "vulnerable_packages": len(vulnerable)})
    caveat = ("" if exact else
              f" Omtrentlig treff: Kali-pakken er sammenlignet med {ecosystem}.")
    findings = []
    for (name, version), ids in vulnerable[:max_findings]:
        shown = ", ".join(ids[:8]) + (f" (+{len(ids) - 8} til)" if len(ids) > 8 else "")
        findings.append(Finding(
            host, Severity.MEDIUM,
            f"Kjente sårbarheter i {name} {version}: {len(ids)}",
            f"OSV ({ecosystem}) lister {len(ids)} sårbarhet(er) for denne versjonen."
            f"{caveat} Alvorlighetsgrad per CVE er ikke vurdert her.",
            "vulnerability", "osv", shown,
            f"Oppdater {name} (apt upgrade) og sjekk hver ID på osv.dev.",
            [f"https://osv.dev/vulnerability/{i}" for i in ids[:5]],
            confirmed=exact))
    if len(vulnerable) > max_findings:
        rest = vulnerable[max_findings:]
        findings.append(Finding(
            host, Severity.LOW,
            f"Ytterligere {len(rest)} pakker med kjente sårbarheter",
            "Listen over er avkortet til pakkene med flest treff.", "vulnerability",
            "osv", ", ".join(n for (n, _), _ in rest[:30]),
            "Kjør en full systemoppdatering.", confirmed=exact))
    return findings
