"""Baseline and change detection (also the file-integrity check).

Each assessment reduces a host to a small snapshot: accounts, privileged
accounts, listening sockets, SUID binaries, services, packages, the sshd config
hash and the hashes of files in approved directories. The first snapshot becomes
the host's baseline. Later runs are compared against it and every difference
becomes a finding, so a new account or a changed file shows up even when it
breaks no rule.

The baseline only moves when a person accepts the current state
(`baseline accept <host>`); until then the same change keeps being reported.
A category is compared only when its source command succeeded in both runs, so
a failed command never reads as "everything was removed".
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path

from .analyzer import Finding, Severity
from ..collector.base import CollectionResult


def _ok(result: CollectionResult, key: str) -> bool:
    o = result.outputs.get(key)
    return o is not None and o.returncode == 0


def _json_rows(text: str) -> list[dict]:
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if isinstance(data, dict):
        return [data]
    return [d for d in data if isinstance(d, dict)] if isinstance(data, list) else []


def snapshot(result: CollectionResult) -> dict:
    snap: dict = {}
    g = result.get
    if result.os_name == "linux":
        if _ok(result, "users"):
            rows = [l.split(":") for l in g("users").splitlines() if l.count(":") >= 6]
            snap["users"] = sorted(r[0] for r in rows)
            snap["privileged"] = sorted(r[0] for r in rows if r[2] == "0")
        if _ok(result, "sudoers_who"):
            members = g("sudoers_who").strip().split(":")[-1]
            snap["sudo"] = sorted(m for m in members.split(",") if m)
        if _ok(result, "listening"):
            socks = set()
            for line in g("listening").splitlines():
                c = line.split()
                if len(c) >= 5 and c[1] in ("LISTEN", "UNCONN"):
                    socks.add(f"{c[0]} {c[4]}")
            snap["listening"] = sorted(socks)
        if _ok(result, "suid_binaries"):
            snap["suid"] = sorted(l.split()[-1] for l in g("suid_binaries").splitlines()
                                  if l.strip())
        if _ok(result, "services_systemd"):
            snap["services"] = sorted({l.split()[0] for l in
                                       g("services_systemd").splitlines() if l.split()})
        if _ok(result, "packages_src"):
            snap["packages"] = sorted({f"{p[0]}={p[1]}" for p in
                                       (l.split("\t") for l in g("packages_src").splitlines())
                                       if len(p) >= 2})
        if _ok(result, "ssh_config"):
            snap["sshd_config"] = [hashlib.sha256(g("ssh_config").encode()).hexdigest()]
    else:
        if _ok(result, "users"):
            snap["users"] = sorted(r.get("Name", "") for r in _json_rows(g("users")))
        if _ok(result, "admins"):
            snap["privileged"] = sorted(r.get("Name", "") for r in _json_rows(g("admins")))
        if _ok(result, "listening"):
            snap["listening"] = sorted({f"tcp {r.get('LocalAddress')}:{r.get('LocalPort')}"
                                        for r in _json_rows(g("listening"))})
        if _ok(result, "services"):
            snap["services"] = sorted(r.get("Name", "") for r in _json_rows(g("services")))
        if _ok(result, "hotfixes"):
            snap["packages"] = sorted(r.get("HotFixID", "") for r in _json_rows(g("hotfixes")))
        if _ok(result, "smb_shares"):
            snap["shares"] = sorted(r.get("Name", "") for r in _json_rows(g("smb_shares")))
    if result.files:
        snap["files"] = {f.path: f.sha256 for f in result.files if f.sha256}
    return snap


# category -> (label, severity when added, severity when removed)
_SETS = {
    "users": ("brukerkonto", Severity.HIGH, Severity.LOW),
    "privileged": ("konto med administrator-/root-rettigheter", Severity.CRITICAL, Severity.LOW),
    "sudo": ("medlem i sudo-gruppen", Severity.HIGH, Severity.LOW),
    "listening": ("lyttende port", Severity.MEDIUM, Severity.INFO),
    "suid": ("SUID-binær", Severity.HIGH, Severity.INFO),
    "services": ("kjørende tjeneste", Severity.LOW, Severity.INFO),
    "shares": ("SMB-deling", Severity.MEDIUM, Severity.INFO),
}


def compare(host: str, old: dict, new: dict) -> list[Finding]:
    out: list[Finding] = []

    def add(sev, title, detail, evidence=""):
        out.append(Finding(host, sev, title, detail, "change", "baseline", evidence,
                           "Bekreft at endringen er tiltenkt. Godta den med "
                           f"«baseline accept {host}» hvis den er det."))

    for key, (label, sev_add, sev_del) in _SETS.items():
        if key not in old or key not in new:
            continue
        for item in sorted(set(new[key]) - set(old[key])):
            add(sev_add, f"Ny {label}: {item}", f"Fantes ikke i baseline for {host}.", item)
        for item in sorted(set(old[key]) - set(new[key])):
            add(sev_del, f"Fjernet {label}: {item}", "Fantes i baseline, men ikke nå.", item)
    if "packages" in old and "packages" in new:
        added = sorted(set(new["packages"]) - set(old["packages"]))
        removed = sorted(set(old["packages"]) - set(new["packages"]))
        if added or removed:
            add(Severity.INFO, f"Pakkeendringer: {len(added)} nye/oppdaterte, {len(removed)} fjernet/erstattet",
                "Installerte pakker eller patcher er endret siden baseline.",
                "\n".join(["+ " + p for p in added[:10]] + ["- " + p for p in removed[:10]]))
    if old.get("sshd_config") and new.get("sshd_config") \
            and old["sshd_config"] != new["sshd_config"]:
        add(Severity.MEDIUM, "sshd_config er endret", "SSH-serverens konfigurasjon avviker fra baseline.")
    if "files" in old and "files" in new:
        o, n = old["files"], new["files"]
        for path in sorted(set(o) & set(n)):
            if o[path] != n[path]:
                add(Severity.MEDIUM, f"Fil endret: {path}", "Innholdet (SHA-256) avviker fra baseline.",
                    f"{o[path][:16]}… → {n[path][:16]}…")
        for path in sorted(set(n) - set(o)):
            add(Severity.LOW, f"Ny fil: {path}", "Filen fantes ikke i baseline.", n[path])
        for path in sorted(set(o) - set(n)):
            add(Severity.LOW, f"Fil fjernet: {path}", "Filen fantes i baseline, men ikke nå.")
    return out


class BaselineStore:
    def __init__(self, state_dir: str | Path = "state"):
        self.dir = Path(state_dir) / "baselines"

    def _path(self, host: str) -> Path:
        return self.dir / (re.sub(r"[^A-Za-z0-9._-]", "_", host) + ".json")

    def load(self, host: str) -> dict | None:
        p = self._path(host)
        return json.loads(p.read_text()) if p.exists() else None

    def _save(self, host: str, doc: dict) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        tmp = self._path(host).with_suffix(".tmp")
        tmp.write_text(json.dumps(doc, indent=1, sort_keys=True))
        os.replace(tmp, self._path(host))

    def evaluate(self, host: str, snap: dict) -> list[Finding]:
        """Compare against the baseline, remember this run as the latest state."""
        doc = self.load(host)
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if doc is None:
            self._save(host, {"baseline": snap, "baseline_at": now,
                              "latest": snap, "latest_at": now})
            return [Finding(host, Severity.INFO, "Baseline opprettet",
                            "Første kjøring mot denne verten. Senere kjøringer "
                            "sammenlignes med denne tilstanden.", "change", "baseline")]
        doc["latest"], doc["latest_at"] = snap, now
        self._save(host, doc)
        return compare(host, doc["baseline"], snap)

    def accept(self, host: str) -> str:
        """Make the latest observed state the new baseline."""
        doc = self.load(host)
        if doc is None:
            raise ValueError(f"no baseline recorded for {host}")
        doc["baseline"], doc["baseline_at"] = doc["latest"], doc["latest_at"]
        self._save(host, doc)
        return doc["baseline_at"]

    def hosts(self) -> list[dict]:
        if not self.dir.exists():
            return []
        out = []
        for p in sorted(self.dir.glob("*.json")):
            d = json.loads(p.read_text())
            out.append({"host": p.stem, "baseline_at": d.get("baseline_at"),
                        "latest_at": d.get("latest_at")})
        return out
