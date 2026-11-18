"""Sigma detection over collected endpoint facts and logs.

Sigma rules (SigmaHQ) are the standard format for shareable detections. pySigma
converts rules into SIEM queries but has no in-memory matcher, so this module
carries its own small evaluator and uses pySigma (when installed) only to
validate rule syntax.

What gets evaluated, per host:
  * process_creation   -- the process snapshot (and Windows event 4688)
  * network_connection -- the socket snapshot
  * product: linux, service: auth / sshd / sudo / syslog / cron
                       -- lines from the auth log and journal
  * product: windows, service: security / system / powershell
                       -- parsed Windows event-log records

The evaluator supports the common Sigma surface: field selections (AND), lists
(OR), keyword lists, wildcards, the modifiers contains / startswith / endswith /
all / re / cidr / exists, and conditions with and / or / not, parentheses and
"1 of" / "all of" / "any of" with name patterns. Rules that need anything else
(aggregations, base64 modifiers, correlation) are skipped and listed in
`skipped`, never half-evaluated. Conditions are parsed, not eval()'d.
"""
from __future__ import annotations

import fnmatch
import glob
import ipaddress
import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any

import yaml

from .analyzer import Finding, Severity
from ..collector.base import CollectionResult

try:
    from sigma.rule import SigmaRule as _PySigmaRule
    _HAVE_PYSIGMA = True
except Exception:
    _HAVE_PYSIGMA = False

_SEV = {"informational": Severity.INFO, "low": Severity.LOW,
        "medium": Severity.MEDIUM, "high": Severity.HIGH,
        "critical": Severity.CRITICAL}

_MODIFIERS = {"contains", "startswith", "endswith", "all", "re", "cidr", "exists"}
_LINUX_SERVICES = {"auth", "sshd", "sudo", "syslog", "cron"}
_WIN_SERVICES = {"security": "Security", "system": "System",
                 "powershell": "Microsoft-Windows-PowerShell/Operational"}


class _Unsupported(Exception):
    pass


@dataclass
class _Rule:
    title: str
    level: str
    stream: str                 # which event stream it is evaluated against
    product: str                # "" | "linux" | "windows"
    detection: dict
    condition: Any              # parsed condition tree
    id: str = ""
    refs: list[str] = field(default_factory=list)


# --------------------------------------------------------------- conditions
def _tokenize(cond: str) -> list[str]:
    return re.findall(r"\(|\)|[^\s()]+", cond)


def _parse_condition(cond: str):
    if "|" in cond:
        raise _Unsupported("aggregation in condition")
    toks = _tokenize(cond)
    pos = 0

    def peek():
        return toks[pos] if pos < len(toks) else None

    def take():
        nonlocal pos
        pos += 1
        return toks[pos - 1]

    def parse_or():
        node = parse_and()
        while peek() == "or":
            take()
            node = ("or", node, parse_and())
        return node

    def parse_and():
        node = parse_not()
        while peek() == "and":
            take()
            node = ("and", node, parse_not())
        return node

    def parse_not():
        if peek() == "not":
            take()
            return ("not", parse_not())
        return parse_atom()

    def parse_atom():
        tok = peek()
        if tok is None:
            raise _Unsupported("unexpected end of condition")
        if tok == "(":
            take()
            node = parse_or()
            if peek() != ")":
                raise _Unsupported("unbalanced parentheses")
            take()
            return node
        if tok in ("1", "all", "any") and pos + 1 < len(toks) and toks[pos + 1] == "of":
            quant = take()
            take()
            return ("of", "all" if quant == "all" else "any", take())
        if tok in (")", "and", "or", "of"):
            raise _Unsupported(f"unexpected token {tok!r}")
        return ("sel", take())

    tree = parse_or()
    if pos != len(toks):
        raise _Unsupported(f"trailing tokens in condition: {toks[pos:]}")
    return tree


# ----------------------------------------------------------------- matching
def _one(value: str, want: Any, mods: list[str]) -> bool:
    if want is None:
        return value == ""
    w = str(want)
    if "re" in mods:
        try:
            return re.search(w, value) is not None
        except re.error:
            return False
    if "cidr" in mods:
        try:
            return ipaddress.ip_address(value.strip()) in ipaddress.ip_network(w, strict=False)
        except ValueError:
            return False
    v, w = value.lower(), w.lower()
    if "contains" in mods:
        return w in v if "*" not in w and "?" not in w else fnmatch.fnmatchcase(v, f"*{w}*")
    if "startswith" in mods:
        return v.startswith(w)
    if "endswith" in mods:
        return v.endswith(w)
    if "*" in w or "?" in w:
        return fnmatch.fnmatchcase(v, w)
    return v == w


def _field_match(event: dict, key: str, want: Any) -> bool:
    name, *mods = key.split("|")
    if "exists" in mods:
        return (name in event) == bool(want)
    if name not in event:
        return False
    value = str(event[name])
    wants = want if isinstance(want, list) else [want]
    if "all" in mods:
        return all(_one(value, w, mods) for w in wants)
    return any(_one(value, w, mods) for w in wants)


def _keyword_match(event: dict, word: Any) -> bool:
    w = str(word).lower()
    for value in event.values():
        v = str(value).lower()
        if (fnmatch.fnmatchcase(v, f"*{w}*") if ("*" in w or "?" in w) else w in v):
            return True
    return False


def _selection_match(sel: Any, event: dict) -> bool:
    if isinstance(sel, dict):
        return all(_field_match(event, k, v) for k, v in sel.items())
    if isinstance(sel, list):
        if all(isinstance(i, dict) for i in sel):
            return any(_selection_match(i, event) for i in sel)
        return any(_keyword_match(event, i) for i in sel)
    return _keyword_match(event, sel)


def _eval(tree, detection: dict, event: dict) -> bool:
    kind = tree[0]
    if kind == "and":
        return _eval(tree[1], detection, event) and _eval(tree[2], detection, event)
    if kind == "or":
        return _eval(tree[1], detection, event) or _eval(tree[2], detection, event)
    if kind == "not":
        return not _eval(tree[1], detection, event)
    if kind == "sel":
        return _selection_match(detection[tree[1]], event)
    if kind == "of":
        pattern = "*" if tree[2] == "them" else tree[2]
        names = [n for n in detection if fnmatch.fnmatchcase(n, pattern)]
        hits = [_selection_match(detection[n], event) for n in names]
        return bool(hits) and (all(hits) if tree[1] == "all" else any(hits))
    return False


def _check_supported(detection: dict, tree) -> None:
    def names(t):
        if t[0] == "sel":
            yield t[1]
        elif t[0] in ("and", "or"):
            yield from names(t[1]); yield from names(t[2])
        elif t[0] == "not":
            yield from names(t[1])
    for n in names(tree):
        if n not in detection:
            raise _Unsupported(f"condition references unknown selection {n!r}")

    def walk(sel):
        if isinstance(sel, dict):
            for key in sel:
                for mod in key.split("|")[1:]:
                    if mod not in _MODIFIERS:
                        raise _Unsupported(f"modifier |{mod}")
        elif isinstance(sel, list):
            for i in sel:
                walk(i)
    for sel in detection.values():
        walk(sel)


# -------------------------------------------------------------------- engine
class SigmaEngine:
    def __init__(self, rules_dir: str = "rules/sigma"):
        self.rules_dir = rules_dir
        self.rules: list[_Rule] = []
        self.load_errors: list[str] = []
        self.skipped: list[str] = []          # "<file>: <why>"
        self.have_pysigma = _HAVE_PYSIGMA
        self._load()

    def _stream(self, logsource: dict) -> str | None:
        cat = logsource.get("category", "")
        product = logsource.get("product", "")
        service = logsource.get("service", "")
        if cat in ("process_creation", "network_connection"):
            return cat
        if product == "linux" and service in _LINUX_SERVICES:
            return "linux_log"
        if product == "windows" and service in _WIN_SERVICES:
            return "win:" + _WIN_SERVICES[service]
        return None

    def _load(self) -> None:
        if not os.path.isdir(self.rules_dir):
            return
        paths = sorted(set(
            glob.glob(os.path.join(self.rules_dir, "**", "*.yml"), recursive=True) +
            glob.glob(os.path.join(self.rules_dir, "**", "*.yaml"), recursive=True)))
        for path in paths:
            name = os.path.relpath(path, self.rules_dir)
            try:
                text = open(path, encoding="utf-8").read()
                doc = yaml.safe_load(text)
            except Exception as e:
                self.load_errors.append(f"{name}: {e}")
                continue
            if not isinstance(doc, dict) or not isinstance(doc.get("detection"), dict):
                continue
            if _HAVE_PYSIGMA:
                try:
                    _PySigmaRule.from_yaml(text)
                except Exception as e:
                    # pySigma validation is advisory — our own evaluator may
                    # still handle the rule fine, so log but don't skip.
                    self.load_errors.append(f"{name}: pySigma warning: {e}")
            logsource = doc.get("logsource") or {}
            stream = self._stream(logsource)
            if stream is None:
                self.skipped.append(f"{name}: logsource not collected by this agent")
                continue
            detection = {k: v for k, v in doc["detection"].items()
                         if k not in ("condition", "timeframe")}
            cond = doc["detection"].get("condition", "")
            if isinstance(cond, list):
                cond = " or ".join(f"({c})" for c in cond)
            try:
                tree = _parse_condition(str(cond).strip() or "1 of them")
                _check_supported(detection, tree)
            except _Unsupported as e:
                self.skipped.append(f"{name}: {e}")
                continue
            self.rules.append(_Rule(
                title=doc.get("title", name), level=str(doc.get("level") or "medium").lower(),
                stream=stream, product=logsource.get("product", ""),
                detection=detection, condition=tree, id=str(doc.get("id", "")),
                refs=doc.get("references") or []))

    # ---------------------------------------------------------------- match
    def match(self, result: CollectionResult) -> list[Finding]:
        if not self.rules:
            return []
        streams = build_events(result)
        findings: list[Finding] = []
        for rule in self.rules:
            if rule.product and rule.product != result.os_name:
                continue
            hits = [ev for ev in streams.get(rule.stream, [])
                    if _eval(rule.condition, rule.detection, ev)]
            if not hits:
                continue
            first = hits[0]
            evidence = first.get("CommandLine") or first.get("_raw") or str(first)
            findings.append(Finding(
                host=result.host, severity=_SEV.get(rule.level, Severity.MEDIUM),
                title=f"Sigma: {rule.title}",
                detail=f"Sigma-regel traff {len(hits)} hendelse(r) ({rule.stream}).",
                category="detection", source="sigma", evidence=str(evidence)[:300],
                recommendation="Undersøk hendelsen og bekreft om aktiviteten er forventet.",
                refs=list(rule.refs)))
        return findings


# ------------------------------------------------------------ event building
_SS_USERS = re.compile(r'users:\(\("([^"]+)",pid=(\d+)')


def build_events(result: CollectionResult) -> dict[str, list[dict]]:
    """Turn collected facts and logs into Sigma-style events, per stream."""
    evs: dict[str, list[dict]] = {"process_creation": [], "network_connection": [],
                                  "linux_log": []}
    if result.os_name == "linux":
        for line in result.get("processes").splitlines():
            parts = line.split(None, 4)
            if len(parts) < 5 or not parts[0].isdigit():
                continue                                  # header / short line
            pid, ppid, user, comm, args = parts
            first = args.split()[0] if args.split() else comm
            evs["process_creation"].append({
                "ProcessId": pid, "ParentProcessId": ppid, "User": user,
                "Image": first if "/" in first else comm, "CommandLine": args})
        for line in result.get("connections").splitlines():
            cols = line.split()
            if len(cols) < 6 or ":" not in cols[5]:
                continue
            dip, _, dport = cols[5].rpartition(":")
            m = _SS_USERS.search(line)
            evs["network_connection"].append({
                "DestinationIp": dip.strip("[]"), "DestinationPort": dport,
                "Image": m.group(1) if m else "", "_raw": line.strip()})
        for key in ("auth_log", "journal"):
            for line in result.get(key).splitlines():
                if line.strip():
                    evs["linux_log"].append({"_raw": line.strip()})
    else:
        for key, channel in (("events_security", "Security"),
                             ("events_system", "System"),
                             ("events_powershell",
                              "Microsoft-Windows-PowerShell/Operational")):
            records = parse_winevents(result.get(key))
            evs["win:" + channel] = records
            for r in records:
                if r.get("EventID") == "4688":
                    evs["process_creation"].append({
                        "Image": r.get("NewProcessName", ""),
                        "CommandLine": r.get("CommandLine", ""),
                        "ParentImage": r.get("ParentProcessName", ""),
                        "User": r.get("SubjectUserName", ""),
                        "ProcessId": r.get("NewProcessId", "")})
    return evs


def parse_winevents(text: str) -> list[dict]:
    """Parse the XML records written by `Get-WinEvent | % ToXml()`."""
    out: list[dict] = []
    if not text or "<!DOCTYPE" in text or "<!ENTITY" in text:
        return out                    # never expand entities from an endpoint
    for chunk in re.findall(r"<Event[ >].*?</Event>", text, re.S):
        try:
            root = ET.fromstring(chunk)
        except ET.ParseError:
            continue
        rec: dict[str, str] = {}
        for el in root.iter():
            tag = el.tag.rsplit("}", 1)[-1]
            if tag == "EventID":
                rec["EventID"] = (el.text or "").strip()
            elif tag == "Channel":
                rec["Channel"] = (el.text or "").strip()
            elif tag == "Provider":
                rec["Provider_Name"] = el.attrib.get("Name", "")
            elif tag == "Computer":
                rec["Computer"] = (el.text or "").strip()
            elif tag == "Data" and el.attrib.get("Name"):
                rec[el.attrib["Name"]] = (el.text or "").strip()
        if rec:
            out.append(rec)
    return out
