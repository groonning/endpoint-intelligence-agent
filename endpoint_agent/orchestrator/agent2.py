"""EndpointIntelligenceAgent — the Agent 2 façade.

Wires the core safety layer and the modules into one object with a small,
stable API that the CLI, the dashboard and the Security Orchestrator all call:

    agent.discover()                      -> list[DiscoveredHost]
    agent.collect(host, os_name, cred_id) -> CollectionResult
    agent.analyze(result)                 -> list[Finding]
    agent.assess_host(...)                -> HostReport (collect + analyze + baseline + AI)
    agent.run_sweep(...)                  -> session dict (+ written report)
    agent.handle_task(Task)               -> TaskResult   (orchestrator entry)
    agent.add_scope / request_scope_add / decide_request   (access changes)
    agent.engage_kill(reason)

Every path re-checks scope + RBAC + rate limit + kill switch through the core
primitives; this façade only composes them.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from ..core.config import AgentConfig, load_config
from ..core.scope import Scope, Endpoint
from ..core.rbac import RBAC
from ..core.audit import AuditLog
from ..core.ratelimit import RateLimiter
from ..core.killswitch import KillSwitch
from ..core.credentials import CredentialVault
from ..core.hostkeys import HostKeyStore
from ..core.approvals import ApprovalQueue, ApprovalRequest

from ..discovery.discovery import EndpointDiscovery, DiscoveredHost
from ..collector.base import CollectionResult, CollectionError
from ..collector.files import FilePolicy
from ..collector.local_collector import LocalCollector
from ..analyzer.analyzer import SecurityAnalyzer, Finding
from ..analyzer.sigma_engine import SigmaEngine
from ..analyzer.yara_engine import YaraEngine
from ..analyzer.baseline import BaselineStore, snapshot
from ..analyzer.vuln import OSVClient, vuln_findings
from ..analyzer.lynis import lynis_findings
from ..ai.engine import AIAnalysisEngine
from ..ai.router import ModelRouter
from ..ai.ollama_backend import OllamaBackend
from ..ai.claude_backend import ClaudeBackend
from ..reporting.report import ReportBuilder

from .bus import Task, TaskResult, OrchestratorBus

_LOCALHOST = ("127.0.0.1", "localhost", "::1")


@dataclass
class HostReport:
    host: str
    os_name: str
    method: str
    collected_at: str
    findings: list[Finding] = field(default_factory=list)
    ai: dict | None = None
    files: list[dict] = field(default_factory=list)
    error: str = ""

    def dict(self) -> dict:
        return {"host": self.host, "os_name": self.os_name, "method": self.method,
                "collected_at": self.collected_at,
                "findings": [f.dict() for f in self.findings],
                "files": self.files, "ai": self.ai, "error": self.error}


class EndpointIntelligenceAgent:
    agent = "agent2"

    def __init__(self, config: AgentConfig | None = None, role: str | None = None,
                 vault: CredentialVault | None = None,
                 collector_factory=None, enable_ai: bool = True, osv_post=None):
        self.cfg = cfg = config or load_config()
        self.scope = Scope.load(cfg.scope_path)
        self.rbac = RBAC.load(cfg.roles_path)
        self.audit = AuditLog(cfg.audit_path)
        self.kill = KillSwitch(cfg.killswitch_path)
        self.rate = RateLimiter(cfg.limits.rate_per_sec, cfg.limits.burst)
        self.role = role or cfg.default_role
        self.rbac.role(self.role)                       # fail early on a bad role
        self.vault = vault
        self.hostkeys = HostKeyStore(cfg.known_hosts_path, cfg.ssh_strict_host_keys)
        self.approvals = ApprovalQueue(cfg.approvals_path)
        self.baselines = BaselineStore(cfg.state_dir)
        self.file_policy = (FilePolicy(cfg.files.linux_paths, cfg.files.windows_paths,
                                       cfg.files.max_file_bytes, cfg.files.max_files,
                                       cfg.files.max_depth)
                            if cfg.files.enabled else None)
        # collector_factory(os_name, host) -> EndpointCollector
        self._collector_factory = collector_factory or self._default_collector

        self.discovery = EndpointDiscovery(
            self.scope, self.rate, self.kill, self.audit, actor=self.agent)

        sources = [lynis_findings]
        if cfg.vuln.enabled:
            osv = OSVClient(cfg.vuln.osv_url, Path(cfg.state_dir) / "osv_cache.json",
                            cfg.vuln.cache_ttl_hours, post=osv_post)
            sources.append(lambda r: vuln_findings(
                r, osv, cfg.vuln.kali_as_debian, cfg.vuln.max_findings,
                self.audit, self.agent))
        self.analyzer = SecurityAnalyzer(
            sigma=SigmaEngine(cfg.sigma_rules_dir),
            yara=YaraEngine(cfg.yara_rules_dir), extra_sources=sources)
        self.reporter = ReportBuilder(cfg.reports_dir)

        self.ai: AIAnalysisEngine | None = None
        if enable_ai:
            ollama = OllamaBackend(cfg.ai.ollama_url, cfg.ai.ollama_model)
            claude = ClaudeBackend(cfg.ai.anthropic_model_complex)
            ext_ok = cfg.ai.allow_external and claude.available()[0]
            router = ModelRouter(
                cfg.ai.ollama_model, cfg.ai.anthropic_model_complex,
                cfg.ai.anthropic_model_critical,
                allow_external=cfg.ai.allow_external, external_available=ext_ok,
                max_external_tokens=cfg.ai.max_external_tokens_per_run)
            self.ai = AIAnalysisEngine(
                router, ollama, claude, audit=self.audit, actor=self.agent,
                redact_external=cfg.ai.redact_before_external,
                rbac=self.rbac, role=self.role,
                max_external_tokens_per_run=cfg.ai.max_external_tokens_per_run)

    # --------------------------------------------------- default collector
    def _collector_kwargs(self) -> dict:
        return dict(rbac=self.rbac, audit=self.audit, rate=self.rate, kill=self.kill,
                    actor=self.agent, role=self.role,
                    command_timeout=self.cfg.limits.command_timeout_s,
                    include_logs=self.cfg.logs.enabled,
                    extras=["lynis"] if self.cfg.lynis.enabled else [],
                    file_policy=self.file_policy)

    def _default_collector(self, os_name: str, host: str):
        kw = self._collector_kwargs()
        if host in _LOCALHOST:
            return LocalCollector(self.scope, **kw)
        if os_name == "windows":
            from ..collector.winrm_collector import WinRMCollector
            return WinRMCollector(self.scope, **kw)
        from ..collector.ssh_collector import SSHCollector
        return SSHCollector(self.scope, hostkeys=self.hostkeys, **kw)

    def credential_for(self, host: str) -> str | None:
        """Credential id mapped to this host in config.credentials_map."""
        cmap = self.cfg.credentials_map or {}
        if host in cmap:
            return cmap[host]
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return None
        for ident, cred in cmap.items():
            try:
                if ip in ipaddress.ip_network(ident, strict=False):
                    return cred
            except ValueError:
                continue
        return None

    # ------------------------------------------------------------- actions
    def discover(self, use_nmap: bool | None = None) -> list[DiscoveredHost]:
        self.rbac.check(self.role, "discovery.sweep")
        return asyncio.run(self.discovery.sweep(
            concurrency=self.cfg.limits.max_concurrency, use_nmap=use_nmap))

    def collect(self, host: str, os_name: str, cred_id: str | None = None,
                only: list[str] | None = None, **connect_kw) -> CollectionResult:
        self.scope.require(host)                 # before touching the vault
        collector = self._collector_factory(os_name, host)
        cred_id = cred_id or self.credential_for(host)
        if cred_id and "credential" not in connect_kw:
            if self.vault is None:
                raise CollectionError(
                    f"credential {cred_id!r} is needed for {host} but the vault is "
                    "not open (use --vault-pass or AGENT2_VAULT_KEY)")
            connect_kw["credential"] = self.vault.get(cred_id)
            self.audit.record(self.agent, "credential.use", host, "ok",
                              {"cred_id": cred_id})
        return collector.collect(host, os_name, only=only, **connect_kw)

    def analyze(self, result: CollectionResult) -> list[Finding]:
        self.rbac.check(self.role, "analyze.run")
        return self.analyzer.analyze(result)

    def assess_host(self, host: str, os_name: str, cred_id: str | None = None,
                    with_ai: bool = True, **connect_kw) -> HostReport:
        result = self.collect(host, os_name, cred_id=cred_id, **connect_kw)
        findings = self.analyze(result)
        findings += self.baselines.evaluate(host, snapshot(result))
        findings.sort(key=lambda f: (-int(f.severity), f.category))
        ai = None
        notable = [f for f in findings if int(f.severity) > 0]
        if with_ai and self.ai is not None and notable:
            ai = self.ai.summarize_findings(host, notable).dict()
        return HostReport(host=host, os_name=os_name, method=result.transport,
                          collected_at=result.finished_at or result.started_at,
                          findings=findings, ai=ai,
                          files=[f.dict() for f in result.files])

    def run_sweep(self, hosts: list[tuple[str, str, str | None]] | None = None,
                  with_ai: bool = True, write_report: bool = True) -> dict:
        """Assess several hosts in parallel and write one report.

        hosts: list of (host, os_name, cred_id). Without it, every localhost
        entry in scope is self-audited, plus every single-host scope entry that
        has an os_hint and a credential in config.credentials_map."""
        self.kill.check()
        if hosts is None:
            hosts = []
            for e in self.scope.all():
                if e.identifier in _LOCALHOST:
                    hosts.append((e.identifier, e.os_hint or "linux", None))
                elif "/" not in e.identifier:
                    cred = self.credential_for(e.identifier)
                    if cred and e.os_hint:
                        hosts.append((e.identifier, e.os_hint, cred))
        if not hosts:
            raise ValueError(
                "no hosts to sweep: add 127.0.0.1 to the scope for a self-audit, "
                "or pass hosts explicitly as (host, os, cred_id)")
        if self.ai is not None:
            self.ai.reset_budget()

        def one(spec) -> HostReport:
            host, os_name, cred_id = spec
            try:
                self.kill.check()
                return self.assess_host(host, os_name, cred_id=cred_id, with_ai=with_ai)
            except Exception as e:
                self.audit.record(self.agent, "sweep.host", host, "error",
                                  {"error": str(e)[:200]})
                return HostReport(host=host, os_name=os_name, method="error",
                                  collected_at=_iso(), error=str(e))

        workers = max(1, min(self.cfg.limits.max_concurrency, len(hosts)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            reports = list(pool.map(one, [tuple(h) for h in hosts]))
        self.kill.check()            # a sweep stopped midway is not reported as done

        per_host = {r.host: [f for f in r.findings if int(f.severity) > 0]
                    for r in reports}
        correlation = None
        if with_ai and self.ai is not None and sum(1 for v in per_host.values() if v) > 1:
            correlation = self.ai.correlate(per_host).dict()

        ok, _ = self.audit.verify()
        session = {
            "generated_at": _iso(),
            "scope": self.scope.networks(),
            "hosts": [r.dict() for r in reports],
            "ai_correlation": correlation,
            "audit_verified": ok,
            "agent": self.agent, "role": self.role,
            "external_tokens_used": self.ai.external_tokens_used if self.ai else 0,
        }
        if write_report:
            rep = self.reporter.build(session)
            session["report"] = {"json": rep.json_path, "html": rep.html_path,
                                 "pdf": rep.pdf_path,
                                 "pdf_skipped": rep.pdf_skipped_reason}
        self._save_last(session)
        return session

    def _save_last(self, session: dict) -> None:
        p = Path(self.cfg.state_dir) / "last_session.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(session, ensure_ascii=False))
        os.replace(tmp, p)

    def last_session(self) -> dict | None:
        p = Path(self.cfg.state_dir) / "last_session.json"
        return json.loads(p.read_text()) if p.exists() else None

    # ------------------------------------------------- access changes
    def add_scope(self, identifier: str, note: str, os_hint: str = "",
                  confirmed: bool = False) -> Endpoint:
        """Authorise a new endpoint. Needs scope.modify AND an explicit human
        confirmation; automated callers must use request_scope_add()."""
        self.rbac.check(self.role, "scope.modify")
        if not confirmed:
            raise PermissionError(
                "adding to the scope needs explicit confirmation that you are "
                "authorised to test this target")
        ep = self.scope.add(identifier, note, os_hint)
        self.audit.record(self.role, "scope.add", identifier, "ok", {"note": note})
        return ep

    def remove_scope(self, identifier: str) -> None:
        self.rbac.check(self.role, "scope.modify")
        self.scope.remove(identifier)
        self.audit.record(self.role, "scope.remove", identifier, "ok")

    def request_scope_add(self, identifier: str, requested_by: str,
                          reason: str = "", os_hint: str = "") -> ApprovalRequest:
        Endpoint(identifier)                              # validate the identifier
        req = self.approvals.request("scope.add", identifier, requested_by, reason,
                                     {"os_hint": os_hint})
        self.audit.record(requested_by, "approval.request", identifier, "ok",
                          {"id": req.id, "action": "scope.add"})
        return req

    def decide_request(self, req_id: str, approve: bool) -> ApprovalRequest:
        self.rbac.check(self.role, "approval.grant")
        req = self.approvals.decide(req_id, approve, self.role)
        if approve and req.action == "scope.add":
            self.scope.add(req.target,
                           f"approved request {req.id} from {req.requested_by}: {req.reason}",
                           req.params.get("os_hint", ""))
        self.audit.record(self.role, "approval." + req.status, req.target, "ok",
                          {"id": req.id, "action": req.action})
        return req

    def accept_baseline(self, host: str) -> str:
        self.rbac.check(self.role, "baseline.accept")
        at = self.baselines.accept(host)
        self.audit.record(self.role, "baseline.accept", host, "ok", {"state_from": at})
        return at

    # ----------------------------------------------------- kill switch
    def engage_kill(self, reason: str = "manual") -> None:
        self.rbac.check(self.role, "killswitch.engage")
        self.kill.engage(reason)
        self.audit.record(self.role, "killswitch.engage", "self", "ok",
                          {"reason": reason})

    def reset_kill(self) -> None:
        self.rbac.check(self.role, "killswitch.reset")
        self.kill.reset()
        self.audit.record(self.role, "killswitch.reset", "self", "ok")

    def status(self) -> dict:
        ok, msg = self.audit.verify()
        return {"agent": self.agent, "role": self.role,
                "kill": self.kill.status(),
                "scope": [{"identifier": e.identifier, "note": e.note,
                           "os_hint": e.os_hint} for e in self.scope.all()],
                "audit": {"ok": ok, "detail": msg},
                "pending_approvals": len(self.approvals.pending()),
                "ai": {"enabled": self.ai is not None,
                       "external_allowed": self.cfg.ai.allow_external,
                       "model": self.cfg.ai.ollama_model},
                "features": {"files": self.file_policy is not None,
                             "logs": self.cfg.logs.enabled,
                             "vuln": self.cfg.vuln.enabled,
                             "lynis": self.cfg.lynis.enabled,
                             "sigma_rules": len(self.analyzer.sigma.rules),
                             "sigma_skipped": len(self.analyzer.sigma.skipped),
                             "yara": self.analyzer.yara.available,
                             "strict_host_keys": self.cfg.ssh_strict_host_keys}}

    # -------------------------------------------- orchestrator entrypoint
    def handle_task(self, task: Task) -> TaskResult:
        """Execute an Orchestrator Task and return a TaskResult. Scope and RBAC
        are enforced inside each action, so a task cannot exceed the agent's
        authority; a task that wants more scope can only file a request."""
        p = task.params
        try:
            if task.kind == "discover":
                hosts = self.discover(use_nmap=p.get("use_nmap"))
                data = {"hosts": [h.dict() for h in hosts]}
            elif task.kind == "collect":
                res = self.collect(p["host"], p["os_name"], cred_id=p.get("cred_id"),
                                   only=p.get("only"))
                data = {"result": res.dict()}
            elif task.kind == "assess":
                hr = self.assess_host(p["host"], p["os_name"], cred_id=p.get("cred_id"),
                                      with_ai=p.get("with_ai", True))
                data = {"host_report": hr.dict()}
            elif task.kind == "full_sweep":
                data = self.run_sweep(hosts=p.get("hosts"),
                                      with_ai=p.get("with_ai", True))
            elif task.kind == "scope_request":
                req = self.request_scope_add(p["identifier"], task.origin,
                                             p.get("reason", ""), p.get("os_hint", ""))
                data = {"approval": req.dict()}
            elif task.kind == "status":
                data = self.status()
            else:
                return TaskResult(task.id, self.agent, False, task.kind,
                                  error=f"unknown task kind {task.kind!r}")
            return TaskResult(task.id, self.agent, True, task.kind, data=data)
        except Exception as e:
            self.audit.record(self.agent, f"task.{task.kind}",
                              str(p.get("host", "")), "error", {"error": str(e)[:200]})
            return TaskResult(task.id, self.agent, False, task.kind, error=str(e))

    def work(self, bus: OrchestratorBus, once: bool = False,
             interval: float = 2.0) -> int:
        """Worker loop: take tasks off the bus, run them, publish the results.
        Stops when the kill switch is engaged. Returns the number handled."""
        handled = 0
        while True:
            if self.kill.engaged:
                return handled
            for task in bus.poll():
                bus.publish(self.handle_task(task))
                handled += 1
            if once:
                return handled
            time.sleep(interval)


def _iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
