"""Local web dashboard for Agent 2 — full control panel.

    endpoint-agent              ->  starts dashboard + opens browser
    endpoint-agent dashboard    ->  http://127.0.0.1:8778

Everything is controlled from the dashboard: scope, vault, sweep, assess,
approvals, baselines, kill switch, bridge sync. The CLI remains available
but is not required for normal operation.
"""
from __future__ import annotations

import hmac
import os
import secrets
import threading
import time
import webbrowser

try:
    from flask import Flask, jsonify, request, abort, Response
    _HAVE_FLASK = True
except Exception:  # pragma: no cover
    _HAVE_FLASK = False

from .core.rbac import AccessDenied
from .core.scope import ScopeError
from .core.killswitch import KillSwitchEngaged
from .core.credentials import CredentialVault, Credential, VaultError
from .orchestrator.agent2 import EndpointIntelligenceAgent
from .orchestrator.agent1_bridge import Agent1Bridge
from .orchestrator.bus import FileBus

HERE = os.path.dirname(__file__)


def create_app(agent: EndpointIntelligenceAgent, allowed_hosts: set[str] | None = None,
               token: str | None = None):
    if not _HAVE_FLASK:
        raise RuntimeError("Flask is required for the dashboard (pip install flask)")
    app = Flask(__name__)
    token = token or secrets.token_urlsafe(24)
    app.config["AGENT2_TOKEN"] = token
    job = {"running": False, "error": "", "started_at": None, "type": ""}
    job_lock = threading.Lock()

    @app.before_request
    def _guard():
        if allowed_hosts and request.host not in allowed_hosts:
            abort(403)
        if request.path.startswith("/api/"):
            sent = request.headers.get("X-Agent2-Token", "")
            if not hmac.compare_digest(sent, token):
                abort(403)

    @app.errorhandler(AccessDenied)
    @app.errorhandler(ScopeError)
    @app.errorhandler(PermissionError)
    def _denied(e):
        return jsonify(ok=False, error=str(e)), 403

    @app.errorhandler(KillSwitchEngaged)
    def _killed(e):
        return jsonify(ok=False, error=f"kill switch engaged: {e}"), 409

    @app.errorhandler(ValueError)
    @app.errorhandler(VaultError)
    def _bad(e):
        return jsonify(ok=False, error=str(e)), 400

    @app.get("/")
    def index():
        page = open(os.path.join(HERE, "static", "dashboard.html"), encoding="utf-8").read()
        resp = Response(page.replace("__AGENT2_TOKEN__", token), mimetype="text/html")
        resp.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
            "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        resp.headers["Cache-Control"] = "no-store"
        return resp

    # ── Status & session ──────────────────────────────────────────────
    @app.get("/api/status")
    def status():
        s = agent.status()
        s["sweep"] = dict(job)
        return jsonify(s)

    @app.get("/api/session")
    def session():
        return jsonify(agent.last_session() or {})

    @app.get("/api/audit")
    def audit():
        n = min(int(request.args.get("n", 40)), 500)
        return jsonify(agent.audit.tail(n))

    # ── Scope management ──────────────────────────────────────────────
    @app.get("/api/scope")
    def scope_list():
        return jsonify([e.__dict__ for e in agent.scope.all()])

    @app.post("/api/scope/add")
    def scope_add():
        body = request.json or {}
        ident = body.get("identifier", "").strip()
        if not ident:
            return jsonify(ok=False, error="identifier required"), 400
        note = body.get("note", "added via dashboard")
        os_hint = body.get("os_hint", "")
        agent.add_scope(ident, note, os_hint, confirmed=True)
        return jsonify(ok=True)

    @app.post("/api/scope/remove")
    def scope_remove():
        body = request.json or {}
        ident = body.get("identifier", "").strip()
        if not ident:
            return jsonify(ok=False, error="identifier required"), 400
        agent.remove_scope(ident)
        return jsonify(ok=True)

    # ── Approvals ─────────────────────────────────────────────────────
    @app.get("/api/approvals")
    def approvals():
        return jsonify([r.dict() for r in agent.approvals.all()][-50:])

    @app.post("/api/approvals/<req_id>")
    def decide(req_id):
        approve = bool((request.json or {}).get("approve"))
        return jsonify(ok=True, request=agent.decide_request(req_id, approve).dict())

    # ── Vault management ──────────────────────────────────────────────
    @app.get("/api/vault")
    def vault_list():
        if not agent.vault:
            return jsonify(ids=[], available=False)
        return jsonify(ids=agent.vault.ids(), available=True)

    @app.post("/api/vault/add")
    def vault_add():
        if not agent.vault:
            return jsonify(ok=False, error="Vault not configured — set AGENT2_VAULT_KEY"), 400
        body = request.json or {}
        cred_id = body.get("id", "").strip()
        kind = body.get("kind", "ssh_password")
        username = body.get("username", "")
        secret = body.get("secret", "")
        if not cred_id or not secret:
            return jsonify(ok=False, error="id and secret required"), 400
        agent.vault.put(Credential(id=cred_id, kind=kind, username=username, secret=secret))
        return jsonify(ok=True)

    @app.post("/api/vault/remove")
    def vault_remove():
        if not agent.vault:
            return jsonify(ok=False, error="Vault not configured"), 400
        body = request.json or {}
        cred_id = body.get("id", "").strip()
        if not cred_id:
            return jsonify(ok=False, error="id required"), 400
        agent.vault.delete(cred_id)
        return jsonify(ok=True)

    # ── Host keys ─────────────────────────────────────────────────────
    @app.get("/api/hostkeys")
    def hostkeys_list():
        return jsonify(agent.hostkeys.all())

    @app.post("/api/hostkeys/forget")
    def hostkeys_forget():
        body = request.json or {}
        host = body.get("host", "").strip()
        port = int(body.get("port", 22))
        if not host:
            return jsonify(ok=False, error="host required"), 400
        agent.rbac.check(agent.role, "hostkeys.modify")
        gone = agent.hostkeys.forget(host, port)
        agent.audit.record(agent.role, "hostkey.forget", host, "ok", {"port": port, "existed": gone})
        return jsonify(ok=True, existed=gone)

    # ── Discover ──────────────────────────────────────────────────────
    @app.post("/api/discover")
    def discover():
        agent.kill.check()
        agent.rbac.check(agent.role, "scan.active")
        with job_lock:
            if job["running"]:
                return jsonify(ok=False, error="a job is already running"), 409
            job.update(running=True, error="", type="discover",
                       started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        results = []

        def run():
            try:
                import asyncio
                loop = asyncio.new_event_loop()
                res = loop.run_until_complete(agent.discover())
                results.extend([h.dict() for h in res])
            except Exception as e:
                job["error"] = str(e)
            finally:
                job["running"] = False

        t = threading.Thread(target=run, daemon=True)
        t.start()
        t.join(timeout=120)
        return jsonify(ok=True, hosts=results)

    # ── Assess single host ────────────────────────────────────────────
    @app.post("/api/assess")
    def assess():
        body = request.json or {}
        host = body.get("host", "").strip()
        os_name = body.get("os", "linux")
        cred_id = body.get("cred_id")
        with_ai = body.get("with_ai", True)
        if not host:
            return jsonify(ok=False, error="host required"), 400
        agent.kill.check()
        agent.rbac.check(agent.role, "collect.read")
        with job_lock:
            if job["running"]:
                return jsonify(ok=False, error="a job is already running"), 409
            job.update(running=True, error="", type="assess",
                       started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

        def run():
            try:
                agent.assess_host(host, os_name, cred_id=cred_id, with_ai=bool(with_ai))
            except Exception as e:
                job["error"] = str(e)
            finally:
                job["running"] = False

        threading.Thread(target=run, daemon=True).start()
        return jsonify(ok=True)

    # ── Sweep ─────────────────────────────────────────────────────────
    @app.post("/api/sweep")
    def sweep():
        body = request.json or {}
        agent.kill.check()
        agent.rbac.check(agent.role, "collect.read")
        with job_lock:
            if job["running"]:
                return jsonify(ok=False, error="a job is already running"), 409
            job.update(running=True, error="", type="sweep",
                       started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

        def run():
            try:
                agent.run_sweep(with_ai=bool(body.get("with_ai", True)))
            except Exception as e:
                job["error"] = str(e)
            finally:
                job["running"] = False

        threading.Thread(target=run, daemon=True).start()
        return jsonify(ok=True)

    # ── Kill switch ───────────────────────────────────────────────────
    @app.post("/api/kill")
    def kill():
        agent.engage_kill((request.json or {}).get("reason") or "dashboard")
        return jsonify(ok=True)

    @app.post("/api/reset-kill")
    def reset_kill():
        agent.reset_kill()
        return jsonify(ok=True)

    # ── Baseline ──────────────────────────────────────────────────────
    @app.get("/api/baselines")
    def baselines():
        return jsonify(agent.baselines.hosts())

    @app.post("/api/baseline/accept")
    def baseline_accept():
        host = (request.json or {}).get("host", "")
        return jsonify(ok=True, state_from=agent.accept_baseline(host))

    # ── Agent 1 bridge ────────────────────────────────────────────────
    @app.post("/api/bridge/sync")
    def bridge_sync():
        try:
            summary = Agent1Bridge(agent, FileBus(agent.cfg.bus_dir)).sync()
        except OSError as e:
            return jsonify(ok=False, error=f"Agent 1 is not reachable: {e}"), 502
        return jsonify(ok=True, summary=summary)

    return app


def run_dashboard(agent: EndpointIntelligenceAgent, host: str | None = None,
                  port: int | None = None, open_browser: bool = True) -> None:
    host = host or agent.cfg.dashboard.host
    port = port or agent.cfg.dashboard.port
    allowed = {f"{host}:{port}"}
    if host in ("127.0.0.1", "localhost"):
        allowed |= {f"127.0.0.1:{port}", f"localhost:{port}"}
    else:
        print(f"WARNING: the dashboard is listening on {host}, not just this machine. "
              "Anyone who can reach it and load the page can drive the agent.")
    app = create_app(agent, allowed_hosts=allowed)
    url = f"http://{host}:{port}"
    print(f"Agent 2 dashboard: {url}  (role: {agent.role})")
    if open_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    app.run(host=host, port=port, threaded=True)
