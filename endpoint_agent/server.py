"""Local web dashboard for Agent 2 (same look as Agent 1's, on its own port).

    endpoint-agent dashboard            ->  http://127.0.0.1:8778

It shows the last sweep, pending approvals, the scope and the audit trail, and
offers the same actions as the CLI: start a sweep, stop everything, approve or
deny access requests, accept a baseline, pull devices from Agent 1.

The server only listens on localhost by default. Every /api call must carry the
per-process token that is embedded in the page, and the Host header must be the
address the server was started on; together these stop other websites open in
the browser from driving the agent. Every action still goes through the agent's
own scope and RBAC checks, with the role the dashboard was started as.
"""
from __future__ import annotations

import hmac
import os
import secrets
import threading
import time

try:
    from flask import Flask, jsonify, request, abort, Response
    _HAVE_FLASK = True
except Exception:  # pragma: no cover
    _HAVE_FLASK = False

from .core.rbac import AccessDenied
from .core.scope import ScopeError
from .core.killswitch import KillSwitchEngaged
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
    job = {"running": False, "error": "", "started_at": None}
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

    @app.get("/api/approvals")
    def approvals():
        return jsonify([r.dict() for r in agent.approvals.all()][-50:])

    @app.post("/api/approvals/<req_id>")
    def decide(req_id):
        approve = bool((request.json or {}).get("approve"))
        return jsonify(ok=True, request=agent.decide_request(req_id, approve).dict())

    @app.post("/api/sweep")
    def sweep():
        body = request.json or {}
        agent.kill.check()
        agent.rbac.check(agent.role, "collect.read")
        with job_lock:
            if job["running"]:
                return jsonify(ok=False, error="a sweep is already running"), 409
            job.update(running=True, error="",
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

    @app.post("/api/kill")
    def kill():
        agent.engage_kill((request.json or {}).get("reason") or "dashboard")
        return jsonify(ok=True)

    @app.post("/api/reset-kill")
    def reset_kill():
        agent.reset_kill()
        return jsonify(ok=True)

    @app.post("/api/baseline/accept")
    def baseline_accept():
        host = (request.json or {}).get("host", "")
        return jsonify(ok=True, state_from=agent.accept_baseline(host))

    @app.post("/api/bridge/sync")
    def bridge_sync():
        try:
            summary = Agent1Bridge(agent, FileBus(agent.cfg.bus_dir)).sync()
        except OSError as e:
            return jsonify(ok=False, error=f"Agent 1 is not reachable: {e}"), 502
        return jsonify(ok=True, summary=summary)

    return app


def run_dashboard(agent: EndpointIntelligenceAgent, host: str | None = None,
                  port: int | None = None) -> None:
    host = host or agent.cfg.dashboard.host
    port = port or agent.cfg.dashboard.port
    allowed = {f"{host}:{port}"}
    if host in ("127.0.0.1", "localhost"):
        allowed |= {f"127.0.0.1:{port}", f"localhost:{port}"}
    else:
        print(f"WARNING: the dashboard is listening on {host}, not just this machine. "
              "Anyone who can reach it and load the page can drive the agent.")
    app = create_app(agent, allowed_hosts=allowed)
    print(f"Agent 2 dashboard: http://{host}:{port}  (role: {agent.role})")
    app.run(host=host, port=port, threaded=True)
