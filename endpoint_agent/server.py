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

    # ── Network scan (find hosts without scope) ─────────────────────
    # Stores discovered-but-not-yet-approved hosts
    discovered = {"hosts": [], "scanning": False, "error": ""}

    @app.get("/api/discovered")
    def discovered_list():
        return jsonify(hosts=discovered["hosts"], scanning=discovered["scanning"],
                       error=discovered["error"])

    @app.post("/api/network-scan")
    def network_scan():
        """Scan the local network for live hosts — no scope required."""
        if discovered["scanning"]:
            return jsonify(ok=False, error="Nettverkssøk kjører allerede"), 409

        discovered["scanning"] = True
        discovered["error"] = ""

        def run():
            try:
                import asyncio
                import subprocess
                import ipaddress as _ipa
                import re as _re

                # Find local subnets from network interfaces
                subnets = set()
                try:
                    out = subprocess.run(["ip", "-4", "addr"], capture_output=True,
                                         text=True, timeout=5).stdout
                    for m in _re.finditer(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", out):
                        net = _ipa.ip_network(m.group(1), strict=False)
                        # Skip loopback and link-local
                        if net.is_loopback or net.is_link_local:
                            continue
                        # Cap at /22 (1024 hosts)
                        if net.prefixlen < 22:
                            net = _ipa.ip_network(f"{net.network_address}/24", strict=False)
                        subnets.add(str(net))
                except Exception:
                    pass

                if not subnets:
                    # Fallback: try common private ranges
                    subnets = {"192.168.1.0/24"}

                # TCP probe each host on management ports
                from ..discovery.discovery import MGMT_PORTS, DiscoveredHost

                async def _probe_all():
                    results = []
                    sem = asyncio.Semaphore(32)

                    async def _one(ip_str):
                        async with sem:
                            host = DiscoveredHost(ip=ip_str, source="tcp")
                            for port in MGMT_PORTS:
                                try:
                                    fut = asyncio.open_connection(ip_str, port)
                                    r, w = await asyncio.wait_for(fut, timeout=1.5)
                                    w.close()
                                    try: await w.wait_closed()
                                    except: pass
                                    host.alive = True
                                    host.open_mgmt_ports.append(port)
                                    host.services[port] = MGMT_PORTS[port]
                                except (asyncio.TimeoutError, OSError):
                                    pass
                            if host.alive:
                                # Guess OS from ports
                                if 5985 in host.open_mgmt_ports or 5986 in host.open_mgmt_ports or 3389 in host.open_mgmt_ports:
                                    host.os_guess = "windows"
                                elif 22 in host.open_mgmt_ports:
                                    host.os_guess = "linux"
                                # Check if already in scope
                                results.append(host)

                    all_ips = []
                    for sn in subnets:
                        net = _ipa.ip_network(sn, strict=False)
                        if net.num_addresses == 1:
                            all_ips.append(str(net.network_address))
                        else:
                            all_ips.extend(str(h) for h in net.hosts())

                    # Also try ARP/ping scan via nmap if available
                    try:
                        for sn in subnets:
                            nmap_res = subprocess.run(
                                ["nmap", "-sn", "-n", str(sn)],
                                capture_output=True, text=True, timeout=60)
                            for m in _re.finditer(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)", nmap_res.stdout):
                                ip = m.group(1)
                                if ip not in all_ips:
                                    all_ips.append(ip)
                    except Exception:
                        pass

                    await asyncio.gather(*(_one(ip) for ip in all_ips[:1024]))
                    return results

                loop = asyncio.new_event_loop()
                hosts = loop.run_until_complete(_probe_all())
                loop.close()

                # Mark which are already in scope
                scope_ids = {e.identifier for e in agent.scope.all()}
                host_dicts = []
                for h in sorted(hosts, key=lambda x: x.ip):
                    d = h.dict()
                    d["in_scope"] = h.ip in scope_ids
                    host_dicts.append(d)

                discovered["hosts"] = host_dicts

            except Exception as e:
                discovered["error"] = str(e)
            finally:
                discovered["scanning"] = False

        threading.Thread(target=run, daemon=True, name="network-scan").start()
        return jsonify(ok=True, subnets=list(subnets) if 'subnets' in dir() else [])

    # ── Approve + assess a discovered host ────────────────────────────
    @app.post("/api/approve-and-scan")
    def approve_and_scan():
        body = request.json or {}
        host = body.get("host", "").strip()
        os_name = body.get("os", "linux")
        if not host:
            return jsonify(ok=False, error="host required"), 400

        # Add to scope
        try:
            agent.add_scope(host, "godkjent via dashboard", os_name, confirmed=True)
        except Exception:
            pass  # Already in scope is fine

        # Mark as in_scope in discovered list
        for h in discovered["hosts"]:
            if h["ip"] == host:
                h["in_scope"] = True

        # Start assessment
        agent.kill.check()
        agent.rbac.check(agent.role, "collect.read")
        with job_lock:
            if job["running"]:
                return jsonify(ok=False, error="En jobb kjører allerede — vent til den er ferdig"), 409
            job.update(running=True, error="", type="assess",
                       started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

        def run():
            try:
                agent.assess_host(host, os_name, with_ai=True)
            except Exception as e:
                job["error"] = str(e)
            finally:
                job["running"] = False

        threading.Thread(target=run, daemon=True).start()
        return jsonify(ok=True)

    # ── Discover (scope-based, kept for compatibility) ────────────────
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
