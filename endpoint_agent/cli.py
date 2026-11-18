"""Command-line interface for Agent 2.

    endpoint-agent scope list | add <id> | remove <id> | request <id>
    endpoint-agent approvals list | approve <id> | deny <id>
    endpoint-agent discover
    endpoint-agent self-audit
    endpoint-agent assess <host> --os linux|windows [--cred ID]
    endpoint-agent sweep [--host HOST:OS[:CRED] ...]
    endpoint-agent baseline list | accept <host>
    endpoint-agent hostkeys list | forget <host> [--port N]
    endpoint-agent vault list | add <id> | remove <id> | init-key
    endpoint-agent audit verify | tail
    endpoint-agent status
    endpoint-agent worker [--once]          # serve tasks from the orchestrator bus
    endpoint-agent bridge                   # pull devices from Agent 1, queue work
    endpoint-agent dashboard                # local web dashboard
    endpoint-agent kill [reason] | reset-kill

(`python3 -m endpoint_agent.cli ...` works the same.)
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys

from .core.config import load_config
from .core.credentials import CredentialVault, Credential, VaultError
from .core.hostkeys import HostKeyError
from .orchestrator.agent2 import EndpointIntelligenceAgent


def _open_vault(cfg, args, create: bool = False) -> CredentialVault | None:
    """Open the vault if a key is available: AGENT2_VAULT_KEY, or a passphrase
    when --vault-pass is given (or when `create` forces a prompt)."""
    if os.environ.get("AGENT2_VAULT_KEY") and not args.vault_pass:
        return CredentialVault(cfg.vault_path)
    if args.vault_pass or create:
        return CredentialVault(cfg.vault_path,
                               passphrase=getpass.getpass("vault passphrase: "))
    return None


def _agent(args) -> EndpointIntelligenceAgent:
    cfg = load_config(args.config)
    return EndpointIntelligenceAgent(cfg, role=args.role, vault=_open_vault(cfg, args),
                                     enable_ai=not args.no_ai)


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False))


def main(argv=None) -> int:
    """Entry point: run the command and turn expected failures into a clean
    one-line error (exit code 2) instead of a traceback."""
    from .core.scope import ScopeError
    from .core.rbac import AccessDenied
    from .core.killswitch import KillSwitchEngaged
    from .core.ratelimit import RateLimitExceeded
    from .collector.base import CollectionError
    from .collector.files import FilePolicyError
    try:
        return _main(argv)
    except KillSwitchEngaged as e:
        print(f"stopped: kill switch engaged ({e}). Re-arm with: reset-kill",
              file=sys.stderr)
    except (ScopeError, AccessDenied, RateLimitExceeded, CollectionError, VaultError,
            HostKeyError, FilePolicyError, PermissionError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
    return 2


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser("endpoint-agent",
                                description="Endpoint Intelligence Agent (Agent 2)")
    p.add_argument("--config", default="config/agent2.yaml")
    p.add_argument("--role", default=None, help="role to act as (default: config default_role)")
    p.add_argument("--no-ai", action="store_true", help="disable the AI layer")
    p.add_argument("--vault-pass", action="store_true",
                   help="open the credential vault with a passphrase prompt")
    p.add_argument("--vault-env", action="store_true", help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="cmd")

    sp = sub.add_parser("scope", help="manage authorised endpoints")
    sp.add_argument("action", choices=["list", "add", "remove", "request"])
    sp.add_argument("identifier", nargs="?")
    sp.add_argument("--note", default="")
    sp.add_argument("--os", dest="os_hint", default="", choices=["", "linux", "windows"])
    sp.add_argument("--yes", action="store_true",
                    help="confirm on the command line that you are authorised")

    ap = sub.add_parser("approvals", help="requests that would widen the agent's access")
    ap.add_argument("action", choices=["list", "approve", "deny"])
    ap.add_argument("req_id", nargs="?")

    sub.add_parser("discover", help="sweep authorised ranges for live hosts")
    sub.add_parser("self-audit", help="collect + analyze localhost")
    sub.add_parser("status", help="show agent state and enabled features")

    asp = sub.add_parser("assess", help="collect + analyze one host")
    asp.add_argument("host")
    asp.add_argument("--os", dest="os_name", required=True, choices=["linux", "windows"])
    asp.add_argument("--cred", dest="cred_id", default=None)

    swp = sub.add_parser("sweep", help="assess hosts in parallel and write a report")
    swp.add_argument("--no-report", action="store_true")
    swp.add_argument("--host", action="append", default=[], metavar="HOST:OS[:CRED]",
                     help="host to include, e.g. 192.168.56.10:linux:lab-ssh (repeatable)")

    bp = sub.add_parser("baseline", help="change-detection baselines")
    bp.add_argument("action", choices=["list", "accept"])
    bp.add_argument("host", nargs="?")

    hp = sub.add_parser("hostkeys", help="pinned SSH host keys")
    hp.add_argument("action", choices=["list", "forget"])
    hp.add_argument("host", nargs="?")
    hp.add_argument("--port", type=int, default=22)

    vp = sub.add_parser("vault", help="manage the credential vault")
    vp.add_argument("action", choices=["list", "add", "remove", "init-key"])
    vp.add_argument("cred_id", nargs="?")
    vp.add_argument("--kind", default="ssh_password",
                    choices=["ssh_password", "ssh_key", "winrm_password", "api_token"])
    vp.add_argument("--user", default="")
    vp.add_argument("--key-file", default="", help="read the secret (e.g. a private key) from a file")

    aup = sub.add_parser("audit", help="audit log")
    aup.add_argument("action", choices=["verify", "tail"])

    wp = sub.add_parser("worker", help="serve tasks from the orchestrator bus")
    wp.add_argument("--once", action="store_true", help="handle what is queued, then exit")

    sub.add_parser("bridge", help="pull devices from Agent 1 and queue work for them")

    dp = sub.add_parser("dashboard", help="start the local web dashboard")
    dp.add_argument("--host", default=None)
    dp.add_argument("--port", type=int, default=None)

    kp = sub.add_parser("kill", help="engage the kill switch")
    kp.add_argument("reason", nargs="?", default="manual CLI kill")
    sub.add_parser("reset-kill", help="re-arm the kill switch")
    return p


def _main(argv=None) -> int:
    args = _parser().parse_args(argv)

    # No subcommand → start dashboard (the main way to use the agent)
    if not args.cmd:
        agent = _agent(args)
        from .server import run_dashboard
        run_dashboard(agent, open_browser=True)
        return 0

    if args.cmd == "vault":
        return _cmd_vault(args)
    agent = _agent(args)

    if args.cmd == "scope":
        return _cmd_scope(agent, args)
    if args.cmd == "approvals":
        return _cmd_approvals(agent, args)
    if args.cmd == "discover":
        _print([h.dict() for h in agent.discover()])
    elif args.cmd == "status":
        _print(agent.status())
    elif args.cmd == "self-audit":
        _print(agent.assess_host("127.0.0.1", "linux", with_ai=not args.no_ai).dict())
    elif args.cmd == "assess":
        _print(agent.assess_host(args.host, args.os_name, cred_id=args.cred_id,
                                 with_ai=not args.no_ai).dict())
    elif args.cmd == "sweep":
        hosts = None
        if args.host:
            hosts = []
            for spec in args.host:
                parts = spec.split(":")
                if len(parts) < 2 or parts[1] not in ("linux", "windows"):
                    raise ValueError(f"bad --host {spec!r}; expected HOST:linux|windows[:CRED]")
                hosts.append((parts[0], parts[1], parts[2] if len(parts) > 2 else None))
        session = agent.run_sweep(hosts=hosts, with_ai=not args.no_ai,
                                  write_report=not args.no_report)
        _print(session)
        if session.get("report"):
            print(f"\nReport: {session['report'].get('html')}", file=sys.stderr)
    elif args.cmd == "baseline":
        if args.action == "list":
            _print(agent.baselines.hosts())
        else:
            if not args.host:
                raise ValueError("host required")
            print(f"baseline for {args.host} now reflects the state seen at "
                  f"{agent.accept_baseline(args.host)}")
    elif args.cmd == "hostkeys":
        if args.action == "list":
            _print(agent.hostkeys.all())
        else:
            agent.rbac.check(agent.role, "hostkeys.modify")
            if not args.host:
                raise ValueError("host required")
            gone = agent.hostkeys.forget(args.host, args.port)
            agent.audit.record(agent.role, "hostkey.forget", args.host, "ok",
                               {"port": args.port, "existed": gone})
            print("pin removed" if gone else "no pin for that host")
    elif args.cmd == "audit":
        if args.action == "verify":
            ok, msg = agent.audit.verify()
            print(msg)
            return 0 if ok else 2
        _print(agent.audit.tail())
    elif args.cmd == "worker":
        from .orchestrator.bus import FileBus
        bus = FileBus(agent.cfg.bus_dir)
        print(f"serving tasks from {agent.cfg.bus_dir}/inbox (Ctrl-C to stop)",
              file=sys.stderr)
        try:
            n = agent.work(bus, once=args.once)
        except KeyboardInterrupt:
            n = 0
        print(f"handled {n} task(s)")
    elif args.cmd == "bridge":
        from .orchestrator.bus import FileBus
        from .orchestrator.agent1_bridge import Agent1Bridge
        _print(Agent1Bridge(agent, FileBus(agent.cfg.bus_dir)).sync(
            with_ai=not args.no_ai))
    elif args.cmd == "dashboard":
        from .server import run_dashboard
        run_dashboard(agent, host=args.host, port=args.port)
    elif args.cmd == "kill":
        agent.engage_kill(args.reason)
        print(f"kill switch engaged: {args.reason}")
    elif args.cmd == "reset-kill":
        agent.reset_kill()
        print("kill switch re-armed")
    return 0


def _cmd_scope(agent: EndpointIntelligenceAgent, args) -> int:
    if args.action == "list":
        for e in agent.scope.all():
            print(f"{e.identifier:<22} {e.os_hint or '-':<8} {e.note}")
        return 0
    if not args.identifier:
        raise ValueError("identifier required")
    if args.action == "remove":
        agent.remove_scope(args.identifier)
        print(f"removed {args.identifier}")
    elif args.action == "request" or not agent.rbac.allows(agent.role, "scope.modify"):
        req = agent.request_scope_add(args.identifier, agent.role, args.note, args.os_hint)
        print(f"request {req.id} filed for {args.identifier}; an admin approves it with: "
              f"approvals approve {req.id}")
    else:
        confirmed = args.yes
        if not confirmed:
            answer = input(f"Do you own {args.identifier} or hold written permission "
                           "to test it? Type 'yes' to authorise: ")
            confirmed = answer.strip().lower() in ("yes", "ja")
        agent.add_scope(args.identifier, args.note or "authorised via CLI",
                        args.os_hint, confirmed=confirmed)
        print(f"added {args.identifier}")
    return 0


def _cmd_approvals(agent: EndpointIntelligenceAgent, args) -> int:
    if args.action == "list":
        _print([r.dict() for r in agent.approvals.all()])
        return 0
    if not args.req_id:
        raise ValueError("request id required")
    req = agent.decide_request(args.req_id, approve=args.action == "approve")
    print(f"{req.action} {req.target}: {req.status}")
    return 0


def _cmd_vault(args) -> int:
    cfg = load_config(args.config)
    if args.action == "init-key":
        print(CredentialVault.generate_key().decode())
        print("# export AGENT2_VAULT_KEY=<the line above>", file=sys.stderr)
        return 0
    vault = _open_vault(cfg, args, create=True)
    if args.action == "list":
        for cid in vault.ids():
            print(cid)
        return 0
    if not args.cred_id:
        raise ValueError("credential id required")
    if args.action == "add":
        if args.key_file:
            secret = open(os.path.expanduser(args.key_file)).read()
        else:
            secret = getpass.getpass("secret (password/key/token): ")
        vault.put(Credential(id=args.cred_id, kind=args.kind, username=args.user,
                             secret=secret))
        print(f"stored {args.cred_id}")
    else:
        vault.delete(args.cred_id)
        print(f"removed {args.cred_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
