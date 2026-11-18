# API — Agent 2

Tre innganger: Python-fasaden, oppgavebussen (JSON) og dashbordets HTTP-API.
CLI-en er et tynt lag over fasaden.

## Python

```python
from endpoint_agent.core.config import load_config
from endpoint_agent.core.credentials import CredentialVault
from endpoint_agent.orchestrator.agent2 import EndpointIntelligenceAgent

cfg = load_config("config/agent2.yaml")
agent = EndpointIntelligenceAgent(cfg, role="operator",
                                  vault=CredentialVault(cfg.vault_path))  # AGENT2_VAULT_KEY
```

| Metode | Returnerer | Krever |
|---|---|---|
| `discover(use_nmap=None)` | `list[DiscoveredHost]` | `discovery.sweep` |
| `collect(host, os_name, cred_id=None, only=None)` | `CollectionResult` | `collect.read`, vert i scope |
| `analyze(result)` | `list[Finding]` | `analyze.run` |
| `assess_host(host, os_name, cred_id=None, with_ai=True)` | `HostReport` (innsamling, analyse, baseline, AI) | som over |
| `run_sweep(hosts=None, with_ai=True, write_report=True)` | session-dict | som over |
| `add_scope(identifier, note, os_hint="", confirmed=False)` | `Endpoint` | `scope.modify` og `confirmed=True` |
| `request_scope_add(identifier, requested_by, reason="")` | `ApprovalRequest` | ingen (gir ingen tilgang) |
| `decide_request(req_id, approve)` | `ApprovalRequest` | `approval.grant` |
| `accept_baseline(host)` | tidspunkt | `baseline.accept` |
| `engage_kill(reason)` / `reset_kill()` | | `killswitch.engage` / `killswitch.reset` |
| `status()` | dict | |
| `handle_task(task)` | `TaskResult` | per oppgavetype |
| `work(bus, once=False)` | antall utført | |

`cred_id` kan utelates når verten finnes i `credentials_map`.

### Finding

```json
{"host":"192.168.56.10","severity":4,"severity_label":"critical",
 "title":"Ekstra UID 0-konto: backdoor","detail":"…","category":"users",
 "source":"rule","evidence":"backdoor:x:0:0:…","recommendation":"…","refs":[],
 "confirmed":true}
```

`source`: `rule`, `sigma`, `yara`, `lynis`, `osv`, `baseline`.
`confirmed` er `false` bare for omtrentlige treff (Kali sjekket mot Debian).

### Session (`run_sweep`)

```json
{"generated_at":"…Z","scope":["192.168.56.0/24"],
 "hosts":[{"host":"…","os_name":"linux","method":"ssh","collected_at":"…",
           "findings":[…],"files":[{"path":"…","size":120,"sha256":"…","yara":[]}],
           "ai":{"ok":true,"text":"…","hypothesis":true,"route":{…}},"error":""}],
 "ai_correlation":null,"audit_verified":true,"external_tokens_used":0,
 "report":{"json":"…","html":"…","pdf":"…","pdf_skipped":""}}
```

En vert som ikke kunne undersøkes har `method: "error"` og tekst i `error`.

## Oppgavebuss

`FileBus(cfg.bus_dir)`: legg en JSON-fil i `inbox/`, les svaret i `outbox/<id>.json`.
`endpoint-agent worker` utfører oppgavene.

```json
{"kind":"assess","id":"valgfri","origin":"agent1",
 "params":{"host":"192.168.56.10","os_name":"linux","with_ai":true}}
```

| `kind` | `params` | `data` i svaret |
|---|---|---|
| `discover` | `use_nmap?` | `hosts` |
| `collect` | `host`, `os_name`, `cred_id?`, `only?` | `result` |
| `assess` | `host`, `os_name`, `cred_id?`, `with_ai?` | `host_report` |
| `full_sweep` | `hosts?` (`[[host, os, cred], …]`), `with_ai?` | session |
| `scope_request` | `identifier`, `reason?`, `os_hint?` | `approval` (status `pending`) |
| `status` | | agentens status |

Svar: `{"task_id","agent":"agent2","ok","kind","data","error","finished_at"}`.
En oppgave kan aldri utvide scope. Den kan bare be om det.

## Dashbord (HTTP)

Alle `/api`-kall krever headeren `X-Agent2-Token` (ligger i siden).

| Kall | Gjør |
|---|---|
| `GET /api/status` | status, funksjoner, om en sweep kjører |
| `GET /api/session` | siste sweep |
| `GET /api/audit?n=40` | siste hendelser |
| `GET /api/approvals` | forespørsler |
| `POST /api/approvals/<id>` `{"approve":bool}` | godkjenn eller avslå |
| `POST /api/sweep` `{"with_ai":bool}` | start sweep i bakgrunnen |
| `POST /api/baseline/accept` `{"host":"…"}` | godta endringer |
| `POST /api/bridge/sync` | hent enheter fra Agent 1 |
| `POST /api/kill`, `POST /api/reset-kill` | nødstopp |

Feil: 403 (rolle, scope eller token), 409 (nødstopp aktiv eller sweep kjører), 400.

## Innsamlingsnøkler

- **Linux:** `os_release, kernel, uptime, hostname, users, logged_in, sudoers_who,
  processes, listening, connections, routes, interfaces, services_systemd,
  listening_units, packages_dpkg, packages_src, cron_system, world_writable,
  suid_binaries, ssh_config, firewall_nft, auth_log, journal` (+ `lynis`)
- **Windows:** `os_info, hotfixes, users, admins, processes, services, listening,
  connections, firewall, smb_shares, defender, events_security, events_system,
  events_powershell`

## Unntak

`ScopeError`, `AccessDenied`, `KillSwitchEngaged`, `RateLimitExceeded`,
`CollectionError` (også ved endret vertsnøkkel), `HostKeyError`, `VaultError`,
`FilePolicyError`, `PermissionError` (scope uten bekreftelse). CLI-en skriver
én feillinje og avslutter med kode 2.
