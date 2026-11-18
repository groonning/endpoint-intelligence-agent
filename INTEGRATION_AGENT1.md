# Integrasjon med Agent 1 (WiFi-agenten) og Security Orchestrator

Agent 2 er bygget for å stå **ved siden av** Agent 1 (`wifi_agent/` i Connect-repoet,
github.com/groonning/Connect), ikke oppå den. Dette dokumentet beskriver hvordan
de to henger sammen uten at Agent 1 sin kode endres.

## Prinsipper

1. **Ingen endring av Agent 1.** Agent 2 importerer ikke `wifi_agent` og rører
   ingen av filene dens. Analysen av Agent 1 (gjort før kodingen) ligger til grunn
   for at vi **gjenbruker konvensjoner**, ikke kode.
2. **Separate pakker.** Agent 1 = `wifi_agent/`, Agent 2 = `endpoint_agent/`.
   De kan ligge i hvert sitt repo eller side om side.
3. **Eksplisitt kontrakt.** All kommunikasjon er serialiserbare `Task`/`TaskResult`
   (JSON) over `orchestrator/bus.py`. Bussen bærer intensjon; scope + RBAC
   håndheves alltid på nytt i Agent 2.

## Hva som gjenbrukes fra Agent 1 (som mønster)

| Agent 1 | Agent 2 | Felles konvensjon |
|---|---|---|
| `wifi_agent/llm.py` (Ollama, stdlib) | `ai/ollama_backend.py` | Samme URL `127.0.0.1:11434`, modell `qwen3:30b-a3b`, `chat(system,user)`-signatur |
| `wifi_agent/runner.py` (`RunResult`, no-shell) | `core/runner.py` | Samme `RunResult`-form; Agent 2 legger til async `arun` |
| `wifi_agent/scope.py` (BSSID-allowlist) | `core/scope.py` | Samme «å legge til = å autorisere»-modell, generalisert til IP/CIDR/host |
| `.run/`-filkonvensjon (f.eks. `.run/step1_done`) | `orchestrator/bus.py` `FileBus` | `.run/orchestrator/{inbox,outbox,done}` |
| Flask-dashbord på `:8777` | `server.py` på `:8778` | Samme utseende, egen port |

Fordi Ollama-konvensjonen er delt, bruker begge agentene **samme kjørende
Ollama-instans** på Kali-boksen — ingen dobbel modell-last.

## Security Orchestrator

«Security Orchestrator» er den koordinerende parten som fordeler oppgaver mellom
agentene. Den trenger ikke å eksistere som egen tjeneste ennå — `FileBus` lar en
hvilken som helst prosess (et skript, en cron-jobb, en fremtidig orchestrator,
eller Agent 1) slippe en task-JSON i `inbox/` og lese svaret fra `outbox/`.

### Flyt

```
  Agent 1  (eller orchestrator)                 Agent 2
  ────────────────────────────                 ─────────
  skriver .run/orchestrator/inbox/<id>.json
     {"kind":"assess",
      "params":{"host":"192.168.56.10",
                "os_name":"linux","cred_id":"lab-ssh"}}
                                   ──────────►  bus.poll()  → handle_task()
                                                  scope ✓ rbac ✓ collect ✓ analyze ✓
                                   ◄──────────  bus.publish(TaskResult)
  leser .run/orchestrator/outbox/<id>.json
     {"ok":true,"data":{"host_report":{…funn…}}}
```

### Typisk arbeidsdeling

- **Agent 1** kartlegger trådløst, knekker/autentiserer mot et autorisert nett,
  og får dekryptert nett-tilgang (steg 2). Den vet hvilke **enheter/IP-er** som er
  på nettet.
- **Agent 1 → Agent 2:** for hver autorisert enhet med kjent IP sender den en
  `assess`- eller `collect`-task til Agent 2.
- **Agent 2** gjør den dype, autentiserte endpoint-analysen (read-only) og
  returnerer strukturerte funn, som Agent 1/orchestrator kan flette inn i sin
  samlede rapport.

> Viktig: IP-ene Agent 1 finner må også ligge i Agent 2 sin
> `authorized_endpoints.yaml`. Agent 2 stoler aldri på at en task er autorisert —
> den re-sjekker scope selv. Dette er bevisst: bussen flytter intensjon, ikke
> tillatelse.

## Kjøreeksempel (Python)

```python
from endpoint_agent.core.config import load_config
from endpoint_agent.orchestrator.agent2 import EndpointIntelligenceAgent
from endpoint_agent.orchestrator.bus import FileBus, Task

agent = EndpointIntelligenceAgent(load_config("config/agent2.yaml"), role="operator")
bus = FileBus(".run/orchestrator")

# (Agent 1 / orchestrator legger inn tasks i inbox/ … her simulerer vi én:)
bus.submit(Task(kind="assess",
                params={"host": "192.168.56.10", "os_name": "linux",
                        "cred_id": "lab-ssh", "with_ai": True}))

# Agent 2 sin arbeidssløyfe:
for task in bus.poll():
    bus.publish(agent.handle_task(task))

# Orchestrator henter svar:
for res in bus.read_results():
    print(res.ok, res.kind, res.data.get("host_report", {}).get("host"))
```

## Delt revisjon

Begge agentene kan skrive til hver sin revisjonslogg. Agent 2 sin logg er
hash-kjedet (`core/audit.py`) og ligger i `audit/agent2-audit.jsonl`, slik at en
orchestrator kan samle begge agentenes handlinger i ett reviderbart spor.

## Broen fra Agent 1 (`orchestrator/agent1_bridge.py`)

Agent 1 sitt dashbord-API returnerer hvilke enheter den ser på nettet
(`GET /api/traffic` gir `mac_ip`, MAC til IP). Broen leser dette og gjør det om
til arbeid for Agent 2. Agent 1 sin kode er ikke endret.

| Enheten er | Broen gjør |
|---|---|
| i scope, credential i `credentials_map` | legger en `assess`-oppgave i `inbox/` |
| i scope, uten credential | lister den som «mangler credential» |
| ikke i scope | legger inn en forespørsel om godkjenning |

At en enhet er på WiFi-nettet gir ikke tillatelse til å logge inn på den, så
nye enheter blir aldri autorisert automatisk. Offentlige adresser ignoreres.

```bash
# Agent 1 kjører på :8777 (steg 2, så den ser IP-adresser)
endpoint-agent bridge            # les enheter, legg oppgaver i kø, be om godkjenning
endpoint-agent --role admin approvals list
endpoint-agent --role admin approvals approve <id>
endpoint-agent worker            # utfør køen (Ctrl-C eller nødstopp for å avslutte)
```

Det samme finnes som knapp i dashbordet («Hent enheter fra Agent 1»).
Broen er testet mot et etterlignet svar fra Agent 1, ikke mot Agent 1 i drift.
