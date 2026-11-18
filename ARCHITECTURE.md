# Arkitektur — Agent 2 (Endpoint Intelligence Agent)

Agent 2 er en egen pakke (`endpoint_agent/`) ved siden av Agent 1 (`wifi_agent/`).
Den importerer ikke Agent 1 og endrer ingen av filene dens.

```
   Agent 1 (WiFi)  ──GET /api/traffic──►  Agent1Bridge ─┐
   Orchestrator / skript ───────────────────────────────┤  Task (JSON)
                                                        ▼
                                              .run/orchestrator/inbox
                                                        │  worker
┌──────────────────────────── endpoint_agent ───────────▼──────────────────┐
│ orchestrator/agent2.py   EndpointIntelligenceAgent (fasade)              │
│   discovery/   oppdagelse (nmap / TCP, asynkron)                         │
│   collector/   SSH · WinRM · lokal  — fast liste lesekommandoer + filer  │
│   analyzer/    regler · Sigma · YARA-X · Lynis · OSV · baseline          │
│   ai/          Ollama + Claude, ruting og budsjett                       │
│   reporting/   JSON · HTML · PDF                                         │
│ server.py      dashbord (Flask, localhost)        cli.py   kommandolinje │
│ core/          scope · rbac · approvals · credentials · hostkeys ·       │
│                audit · ratelimit · killswitch · runner · config          │
└──────────────────────────────────────────────────────────────────────────┘
```

Hver handling mot en vert går gjennom scope-gate, rollesjekk, rate-limit og
nødstopp, og skrives til revisjonsloggen.

## Moduler

**Discovery** (`discovery/discovery.py`). Utvider autoriserte områder til
enkeltadresser (maks 4096), sjekker hver adresse mot scope på nytt og prober
administrasjonsportene. Gjetter OS ut fra åpne porter.

**Collector** (`collector/`). `base.py` kjører kommandoene i `commands.py` for
riktig OS. En kaller velger nøkler, aldri kommandotekst. Transporter:
`ssh_collector` (paramiko), `winrm_collector` (pywinrm), `local_collector`.
Logger (auth-logg, journal, Windows-hendelseslogg som XML) hentes som egne
kommandoer. `files.py` leser filinnhold kun under kataloger fra konfigurasjonen:
endepunktet lister filer, hver sti valideres på nytt hos oss (innenfor katalogen,
ikke på sperrelisten, under størrelsesgrensen), og innholdet hentes base64-kodet.
Innholdet holdes i minnet for hashing og YARA og skrives aldri til disk.

**Analyzer** (`analyzer/`).

| Kilde | Fil | Gir |
|---|---|---|
| Egne regler | `analyzer.py` | sshd-oppsett, risikable porter, ekstra UID 0, SUID, Windows-brannmur, Defender, delinger |
| Sigma | `sigma_engine.py` | treff på prosesser, forbindelser, Linux-logglinjer og Windows-hendelser |
| YARA-X | `yara_engine.py` | treff i innsamlede filer |
| Lynis | `lynis.py` | advarsler, forslag og herdingsindeks fra Lynis-rapporten |
| OSV | `vuln.py` | pakker med kjente sårbarheter |
| Baseline | `baseline.py` | endringer siden godkjent tilstand, inkludert filhasher |

Sigma: pySigma har ingen innebygd matcher, så modulen har sin egen evaluator.
Betingelser parses til et tre og evalueres uten `eval`. Støttet: feltutvalg,
lister, nøkkelord, jokertegn, `contains`/`startswith`/`endswith`/`all`/`re`/
`cidr`/`exists`, `and`/`or`/`not`, parenteser og `1 of`/`all of`. Regler som
trenger mer (aggregering, base64-modifikatorer) hoppes over og listes i
`skipped`. pySigma brukes til syntaksvalidering når det er installert.

Baseline: første kjøring lagrer tilstanden. Senere avvik rapporteres hver gang
til noen kjører `baseline accept`. En kategori sammenlignes bare når kommandoen
lyktes i begge kjøringene.

**AI** (`ai/`). `router.py` velger modell ut fra oppgavetype, risiko og
størrelse. `engine.py` håndhever at eksterne kall krever `ai.external`, teller
mot ett token-budsjett per kjøring, fjerner IP og vertsnavn før sending og
logger hvert kall. Faller tilbake til lokal modell når noe av dette stopper et
eksternt kall. AI-tekst er alltid merket som hypotese.

**Reporting** (`reporting/report.py`). JSON og HTML alltid, PDF når weasyprint
eller wkhtmltopdf finnes. Omtrentlige treff merkes «ubekreftet».

**Dashbord** (`server.py`). Lytter på localhost. Alle API-kall krever et token
som bare ligger i siden, og Host-headeren må stemme, slik at andre nettsider i
nettleseren ikke kan styre agenten. Data fra endepunkter settes inn som tekst,
aldri som HTML.

## Kjernen (`core/`)

| Modul | Ansvar |
|---|---|
| `scope.py` | Allowlist. `0.0.0.0/0` avvises. |
| `approvals.py` | Kø med forespørsler om utvidet tilgang. Ingenting skjer før en med `approval.grant` godkjenner. |
| `rbac.py` | Rolle til handlinger. Alle roller kan stoppe agenten. |
| `credentials.py` | Fernet-vault, nøkkel fra passordfrase (scrypt) eller `AGENT2_VAULT_KEY`. |
| `hostkeys.py` | SSH-nøkler låses ved første bruk. Endret nøkkel gir feil før autentisering. |
| `audit.py` | JSONL der hver linje inneholder hashen av forrige. |
| `ratelimit.py` | Token-bucket, delt mellom tråder. |
| `killswitch.py` | Flagg i minnet og som fil, så en annen prosess kan utløse det. |
| `config.py` | Typet konfigurasjon. Ukjente nøkler gir feil. |

## Krav og hvor de er løst

| Krav | Løsning |
|---|---|
| Allowlist | `scope.py`, sjekket i discovery, collector og fasade |
| Rollebasert tilgang | `rbac.py`, sjekket for scope-endring, innsamling, AI, godkjenning, nødstopp |
| Krypterte credentials | `credentials.py` |
| Revisjonslogg | `audit.py` |
| Ressurs- og hastighetsgrenser | `ratelimit.py`, `limits.max_concurrency`, token-budsjett |
| Kill switch | `killswitch.py`, sjekkes mellom kommandoer, filer og verter |
| Godkjenning før utvidet tilgang | `approvals.py` + bekreftelse i CLI og dashbord |
| Ingen eskalering, passorduthenting eller filoverføring | fast kommandoliste, sperreliste for filer, innhold lagres ikke |

## Parallellitet

`run_sweep` vurderer verter i en trådpool (`limits.max_concurrency`). Hver vert
har sin egen collector. Revisjonslogg, rate-limiter og token-budsjett er låst.
En vert som feiler rapporteres som «ikke undersøkt» uten å stoppe de andre.
Utløses nødstoppen underveis, avbrytes kjøringen uten rapport.

## Hva som er testet hvordan

| Del | Testet |
|---|---|
| Scope, roller, godkjenning, vault, audit, rate-limit, nødstopp, konfig | Enhetstester |
| SSH-innsamling, feil passord, vertsnøkkel-låsing | Ekte SSH mot en paramiko-server på localhost |
| Filinnsamling | Ekte filer via lokal collector |
| Sigma, Lynis-parser, OSV, baseline | Enhetstester med faste data og falsk HTTP |
| Parallell sweep, bro, worker | Simulerte verter |
| Dashbord | Flask testklient, og sett i nettleser |
| **Ikke testet mot ekte systemer** | WinRM/Windows, Windows-filinnsamling, Ollama- og Claude-kall, OSV-API-et (nettverket var sperret under utvikling), Lynis-kjøring, nmap-grenen |
