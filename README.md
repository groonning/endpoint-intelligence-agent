# Endpoint Intelligence Agent (Agent 2)

En modulær, skrivebeskyttet endpoint-sikkerhetsagent for autoriserte testmiljøer.
Den oppdager maskiner, samler systemfakta og logger over autentisert SSH/WinRM,
finner feilkonfigurasjon, kjente sårbarheter og endringer siden sist, og skriver
rapporter (JSON/HTML/PDF). Den står ved siden av Agent 1 (WiFi-agenten) og
snakker med den over en liten oppgavebuss.

> **Autorisasjon.** Agenten gjør kun aktive operasjoner mot maskiner som står i
> `config/authorized_endpoints.yaml`. Å teste et system du ikke eier eller ikke
> har skriftlig tillatelse til å teste er ulovlig. Scope-gaten er en hard blokk.

## Hva den gjør

| | |
|---|---|
| Oppdager | Levende verter i autoriserte områder (nmap, ellers TCP). |
| Samler | OS, brukere, prosesser, tjenester, nettverk, pakker og logger, fra en fast liste med lesekommandoer. Filinnhold kun fra kataloger du har godkjent. |
| Analyserer | Egne regler, Sigma (prosesser, nettverk, auth-logg, journal, Windows-hendelseslogg), YARA-X på filer, Lynis og CVE-oppslag mot OSV. |
| Sammenligner | Hver kjøring mot en baseline per vert: ny bruker, ny port, ny SUID-fil, endret fil. |
| Vurderer | Lokal Ollama som standard. Claude Sonnet/Opus for tunge oppgaver hvis du slår det på. AI-tekst merkes som hypotese. |
| Rapporterer | JSON, HTML og PDF, pluss et lokalt dashbord. |

## Sikkerhet

- **Scope:** allowlist for IP, CIDR og vertsnavn. Nye mål krever bekreftelse fra et menneske. Automatiske kilder (bussen, Agent 1-broen) kan bare be om godkjenning.
- **Roller:** `viewer`, `operator`, `admin`. Alle kan stoppe agenten, bare `admin` godkjenner nye mål og bruker eksterne modeller.
- **Credentials:** Fernet-kryptert vault. Hemmeligheter skrives aldri i klartekst eller til logg.
- **SSH-vertsnøkler:** låses ved første tilkobling. Endret nøkkel avbryter før passordet sendes.
- **Revisjonslogg:** hash-kjedet, tukling oppdages av `audit verify`.
- **Grenser:** rate-limit, samtidighetstak, token-budsjett per kjøring for eksterne modeller.
- **Nødstopp:** `endpoint-agent kill`, knapp i dashbordet, eller `touch .run/killswitch`.
- **Kun lesing:** ingen privilegie-eskalering, ingen passord- eller nøkkeluthenting. Filinnhold lagres ikke, bare sti, størrelse og SHA-256.

## Installer (Kali)

Full veiledning i `INSTALL_KALI.md`.

```bash
cd "Endpoint connect"
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[ssh,dashboard,dev]"        # legg til winrm, yara, sigma, pdf, claude ved behov
cp config/agent2.example.yaml config/agent2.yaml
cp config/authorized_endpoints.example.yaml config/authorized_endpoints.yaml
cp config/roles.example.yaml config/roles.yaml
pytest -q
```

## Bruk

```bash
endpoint-agent scope add 192.168.56.0/24 --note "min lab" --os linux   # spør om bekreftelse
endpoint-agent self-audit                       # Kali-boksen selv, uten credentials
endpoint-agent discover

export AGENT2_VAULT_KEY="$(endpoint-agent vault init-key)"   # ta vare på nøkkelen
endpoint-agent vault add lab-ssh --kind ssh_password --user kali

endpoint-agent assess 192.168.56.10 --os linux --cred lab-ssh
endpoint-agent sweep --host 192.168.56.10:linux:lab-ssh --host 192.168.56.11:linux:lab-ssh
endpoint-agent baseline accept 192.168.56.10    # godta dagens tilstand som ny baseline

endpoint-agent dashboard                        # http://127.0.0.1:8778
endpoint-agent bridge                           # hent enheter fra Agent 1, legg oppgaver i kø
endpoint-agent worker                           # utfør oppgaver fra bussen
endpoint-agent approvals list                   # --role admin approvals approve <id>

endpoint-agent status
endpoint-agent audit verify
endpoint-agent kill "stopp alt"                 # reset-kill for å fortsette
```

Med `credentials_map` i `config/agent2.yaml` trenger du ikke `--cred`, og `sweep`
uten `--host` tar alle enkeltverter i scope som har `os_hint` og credential.

## Valgfrie funksjoner (av som standard)

| Funksjon | Slås på med | Merk |
|---|---|---|
| Filinnsamling + YARA-X | `files.enabled` + kataloger | Nøkkel- og passordfiler leses aldri. |
| CVE-oppslag | `vuln.enabled` | Sender pakkenavn og versjoner til osv.dev. Debian og Ubuntu treffer eksakt, Kali omtrentlig via `kali_as_debian`. |
| Lynis | `lynis.enabled` | Lynis skriver en midlertidig fil på endepunktet mens den kjører. |
| Eksterne modeller | `ai.allow_external`, `ANTHROPIC_API_KEY`, rolle med `ai.external` | IP og vertsnavn fjernes før sending. |
| Strenge vertsnøkler | `ssh_strict_host_keys` | Ukjente verter avvises. |

## Status

Se `ARCHITECTURE.md` for hva som er testet hvordan. Kort: 147 automatiske tester,
inkludert ekte SSH-runder mot en lokal testserver. Ikke prøvd mot ekte maskiner:
WinRM/Windows, Ollama- og Claude-kall, OSV-API-et og Lynis.

Dokumentasjon: `ARCHITECTURE.md`, `API.md`, `INTEGRATION_AGENT1.md`,
`INSTALL_KALI.md`, `RESEARCH.md`.
