# Installasjonsveiledning — Kali Linux

Testet mot Kali Rolling (2026.x) med Python ≥ 3.10. Agenten kjører på samme boks
som Agent 1 (din ThinkPad E14 / Kali).

## 1. Systemverktøy

Kjernen trenger bare Python. Disse gjør discovery/analyse rikere og finnes i Kali:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip nmap lynis
# Valgfritt for PDF uten weasyprint-avhengigheter:
sudo apt install -y wkhtmltopdf
```

`nmap` brukes av discovery og den valgfrie CVE-skanningen. Uten nmap faller
discovery tilbake på ren Python TCP-sweep (fungerer, men grunnere).

## 2. Hent prosjektet og lag et virtuelt miljø

```bash
cd ~/"Endpoint connect"      # der denne koden ligger
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
```

## 3. Installer Agent 2

```bash
# Kjerne (alltid): PyYAML + cryptography
pip install -e .

# Legg til det du trenger:
pip install -e ".[ssh]"      # SSH-innsamling (Linux-endpoints, paramiko)
pip install -e ".[winrm]"    # WinRM-innsamling (Windows-endpoints, pywinrm)
pip install -e ".[yara]"     # YARA-X fil-analyse
pip install -e ".[sigma]"    # pySigma regelvalidering (matcheren virker uten)
pip install -e ".[pdf]"      # PDF-rapporter (weasyprint)
pip install -e ".[claude]"   # ekstern Claude-analyse (valgfritt)
pip install -e ".[dashboard]" # lokalt dashbord (Flask)
# eller alt på én gang:
pip install -e ".[all]"
```

> **Merk (weasyprint):** på noen Kali-oppsett trenger weasyprint systembiblioteker
> (`libpango`, `libcairo`). Hvis `pip install` feiler, dropp `[pdf]` — HTML/JSON
> produseres uansett — eller bruk `wkhtmltopdf` + `pip install pdfkit`.

## 4. Ollama (lokal modell — delt med Agent 1)

Hvis du allerede kjører Ollama for Agent 1, er du i mål. Ellers:

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen3:30b-a3b     # samme modell Agent 1 bruker (MoE, ~20GB, passer 40GB RAM)
```

Agent 2 snakker med Ollama på `http://127.0.0.1:11434`. Overstyr med
`OLLAMA_URL` / `OLLAMA_MODEL`.

## 5. Konfigurasjon

```bash
cp config/agent2.example.yaml              config/agent2.yaml
cp config/authorized_endpoints.example.yaml config/authorized_endpoints.yaml
cp config/roles.example.yaml               config/roles.yaml
```

Rediger `config/authorized_endpoints.yaml` så den **kun** inneholder maskiner du
eier eller har skriftlig tillatelse til å teste.

## 6. Credential-vault

```bash
endpoint-agent vault init-key                 # skriver ut en nøkkel
export AGENT2_VAULT_KEY='<nøkkelen>'          # legg den et trygt sted, f.eks. en passordbehandler
endpoint-agent vault add lab-ssh --kind ssh_password --user kali
endpoint-agent vault add lab-key --kind ssh_key --user kali --key-file ~/.ssh/lab_ed25519
```

Mister du nøkkelen, må credentials legges inn på nytt. Vil du heller bruke en
passordfrase, legg til `--vault-pass` på kommandoene (du blir spurt hver gang).

Knytt credentials til verter i `config/agent2.yaml`, så slipper du `--cred`:

```yaml
credentials_map:
  192.168.56.0/24: lab-ssh
```

## 7. Røyktest

```bash
# Selv-revisjon av Kali-boksen (ingen eksterne tilkoblinger)
python3 -m endpoint_agent.cli self-audit

# Full sweep + rapport
python3 -m endpoint_agent.cli sweep
xdg-open reports/endpoint_session_*.html

# Verifiser revisjonskjeden
python3 -m endpoint_agent.cli audit verify

# Dashbord
endpoint-agent dashboard          # http://127.0.0.1:8778
```

## 8. Kjør testene (valgfritt)

```bash
pip install -e ".[dev]"
pytest -q
```

## Feilsøking

| Symptom | Årsak / løsning |
|---|---|
| `paramiko is required for SSHCollector` | `pip install -e ".[ssh]"` |
| `pywinrm is required for WinRMCollector` | `pip install -e ".[winrm]"` |
| PDF hoppes over (`pdf_skipped`) | Installer `[pdf]` eller `wkhtmltopdf`; HTML/JSON er upåvirket |
| `Ollama unavailable` | Start `ollama serve`, eller kjør med `--no-ai` |
| Discovery finner ingenting | Sjekk at vertene er i scope og at nmap/TCP når dem |
| `HOST KEY CHANGED` | Vertens SSH-nøkkel er en annen enn sist. Er maskinen reinstallert: `endpoint-agent hostkeys forget <vert>`. Hvis ikke, undersøk før du kobler til. |
| `unknown config key(s)` | Skrivefeil i `config/agent2.yaml`; sammenlign med eksempelfilen |
| `is NOT ... refusing to act` | Verten er ikke i `authorized_endpoints.yaml` — som tiltenkt |
