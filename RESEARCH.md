# GitHub-research og teknologivalg — Agent 2

Research utført 2026-11-17. Alle lenker og fakta er verifisert mot repo/offisielle
kilder på denne datoen. Prosjekter er **ikke** valgt på stjerner alene, men på
lisens, vedlikehold, Kali-kompatibilitet, integrasjonsflate (API/SDK),
ressursbruk og hvor godt de passer en **skrivebeskyttet, autonom** endpoint-agent.

## Kort konklusjon (verdikt per prosjekt)

| Prosjekt | Lisens | Vedlikehold (per nov 2026) | Rolle i Agent 2 |
|---|---|---|---|
| **osquery** | Apache-2.0 / GPL-2.0 | Aktiv, v5.23.x (2026) | **Inspirasjon** — kommandokatalogen vår speiler osquery-tabeller; valgfri fremtidig innsamler |
| **Wazuh** | GPL-2.0 | Svært aktiv, 4.14.x + 5.0-rc (2026) | **Utelatt som kjerne** (agent+server-tungt), men REST-API er et naturlig eksportmål |
| **Velociraptor** | AGPL-3.0 | Aktiv (Rapid7), VQL + gRPC-API | **Integrasjon (valgfri)** — pyvelociraptor-bindinger for dyp forensikk |
| **FleetDM** | MIT (fri utgave) | Svært aktiv, v4.8x (2026) | **Utelatt** — overlapper Wazuh/osquery-flåtestyring; ikke nødvendig for lab |
| **Lynis** | GPL-3.0 | Aktiv, 3.1.7 (2026-06-25) | **Integrasjon** — agentløs host-revisjon, finnes i Kali (`apt install lynis`) |
| **Greenbone/OpenVAS** | GPL-2.0 (scanner), python-gvm GPL-3.0 | Aktiv, OpenVAS 23.52.x (okt 2026) | **Integrasjon (valgfri)** via `python-gvm` for CVE-skann |
| **SigmaHQ/sigma** | DRL 1.1 (regler) + MIT/LGPL (verktøy) | Regler aktive; pySigma LGPL-2.1 | **Integrasjon** — deteksjonsregler (vår egen matcher + valgfri pySigma) |
| **YARA-X** | BSD-3-Clause | Svært aktiv, 1.x stabil (1.16+, 2026) | **Integrasjon** — fil-/innholdsanalyse via offisielle `yara-x` Python-bindinger |

---

## Detaljer

### osquery — github.com/osquery/osquery
- **Lisens:** dual Apache-2.0 / GPL-2.0 (`LICENSE-Apache-2.0`, `LICENSE-GPL-2.0`).
- **Vedlikehold:** aktiv; stabile utgaver gjennom 2026 (v5.21–v5.23.x; v5.23.1 jul 2026).
- **Kali:** kjører på Linux/macOS/Windows; .deb tilgjengelig.
- **API/SDK:** Thrift-API; «tables» spørres med SQL via `osqueryi`/`osqueryd`.
- **Ressurs:** daemon er lett, men å kreve osquery på hver endpoint bryter med
  vårt **agentløse** utgangspunkt (vi vil kunne undersøke en maskin med kun SSH).
- **Verdikt:** **Inspirasjon.** Vår read-only-kommandokatalog
  (`collector/commands.py`) er modellert på osquery-tabeller (processes, listening
  ports, users, suid). osquery kan senere legges til som en ekstra innsamler der
  en agent allerede er installert, men er ikke en kjerneavhengighet.

### Wazuh — github.com/wazuh/wazuh
- **Lisens:** GPL-2.0 (bekreftet i API: `"license_name": "GPL 2.0"`).
- **Vedlikehold:** svært aktiv; 4.14.x gjennom 2026 (4.14.9 okt 2026), 5.0 i RC.
- **API:** full REST-API (manager på port 55000, JWT-auth).
- **Ressurs:** krever manager + indexer (OpenSearch) + agenter — tungt for en
  enkelt-boks lab, og overlapper vårt analyse-/innsamlingsansvar.
- **Verdikt:** **Utelatt som kjerne.** For stor og agent/server-sentrert for en
  autonom, lettvekts labagent. REST-API-et er likevel et godt **eksportmål** —
  Agent 2 sine JSON-funn kan sendes til et eksisterende Wazuh-oppsett.

### Velociraptor — github.com/Velocidex/velociraptor
- **Lisens:** AGPL-3.0; Python-bindinger `pyvelociraptor` er MIT.
- **API:** gRPC; VQL-spørringer kjøres eksternt og returnerer JSON
  (`velocidex/pyvelociraptor`).
- **Verdikt:** **Valgfri integrasjon.** Der dyp DFIR trengs (minne, dead-disk),
  kan Agent 2 kalle en Velociraptor-server via pyvelociraptor. Holdt utenfor
  kjernen pga. AGPL (smitter ved distribusjon) og at det krever egen server.

### FleetDM — github.com/fleetdm/fleet
- **Lisens:** MIT (fri utgave; kommersielle tillegg egen lisens).
- **Vedlikehold:** svært aktiv (v4.81, feb 2026), bygger på osquery (`fleetd`).
- **Verdikt:** **Utelatt.** Flåtestyring over osquery — overlapper både osquery
  og Wazuh, og tilfører lite for en lab med få, autoriserte maskiner.

### Lynis — github.com/CISOfy/lynis
- **Lisens:** GPL-3.0.
- **Vedlikehold:** aktiv, 3.1.7 (2026-06-25).
- **Kali:** i standard repo — `sudo apt install lynis`. Agentløst shell-script,
  ingen kompilering.
- **Verdikt:** **Integrasjon.** Agent 2 kan kjøre `lynis audit system` på en
  Linux-endpoint (eller lokalt) og parse rapporten som en ekstra funnkilde ved
  siden av våre egne regler. Lav risiko, read-only, perfekt Kali-passform.

### Greenbone / OpenVAS — github.com/greenbone/openvas-scanner, greenbone/python-gvm
- **Lisens:** OpenVAS-scanner GPL-2.0; `python-gvm` GPL-3.0; `gvm-tools` GPL-3.0.
- **Vedlikehold:** aktiv; OpenVAS-scanner 23.52.x (29. okt 2026).
- **API/SDK:** `python-gvm` (GMP/OSP-protokoll) styrer en Greenbone-instans fra
  Python.
- **Ressurs:** feed + scanner + gvmd er tungt; førstegangs-feedsync er stor.
- **Verdikt:** **Valgfri integrasjon** for autoritativ CVE-skann. Agent 2 holder
  et lett `nmap --script vuln`-nivå i kjernen (som Agent 1 gjør for enheter), og
  lar `python-gvm` være en opt-in dyp-skann-bro der en Greenbone-server finnes.

### SigmaHQ / sigma — github.com/SigmaHQ/sigma, SigmaHQ/pySigma
- **Lisens:** regler under **Detection Rule License (DRL) 1.1**; verktøy MIT
  (hovedrepo) / pySigma + sigma-cli LGPL-2.1.
- **Vedlikehold:** stort, aktivt regelbibliotek; pySigma vedlikeholdt.
- **Verdikt:** **Integrasjon.** Agent 2 har en egen, avhengighetsfri Sigma-matcher
  for `process_creation`/`network_connection` mot innsamlede fakta, og bruker
  pySigma til regelvalidering når det er installert. DRL tillater fri bruk; vi
  **distribuerer ikke** regler — brukeren legger dem i `rules/sigma/`.

### YARA-X — github.com/VirusTotal/yara-x
- **Lisens:** BSD-3-Clause.
- **Vedlikehold:** svært aktiv; 1.0 stabil (jun 2025), 1.16+ gjennom 2026.
  Rust-reimplementasjon, kjøres i produksjon hos VirusTotal.
- **SDK:** offisielle `yara-x` Python-bindinger (PyPI), Python 3.8+ Linux/Mac/Win.
- **Verdikt:** **Integrasjon.** Foretrukket fremfor klassisk YARA (nyere, raskere,
  vedlikeholdt). Agent 2 kompilerer brukerens regler og skanner innhold samlet
  fra eksplisitt godkjente kataloger. Valgfri avhengighet — degraderer pent.

---

## Prinsipper bak valgene

1. **Agentløst først.** Vi antar at vi bare har autentisert SSH/WinRM mot en
   godkjent maskin. Tunge agent/server-plattformer (Wazuh, FleetDM, full
   Greenbone) blir derfor valgfrie integrasjoner/eksportmål, ikke kjerne.
2. **Lisens-hygiene.** Kjernen holder seg til tillatende/ svakt-copyleft
   komponenter. AGPL (Velociraptor) og tung GPL-infrastruktur isoleres bak
   valgfrie broer, og regelinnhold (DRL/Sigma, YARA) distribueres aldri med koden.
3. **Kali-passform.** Alt i kjernen kjører på en standard Kali-boks med Python +
   `nmap`; Lynis og YARA-X hentes med `apt`/`pip`.
4. **Read-only og reviderbart.** Verktøy som *rapporterer* (Lynis, Sigma, YARA-X,
   `nmap --script vuln`) foretrekkes over verktøy som *endrer* tilstand.

## Oppdatering 2026-11-18: hva som faktisk ble integrert

| Prosjekt | Status i koden |
|---|---|
| Lynis | Integrert (`analyzer/lynis.py`, valgfri kommando). Parseren er testet, selve Lynis-kjøringen er ikke prøvd. |
| Sigma | Integrert med egen evaluator. pySigma viste seg å ikke ha en matcher for hendelser i minnet, bare konvertering til SIEM-spørringer, så den brukes kun til validering. |
| YARA-X | Integrert mot filer fra godkjente kataloger. |
| OSV (osv.dev) | Lagt til som kilde for kjente sårbarheter i stedet for en full Greenbone-installasjon: ett HTTP-API, ingen lokal skanner. Kali har ikke eget OSV-økosystem. |
| osquery, Wazuh, FleetDM, Velociraptor, Greenbone | Uendret: ikke integrert. |
