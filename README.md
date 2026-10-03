# homepage

Eigen homelab-dashboard in de stijl van aiverslag: een vervanger voor homepage.dev
waarin je alles vanuit de browser beheert.

Fase 1 en 2 van het [stappenplan](https://claude.ai/code/artifact/fe2b226c-d5ef-4cef-9b02-6047fcc63504):

- inloggen met wachtwoord en verplichte 2FA (TOTP), eerste account via een eenmalige setup-code
- pagina's, groepen en services, aanpasbaar in een edit mode met slepen
- import van je homepage.dev `services.yaml` (widget-wachtwoorden en API-sleutels worden versleuteld bewaard)
- export naar YAML, en een versiegeschiedenis van de layout waarmee je elke wijziging terugzet
- eigen meldingencentrum in de titelbalk (bv. login vanaf een nieuw IP)
- zoeken met `Ctrl+K` of `/`, Enter opent het eerste resultaat
- dagelijkse back-up van de database (`/var/backups/homepage`, 14 dagen)

Fase 3, monitoring:

- checks per service: HTTP(S), ping of TCP-poort, met eigen interval (minstens 15 s)
- status, latency en een sparkline op elke tegel; samenvatting "x up · y down" bovenaan
- mini dashboard per service (▤ op de tegel): latency-grafiek met min/max, uptime-strook,
  verstoringen en de laatste checks, over 1 u, 24 u, 7 d, 30 d of 1 jaar
- melding in het meldingencentrum als een service down gaat (na 3 mislukte checks) en weer terugkomt
- historiek: met TimescaleDB 1 jaar (gecomprimeerd na 7 dagen), zonder TimescaleDB 90 dagen

Fase 4, integraties (type van de service kiezen onder **bewerken → Integratie en API**):

| Type | Op de tegel | In het mini dashboard |
| --- | --- | --- |
| `proxmox` | VM's en containers aan, CPU, RAM, offline nodes | nodes, opslag, alle VM's/CT's met start, afsluiten, herstart, forceer stop |
| `proxmoxbackupserver` | opslag, mislukte taken, oudste back-up, verify-fouten | datastores met verwachte "vol"-datum, laatste back-up en verify per VM/CT, mislukte taken |
| `adguard` | verzoeken, % geblokkeerd, latency, bescherming | top geblokkeerde domeinen en clients, bescherming aan/uit |
| `npm` | aantal hosts, eerstvolgende vervaldatum certificaat | certificaten, proxy hosts, **import van proxy hosts als tegels** |
| `portainer` | omgevingen, draaiende en gestopte containers | containers per omgeving met start, stop, herstart |
| `json` / `customapi` | zelfgekozen velden uit een JSON-API | dezelfde velden plus het ruwe antwoord |

Acties (VM herstarten, AdGuard uitzetten, ...) vragen je 2FA-code als je langer dan 15 minuten
niet bevestigd hebt, en komen in de audit-log en het meldingencentrum. Widgets uit je homepage.dev-import
gebruiken dezelfde namen (`url`, `username`, `password`) en werken meteen zodra de geheimen kloppen.

Een token voor Proxmox VE (op een node, alleen-lezen plus aan/uitzetten):

```bash
pveum user add homepage@pve
pveum aclmod / -user homepage@pve -role PVEAuditor
pveum role add HomepagePower -privs VM.PowerMgmt && pveum aclmod /vms -user homepage@pve -role HomepagePower
pveum user token add homepage@pve dashboard --privsep 0
```

Gebruik `homepage@pve!dashboard` als `username` en het getoonde geheim als `password`.
Voor PBS (alleen lezen):

```bash
proxmox-backup-manager user create homepage@pbs
proxmox-backup-manager user generate-token homepage@pbs dashboard
proxmox-backup-manager acl update / Audit --auth-id 'homepage@pbs!dashboard'
```

Fase 5, SSH-terminal (knop `>_` in de titelbalk):

- hosts beheren (naam, IP, poort, gebruiker, sleutel of wachtwoord), tabbladen met meerdere sessies tegelijk
- sleutels maken (ed25519) of een bestaande plakken; de private sleutel staat versleuteld in de database
  en komt nooit in de browser. Kopieer de publieke sleutel naar `~/.ssh/authorized_keys` op de host
- hostsleutel wordt bij de eerste verbinding getoond en pas na jouw bevestiging bewaard; verandert hij
  later, dan weigert de terminal te verbinden (bescherming tegen man-in-the-middle)
- een terminal openen vraagt je 2FA-code als je langer dan 15 minuten niet bevestigd hebt;
  na 30 minuten zonder typen wordt de sessie gesloten; openen en sluiten komen in de audit-log
- koppel een host aan een service, dan staat er een `>_`-knop in het mini dashboard van die service

Fase 6, logs (knop `logs` in de titelbalk):

- eigen syslog-ontvanger op poort 514 (udp en tcp, service `homepage-syslog`), alleen van je eigen netwerken
- alle regels in PostgreSQL; met TimescaleDB gecomprimeerd na 3 dagen en 30 dagen bewaard
- logviewer: per machine, zoeken, filter op ernst, 1 u tot 30 dagen, histogram, live meekijken
- meldingsregels (regex, machine, ernst, max. één melding per x minuten) naar het meldingencentrum;
  standaard staat "alles vanaf crit" aan
- **machines toevoegen**: kies een SSH-host en het dashboard installeert en configureert rsyslog. Op een
  Proxmox-node kan dat meteen voor alle draaiende containers (via `pct`). Of plak het getoonde script zelf

Extra's, deel 1 (checks en meldingen):

- **certificaten**: elke HTTPS-check leest de vervaldatum; op de tegel vanaf 21 dagen, melding 14 en 3 dagen vooraf
- **onderhoud**: per service (mini dashboard) of per groep (⏸ in bewerkmodus) voor x minuten. Geen meldingen,
  tegel oranje, telt niet mee voor de uptime, en geldt ook voor alles wat ervan afhangt
- **afhankelijkheden**: kies bij een service "hangt af van" (bv. de Proxmox-node). Valt de node uit, dan krijg je
  één melding "proxmox100 is down (23 services getroffen)" en tonen de andere tegels "down via proxmox100"
- **slimmere checks**: woord op de pagina (of juist niet), JSON-veld met verwachte waarde, DNS-check via een
  gekozen server (bv. AdGuard) met verwacht IP
- **nieuwe hosts in NPM**: elk half uur kijkt de worker of er proxy hosts bij zijn die nog geen tegel hebben

Extra's, deel 2 (beheer):

- **beveiliging** (⚿ in de titelbalk): alle apparaten waar je ingelogd bent, met IP, land (van Cloudflare),
  browser en laatst actief; één of alle andere afmelden (vraagt 2FA). Plus de auditlog met filter, en
  je wachtwoord wijzigen (meldt andere apparaten af)
- **notities** per service in Markdown (mini dashboard → Notities): hoe herstellen, waar de config staat, ...
  Zoeken met `Ctrl+K` doorzoekt ook de notities
- **snelle acties** in de zoekbalk: typ bv. `herstart vaultwarden` of `start 101` en klik, zonder het mini
  dashboard te openen. Ook `logs`, `terminal`, `beveiliging`. Enter voert de eerste uit als er geen tegel past
- **Portainer**-integratie (type `portainer`, geheim `key` = API-sleutel): omgevingen, draaiende en gestopte
  containers, en containers starten, stoppen of herstarten

Extra's, deel 3 (back-ups en capaciteit):

- **back-ups (PBS)**: per VM/CT de laatste back-up en de verify-status. Oranje als de laatste back-up ouder is dan
  26 uur, rood bij een mislukte back-up of verify (of na 3 dagen niets). Elk half uur kijkt de worker en meldt nieuwe
  problemen één keer in het meldingencentrum
- **capaciteit** (knop `df` in de titelbalk): de worker bewaart elke 10 minuten CPU, RAM en schijf van alle nodes,
  VM's/CT's en opslag uit Proxmox (met TimescaleDB 180 dagen, gecomprimeerd na 7 dagen). Per opslag een trend over
  7 dagen en "vol over x dagen"; melding als iets binnen 14 dagen en nog eens binnen 3 dagen vol loopt. Na een grote
  opkuis telt alleen de trend van daarna

Optimalisaties:

- je blijft ingelogd zolang je het dashboard gebruikt (sessie verlengt zich, na 14 dagen niets doen moet je opnieuw inloggen)
- geen verzoeken naar de server zolang het tabblad verborgen is, bij terugkeren meteen verse status
- achter Cloudflare zien login-limiet, audit-log en meldingen het echte IP van de bezoeker
- gzip, beveiligingsheaders op elke response, installeerbaar als app (manifest)
- de worker hergebruikt HTTP-verbindingen en ruimt verlopen sessies, oude audit-regels (1 jaar) en gelezen meldingen (30 dagen) op

## Installeren in een Proxmox-container

Container: Debian 13 (of 12), unprivileged, `nesting=1`, 2 cores, 4 GB RAM, 32 GB disk, vast IP.
Kies een x86-node (niet de Raspberry Pi).

```bash
apt update && apt install -y git
git clone https://github.com/Jonasz1996/homepage /opt/homepage
bash /opt/homepage/deploy/install.sh
```

Het script toont op het einde de **setup-code** voor het eerste account.
Maak daarna in Nginx Proxy Manager een proxy host (bv. `home.jbogaert.be` → `http://<IP van de container>:80`)
met SSL en "Websockets Support" aan.

Inloggen werkt alleen via HTTPS. Wil je eerst rechtstreeks via `http://<IP>` testen, zet dan
`HOMEPAGE_COOKIE_SECURE=false` in `/etc/homepage/homepage.env` en voer `systemctl restart homepage-api` uit.

Zet in Proxmox de firewall van de container aan en laat poort 80 alleen toe vanaf NPM (192.168.0.245).
nginx gelooft de `X-Forwarded-For`- en `CF-Connecting-IP`-headers enkel van dat adres, maar zo kan
niemand op het LAN NPM en Cloudflare omzeilen. Laat daarnaast poort 514 (udp en tcp) toe vanaf je LAN voor de logs.

**Bewaar een kopie van `/etc/homepage/secret.key`.** Zonder die sleutel zijn de opgeslagen
wachtwoorden, API-sleutels en 2FA-geheimen onleesbaar.

## Bijwerken

```bash
cd /opt/homepage && git pull && bash deploy/install.sh
```

## Opbouw

| Map | Inhoud |
| --- | --- |
| `backend/` | FastAPI, SQLAlchemy (async), Alembic-migraties, tests. De checks draaien in `app/monitoring/worker.py` (service `homepage-worker`) |
| `frontend/` | Svelte 5 + Vite. Kleuren en stijl staan in `src/app.css` |
| `deploy/` | Installatiescript, nginx-config, systemd-units |

De database is PostgreSQL. TimescaleDB wordt al geïnstalleerd voor de ping- en uptime-historiek van fase 3.

## Ontwikkelen

```bash
python3 -m venv .venv && .venv/bin/pip install -e "backend[dev]"
cd backend && ../.venv/bin/pytest            # tests op SQLite
HOMEPAGE_TEST_DATABASE_URL=postgresql+asyncpg://... ../.venv/bin/pytest   # tests op PostgreSQL

cd frontend && npm ci && npm run dev         # proxy't /api naar 127.0.0.1:8000
```
