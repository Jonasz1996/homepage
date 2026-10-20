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

Snapshots verwijderen vanuit **hw → snapshots** vraagt daarnaast `VM.Snapshot`
(`pveum role modify HomepagePower -privs VM.PowerMgmt,VM.Snapshot`; bestaat de rol al met meer rechten, voeg het er dan bij).

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

Later, deel 1 (tijdlijn, weekrapport en updates):

- **tijdlijn** (knop `history` in de titelbalk): storingen met hun duur, herstarts van nodes en het starten of stoppen
  van VM's/CT's (uit de uptime in Proxmox), gemaakte back-ups, geïnstalleerde updates, acties en wijzigingen aan het
  dashboard, per dag en met filter. Blijft een jaar staan, ook als je de meldingen wist. Het mini dashboard van een
  service toont zijn eigen laatste gebeurtenissen. Een herstarte node geeft één melding, met wat er daarna opkwam en
  wat niet
- **weekrapport** (`history` → weekrapport): uptime per service zonder onderhoud, traagste services, aantal en langste
  storing, gemaakte en gemiste back-ups, herstarts, updates en opslag die vol loopt. Elke maandag vanaf 8 uur komt de
  samenvatting van de vorige week in het meldingencentrum; klik erop voor het volledige rapport
- **updates** (knop `apt` in de titelbalk, met teller; `↑n` op de tegel): elke 6 uur of met "nu controleren".
  Proxmox-nodes en PBS via hun eigen API, andere machines via SSH (bij de host in de terminal: *updates opvolgen*,
  apt of apk). Op een Proxmox-node kan dat meteen voor alle draaiende containers (via `pct exec`). Portainer meldt
  welke containers een nieuwer image hebben (Portainer 2.20 of nieuwer). Beveiligingsupdates in het oranje.
  Containers krijgen hun teller op de tegel met dezelfde naam

  Rechten: het Proxmox-token heeft voor de lijst met updates `Sys.Modify` op `/nodes` nodig
  (`pveum role add HomepageApt -privs Sys.Modify && pveum aclmod /nodes -user homepage@pve -role HomepageApt`); het
  PBS-token van hierboven mag het al. Zonder die rechten staat er een duidelijke melding bij die machine en werkt de
  rest gewoon
- **updates installeren** (in `apt`): vink machines en containers aan en klik *installeren*. Eerst een snapshot
  (containers op een node met `pct snapshot` via SSH; een SSH-host die zelf een VM/CT is via de Proxmox-API, daarvoor
  heeft het token `VM.Snapshot` en `VM.Snapshot.Rollback` nodig), dan `apt-get upgrade` (op Proxmox en PBS
  `dist-upgrade`), met de uitvoer live. Daarna worden de services met dezelfde naam of hetzelfde IP nagekeken. Faalt
  apt of is een service down, dan krijg je een melding en zet *terugdraaien* de machine terug naar de snapshot.
  Fysieke nodes kunnen geen snapshot: dat moet je bewust kiezen (*toch installeren zonder snapshot*). Optioneel
  *alleen beveiligingsupdates*. Onder *'s nachts*: elke nacht om een gekozen uur de beveiligingsupdates, alleen waar
  een snapshot kan; gaat het mis, dan draait de homepage zelf terug. Eigen snapshots (`hp-upd-…`) van geslaagde
  installaties verdwijnen na 7 dagen (instelbaar)
- **zelfherstel** (in het mini dashboard van een service): "als Plex 3 checks na elkaar down is, herstart CT 105".
  Acties: de knoppen van de integraties (Proxmox herstart of start een VM/CT, Portainer herstart een container) of
  via SSH `systemctl restart` / `docker restart`. Hoogstens 2 keer per uur (instelbaar), minstens 10 minuten
  ertussen, niet als iets waar de service van afhangt plat ligt. Elke poging komt in het meldingencentrum; bij de
  limiet pauzeert de regel met een melding. *Nu testen* voert de actie één keer uit

Later, deel 2 (internet, Wake-on-LAN en stroom):

- **internet** (knop `net` in de titelbalk, met een groen, oranje of rood bolletje): het publieke IP met sinds wanneer
  en de vorige IP's (elke 5 minuten via Cloudflare, melding als het verandert; uitzetten met
  `HOMEPAGE_PUBLIC_IP_CHECK=false`), de WAN-gateways uit OPNsense en je Cloudflare-tunnels. Een gateway of tunnel die
  down gaat of terugkomt geeft een melding, pas als dat twee keer na elkaar (2 minuten) gezien wordt
- **OPNsense** (type `opnsense`, geheimen `key` en `secret` van een API-key): WAN-status, latency en verlies op de
  tegel, alle gateways en de firmwarestatus in het mini dashboard. Firmware-updates tellen mee in `apt`
- **Cloudflare Tunnel** (type `cloudflared`, instelling `account` = account-id, geheim `token` = API-token met
  *Account → Cloudflare Tunnel → Read*): status, verbindingen en datacenters per tunnel
- **Wake-on-LAN**: zet bij een service (bv. een HP-node) onder bewerken → Monitoring het MAC-adres. Wekken kan dan
  vanuit het mini dashboard, het netwerkoverzicht of met `Ctrl+K` → "wekken"; het vraagt je 2FA als je langer dan 15
  minuten niet bevestigd hebt. Werkt niet het standaard-broadcastadres in jouw netwerk, zet dan `"wol_broadcast":
  "192.168.0.255"` in de instellingen van die service. De machine moet WoL aan hebben in het BIOS
- **stroomverbruik** (type `homeassistant`, geheim `token` = long-lived access token): per node een sensor met het
  vermogen in W, en als je die hebt een energiesensor in kWh. Instellingen bv.
  `{"price": 0.30, "nodes": {"pve50": {"power": "sensor.pve50_power", "energy": "sensor.pve50_energy"}, "pve51": "sensor.pve51_power"}}`.
  Op de tegel het verbruik nu; in `df` per node watt, gemiddelde over 24 u, kWh en kost deze maand, een prognose voor
  de hele maand en een staafje per dag. Zonder energiesensor rekent het dashboard de kWh uit zijn eigen metingen om de
  10 minuten (aangeduid met ≈)

Later, deel 3 (Authentik en gsm):

- **inloggen met Authentik**: maak in Authentik een *OAuth2/OpenID Provider* (type confidential, signing key
  ingesteld) met als redirect-URI `https://homepage.jbogaert.be/api/auth/oidc/callback`, en een application met slug
  bv. `homepage`. Vul in het dashboard bij ⚿ → *authentik* de issuer in
  (`https://auth.jbogaert.be/application/o/homepage/`), de client-id en het client secret en zet het aan; het
  dashboard toont daar ook de exacte redirect-URI. Alleen bestaande gebruikers met 2FA kunnen zo binnen, de
  gebruikersnaam bij Authentik moet dezelfde zijn. Standaard moet Authentik in het ID-token melden dat er een tweede
  factor gebruikt is (`amr`, zit erin als je flow een authenticator-validatie-stap heeft); dat kan je uitzetten als
  je dat bewust bij Authentik regelt. Inloggen met wachtwoord en 2FA blijft altijd werken
- **SSH-terminal** (knop `>_`), het beste van PuTTY en RDM in de browser:
  - **⟳ pve** haalt alle nodes, containers en VM's met hun IP uit je Proxmox-tegels (VM's via de QEMU guest agent),
    in mappen per node. Onder ⚙ standaard kan dat elk half uur automatisch: nieuwe machines erbij, IP's bijgewerkt
  - **⚙ standaard**: één gebruiker, wachtwoord en/of sleutel voor elke host zonder eigen login; per host te
    overschrijven onder ✎
  - selecteren = kopiëren, rechtsklik = plakken, middenklik = laatste selectie plakken, Ctrl+Shift+C/V. Over gewoon
    http mag de browser het klembord niet lezen: dan plakt rechtsklik je laatste selectie en Ctrl+V het klembord
  - snel verbinden (`root@192.168.0.50:22`), zoeken in de hosts, snippets (opgeslagen commando's), typen in alle tabs
    tegelijk, zoeken in de uitvoer (Ctrl+Shift+F), lettergrootte (Ctrl+scroll), tab dupliceren (Ctrl+Shift+D), van tab
    wisselen (Ctrl+Shift+←/→), klikbare links, de uitvoer opslaan als .log, bevestiging bij het plakken van meerdere
    regels, keepalive zodat een stille sessie niet wegvalt
- **cron** (knop in de titelbalk): alles wat er gepland staat op al je machines, elk kwartier opnieuw gescand
  - via SSH (de standaard login, als root) op elke host waarvan je de hostsleutel al bevestigde; een Proxmox-node
    neemt ook zijn draaiende containers mee (`pct exec`). Gelezen worden crontabs, `/etc/cron.d`, cron.daily en
    co, systemd-timers (met hun laatste run en uitvoer), Proxmox-back-up- en replicatiejobs en de sync-, verify-,
    prune- en GC-jobs van PBS met hun taken. Ook de scripts die een job aanroept worden gelezen
  - per job het schema in gewone taal ("ma–vr om 03:30"), de volgende keren in de tijdzone van de machine, de
    laatste runs en waar hij aan komt (rsync naar de NAS, back-up naar pbs-pi, rclone naar Google Drive, ...)
  - **mislukt** (exitcode, PBS/Proxmox-taak) en **niet gelopen** (de geplande keer ontbreekt in de cronlog) geven
    een melding; nieuwe, gewijzigde en verdwenen jobs komen op de tijdlijn. Per job "meldingen uit"
  - **bewaken**: zet een cronregel via `/usr/local/bin/hp-cron`, dan meldt elke run zijn exitcode, duur en
    uitvoer. Alleen die ene regel wordt aangepast, met eerst een kopie in `/var/backups/hp-cron/`. Uitzetten zet
    de regel terug zoals hij was
  - **▶ nu uitvoeren** met live uitvoer (vraagt een recente 2FA), en **live**: de cronlog van een machine terwijl
    hij binnenkomt, met de uitvoer van bewaakte jobs
  - **agenda**: per machine wat wanneer loopt, met de zware jobs (back-ups, syncs, verify, gc) apart en een lijst
    van **botsingen**: zware jobs die tegelijk dezelfde datastore of machine belasten
  - **verbanden**: wat van welke machine naar welke andere gaat, als schema en als lijst
- **hw** (knop in de titelbalk): gezondheid van de hardware en van de homepage zelf
  - **schijven**: elke 10 minuten SMART van elke schijf (vervangen en wachtende sectoren, onherstelbare fouten,
    slijtage van SSD's en NVMe, uren in gebruik) en de ZFS-pools (status, vulling, laatste scrub). Via SSH als root
    op de fysieke machines uit de terminal; containers en VM's worden overgeslagen, slapende harde schijven niet
    gewekt (`smartctl -n standby`). Nodig op elke node: `apt install smartmontools` (staat al op Proxmox)
  - **temperatuur**: processor en schijven, 30 dagen grafiek, melding boven de grens (standaard 85 °C en 55 °C).
    Op een Raspberry Pi ook **throttling en te lage spanning** (nu en sinds het opstarten)
  - een melding als een schijf achteruitgaat (een teller stijgt, slijtage voorbij 80/90/95 %), een pool slechter
    wordt of een scrub fouten vindt
  - **snapshots**: elke 6 uur alle snapshots van VM's en CT's via de Proxmox-API, met hun leeftijd. Ouder dan 14 dagen
    (instelbaar) = vergeten, met een melding. Verwijderen kan vanuit het overzicht (recente 2FA); daarvoor heeft het
    Proxmox-token het recht `VM.Snapshot` nodig (zet het bij in de eigen rol van `homepage@pve`)
  - **domeinen**: dagelijks vervaldatum, registrar en nameservers via RDAP (rdap.org). Meldingen 30, 7 en 1 dag op
    voorhand, en als de nameservers veranderen. DNS Belgium geeft voor .be geen vervaldatum: vul die zelf in
  - **homepage zelf**: leeft de worker (zo niet, dan meldt de API het), is er een back-up van vannacht en is die
    leesbaar (`pg_restore --list`), hoe groot is de database per tabel, hoe vol de schijf
  - **kopie buiten de container**: elk uur de nieuwste dumps naar `/mnt/homepage-backup`, samen met `secret.key`
    versleuteld met een wachtzin die nergens bewaard wordt (scrypt + AES-GCM). Koppel er een NAS-share, PBS-opslag of
    USB-schijf aan, bv. `pct set <id> -mp0 /mnt/nas/homepage,mp=/mnt/homepage-backup` en
    `chown homepage: /mnt/homepage-backup` in de container, daarna `systemctl restart homepage-worker`. Terugzetten
    staat in `LEESMIJ.txt` in die map
- **diff** (knop in de titelbalk): configuratiewijzigingen. Elke nacht (standaard om 2:00) een kopie van de
  config.xml van OPNsense, de proxy hosts, redirections en streams van Nginx Proxy Manager, de `.conf` van elke VM en
  container in Proxmox, en de bestanden of mappen die je zelf kiest op een SSH-host (bv. `/etc/nginx`, als root gelezen,
  alleen tekstbestanden tot 256 kB). Een nieuwe versie wordt alleen bewaard als er iets veranderd is: dan een melding
  en een regel op de tijdlijn. Per configuratie de versies met een gekleurde diff (wachtwoorden en sleutels
  gemaskeerd), twee willekeurige versies vergelijken, en een oude versie volledig downloaden (recente 2FA). De
  laatste 90 versies per bestand blijven bewaard, versleuteld. Voor OPNsense heeft de API-key het recht
  *Diagnostics: Configuration History* nodig
- **net → apparaten**: elke 5 minuten de ARP- en DHCP-tabel van OPNsense (ISC en Kea), met IP, MAC, fabrikant,
  hostnaam en interface. Wat er bij de eerste keer al is, geldt als gekend; een nieuw MAC-adres daarna geeft een
  melding. Geef apparaten een naam of zet ze op "ken ik". Met **volgen** wordt een apparaat elke 6 uur gescand op
  ongeveer 60 gebruikelijke poorten (ssh, http, smb, rdp, docker, databanken, ...) en komt er een melding als er een
  nieuwe poort openstaat. Rechten voor de API-key: *Diagnostics: ARP Table* en *Services: DHCP: Leases* (of
  *Services: Kea DHCP*)
- **effecten** zoals in aiverslag: een achtergrond van punten en 0/1 die voor de muis wijken, een ripple op elke knop,
  bliksem en vonken bij een geslaagde actie (herstarten, wekken), een vuurbal met flits en schudden bij verwijderen
  en uitloggen, en een bliksem op het belletje als er een nieuwe storing binnenkomt. Uit te zetten met `Ctrl+K` →
  "effecten"; staat ook uit als je systeem "minder beweging" vraagt
- **gsm**: onder 760 px breed zitten de knoppen van de titelbalk achter ☰, tegels staan met twee naast elkaar en
  vensters vullen het scherm. Respecteert de notch en de gebarenbalk
- **als app**: in Chrome op Android *Toevoegen aan startscherm* (op iOS via Delen). Eigen icoon, opent zonder
  adresbalk, met snelkoppelingen (lang drukken op het icoon) naar history, updates, net en terminal. Een service
  worker houdt de vormgeving offline beschikbaar; gegevens van `/api` worden nooit bewaard
- **Android-app (WebView)**: laad `https://homepage.jbogaert.be/` en zet `javaScriptEnabled`, `domStorageEnabled` en
  cookies aan (`CookieManager.setAcceptCookie(true)`). Third-party cookies zijn niet nodig:
  alles blijft op dezelfde site als Authentik op een subdomein staat. Rechtstreeks openen kan met
  `/?open=history`, `updates`, `network`, `devices`, `configs`, `cron`, `health` of `terminal`. Links naar andere services kan de app in dezelfde WebView
  openen (`shouldOverrideUrlLoading` false teruggeven voor `*.jbogaert.be`)

Optimalisaties:

- je blijft ingelogd zolang je het dashboard gebruikt (sessie verlengt zich, na 14 dagen niets doen moet je opnieuw inloggen)
- geen verzoeken naar de server zolang het tabblad verborgen is, bij terugkeren meteen verse status
- achter Cloudflare zien login-limiet, audit-log en meldingen het echte IP van de bezoeker
- gzip, beveiligingsheaders op elke response, installeerbaar als app (manifest)
- de worker hergebruikt HTTP-verbindingen en ruimt verlopen sessies, oude audit-regels (1 jaar) en gelezen meldingen (30 dagen) op

## Installeren in een Proxmox-container

Container: Debian 13 (of 12), unprivileged, `nesting=1`, 2 cores, 4 GB RAM, 32 GB disk, vast IP.
Kies een x86-node (niet de Raspberry Pi).

Eén commando als root in de lege container (installeert alles, haalt de code op en start de services):

```bash
apt update && apt install -y curl && bash <(curl -fsSL https://raw.githubusercontent.com/Jonasz1996/homepage/nieuwste/deploy/bootstrap.sh)
```

Het script neemt de branch `nieuwste` (altijd de nieuwste versie, ook als die nog niet gemerged is); bestaat die niet meer, dan `main`.
Hetzelfde commando opnieuw uitvoeren werkt alles bij.

Het script toont op het einde de **setup-code** voor het eerste account.
Maak daarna in Nginx Proxy Manager een proxy host (bv. `home.jbogaert.be` → `http://<IP van de container>:80`)
met SSL en "Websockets Support" aan.

Testen kan meteen op `http://<IP>`. Via NPM met HTTPS is de sessiecookie automatisch `Secure`
(`HOMEPAGE_COOKIE_SECURE=auto`).

Zet in Proxmox de firewall van de container aan en laat poort 80 alleen toe vanaf NPM (192.168.0.245).
nginx gelooft de `X-Forwarded-For`- en `CF-Connecting-IP`-headers enkel van dat adres, maar zo kan
niemand op het LAN NPM en Cloudflare omzeilen. Laat daarnaast poort 514 (udp en tcp) toe vanaf je LAN voor de logs.

**Bewaar een kopie van `/etc/homepage/secret.key`.** Zonder die sleutel zijn de opgeslagen
wachtwoorden, API-sleutels en 2FA-geheimen onleesbaar.

## Bijwerken

Hetzelfde bootstrap-commando opnieuw, of:

```bash
bash /opt/homepage/deploy/bootstrap.sh
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
