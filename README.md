# homepage

Eigen homelab-dashboard in de stijl van aiverslag: een vervanger voor homepage.dev
waarin je alles vanuit de browser beheert.

Fase 1 en 2 van het [stappenplan](https://claude.ai/code/artifact/fe2b226c-d5ef-4cef-9b02-6047fcc63504):

- inloggen met wachtwoord en verplichte 2FA (TOTP), eerste account via een eenmalige setup-code. Bevestigen (een
  actie, de terminal, een geheim wijzigen) gebeurt altijd met je 2FA-code, nooit met je wachtwoord
- **bekende toestellen**: een toestel waarop je al met 2FA inlogde, krijgt een cookie (`hp_device`, een jaar geldig,
  bij elke login vernieuwd). Daar geldt de limiet van 30 foute pogingen per gebruikersnaam niet, die iedereen kan
  vullen, maar wel die per IP (5), per toestel (5) en op 2FA-codes (5). Zit de gebruikersnaam op slot, dan moeten
  alleen nieuwe toestellen wachten, en krijg je één melding "Inloggen dicht voor nieuwe toestellen". Een
  privévenster, een andere browser, gewiste cookies of de iPhone-app op je beginscherm (tot die één keer inlogde)
  tellen als nieuw. Je wachtwoord wijzigen of `secret.key` vervangen maakt alle andere toestellen weer onbekend;
  afmelden niet. Een herstart van `homepage-api` wist alle slots (de tellers staan in het geheugen). Hoogstens 8
  wachtwoordcontroles wachten tegelijk; daarboven antwoordt het dashboard "Even te druk, probeer zo opnieuw"
- pagina's, groepen en services, aanpasbaar in een edit mode met slepen
- import van je homepage.dev `services.yaml` (widget-wachtwoorden en API-sleutels worden versleuteld bewaard)
- export naar YAML, en een versiegeschiedenis van de layout waarmee je elke wijziging terugzet
- eigen meldingencentrum in de titelbalk (bv. login vanaf een nieuw IP). *Wis gelezen* laat meldingen staan die nog
  niet naar je gsm gestuurd zijn
- zoeken met `Ctrl+K` of `/`, Enter opent het eerste resultaat
- dagelijkse back-up van de database, zonder de logregels (`/var/backups/homepage`, de 5 nieuwste blijven)

Fase 3, monitoring:

- checks per service: HTTP(S), ping, TCP-poort, DNS, push, Docker-container of de API van de tegel, met eigen
  interval (minstens 15 s); zie [Uptime Kuma vervangen](#uptime-kuma-vervangen)
- status, latency en een sparkline op elke tegel; samenvatting "x up · y down" bovenaan
- mini dashboard per service (▤ op de tegel): latency-grafiek met min/max, uptime-strook,
  verstoringen en de laatste checks, over 1 u, 24 u, 7 d, 30 d of 1 jaar
- melding in het meldingencentrum (en op je gsm) als een service down gaat (standaard na 3 mislukte checks) en weer
  terugkomt
- historiek: elke check 90 dagen, per uur opgeteld 400 dagen (genoeg voor de grafiek en de uptime over een jaar);
  met TimescaleDB gecomprimeerd na 7 dagen. Zonder TimescaleDB blijft alles even lang bewaard en ruimt het dashboard
  zelf op, maar wordt niets gecomprimeerd

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

**Twee tokens voor Proxmox VE** (aanbevolen, op een node): een alleen-lezen token voor monitoring, capaciteit, de
kaart en de cluster, en een apart token voor wat iets verandert (aan/uit, snapshots, updates, de hersteltest). Lekt
het leestoken, dan kan niemand iets uitzetten. Het dashboard kiest per verzoek het juiste:

```bash
# alleen lezen
pveum user add homepage@pve
pveum aclmod / -user homepage@pve -role PVEAuditor
pveum user token add homepage@pve dashboard --privsep 0
# acties
pveum user add homepage-acties@pve
pveum role add HomepageActies -privs "VM.Audit VM.PowerMgmt VM.Snapshot VM.Snapshot.Rollback VM.Allocate VM.Config.Disk VM.Config.Network VM.Config.Options Sys.Audit Sys.Modify Datastore.Audit Datastore.AllocateSpace"
pveum aclmod /vms -user homepage-acties@pve -role HomepageActies
pveum aclmod /nodes -user homepage-acties@pve -role HomepageActies
pveum aclmod /storage -user homepage-acties@pve -role HomepageActies
pveum user token add homepage-acties@pve acties --privsep 0
```

Bij de Proxmox-API (of -tegel): `username` = `homepage@pve!dashboard` en `password` = het geheim van dat token;
`action_username` = `homepage-acties@pve!acties` en `action_password` = het geheim van het tweede. `Sys.Modify` is
er voor de lijst met updates (Proxmox vraagt dat recht om ze te lezen), `VM.Allocate`, `VM.Config.*` en
`Datastore.AllocateSpace` alleen voor de hersteltest. **hw → beveiliging** kijkt na of het leestoken echt niets
kan veranderen.

Eén token voor alles werkt ook nog (zonder `action_username`), maar dat token heeft dan schrijfrechten:

```bash
pveum user add homepage@pve
pveum aclmod / -user homepage@pve -role PVEAuditor
pveum role add HomepagePower -privs VM.PowerMgmt,VM.Snapshot,VM.Snapshot.Rollback && pveum aclmod /vms -user homepage@pve -role HomepagePower
pveum user token add homepage@pve dashboard --privsep 0
```
Voor PBS (alleen lezen):

```bash
proxmox-backup-manager user create homepage@pbs
proxmox-backup-manager user generate-token homepage@pbs dashboard
proxmox-backup-manager acl update / Audit --auth-id homepage@pbs
proxmox-backup-manager acl update / Audit --auth-id 'homepage@pbs!dashboard'
```

Fase 5, SSH-terminal (knop `>_` in de titelbalk):

- hosts beheren (naam, IP, poort, gebruiker, sleutel of wachtwoord), tabbladen met meerdere sessies tegelijk
- sleutels maken (ed25519) of een bestaande plakken; de private sleutel staat versleuteld in de database
  en komt nooit in de browser. Kopieer de publieke sleutel naar `~/.ssh/authorized_keys` op de host
- **vastzetten** (sleutels → vastzetten op het dashboard): zet `from="<IP van het dashboard>"` voor de sleutel in
  `authorized_keys` op elke host, zodat een gestolen sleutel alleen nog vanaf de dashboard-container werkt. Het IP
  is wat de host zelf als afzender ziet (`SSH_CLIENT`). Het oude bestand blijft als
  `~/.ssh/authorized_keys.homepage-bak`; kan het dashboard er daarna niet meer in, dan zet het dat meteen terug. Op
  een Proxmox-node is `authorized_keys` een link naar `/etc/pve/priv` en geldt het voor de hele cluster. Gebruik je
  een geïmporteerde sleutel ook vanaf je pc, zet hem dan niet vast. In `from=` komen alleen losse IP-adressen: wat
  de host als afzender ziet, wat andere hosts zagen en het eigen IP van de container. Geeft een host iets anders door,
  dan zet het dashboard niets vast. Een `from=` met een patroon, netwerk of naam toont het als *elk IP*: zet die
  sleutel opnieuw vast
- hostsleutel wordt bij de eerste verbinding getoond en pas na jouw bevestiging bewaard; verandert hij
  later, dan weigert de terminal te verbinden (bescherming tegen man-in-the-middle)
- een terminal openen vraagt je 2FA-code als je langer dan 15 minuten niet bevestigd hebt;
  na 30 minuten zonder typen wordt de sessie gesloten; openen en sluiten komen in de audit-log
- koppel een host aan een service, dan staat er een `>_`-knop in het mini dashboard van die service

Fase 6, logs (knop `logs` in de titelbalk):

- eigen syslog-ontvanger op poort 514 (udp en tcp, service `homepage-syslog`), alleen van je eigen netwerken
- alle regels in PostgreSQL; met TimescaleDB gecomprimeerd na 1 dag en 30 dagen bewaard. Zit de schijf van de
  container boven 75%, dan gaan de oudste logregels eerder weg (de laatste 3 dagen blijven altijd). De dagelijkse
  back-up neemt de logregels niet mee
- logviewer: per machine, zoeken, filter op ernst, 1 u tot 30 dagen, histogram, live meekijken. Een zoekopdracht
  stopt na 20 seconden (live meekijken en de lijst met machines na 5) en gebruikt maar één processorkern; is het te
  traag, kies dan een kortere periode of één machine
- valt de database even weg, dan houdt de ontvanger tot 50.000 regels in het geheugen en schrijft ze weg zodra ze
  terug is, ook bij een herstart (dan schrijft hij tot 10 seconden zijn wachtrij weg). Over tcp wacht de afzender
  (rsyslog houdt de regels dan zelf vast), over udp gaan de oudste regels weg en worden ze geteld. Raken er regels
  verloren of draait de ontvanger niet, dan staat dat in **!** en in hw → homepage zelf
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
  je wachtwoord wijzigen (vraagt je 2FA-code, meldt andere apparaten af en geeft een melding)
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
- **één node 's nachts uit** (onderaan het venster `df`, knop "voorstel berekenen"): per node of hij leeg kan als zijn
  VM's en CT's naar de andere nodes verhuizen, op basis van de piek-RAM van de laatste 7 dagen met 20% marge en 2 GB
  voor Proxmox zelf. Een gast met passthrough (PCI, USB, een apparaat in een CT) houdt een node aan; de Pi (ARM) en de
  HP's (x86) wisselen geen gasten uit. Je krijgt de `qm migrate`/`pct migrate`-commando's, de lokale schijven en bind
  mounts om op te letten, wat het bespaart (verbruik uit Home Assistant, anders geschat op 25 W) en een cronregel met
  `rtcwake` die de node 's avonds uitzet en de BIOS hem 's ochtends weer laat aanzetten. Alleen advies: het dashboard
  verhuist zelf niets

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

  Rechten: Proxmox vraagt voor de lijst met updates `Sys.Modify` op `/nodes`. Met twee tokens gebruikt het dashboard
  daar het actietoken (dat heeft het al); met één token: `pveum role add HomepageApt -privs Sys.Modify && pveum aclmod
  /nodes -user homepage@pve -role HomepageApt`. Het
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
  via SSH `systemctl restart` / `docker restart`. Hoogstens 2 keer per uur (instelbaar tot 5), minstens 10 minuten
  ertussen, niet als iets waar de service van afhangt plat ligt. Elke poging komt in het meldingencentrum en op de
  tijdlijn; naar je gsm gaat per storing alleen de eerste poging, een herstart die eerst lukte en daarna mislukt, en
  de eerste keer dat de limiet de regel pauzeert. De meldingen volgen *Melden* van de tegel. *Nu testen* voert de
  actie één keer uit

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
  dashboard toont daar ook de exacte redirect-URI. Alleen bestaande gebruikers met 2FA kunnen zo binnen, en
  alleen met het Authentik-account dat ze zelf gekoppeld hebben: log in met wachtwoord en 2FA en kies ⚿ →
  *authentik* → *Koppel Authentik-account* (vraagt je 2FA-code, en Authentik vraagt opnieuw wie je bent). Het
  dashboard herkent het account aan zijn vaste ID (`sub`), niet aan de naam; zet in Authentik bij de provider
  *Subject mode* op *Based on the User's hashed ID* (met username of e-mail weigert het dashboard te koppelen). Koppel
  vanaf het adres in de redirect-URI. Maak je je Authentik-gebruiker opnieuw aan of verander je de issuer, koppel dan
  opnieuw. *Naam tonen uit claim* dient alleen nog om de naam te tonen. Standaard moet Authentik in het ID-token
  melden dat er een tweede factor gebruikt is (`amr`, zit erin als je flow een authenticator-validatie-stap heeft);
  dat kan je uitzetten als je dat bewust bij Authentik regelt. Inloggen met wachtwoord en 2FA blijft altijd werken
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
    leesbaar (`pg_restore --list`), hoe groot is de database per tabel, hoe vol de schijf (oranje vanaf 75%, rood
    vanaf 90%), en telt de worker de checks nog per uur op (anders een waarschuwing in **!** na een dag). De back-up
    van elke nacht (03:30, `homepage-backup`) laat de logregels weg: de tabel is er na het terugzetten wel, maar
    leeg. De 5 nieuwste blijven staan
  - **test van de back-up**: elke 1e van de maand om 04:15 (`homepage-backuptest.timer`) zet de container de
    nieuwste dump echt terug in een tijdelijke database `homepage_backuptest`, kijkt of `alembic_version` en je
    account erin zitten, telt de rijen per tabel en gooit de database daarna altijd weg. Hij slaat over als de schijf
    daardoor boven 70% zou komen, en stopt na een uur. Het resultaat staat in hw → homepage zelf (met de tabellen),
    in `/var/backups/homepage/backuptest` en `backuptest.log`; mislukt het, dan een melding en een rood punt in
    **!**, en een oranje punt als er 40 dagen geen geslaagde test was. Meteen testen: `systemctl start
    homepage-backuptest`
  - **schijfbewaker**: elke 10 minuten kijkt de worker hoe vol de schijf van de container is. Vanaf 75% gooit hij de
    oudste logregels weg, dag per dag, tot de schijf weer onder 75% zit of alleen de laatste 3 dagen nog over zijn.
    Daarover één melding; helpt het niet, dan zegt een melding wat de schijf wel vult (de grootste tabellen en de
    back-ups). Zonder TimescaleDB komt de plaats van verwijderde regels niet terug op de schijf, maar gebruikt
    PostgreSQL ze opnieuw voor nieuwe regels. Staan er bij de back-ups nog meer dan 5 dagelijkse dumps (net na de
    update, met alle logregels erin), dan wacht hij onder 90% op de back-up van 03:30 die ze opruimt; niet
    wachten kan met `systemctl start homepage-backup`
  - **kopie buiten de container**: elk uur de nieuwste dumps naar `/mnt/homepage-backup`, samen met `secret.key`
    versleuteld met een wachtzin die nergens bewaard wordt (scrypt + AES-GCM). Koppel er een NAS-share, PBS-opslag of
    USB-schijf aan, bv. `pct set <id> -mp0 /mnt/nas/homepage,mp=/mnt/homepage-backup` en
    `chown homepage: /mnt/homepage-backup` in de container, daarna `systemctl restart homepage-worker`. Terugzetten
    staat in `LEESMIJ.txt` in die map, met de versies van PostgreSQL en TimescaleDB van de laatste kopie. Verandert
    `secret.key` (bv. na een herinstallatie), stel dan de wachtzin opnieuw in: tot dan meldt de zelfcontrole dat de
    sleutel in de kopie verouderd is. Staat de kopie uit, dan stelt **!** ze voor; zit de CT al in een back-up van
    PBS, dan zitten de dumps en `secret.key` daar ook in en mag je dat punt negeren
- **diff** (knop in de titelbalk): configuratiewijzigingen. Elke nacht (standaard om 2:00) een kopie van de
  config.xml van OPNsense, de proxy hosts, redirections en streams van Nginx Proxy Manager, de `.conf` van elke VM en
  container in Proxmox, en de bestanden of mappen die je zelf kiest op een SSH-host (bv. `/etc/nginx`, als root gelezen,
  alleen tekstbestanden tot 256 kB). Een nieuwe versie wordt alleen bewaard als er iets veranderd is: dan een melding
  en een regel op de tijdlijn. Per configuratie de versies met een gekleurde diff (wachtwoorden en sleutels
  gemaskeerd), twee willekeurige versies vergelijken, en een oude versie volledig downloaden (recente 2FA). De
  laatste 90 versies per bestand blijven bewaard, versleuteld. Voor OPNsense heeft de API-key het recht
  *Diagnostics: Configuration History* nodig
- **webhooks** (in het meldingencentrum ◉ → webhooks): een eigen geheim adres per tool. Proxmox VE (8.3+) en PBS
  (3.3+) sturen hun meldingen (mislukte back-up, replicatie, schijffout, fencing) via *Notifications → Webhook*, Uptime
  Kuma via een Webhook-melding, Home Assistant via `rest_command`. Wat binnenkomt wordt een melding met de juiste
  ernst, eventueel gekoppeld aan een service. Het venster toont per tool de exacte instellingen om te plakken. Een
  adres kan je vernieuwen (het oude werkt dan meteen niet meer); max. 60 meldingen per minuut per adres
- **hw → cluster**: quorum, welke nodes corosync ziet, de Proxmox-versie per node, de stemmen en de QDevice,
  HA-resources en replicatie-jobs, elke 2 minuten via de Proxmox-API (rol PVEAuditor volstaat). Een melding als de
  cluster zijn quorum verliest, een node wegvalt, nodes een andere Proxmox-versie draaien (8.2 naast 8.3; alleen een
  andere patch is een tip), de QDevice niet verbonden is, een HA-resource in error staat of een replicatie mislukt, en
  opnieuw als het weer in orde is. Bij een even aantal stemmen zonder QDevice legt het tabblad uit waarom dat riskant
  is en geeft het de drie commando's om een QDevice op de PBS-Pi te zetten (`corosync-qnetd` op de Pi,
  `corosync-qdevice` op elke node, `pvecm qdevice setup <IP>` op één node)
- **hw → back-ups**: per VM/CT in welke back-upjob van Proxmox hij zit, op hoeveel PBS'en een kopie staat (ook in
  namespaces), hoe oud de nieuwste is en wanneer hij voor het laatst met de hersteltest is teruggezet. Rood: in geen
  enkele job (dan komen er ook geen nieuwe back-ups) of op geen enkele PBS; oranje: maar op één PBS, of een gestopte
  VM/CT zonder job. Elk half uur; de rode staan ook in **!** en tellen mee in de knop hw. Rechten: het Proxmox-leestoken
  (PVEAuditor) en per PBS een tegel met DatastoreAudit
- **PBS-sync** (hw → back-ups): het dashboard stelt voor dat je tweede PBS elke nacht een kopie ophaalt van de PBS
  waar Proxmox naartoe schrijft: welke datastores, een uur waarop geen back-up loopt en of het past. Je krijgt de
  `proxmox-backup-manager`-commando's om te plakken (een gebruiker `homepage-sync@pbs` met alleen leesrecht op de
  bron, een remote en een sync-job op het doel), of één knop die ze zelf via SSH uitvoert (beide PBS'en als SSH-host
  in de terminal, als root; vraagt je 2FA-code, staat van buitenaf uit, komt in het auditlog). Een sync die al bestaat
  ziet het dashboard alleen als het PBS-token ook de rol RemoteAudit op `/remote` heeft. Zet op het doel ook een
  prune-job, anders blijft de kopie groeien
- **gepland onderhoud**: in het mini dashboard van een service (of `Ctrl+K` → "gepland onderhoud" voor groepen)
  onderhoud vooraf plannen: eenmalig, elke dag of op vaste weekdagen (bv. elke zondag 3:00 tot 4:00 tijdens de
  back-up). Een herhalend venster duurt hoogstens 12 uur per keer. Tijdens het venster geen meldingen en telt de
  uptime het niet mee; het begin komt op de tijdlijn
- **incidentnotities**: bij een storing op de tijdlijn of in het mini dashboard noteer je de oorzaak en de oplossing.
  Gaat dezelfde service later weer down, dan toont het mini dashboard die notities meteen bovenaan
- **overal zoeken** met `Ctrl+K`: naast tegels en acties ook notities, cronjobs, SSH-hosts, apparaten,
  configuratiebestanden (in de inhoud, met wachtwoorden gemaskeerd; eigen bestanden alleen op naam) en de logregels
  van de laatste 24 uur, gegroepeerd per soort. Een klik opent het juiste venster (de cronjob, de terminal, het
  apparaat, de diff, de logs met die zoekterm). Typ een IP of MAC en je ziet welk apparaat, welke SSH-host, welke
  NPM-hosts ernaar doorsturen, welke services en welke cronjobs van die machine erbij horen
- **containerlogs uit Portainer** in de logviewer: elke 30 s de nieuwe regels van elke draaiende container, als
  machine met de containernaam (▣) en app `docker`. Zoeken, filters, live meekijken en meldingsregels werken zoals
  bij syslog; de ernst komt uit de regel zelf (ERROR, WARN, ...). Staat standaard uit, want het vult de kleine schijf
  van de container snel: zet het aan per Portainer-tegel met de instelling `logs` = `true` (of in de instellingen
  van de API in API-beheer, dan voor al zijn tegels)
- **net → apparaten**: elke 5 minuten de ARP- en DHCP-tabel van OPNsense (ISC en Kea), met IP, MAC, fabrikant,
  hostnaam en interface. Wat er bij de eerste keer al is, geldt als gekend; een nieuw MAC-adres daarna geeft een
  melding. Geef apparaten een naam of zet ze op "ken ik". Met **volgen** wordt een apparaat elke 6 uur gescand op
  ongeveer 60 gebruikelijke poorten (ssh, http, smb, rdp, docker, databanken, ...) en komt er een melding als er een
  nieuwe poort openstaat. Een privé-adres (willekeurig MAC van een gsm of laptop) heet zo; neemt een gekend toestel
  een nieuw privé-adres met dezelfde hostnaam op dezelfde interface, dan houdt het zijn naam (melding alleen in 🔔).
  Meerdere nieuwe apparaten in één ronde geven één melding. Onbekende apparaten en privé-adressen zonder naam die
  30 dagen niet gezien zijn, verdwijnen; met **vergeten** haal je er zelf een weg. Rechten voor de API-key:
  *Diagnostics: ARP Table* en *Services: DHCP: Leases* (of *Services: Kea DHCP*)
- **net → kaart**: een netwerkkaart van internet → OPNsense → NPM en de Proxmox-nodes met hun CT's en VM's, met de
  services erop, in live kleuren. Klik op een node, CT/VM, OPNsense of NPM en je ziet meteen wat er mee uitvalt (ook
  wat erop "draait"). Een service komt bij een CT/VM via "draait op", het IP in de url of het checkdoel (IP's uit
  ⟳ pve in de terminal), de NPM-host van zijn domein (uit de nachtelijke kopie van NPM) of een CT/VM met dezelfde naam
- **hersteltest** (mini dashboard van een PBS-tegel, of `Ctrl+K` → "hersteltest"): één keer per maand zet de homepage
  een CT uit PBS terug op een vrij ID (vanaf 9900), haalt de netwerkkaarten eraf, start hem, kijkt of hij na 30 s nog
  draait en verwijdert hem weer. Elke keer een andere CT, de langst niet geteste eerst. Het resultaat komt op de
  tijdlijn en in je meldingen. Staat standaard uit. Het gaat via de Proxmox-API, dus de PBS-datastore moet in Proxmox
  gekoppeld zijn (Datacenter → Storage → Add → Proxmox Backup Server). Het token heeft er meer voor nodig dan
  PVEAuditor: VM.Allocate, VM.Config.Disk, VM.Config.Network, VM.Config.Options, VM.PowerMgmt en
  Datastore.AllocateSpace op de doelopslag, Datastore.Audit op de PBS-opslag. Bevoorrechte (privileged) CT's en
  CT's met bind mounts kan alleen root@pam terugzetten: kies dan onder "instellingen" alleen de gewone CT's
- **api** (API-beheer, knop in de titelbalk of `Ctrl+K` → "api-beheer"): alle API's op één plek, per categorie (Proxmox
  en back-up, netwerk, media, downloads, ...). Een API heeft een adres, een aanmelding (sleutel in een header, Bearer,
  `?apikey=` in de url of gebruikersnaam en wachtwoord) en sleutels, die versleuteld bewaard worden en nooit naar de
  browser gaan. Eén API kan door meerdere tegels gebruikt worden (bv. één Proxmox-cluster voor elke node-tegel, met
  `node` in de instellingen van de tegel). Bij een tegel kies je de API onder **bewerken → Integratie en API**, of je
  koppelt hier veel tegels tegelijk.
  - **⚡ tegels herkennen**: tegels die op een bekende app lijken (Sonarr, Radarr, Lidarr, Readarr, Prowlarr, Bazarr,
    SABnzbd, Jellyfin/Emby, Plex, Tautulli, Overseerr/Jellyseerr, Audiobookshelf, Immich, Nextcloud, Paperless-ngx,
    Syncthing, Pi-hole v5, Traefik, Prometheus, Grafana, Glances, Healthchecks, changedetection.io, Frigate) krijgen
    in één keer elk een eigen API met calls die meteen werken; je vult per tegel alleen de sleutel in. Tegels die hun
    sleutels nog zelf hebben (Proxmox, PBS, AdGuard, ...) verhuis je met één knop: tegels met hetzelfde adres en
    dezelfde sleutels delen daarna één API
  - **calls**: eigen endpoints per API. Kies methode en pad (met `{node}` of een andere instelling van de tegel), druk
    op ▶ probeer en klik in het antwoord op wat je wil zien: een waarde wordt een veld op de tegel, bij een lijst kies
    je "# aantal" of "▦ tabel" (een tabel in het mini dashboard). Per veld een formaat (bytes, procent, duur, datum,
    som of aantal over alle items met `*`, ...) en drempels voor geel en rood; is geel groter dan rood, dan is lager
    slechter (bv. vrije ruimte). Ook op de ingebouwde integraties kan je extra calls zetten (het pad komt dan na
    `/api2/json` bij Proxmox, `/api` bij Portainer, ...)
  - alles behalve GET is altijd een knop (actie) in het mini dashboard en in `Ctrl+K`, en vraagt een recente 2FA.
    Het adres, de soort of de aanmelding van een API met sleutels wijzigen vraagt ook een recente 2FA, tenzij je de
    sleutels opnieuw ingeeft. Een pad blijft altijd op het adres van de API
- **zabbix** (een tegel of API van soort `zabbix`): elke minuut haalt de homepage de hosts en open problemen uit
  Zabbix (5.4 en nieuwer). Elke tegel krijgt een stip "zbx": groen, of rood als een host onbereikbaar is of een
  probleem van ernst "gemiddeld" of hoger heeft (de muis erop toont welke). In het mini dashboard staan per host CPU,
  RAM, schijf /, uptime en ping met een grafiek van 24 u, de open problemen en een link naar Zabbix. Bij een tegel
  horen de hosts met hetzelfde IP of dezelfde DNS-naam als de tegel (een domein achter NPM via het doorstuuradres),
  of met dezelfde naam, plus de node waarop hij draait (de map uit ⟳ pve in de terminal, en "hangt af van"). Zelf
  kiezen of uitzetten kan onder **bewerken → Monitoring → Zabbix-hosts**. Nodig: een API-token in Zabbix
  (Gebruikers → API-tokens, voor een gebruiker die alle hosts mag lezen, bv. een eigen gebruiker in een groep met
  leesrechten op alle hostgroepen) en als adres de webinterface (`https://zabbix.jbogaert.be`, zonder
  `/api_jsonrpc.php`). Gebruikt alleen lezen: host.get, trigger.get, item.get en trend.get
- **van buitenaf** (⚿ → van buitenaf): komt een bezoek via Cloudflare (NPM kreeg het met een `CF-Connecting-IP` van
  Cloudflare of een tunnel), met een vervalste header van Cloudflare of vanaf een publiek IP, dan staan de terminal
  (ook cronjobs starten of bewaken, rsyslog uitrollen, sleutels vastzetten), updates installeren, acties (aan/uit,
  Wake-on-LAN, zelfherstel, snapshots verwijderen, hersteltest, API-calls die iets veranderen, poortscan, API's
  instellen of calls uitproberen, een tegel met integratie maken, importeren of een ander adres geven) en
  configuraties downloaden standaard uit. Die tegels en API's vragen van buitenaf ook altijd een verse 2FA-code,
  ook als acties op *altijd aan* staat, want ze halen iets op bij een adres in je netwerk. Kijken kan altijd;
  bovenaan staat dan "buiten". Per functie: uit, één uur aan (ook onderweg, met je 2FA-code) of altijd aan (alleen
  thuis). Aanzetten geeft een melding. Je LAN, VPN en Tailscale tellen als thuis, net als je eigen publieke IP (wie
  thuis via Cloudflare surft); extra thuisnetwerken (bv. je IPv6-voorvoegsel) stel je daar ook in, alleen thuis. Een
  vervalste header van Cloudflare telt altijd als van buitenaf en geeft een melding (zie Installeren → Cloudflare)
- **net → firewall**: welke IP's en poorten het dashboard echt gebruikt (uit de tegels, API-beheer, de SSH-hosts en
  de DNS-server), wat er binnenkomt, en een voorstel voor aliassen en regels in OPNsense voor de firewall tussen de
  VLAN's. Bovenaan staat of er een slot voor het dashboard stond bij het laatste bezoek van buitenaf: Cloudflare
  Access (header `Cf-Access-Jwt-Assertion`) of de forward-auth van Authentik in NPM (`X-authentik-username`)
- **hw → beveiliging**: een veiligheidscheck. Staat 2FA overal aan (ook via Authentik), is er een kopie van
  `secret.key` buiten de container, werkt de kopie van de back-up, zijn er sessies vanaf een publiek IP, wat staat
  er aan van buitenaf, stond er een slot voor het dashboard, is de SSH-sleutel vastgezet en hebben de Proxmox-tokens
  niet te veel rechten. Elk punt heeft een knop naar het venster dat het oplost
- **aandacht** (knop **!** in de titelbalk, `Ctrl+K` → "aandacht", of `/?open=aandacht`): alles wat nu je aandacht
  vraagt, gesorteerd op ernst: services down (een CT onder een node die down is, staat bij die node), back-ups en
  de hersteltest, de cluster, schijven en ZFS, opslag die volloopt, WAN en tunnels, de worker en back-up van het
  dashboard, Zabbix, cronjobs, updates (ook een mislukte installatie of een herstart die nodig is), certificaten die
  binnen 14 dagen verlopen, domeinen, tegels waarvan de API een fout geeft, sessies van buitenaf, nieuwe apparaten,
  oude snapshots en lopend onderhoud. Het leest wat de worker al bijhoudt en vraagt zelf niets aan je machines.
  Bovenaan het dashboard staan de rode en oranje punten (✕ verbergt ze tot er iets verandert). "negeren" verbergt
  een punt tot het verandert of opgelost is
- **instellingen** (! → instellingen, of `/?open=instellingen`): per functie of ze werkt, half ingesteld is (met wat
  er ontbreekt) of nog niet: Proxmox (ook welke rechten elk token mist), PBS, de hersteltest, OPNsense (ook de
  rechten voor apparaten en de config-kopie), NPM, Cloudflare, AdGuard, Wake-on-LAN (welke nodes nog geen
  MAC-adres hebben), de checks op je tegels, meldingen op je gsm, wie het dashboard zelf bewaakt, Zabbix, Home Assistant (welke nodes nog geen sensor hebben), schijven, domeinen, de webhooks
  van Proxmox, PBS en Home Assistant, Portainer, de SSH-login, hosts zonder bevestigde host key, cron, logs,
  nachtelijke updates en de beveiliging. Optionele functies die nog niet ingesteld zijn, staan grijs
- **proefmodus**: elke actie die een machine verandert, heeft een knop *proef* naast de echte knop. De proef toont
  wat er zou gebeuren, zonder het te doen: op welke machine, via SSH of welke API, als wie (de SSH-gebruiker, met of
  zonder `sudo -n`, of het token-ID van het Proxmox-actietoken), het exacte commando of de call, in welke volgorde,
  wat er gebeurt als een stap mislukt, en wat er vooraf nagekeken is (✓, ✕ of ? als het niet na te gaan is). Geen
  geheimen: wachtwoorden en token-geheimen staan nooit in een proef.
  - **updates** (`apt`): naast *installeren*, *toch zonder snapshot* en *terugdraaien*. Per machine de snapshot
    (`pct snapshot` via SSH op de node, of de Proxmox-API), het apt- of apk-commando (het volledige script staat
    erbij), welke services daarna nagekeken worden en hoe terugdraaien gaat. In `apt` → 's nachts tonen *proef van
    vannacht* en *wat zou er opgeruimd worden* wat de volgende nachtelijke run en het volgende opruimen zouden doen,
    ook welke machines de nachtelijke run overslaat (fysieke machines en nodes, daar kan geen snapshot)
  - **zelfherstel** (mini dashboard): per regel en in het formulier. Elke voorwaarde (aan, N× down, onderhoud,
    wachttijd, limiet per uur) en de call of het commando. De proef kijkt ook: via de Proxmox-API of de VM/CT nog
    bestaat en of een herstart een start wordt, in Portainer of de container nog bestaat, en via SSH of `sudo -n`
    werkt en hoe de dienst ervoor staat. Omdat die proef met de bewaarde login via SSH binnengaat, staat hij van
    buitenaf uit zoals de andere acties en komt hij in de audit-log. *nu testen (echt)* voert de actie echt uit
  - **PBS-sync** (hw → back-ups): naast *stap 1 en 2 zelf uitvoeren via SSH*, ook als die knop nog grijs is (de proef
    zegt dan waarom). Per PBS de `proxmox-backup-manager`-commando's met hun voorwaarden, wat er achterblijft als een
    stap mislukt, en de commando's om het ongedaan te maken. Met SSH-hosts loopt hetzelfde script op beide PBS'en in
    proefmodus: alleen de leescommando's (`user list`, `remote list`, `sync-job list`) gaan echt, elke wijziging wordt
    getoond als `+ proxmox-backup-manager ...`. Die proef meldt zich als root aan en komt daarom in de audit-log
  - **hersteltest**: naast *▶ nu testen*. Welke back-up en waarom, welk vrij ID (nagekeken voor de hele cluster), de
    vrije ruimte, de rechten van het actietoken en elke Proxmox-call in volgorde
  - **hw → snapshots**: naast *verwijderen*. Of de snapshot nog bestaat, met of zonder RAM-toestand, welke snapshots
    erna komen, en of een installatie hem nog nodig heeft om terug te draaien

  **Alleen proef** voor wat vanzelf loopt: de nachtelijke updates en het opruimen van hun snapshots (`apt` → 's
  nachts), een zelfherstelregel, en de maandelijkse hersteltest. Ze lopen dan zoals altijd (zelfde uur, wachttijd en
  limiet), maar zetten alleen op de tijdlijn wat ze zouden doen ("Proef: ..."), zonder melding of push. De laatste
  proef staat ook in het venster zelf. Zet het uit als de proef klopt; ! → instellingen toont zolang "half".
  Aanbevolen voor de eerste testronde op je echte nodes: eerst alles wat alleen leest, dan de proefknoppen en
  *alleen proef*, en pas daarna de echte acties.
- **diagnose** (! → *diagnose ↓*): één JSON-bestand om bij een foutmelding te voegen, in plaats van het probleem te
  beschrijven. Erin: de versies (ook PostgreSQL, TimescaleDB en de databasemigratie), de processen, de
  aandachtslijst, de instellingen-checklist, de fouten per tegel en per achtergrondtaak, webhooks, gsm's,
  zelfherstelregels, installaties van de laatste 7 dagen, cronjobs met een fout, de laatste 50 meldingen,
  tijdlijnregels en audit-regels, wat de proefmodus zou doen, en de laatste 200 logregels van de API, de worker en de
  syslog-ontvanger. Elk geheim dat het dashboard bewaart, is gemaskeerd (ook url-gecodeerd en als base64), net als
  alles wat op een token, sleutel of wachtwoord lijkt. IP-adressen, namen en gebruikersnamen staan er nog in: kijk
  het bestand na voor je het deelt. Vraagt je 2FA-code en staat van buitenaf uit zoals configuraties downloaden.
  De processen houden hun laatste logregels zelf bij, want de gebruiker `homepage` kan journald niet lezen. Wat vlak
  voor een crash gebeurde, staat soms alleen in journald: `journalctl -u homepage-worker -n 200` als root
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
  `/?open=history`, `updates`, `network`, `devices`, `configs`, `webhooks`, `planned`, `api`, `cron`, `health` of `terminal`. Links naar andere services kan de app in dezelfde WebView
  openen (`shouldOverrideUrlLoading` false teruggeven voor `*.jbogaert.be`)

Optimalisaties:

- je blijft ingelogd zolang je het dashboard gebruikt (sessie verlengt zich, na 14 dagen niets doen moet je opnieuw inloggen)
- geen verzoeken naar de server zolang het tabblad verborgen is, bij terugkeren meteen verse status
- achter Cloudflare zien login-limiet, audit-log en meldingen het echte IP van de bezoeker (alleen als NPM het
  verzoek van Cloudflare of een tunnel kreeg)
- gzip, beveiligingsheaders op elke response, installeerbaar als app (manifest)
- de worker hergebruikt HTTP-verbindingen en ruimt verlopen sessies, oude audit-regels (1 jaar) en gelezen meldingen (30 dagen) op

## Uptime Kuma vervangen

Het dashboard doet alles wat je in Uptime Kuma gebruikte, zodat Kuma weg kan. Per tegel onder **✎ bewerken →
Monitoring**:

- **soorten checks**: HTTP(S), ping, TCP-poort, DNS (A of AAAA, via een gekozen DNS-server zoals AdGuard, met een
  verwacht IP), **push** (een script meldt zich, zie hieronder), **Docker-container** (draait hij en is hij niet
  unhealthy, via je Portainer-tegel) en **API van de tegel** (de API van de integratie met zijn eigen versleutelde
  sleutels, dus ook achter een login, met een pad en een JSON-veld naar keuze)
- **HTTP-opties**: goede statuscodes (`200-299,401`), woord op de pagina (of juist niet), JSON-veld met een
  verwachte waarde, time-out, methode GET/HEAD/POST met een body, eigen headers (geen wachtwoorden: daarvoor is de
  check "API van de tegel"), doorverwijzingen wel of niet volgen, certificaatfouten negeren. Verwijst een pagina
  door naar een andere host (meestal de loginpagina van Authentik), dan toont de tegel dat; met *down als hij naar
  een andere host doorverwijst* telt het als fout
- **wanneer down**: na 1 tot 10 mislukte checks op rij (standaard 3, bij push 1). Tussen de eerste fout en down
  staat de tegel oranje op *twijfel (1/3)*; met *bij twijfel opnieuw na* kijkt hij dan sneller opnieuw
- **melden**: hier en op je gsm, alleen hier (🔔), of niet (alleen de tijdlijn). Zolang hij down is: nooit, elk uur,
  elke 4 uur of elke dag een herinnering. De melding over het certificaat kan per tegel uit
- **pauzeren** (in het mini dashboard, of in bewerken): de check loopt niet en meldt niets. Pauzeren, de meldingen
  uitzetten, de check weghalen of een tegel (groep, pagina) met een lopende check verwijderen vraagt je 2FA en geeft
  een melding, zodat wie je sessie steelt niet stilletjes de bewaking uitzet. Hetzelfde geldt voor onderhoud
  beginnen of verlengen, gepland onderhoud aanzetten of verschuiven, een cronjob dempen, een webhook uitzetten,
  vernieuwen of weghalen, een logregel uitzetten, lager zetten of weghalen, een beveiligingspunt in **!** negeren,
  de meldingen over een certificaat uitzetten en een check onder een ouder hangen die down of in onderhoud is. Een
  cronjob niet meer bewaken geeft alleen een melding. Een gepauzeerde check staat ter info in **!**, net als
  onderhoud dat met de hand gezet is en meer dan een dag loopt of voor veel services tegelijk geldt
- **uptime** over 24 u, 7 d, 30 d en 1 jaar in het mini dashboard; op de tegel als hij onder 99,9 % zakt
- **afhankelijkheden**: hangt een tegel af van een andere (CT op een node, container op Portainer), dan krijg je één
  melding voor de ouder. Is de ouder terug en het kind niet, dan alsnog een melding voor het kind. Faalt het grootste
  deel van alle checks tegelijk (netwerk of DNS van de container), dan één melding in plaats van honderd; zolang dat
  duurt, staat het bovenaan in **!**. Wat al apart als down gemeld was (een pc die meestal uit staat), telt daarvoor
  niet mee
- verander je wat een check bekijkt (ander type of adres), dan begint de status opnieuw, zonder oude down-status. Een
  push-check begint ook opnieuw na een ander interval of na hervatten: signalen van daarvoor tellen niet

**Push-monitors** (vervangt de push-monitors van Uptime Kuma). Kies bij een tegel als check *push* en maak in het
mini dashboard een push-adres. Een script, een automatisering in Home Assistant of de back-up van je VPS roept dat
adres aan, bv. `curl -fsS -m 10 "https://<dashboard>/api/push/<token>?status=up&msg=OK"`. Dat is dezelfde vorm als
in Kuma: in een bestaand script veranderen alleen de host en het token; `status=down`, `msg` en `ping` mogen erbij,
met GET of POST. Blijft het signaal langer uit dan het interval (minstens 60 s) plus wat speling (10 %, minstens
30 s), of meldt het script `status=down`, dan gaat de tegel down en krijg je een melding. Standaard werkt het adres
alleen thuis (LAN/VPN). Voor een VPS vink je *ook van buitenaf* aan; zet dan in Cloudflare Access of Authentik een uitzondering
voor `/api/push/*`. Het adres zelf is het geheim: met *nieuw adres* maak je een ander, en het oude werkt meteen niet
meer. Tokens komen niet in de logs van nginx en uvicorn in de container. NPM en Cloudflare schrijven het volledige
adres wel in hun eigen logs: zet in NPM bij de proxy host voor `/api/push/` de access log uit als je dat niet wil.

**Docker-containers**: kies *Docker-container (via Portainer)*, je Portainer-tegel en de container (de lijst komt uit
Portainer). Down als de container stopt of *unhealthy* is. De tegel hangt dan automatisch af van Portainer: valt
Portainer uit, dan één melding.

**Meldingen op je gsm (web push).** Het dashboard kan meldingen zelf naar je gsm of browser sturen, ook als het
tabblad dicht is: geen Telegram, ntfy of mail, maar de pushdienst die al in je browser zit (Google voor
Chrome/Android, Apple voor iPhone, Mozilla voor Firefox). Er verandert niets tot je het op een toestel aanzet: open
het belletje → **gsm** (of Ctrl+K → "meldingen op je gsm") en kies **Dit toestel meldingen laten krijgen**; dat vraagt
je 2FA-code. Per toestel kies je welke meldingen: alleen storingen en herstel, ook waarschuwingen, of alles. Herstel,
aanmeldingen vanaf een nieuw IP en het weekrapport komen altijd, en meer dan 10 per minuut worden samengevat in één
bericht. Per tegel kan je onder **bewerken → Monitoring → Melden** kiezen voor *alleen hier*: dan gaat die tegel nooit
naar je gsm. Op een iPhone moet het dashboard eerst als app op je beginscherm staan (Delen → Zet op beginscherm, iOS
16.4 of nieuwer); op Android werkt het in Chrome of als app via Toevoegen aan startscherm. Het werkt alleen via
https. De berichten zijn end-to-end versleuteld (RFC 8291). De server moet uitgaand 443 kunnen naar
`fcm.googleapis.com`, `*.push.apple.com` en `*.push.services.mozilla.com` (zie de firewall-weergave). Een tik op een bericht
opent het dashboard op de juiste plek. Meldt de pushdienst een toestel af, of lukt het afleveren drie keer niet, dan
zie je dat in het meldingencentrum en op je andere toestellen. Komt er 30 dagen niets aan op een toestel dat blijft
mislukken, dan zet het dashboard het uit, met een melding; zet het opnieuw aan in 🔔 → gsm. Valt de worker uit, dan
stuurt de API de meldingen.

**Het dashboard zelf bewaken.** De worker en de API houden elkaar in het oog: valt de worker uit, dan meldt de API
dat (en stuurt hij de meldingen naar je gsm); antwoordt de API niet meer, dan meldt de worker dat. Een check die
geen resultaat meer geeft, wordt grijs in plaats van op zijn laatste kleur te blijven staan. Na een herstart zegt
het dashboard hoe lang het stil was. Valt de hele container uit, dan kan het dashboard niets meer melden: dat moet
iets anders zien. Gebruik daarvoor Zabbix, met een web-scenario op `/api/healthz` (zonder login, alleen thuis;
antwoordt 200 als database, worker en checks lopen, anders 503):

1. In Zabbix: *Data collection → Hosts*, kies de host van de container (of de Zabbix-server) → *Web* → *Create web
   scenario*. Naam `homepage`, interval `1m`, en één stap met URL `http://<IP van de container>/api/healthz` en *Required
   status codes* `200`
2. Een trigger op die host: `last(/<host>/web.test.fail[homepage])<>0`, ernst *High*, met de meldingen die je in
   Zabbix al gebruikt
3. Laat de firewall Zabbix toe naar de container op poort 80. In **! → instellingen** staat de rij *Iemand die het
   dashboard zelf bewaakt* op groen zodra Zabbix het adres opvraagt

**Checks rechtstreeks, zonder DNS.** Een tegel als `https://jelly.jbogaert.be` wijst via DNS naar NPM. Zou elke
check die naam opvragen, dan stelt het dashboard elke minuut honderden DNS-vragen, en test het eigenlijk NPM in
plaats van de app. Met een NPM-tegel (type npm, adres `http://192.168.0.245:81`) haalt de worker daarom elke 5
minuten de proxy hosts op, en stuurt hij de checks rechtstreeks naar de server die NPM erachter gebruikt (bv.
`http://192.168.0.27:8096`). Hij stuurt dezelfde headers mee als NPM (`Host`, `X-Forwarded-Proto`), zodat de app
het niet merkt. Klik je op een tegel, dan opent nog altijd de naam.

- **HTTP** gaat zo rechtstreeks. Een doorverwijzing naar een andere naam achter NPM gaat ook rechtstreeks; een
  naam die NPM niet kent (een externe login) gaat zoals vroeger. De vervaldatum van het certificaat komt uit NPM,
  en een verlopen certificaat geeft een fout, zoals in de browser
- **via NPM, zonder DNS**: lukt rechtstreeks niet, dan gaat de check naar het IP van NPM (de host van de NPM-tegel)
  met de naam erbij: door NPM zoals vroeger, maar zonder DNS. De reden staat in het mini dashboard van de tegel:
  - het dashboard bereikt de server niet, meestal door de firewall tussen de VLAN's. Bereikt het hem later wel, dan
    schakelt de tegel vanzelf over zonder status te verliezen. Lukt verbinden met de server eens niet (bv. net
    verhuisd naar een ander IP), dan probeert de check het meteen via NPM
  - NPM doet zelf iets met de naam: de proxy host staat uit of offline, er staat een toegangslijst of eigen
    nginx-configuratie op (bv. de login van Authentik), een redirection- of 404-host, een locatie met een regex
  - het doel is geen IP-adres (een containernaam), NPM zelf (localhost) of een Docker-netwerk bij NPM (172.17.x)
  - https zonder passend certificaat in NPM, of http waarbij NPM naar https doorstuurt (na die doorverwijzing gaat
    de check wel rechtstreeks)
  - ping en TCP: die testten altijd NPM (de naam wijst ernaar), en dat blijft zo. Rechtstreeks zou een TCP-check
    down gaan als de server uitvalt, en na de volgende ronde weer "up" via NPM. Wil je de server zelf pingen of
    een poort erop testen, vul dan zijn IP in als doel
- **via de naam, met DNS** (zoals vroeger): een naam die NPM niet kent, een adres met een eigen poort
  (`https://naam:8443`), een naam die in meer dan één NPM staat, of als NPM zelf niet te bereiken is
- **firewall**: de container moet de servers zelf bereiken, niet alleen NPM. De NPM-tegel → *rechtstreeks* toont welke
  IP's en poorten niet lukken, en **net → firewall** geeft de regel voor OPNsense. Klik daarna op *nu vernieuwen*.
  Staat er *weigert de verbinding*, dan staat de service meestal uit (of luistert ze op een andere poort dan in
  NPM); alleen een firewallregel met *reject* geeft hetzelfde
- **NPM zelf**: een check die rechtstreeks gaat, ziet een storing van NPM niet meer. Geef de NPM-tegel daarom zijn
  eigen check (http op `http://192.168.0.245:81`)
- **uitzetten**: per tegel onder **✎ bewerken → Monitoring** (*zonder DNS*), of voor
  alles samen op de NPM-tegel. Uit = via de naam, met DNS, zoals vroeger. API-koppelingen (Zabbix, Portainer, ...)
  gebruiken altijd het adres dat je zelf invulde: zet daar een IP als je DNS wil sparen

**Voor je Uptime Kuma uitzet**:

1. **! → instellingen → Checks op je tegels**: elke service die je in Kuma had, heeft hier een tegel met een check
   (de rij zegt welke tegels een adres hebben maar geen check, en welke checks een loginpagina zien)
2. push-monitors: maak ze hier en pas in je scripts host en token aan; elk script één keer laten lopen
3. meldingen op je gsm aanzetten (🔔 → gsm) en een test sturen
4. het web-scenario in Zabbix hierboven
5. wat Kuma nog elders deed: de Kuma-integratie in Home Assistant, statuspagina's of badges (het dashboard heeft
   geen openbare statuspagina), en de Kuma-webhook onder meldingen → webhooks
6. dan Kuma stoppen; bewaar zijn data een paar weken voor het geval je nog iets mist

## Installeren in een Proxmox-container

Container: Debian 13 (of 12), unprivileged, `nesting=1`, 2 cores, 4 GB RAM, 32 GB disk, vast IP.
Kies een x86-node (niet de Raspberry Pi).

Eén commando als root in de lege container (installeert alles, haalt de code op en start de services):

```bash
apt update && apt install -y curl && bash <(curl -fsSL https://raw.githubusercontent.com/Jonasz1996/homepage/nieuwste/deploy/bootstrap.sh)
```

Het script vraagt de eerste keer welke versie je wil en onthoudt dat (in `/etc/homepage/kanaal`):

- **stabiel**: de laatste release (`vX.Y.Z`). Aanbevolen.
- **nieuwste**: wat net gebouwd is, om te testen (branch `nieuwste`, of `main` als die er niet meer is).

Zolang er nog geen release is, neemt het `nieuwste` zonder te vragen. Wisselen kan met `KANAAL=stabiel` of
`KANAAL=nieuwste` voor `bash <(curl ...)`. Hetzelfde commando opnieuw uitvoeren werkt alles bij.

Het script toont op het einde de **setup-code** voor het eerste account.
Maak daarna in Nginx Proxy Manager een proxy host (bv. `home.jbogaert.be` → `http://<IP van de container>:80`)
met SSL en "Websockets Support" aan.

Open het dashboard via zijn naam in NPM. Via NPM met HTTPS is de sessiecookie automatisch `Secure`
(`HOMEPAGE_COOKIE_SECURE=auto`). Geef bij de eerste installatie het IP van NPM mee:
`NPM_IP=192.168.0.245 bash <(curl ...)`; het komt in `/etc/homepage/homepage.env` (`HOMEPAGE_NPM_IP`).

nginx laat zelf alleen dit binnen: van NPM en van de container zelf alles, van je LAN (privé-adressen) alleen
`/api/push/`, `/api/hooks/` en `/api/healthz`, en de rest krijgt een 403 met uitleg. Zo kan niemand op het LAN NPM en
Cloudflare omzeilen, en gaat je wachtwoord nooit onversleuteld over het netwerk. In **! → instellingen** staat dat
als *Dashboard alleen via NPM*. Eerst testen op `http://<IP>` voor er een host in NPM is: zet `HOMEPAGE_LAN_OPEN=1`
in `/etc/homepage/homepage.env`, voer `bash /opt/homepage/deploy/install.sh` uit, en zet het daarna terug op 0. Gaf
je bij de eerste installatie geen `NPM_IP` mee, dan neemt het script 192.168.0.245 en laat het het LAN open tot jij
`HOMEPAGE_LAN_OPEN=0` zet. Krijg je ook via NPM een 403, dan klopt `HOMEPAGE_NPM_IP` niet: zet het juiste IP en
voer `install.sh` opnieuw uit in de container (`pct enter <CTID>`). Wat install.sh koos, staat in
`/etc/homepage/nginx`.

De firewall van de container in Proxmox is een extra laag: laat dan poort 80 toe vanaf NPM én vanaf de machines die
push-monitors, webhooks of `/api/healthz` rechtstreeks aanroepen (Zabbix, Proxmox, PBS, Home Assistant, scripts).
Laat daarnaast poort 514 (udp en tcp) toe vanaf je LAN voor de logs.

**Cloudflare.** De headers van Cloudflare (`CF-Connecting-IP` met het echte IP, `CF-IPCountry` met het land,
`Cf-Access-Jwt-Assertion` van Cloudflare Access) gelooft nginx alleen als het verzoek van NPM komt én NPM het zelf
van Cloudflare of een tunnel kreeg. Dat werkt voor allebei:

- een poortdoorverwijzing naar NPM via de proxy van Cloudflare (oranje wolk): NPM krijgt het verzoek van een adres
  van Cloudflare. Die adresblokken staan in `deploy/nginx-map.conf` (bron: https://www.cloudflare.com/ips)
- een Cloudflare Tunnel: cloudflared (in een CT of op de host van NPM) komt van een privé-adres bij NPM. Laat de
  tunnel naar NPM wijzen, niet rechtstreeks naar de container (die geeft dan een 403). Op de host van NPM mag dat
  `localhost`, het Docker-netwerk of het LAN-adres van NPM zelf zijn

Wie NPM rechtstreeks bereikt (poort 443 zonder Cloudflare, of vanaf het LAN) en zelf zo'n header meestuurt, bv. met
je eigen publieke IP om als thuis te tellen, telt als van buitenaf en geeft een melding "Vervalste Cloudflare-header"
(hoogstens één per uur). Het dashboard neemt dan het adres waarvan NPM het verzoek kreeg: van het internet is dat
het echte IP. NPM gelooft wel `X-Real-IP` van je LAN (en van Cloudflare), dus een toestel op je LAN kan NPM een
ander adres voorwenden: een adres van Cloudflare geeft niets (wie op het LAN zit, is toch thuis), een ander publiek
IP telt als vervalst. Daarom delen alle vervalste verzoeken één limiet op mislukte logins en bevestigingen, welk IP
ze ook tonen. Cloudflare haalt een `X-Real-IP` van de bezoeker weg; alleen een Worker kan er een meesturen. Wil je
dat NPM voor het dashboard nooit `X-Real-IP` gelooft, zet dan in NPM bij de proxy host van het dashboard onder
*Advanced* `set_real_ip_from 192.0.2.255/32;` (een adres dat nooit verbindt: zo vervangt die host de lijst die NPM
vertrouwt). De logs van NPM en een access list op die host zien dan het adres van Cloudflare of cloudflared in
plaats van dat van de bezoeker; het dashboard ziet nog altijd het echte IP.

De adressen van Cloudflare zijn van alle klanten van Cloudflare. Wil je zeker zijn dat alleen je eigen zone bij NPM
komt, gebruik dan alleen een Cloudflare Tunnel (geen poortdoorverwijzing naar 443) of Authenticated Origin Pulls.

Krijg je de melding voor je eigen bezoek via Cloudflare, dan heeft Cloudflare een nieuw adresblok. Dat hoort in
de repository: vul het aan in `deploy/nginx-map.conf` en werk bij (op het kanaal stabiel pas met een nieuwe
release). Een wijziging in `/opt/homepage` zelf verdwijnt bij de update. Tot dan kan het tijdelijk op de server:
voeg het blok toe in `/etc/nginx/conf.d/homepage-map.conf` en doe `nginx -t && systemctl reload nginx` (de
volgende update overschrijft dat bestand weer).

`X-authentik-username` (de forward-auth van Authentik in NPM) telt alleen van NPM en niet samen met een vervalste
header. NPM geeft hem op een host zonder forward-auth ook van de bezoeker door, dus het dashboard gebruikt hem
alleen voor de veiligheidscheck "slot voor het dashboard".

**Bewaar een kopie van `/etc/homepage/secret.key`.** Zonder die sleutel zijn de opgeslagen
wachtwoorden, API-sleutels en 2FA-geheimen onleesbaar.

## Bijwerken

Hetzelfde bootstrap-commando opnieuw, of:

```bash
bash /opt/homepage/deploy/bootstrap.sh
```

Zo verloopt een update:

1. terwijl het dashboard gewoon blijft draaien, worden de bibliotheken en de frontend gebouwd. De bibliotheken
   hebben vaste versies (`backend/requirements.lock`, dezelfde als in de tests) en krijgen een eigen venv per lock:
   `/opt/homepage/.venv-…`, met `.venv` als verwijzing naar de actieve. Verandert de lock niet, dan blijft de venv
   dezelfde. De frontend komt in `frontend/dist.new`
2. is er niet genoeg plaats in `/var/backups/homepage` voor een kopie van de database, dan stopt het hier
3. de diensten stoppen en het script maakt een kopie van de database (`voor-update-*.dump`, de laatste 2 blijven staan)
4. het schakelt over op de nieuwe venv en frontend (de vorige blijven staan) en werkt de database bij
5. de diensten starten weer

Mislukt de kopie of het bijwerken van de database (of al iets daarvoor), dan wordt de update netjes afgebroken: de
vorige versie van de code, de bibliotheken en de frontend komt terug, de database is niet veranderd (alle migraties
lopen samen in één transactie) en de diensten draaien weer. Het script zegt wat er misliep: los dat op en voer de
update opnieuw uit. Pas als de database bijgewerkt is, onthoudt het de nieuwe versie (in `/etc/homepage/versie`).
Een onderbroken update (Ctrl+C, de SSH-verbinding valt weg) wordt net zo afgebroken; was de database op dat moment
al bijgewerkt, dan blijft de nieuwe versie staan en starten de diensten (voer de update dan nog eens uit).

Na de update toont het dashboard één keer wat er nieuw is en wat je zelf moet instellen (later: `Ctrl+K` →
"wat is er nieuw").

**Een update terugdraaien**: `homepage-terugzetten` in de container zet de vorige versie terug, met de database
van vlak voor die update en met de bibliotheken die die versie had (de venv van daarvoor blijft daarvoor staan). Wat
sinds die update in het dashboard veranderde, gaat verloren; de database van daarvoor wordt eerst nog bewaard als
`voor-terugzetten-*.dump` (alleen de laatste blijft staan). `homepage-terugzetten --lijst` toont welke kopieën er
zijn. Stopt het terugzetten halverwege, bijvoorbeeld omdat de frontend niet gebouwd kon worden, los de fout op en
voer het opnieuw uit. Het werkt vanaf de tweede update met deze versie van het script. Het keurt een teruggezette
database af bij elke fout van `pg_restore` behalve de onschuldige over de extensie timescaledb
(`homepage-herstelfouten`), en toont die fouten.

Een release maken (voor `stabiel`): een tag `vX.Y.Z` op `main`, bv. `git tag v1.1.0 && git push origin v1.1.0`.

## Opbouw

| Map | Inhoud |
| --- | --- |
| `backend/` | FastAPI, SQLAlchemy (async), Alembic-migraties, tests. De checks draaien in `app/monitoring/worker.py` (service `homepage-worker`) |
| `frontend/` | Svelte 5 + Vite. Kleuren en stijl staan in `src/app.css` |
| `deploy/` | Installatiescript, nginx-config, systemd-units |

De database is PostgreSQL (15 op Debian 12, 17 op Debian 13; de CI test beide). TimescaleDB wordt al geïnstalleerd
voor de ping- en uptime-historiek van fase 3.

## Ontwikkelen

```bash
python3 -m venv .venv && .venv/bin/pip install -r backend/requirements-dev.lock   # vaste versies, zoals in productie
cd backend && ../.venv/bin/pytest            # tests op SQLite
HOMEPAGE_TEST_DATABASE_URL=postgresql+asyncpg://... ../.venv/bin/pytest   # tests op PostgreSQL

cd frontend && npm ci && npm run dev         # proxy't /api naar 127.0.0.1:8000
cd frontend && npm test                      # unit-tests (node:test), bv. de Markdown van de notities
```

Een bibliotheek toevoegen of bijwerken: in `backend/pyproject.toml`, en daarna `backend/requirements.lock` (en
`requirements-dev.lock`) opnieuw maken, zoals bovenaan dat bestand staat. De tests en de CI controleren dat de lock
bij `pyproject.toml` past.

Zoals in productie, met TimescaleDB (de CI doet dit ook): het schema komt dan uit de migraties en de tests zetten
oude metingen in gecomprimeerde chunks.

```bash
HOMEPAGE_TEST_SCHEMA=migraties HOMEPAGE_TEST_DATABASE_URL=postgresql+asyncpg://... ../.venv/bin/pytest
```

Op PostgreSQL test `tests/test_migraties_met_gegevens.py` ook een update van een oude versie (migratie 0018) met
gegevens in elke tabel. De tests van de back-upscripts slaan over zonder `pg_dump`/`pg_restore` van dezelfde of een
nieuwere versie dan de server; met `HOMEPAGE_TEST_PG_CLIENT=verplicht` (zoals in de CI) falen ze dan.

Browsertests (Playwright) tegen een lege database, met de API op 127.0.0.1:8000 en de setup-code in
`HOMEPAGE_SETUP_TOKEN`: inloggen met 2FA, bewerkmodus, elk venster in de titelbalk en de gsm-weergave.

```bash
cd e2e && npm ci && npx playwright install chromium && HOMEPAGE_SETUP_TOKEN=... npx playwright test
```
