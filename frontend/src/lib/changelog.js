// Wat er nieuw is, nieuwste bovenaan. Na een update toont het dashboard één keer wat je nog niet gezien hebt.
// nr loopt op en verandert nooit: het dashboard onthoudt per gebruiker het hoogste nummer dat het al toonde.
// "instellen": wat je zelf moet doen voor het werkt.
export const CHANGELOG = [
  {
    nr: 34,
    datum: '2026-10-11',
    titel: 'Betrouwbaarheid',
    items: [
      'De grafiek en de uptime over 7 dagen, 30 dagen en een jaar laden veel sneller: de worker telt de checks per uur op. Losse checks blijven 90 dagen, de uurtotalen 400 dagen, dus de jaargrafiek blijft volledig en de database en elke back-up worden veel kleiner. Het weekrapport rekent ook zo, en het mini dashboard laadt die grafieken niet meer elke 30 seconden opnieuw.',
      'Telt de worker de checks een dag lang niet meer per uur op, dan zegt ! dat (met hoelang nog voor er checks voor goed verdwijnen), en staat het in Gezondheid › homepage.',
      'Zoeken in de logs stopt na 20 seconden met een duidelijke melding in plaats van een time-out, en houdt een processorkern vrij voor de checks. Opent de logviewer vanuit de zoekbalk, ! of een melding, dan begint hij bij de laatste 24 uur, en de gevonden regels blijven staan als alleen de grafiek te traag is.',
      'De syslog-ontvanger gooit geen logregels meer weg als de database even weg is: hij houdt er tot 50.000 vast en schrijft ze weg zodra ze terug is, ook bij een herstart of update. Raken er toch regels verloren of draait hij niet, dan staat dat onder ! en in Gezondheid › homepage.',
      'Zelfherstel stuurt per storing nog maar één bericht naar je gsm (plus één als een herstart eerst lukte en daarna mislukt, en één als de regel pauzeert), en volgt "Melden" van de tegel. Elke poging staat wel in 🔔 en op de tijdlijn. Een regel gaat hoogstens 5 keer per uur af.',
      'Net → apparaten herkent privé-adressen van gsm\'s en laptops en houdt hun naam, zet meerdere nieuwe apparaten in één melding, en ruimt onbekende apparaten op die 30 dagen weg zijn; met "vergeten" haal je er zelf een weg.',
      'Een gsm of browser waar 30 dagen geen melding meer aankwam en die blijft mislukken, krijgt geen meldingen meer, met één melding; zet hem opnieuw aan in 🔔 → gsm.',
      'Elke 1e van de maand zet de homepage de nieuwste nachtelijke back-up echt terug in een testdatabase en toont het resultaat met de tabellen onder Gezondheid › homepage. Mislukt het, dan staat het onder ! en krijg je een melding.',
      'Staat de back-up van het dashboard alleen in de container, dan stelt ! een kopie erbuiten voor. Verandert secret.key nadat je de wachtzin instelde, dan zegt de zelfcontrole dat de sleutel in die kopie verouderd is. LEESMIJ.txt bij de kopie noemt de versies van PostgreSQL en TimescaleDB om terug te zetten.',
      'homepage-terugzetten keurt een terugzetting af als de gegevens van een tabel niet terug konden, en "De laatste back-up is onleesbaar" onder ! zegt nu waarom.',
      'Een fout van een proxy zonder uitleg toont nu bv. "Mislukt (fout 504)" in plaats van niets. Alle acties in het auditlog hebben nu een leesbare naam.',
    ],
    instellen: [
      'Niets verplicht. Wil je de test van de back-up meteen zien in plaats van op de 1e: voer in de container één keer systemctl start homepage-backuptest uit.',
    ],
  },
  {
    nr: 33,
    datum: '2026-10-11',
    titel: 'Veiligheid',
    items: [
      'Een gevaarlijke actie bevestigen kan alleen nog met je 2FA-code, niet meer met je wachtwoord. Je wachtwoord wijzigen vraagt ook je 2FA-code en geeft een melding.',
      'Toestellen waarop je al met 2FA inlogde, worden onthouden: vult iemand de limiet op je gebruikersnaam met foute wachtwoorden, dan log je daar gewoon in, en je krijgt één melding "Inloggen dicht voor nieuwe toestellen". De melding over een login vanaf een nieuw IP zegt of het een bekend toestel is.',
      'Wachtwoorden worden naast de hoofdlus gecontroleerd, zodat een reeks loginpogingen het dashboard en de terminal niet trager maakt. Verzoeken tegelijk omzeilen de limieten niet meer, dezelfde 2FA-code werkt maar één keer, en de gebruikersnaam is niet meer hoofdlettergevoelig.',
      'Inloggen via Authentik herkent je account aan zijn vaste ID bij Authentik (sub) en niet meer aan de naam: een ander Authentik-account met dezelfde naam komt er niet meer in.',
      'Van buitenaf valt een API instellen, een call uitproberen of een tegel met integratie een ander adres geven onder acties, en dat vraagt je 2FA-code. Tegels bekijken werkt gewoon.',
      'Onderhoud beginnen of verlengen, gepland onderhoud aanzetten, een cronjob dempen, een webhook of logregel uitzetten en een beveiligingspunt negeren vragen nu je 2FA-code en geven een melding op je gsm, net als een check pauzeren. Een herhalend onderhoudsvenster duurt hoogstens 12 uur per keer.',
      '"Wis gelezen" laat meldingen staan die nog niet naar je gsm gestuurd zijn. In ! zie je onderhoud dat met de hand gezet is en meer dan een dag loopt, of voor veel services tegelijk.',
      'Rechtstreeks op http://IP opent het dashboard alleen nog vanuit de container zelf: open het via zijn naam in NPM. Van het LAN gaan alleen push-monitors, webhooks en /api/healthz nog rechtstreeks. ! → instellingen toont dat als "Dashboard alleen via NPM".',
      'SSH-sleutel vastzetten zet alleen nog losse IP-adressen in from=, en een from= met een patroon of netwerk telt als "elk IP". Een link in een notitie kan geen eigen attributen meer krijgen.',
    ],
    instellen: [
      'Open het dashboard na de update via zijn naam in NPM. Krijg je ook daar een 403 met uitleg, dan klopt HOMEPAGE_NPM_IP in /etc/homepage/homepage.env niet: zet het juiste IP en voer in de container bash /opt/homepage/deploy/install.sh uit.',
      'Log je in via Authentik? Koppel je account één keer onder ⚿ → authentik → Koppel Authentik-account, en zet in Authentik bij de provider Subject mode op "Based on the User\'s hashed ID". Tot dan werkt alleen wachtwoord met 2FA.',
      'Open het dashboard één keer op elk toestel waarop je al ingelogd bent: dan is het een bekend toestel.',
    ],
  },
  {
    nr: 32,
    datum: '2026-10-11',
    titel: 'Proefmodus en diagnose',
    items: [
      'Naast updates installeren en terugdraaien, zelfherstel, de PBS-sync, de hersteltest en snapshots verwijderen staat een knop proef. Die toont welke machine, via SSH of welke API, als wie en met welk commando, zonder iets uit te voeren.',
      'Alleen proef: de nachtelijke updates, het opruimen van hun snapshots, een zelfherstelregel en de maandelijkse hersteltest lopen dan zoals altijd, maar zetten alleen op de tijdlijn wat ze zouden doen, zonder melding.',
      'Onder ! maakt "diagnose ↓" één bestand voor een foutmelding: versies, de instellingen-checklist, de fouten per integratie, wat de proefmodus zou doen en de laatste 200 logregels van API, worker en syslog. Wachtwoorden, tokens en sleutels zijn gemaskeerd; IP-adressen en namen staan er nog in.',
      'Zelfherstel grijpt niet meer in tijdens onderhoud. "nu testen" heet nu "nu testen (echt)", want het herstart echt.',
      'De PBS-sync weigert vooraf wat niet kan, nog voor er iets op de eerste PBS verandert, en vervangt een token alleen als het al bestaat.',
      'Opgelost: de hersteltest aanzetten na het moment van deze maand startte binnen de minuut een echte test. Een update-snapshot die je in hw → snapshots verwijdert, biedt geen terugdraaien meer aan.',
    ],
    instellen: [
      'Voor de testronde op je echte nodes: probeer eerst de proefknoppen en zet de automatische functies op "alleen proef" tot de proef klopt (README → proefmodus).',
    ],
  },
  {
    nr: 31,
    datum: '2026-10-11',
    titel: 'Veiliger en zuiniger met de schijf',
    items: [
      'Een vervalste Cloudflare-header telt niet meer als thuis: het dashboard gelooft die alleen als NPM het verzoek van Cloudflare of van je tunnel kreeg. Een poging geeft een melding.',
      'Logregels worden na 1 dag gecomprimeerd. Vanaf 75 % schijf krijg je een melding en ruimt het dashboard de oudste logregels op; de laatste 3 dagen blijven.',
      'De nachtelijke back-up laat de logregels weg en houdt de 5 nieuwste.',
      'Een update zet het dashboard even stil tijdens de kopie en de migratie. Mislukt een van beide, of breek je de update af, dan blijft de vorige versie draaien. Terugzetten zet ook de bibliotheken van toen terug.',
      'Trage SSH-taken (cron, updates, schijven) houden geen databaseverbinding meer open. Een zoekopdracht in de logs die te lang duurt, stopt met een duidelijke melding.',
    ],
    instellen: [
      'Containerlogs van Portainer staan nu standaard uit. Wil je ze houden, zet dan logs = true op je Portainer-tegel (✎ bewerken → Integratie en API).',
      'Kom je via een Cloudflare Tunnel binnen, laat cloudflared dan naar NPM wijzen en niet rechtstreeks naar het dashboard.',
    ],
  },
  {
    nr: 30,
    datum: '2026-10-05',
    titel: 'Checks zonder DNS',
    items: [
      'Checks op een naam die NPM kent, vragen geen DNS meer: ze gaan rechtstreeks naar de server achter NPM, of naar NPM zelf met de naam erbij. Een klik op de tegel opent nog altijd de naam.',
      'Het mini dashboard zegt waar de check naartoe gaat en waarom.',
    ],
    instellen: [
      'Laat in OPNsense het dashboard door naar de servers en poorten onder NPM-tegel → rechtstreeks, en klik daar op "nu vernieuwen".',
      'Geef de NPM-tegel een eigen http-check.',
    ],
  },
  {
    nr: 29,
    datum: '2026-10-05',
    titel: 'Het dashboard vervangt Uptime Kuma',
    items: [
      'Nieuwe checks: push (een script of cronjob meldt zich op een eigen adres, zoals in Kuma), Docker-container via Portainer, en de API van de tegel met zijn eigen sleutels.',
      'Per check: down na 1 tot 10 fouten, sneller opnieuw kijken bij twijfel, herinneringen zolang hij down is, melden op je gsm, alleen hier of niet, en pauzeren.',
      'HTTP-checks: statuscodes, methode, body, headers, time-out, doorverwijzingen. De tegel ziet het als een check op de loginpagina van Authentik belandt.',
      'Meldingen op je gsm met web push, zonder app of dienst ertussen.',
      'Het dashboard bewaakt zichzelf: worker en API houden elkaar in het oog, vastgelopen checks worden grijs, en /api/healthz is er voor Zabbix.',
      'Uptime over 24 u, 7 d, 30 d en 1 jaar in het mini dashboard.',
    ],
    instellen: [
      'Zet de meldingen op je gsm aan: 🔔 → gsm.',
      'Zet in Zabbix een web-scenario op http://<IP van de container>/api/healthz (README → Uptime Kuma vervangen).',
      'Maak je push-monitors hier opnieuw en pas host en token aan in je scripts.',
      'Kijk ! → instellingen → Checks op je tegels na, en zet Kuma pas daarna uit.',
    ],
  },
  {
    nr: 28,
    datum: '2026-10-05',
    titel: 'Een node \'s nachts uit',
    items: [
      'df → één node \'s nachts uit: welke node leeg kan, welke VM\'s en CT\'s waarheen verhuizen (met de commando\'s), wat het bespaart en een cronregel die hem \'s avonds uitzet en \'s ochtends weer aan.',
    ],
    instellen: [
      'Kijk in df → voorstel berekenen welke HP \'s nachts uit kan.',
    ],
  },
  {
    nr: 27,
    datum: '2026-10-05',
    titel: 'Back-ups dubbel en een sterkere cluster',
    items: [
      'hw → back-ups: per VM/CT in welke back-upjob hij zit, op hoeveel PBS\'en een kopie staat, hoe oud de nieuwste is en wanneer hij hersteld getest is. Rood als hij in geen enkele job zit of nergens een kopie heeft, oranje als hij maar op één PBS staat.',
      'PBS-sync: het dashboard stelt voor welke PBS elke nacht een kopie ophaalt van de andere, op welk uur, en of het past. Commando\'s om te plakken, of één knop die het via SSH zelf instelt.',
      'hw → cluster toont de Proxmox-versie per node en waarschuwt als ze verschillen.',
      'Een even aantal stemmen zonder QDevice: het tabblad cluster legt uit waarom dat riskant is en hoe je in drie commando\'s een QDevice op de PBS-Pi zet.',
    ],
    instellen: [
      'Open hw → back-ups en los op wat rood staat.',
      'Neem de voorgestelde PBS-sync over (commando\'s of de knop; voor de knop moeten beide PBS\'en als SSH-host in de terminal staan).',
      'Optioneel: een QDevice op de PBS-Pi (hw → cluster).',
    ],
  },
  {
    nr: 26,
    datum: '2026-10-05',
    titel: 'Aandacht en instellingen op één plek',
    items: [
      'Nieuwe knop ! in de titelbalk: alles wat nu je aandacht vraagt, van alle vensters samen en gesorteerd op ernst. Services down, mislukte back-ups en cronjobs, schijven, cluster, opslag die volloopt, WAN en tunnels, Zabbix, updates, certificaten, domeinen, nieuwe apparaten, API\'s die een fout geven.',
      'Bovenaan het dashboard staan de rode en oranje punten meteen; klik erop en je komt in het venster waar je het oplost. ✕ verbergt de strook tot er iets verandert.',
      '"negeren" verbergt één punt tot het verandert of opgelost is.',
      'Tabblad instellingen: per functie of ze werkt, half ingesteld is (met wat er ontbreekt) of nog niet. Het kijkt ook na welke rechten je Proxmox-tokens missen.',
    ],
    instellen: [
      'Open ! → instellingen en werk af wat rood of oranje staat.',
    ],
  },
  {
    nr: 25,
    datum: '2026-10-05',
    titel: 'Veiliger van buitenaf',
    items: [
      'Van buitenaf (via Cloudflare of een publiek IP) staan de terminal, updates installeren, acties (VM\'s aan/uit, Wake-on-LAN, zelfherstel, snapshots, hersteltest) en configuraties downloaden standaard uit. Kijken kan altijd. Bovenaan staat dan "buiten".',
      'Heb je onderweg iets nodig: zet het voor één uur aan met je 2FA-code (je krijgt een melding). Altijd aanzetten kan alleen thuis: ⚿ → van buitenaf.',
      'Proxmox kan nu met twee tokens: een alleen-lezen token voor monitoring en een apart actietoken voor acties, snapshots, updates en de hersteltest.',
      'Terminal → sleutels → vastzetten: de SSH-sleutel van het dashboard werkt daarna alleen nog vanaf het dashboard (from= in authorized_keys). Het dashboard kijkt na of het er nog in kan en zet het anders terug.',
      'net → firewall: welke IP\'s en poorten het dashboard echt gebruikt, met een voorstel voor aliassen en regels in OPNsense, en of er Cloudflare Access of Authentik voor het dashboard staat.',
      'hw → beveiliging: een veiligheidscheck van 2FA, secret.key, de kopie buiten de container, sessies van buitenaf, de tokens, de SSH-sleutel en wat er van buitenaf mag.',
    ],
    instellen: [
      'Proxmox: maak een tweede token voor acties (README, "Twee tokens") en zet het bij je Proxmox-API als action_username en action_password. Maak daarna het eerste token alleen-lezen.',
      'Kijk hw → beveiliging na en volg wat oranje staat.',
    ],
  },
  {
    nr: 24,
    datum: '2026-10-05',
    titel: 'Vaste versies en een update terugdraaien',
    items: [
      'Het installatiescript vraagt één keer welke versie je wil: "stabiel" (de laatste release, aanbevolen) of "nieuwste" (om nieuwe functies te testen), en onthoudt dat. Wisselen kan met KANAAL=stabiel of KANAAL=nieuwste voor het commando.',
      'Werkt iets niet na een update: homepage-terugzetten in de container zet de vorige versie terug, met de database van vlak voor die update.',
      'Dit venster: na een update zie je één keer wat er nieuw is. Later terugvinden via Ctrl+K → "wat is er nieuw".',
      'Een verse installatie liep vast op een container zonder eerdere configuratie; opgelost.',
    ],
    instellen: [],
  },
  {
    nr: 23,
    datum: '2026-10-05',
    titel: 'Zabbix bij elke tegel',
    items: [
      'Elke tegel krijgt een stip "zbx": rood als een Zabbix-host erachter onbereikbaar is of een probleem van ernst "gemiddeld" of hoger heeft.',
      'In het mini dashboard: CPU, RAM, schijf, uptime en ping met een grafiek van 24 uur, en de open problemen.',
      'Klopt een koppeling niet: bewerken → Monitoring → Zabbix-hosts.',
    ],
    instellen: [
      'In Zabbix: Gebruikers → API-tokens, een token voor een gebruiker die alle hosts mag lezen.',
      'Een tegel of API van soort "zabbix" met de url van de webinterface en het token als geheim "token".',
    ],
  },
  {
    nr: 22,
    datum: '2026-10-05',
    titel: 'API-beheer',
    items: [
      'Knop "api" in de titelbalk: al je API\'s per categorie, met eigen calls en welke tegel welke API gebruikt.',
      '"⚡ tegels herkennen" maakt voor 25 bekende apps (Radarr, Sonarr, Jellyfin, Plex, Immich, ...) meteen werkende calls.',
    ],
    instellen: ['Per herkende app de API-sleutel invullen in het api-venster.'],
  },
  {
    nr: 21,
    datum: '2026-10-05',
    titel: 'Meldingen, onderhoud, zoeken, kaart en hersteltest',
    items: [
      'Webhooks van Proxmox, PBS en Home Assistant komen in je meldingen; onderhoud vooraf plannen; notities tijdens een storing.',
      'Ctrl+K zoekt overal, ook op IP of MAC. Containerlogs van Portainer in de logviewer.',
      'net → kaart: zie wat er mee uitvalt als een node stopt. Maandelijkse hersteltest van een back-up uit PBS (staat uit).',
    ],
    instellen: [
      'Webhooks: per tool aanmaken via Ctrl+K → "webhooks"; het venster toont wat je aan de andere kant invult.',
      'Hersteltest: PBS als opslag in Proxmox koppelen en aanzetten in het mini dashboard van de PBS-tegel.',
    ],
  },
]
