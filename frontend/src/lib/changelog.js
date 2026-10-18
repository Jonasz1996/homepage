// Wat er nieuw is, nieuwste bovenaan. Na een update toont het dashboard één keer wat je nog niet gezien hebt.
// nr loopt op en verandert nooit: het dashboard onthoudt per gebruiker het hoogste nummer dat het al toonde.
// "instellen": wat je zelf moet doen voor het werkt.
export const CHANGELOG = [
  {
    nr: 43,
    datum: '2026-10-18',
    titel: 'Geen login en geen 2FA meer',
    items: [
      'Het dashboard vraagt geen wachtwoord en geen 2FA-code meer, thuis en van buitenaf, tot Authentik ervoor staat. Je bent dan je eigen account; bovenaan staat "zonder login". Uitloggen staat er dan niet meer bij.',
      'Van buitenaf blijven terminal, updates, acties en downloads zonder login altijd dicht, ook als ze op "altijd" stonden, en ze gaan dan ook niet aan. Ook Authentik instellen kan van buitenaf alleen met een echte login. Thuis werkt alles.',
      'Zonder login werkt op een IP-adres en op elke naam waarop je al eens aanmeldde (bv. homepage.jbogaert.be). Op een nieuwe naam vraagt het één keer je login, daarna niet meer. Zo kan een vreemde website die je thuis opent het dashboard niet bedienen.',
      'Terug aanzetten: ⚿ → van buitenaf → Aanmelden (altijd met 2FA, thuis zonder, of overal zonder). Uitzetten kan alleen thuis, aanzetten overal. Elke wijziging komt in de meldingen en de auditlog.',
    ],
    instellen: [],
  },
  {
    nr: 42,
    datum: '2026-10-17',
    titel: 'Terminal: zegt waarom verbinden niet lukt',
    items: [
      'Bij de eerste verbinding met een host staat er nu dat het dashboard de vingerafdruk van de server ophaalt, nog voor het aanmelden: dat is geen login-sleutel. Daarna zie je waarmee het aanmeldt, bijvoorbeeld "wachtwoord uit ⚙ standaard" of "sleutel van deze host".',
      'Antwoordt een host niet, dan stond er na 10 s alleen "Verbinden mislukt:". Nu zie je welk IP en welke poort, en of er geen antwoord kwam (machine uit of firewall), de verbinding geweigerd werd, er geen route is, de naam onbekend is, of de server wel antwoordt maar het aanmelden te lang duurt. Wordt het aanmelden geweigerd, dan staat erbij wat je nakijkt (wachtwoord, sleutel in authorized_keys, of root met wachtwoord in sshd). Hetzelfde overal waar het dashboard via SSH werkt (cron, updates, diff, hw, back-ups, syslog instellen).',
      'Typen of het venster vergroten terwijl de vraag "Klopt deze hostsleutel?" openstaat, telt niet meer als Weigeren en sluit de verbinding niet meer af.',
    ],
    instellen: [],
  },
  {
    nr: 41,
    datum: '2026-10-17',
    titel: 'Toestellen uit Proxmox: sneller en duidelijker',
    items: [
      '⟳ pve in de terminal vraagt elke Proxmox nu één keer, en allemaal tegelijk. Antwoordt er een niet (bijvoorbeeld een oud adres na een nieuwe cluster), dan zie je na 8 s welk adres en wat je kunt nakijken, in plaats van een halve minuut wachten en "voeg eerst een Proxmox-tegel toe". Tegels van type proxmox zonder token staan apart op één regel.',
    ],
    instellen: [],
  },
  {
    nr: 40,
    datum: '2026-10-17',
    titel: 'Vangnetten die echt werken',
    items: [
      'homepage-terugzetten kijkt nu eerst alles na terwijl het dashboard nog draait (de kopie leesbaar, de juiste versie van TimescaleDB, genoeg vrije schijfruimte) en weigert anders zonder iets te veranderen. Bij een grote database liep het vroeger mis nadat de live database al weg was. Gaat er toch iets mis, dan zegt het precies waar je staat en hoe je terugkomt.',
      'Nachtelijke updates en "alles bijwerken" slaan de container van het dashboard zelf over: de machine krijgt in Beheer → Updates het label "het dashboard zelf". Mislukt het verversen of downloaden van de pakketten (mirror of DNS weg), dan is er niets geïnstalleerd en wordt er niet meer teruggedraaid.',
      'Nieuwe service staat standaard alleen op proef. Maken, opruimen en ongedaan maken werken pas als je bovenaan in het venster "echt uitvoeren" aanzet (met je 2FA-code).',
      'Elke installatie of update schrijft een log in /var/log/homepage, kijkt na of de API, de worker en de syslog-ontvanger echt draaien, en zet max_connections van PostgreSQL hoger als dat nodig is. Nieuw commando homepage-diagnose: één tekstbestand met wat er mis is, ook als het dashboard zelf niet opstart.',
      'De herstelstappen naast de back-ups en in het noodplan werken nu op een nieuwe container: zonder sudo, met de juiste versie van TimescaleDB en met de databasemigratie.',
      'De diagnose (! → diagnose ↓) bevat nu ook de laatste runs van Nieuwe service, de stand van het noodplan, de laatste proeven en de fouten uit je browser.',
    ],
    instellen: [
      'Kijk in Beheer → Updates of precies één machine "het dashboard zelf" heet, en of het de juiste is. Update die container voortaan met het installatiecommando, of vanuit de Proxmox-console.',
      'Na een eerste proef van Nieuwe service op je echte systemen: zet "echt uitvoeren" aan als alles klopt.',
    ],
  },
  {
    nr: 39,
    datum: '2026-10-11',
    titel: 'Noodplan',
    items: [
      'Infrastructuur → Noodplan: één document om af te drukken of als pdf te bewaren, met per node elke VM en CT (ID, IP, MAC, opslag, autostart) en welke schijven niet in de back-up zitten, waar de back-ups staan, een commando per VM en CT om hem terug te zetten, waar de kopieën van OPNsense en NPM staan, welke sleutels je nodig hebt en waar ze liggen, hoe je het dashboard zelf terugzet, en de adressen van Proxmox, PBS en OPNsense op IP. Er staan geen wachtwoorden of sleutels in.',
      'Het wordt elke maandagochtend vanzelf bijgewerkt, of met "nu bijwerken". Staat de kopie buiten de container aan, dan staan noodplan.html en noodplan.md ook in /mnt/homepage-backup, voor als het dashboard zelf plat ligt. Tonen en downloaden vraagt je 2FA-code. Lukt een Proxmox of PBS al twee weken niet, of is het noodplan te oud, dan staat het onder !.',
    ],
    instellen: [
      'Niets nodig. Wil je het ook buiten de container: Gezondheid › homepage zelf → kopie buiten de container aan, met een wachtzin. Open noodplan.html daarna eens vanaf je pc via de share, en kijk of elke VM en CT een IP en MAC heeft.',
    ],
  },
  {
    nr: 38,
    datum: '2026-10-11',
    titel: 'Nieuwe service in één keer',
    items: [
      'Beheer → Nieuwe service: één formulier met naam, IP en poort maakt de proxy host in NPM (met het wildcardcertificaat of een eigen Let\'s Encrypt-certificaat), het record in Cloudflare of een regel in de tunnel, de naam in AdGuard, een tegel met check (en de koppeling met Zabbix), en zet de CT/VM in een back-upjob van PBS. Kies "alleen thuis" of publiek; "alleen thuis" vraagt een toegangslijst van NPM die alleen je LAN en VPN toelaat.',
      'Eerst een proef: die zegt per systeem wat er zou gebeuren en wat ontbreekt, en voert niets uit. Pas je daarna iets aan, dan moet de proef opnieuw. Uitvoeren vraagt je 2FA en komt in de audit-log; je ziet stap per stap wat lukt.',
      'Stopt een run halverwege (of herstart de homepage ondertussen), dan haalt "ongedaan maken" weg wat hij al maakte, ook weer na een proef. Zo\'n halve run staat onder ! tot je hem ongedaan maakt (een gestopte opruimrun: tot opruimen van die naam lukt). Moet je na een geslaagde run nog iets zelf doen, zoals de hostname in config.yml van een lokaal beheerde tunnel, dan zegt het venster dat in plaats van "werkt".',
      'Het tabblad opruimen (of "opruimen…" bij een tegel op je domein) doet het omgekeerde: DNS eerst, dan AdGuard, NPM, eventueel de back-up en de tegel als laatste. Het raakt alleen records en rewrites die naar NPM wijzen of die het dashboard zelf maakte; wat blijft staan, zegt de proef. Records van het dashboard waarvan de host in NPM weg is, staan eronder om op te ruimen.',
      'Het tabblad geschiedenis toont elke run met zijn stappen. De Instellingen-checklist heeft een rij "Nieuwe service in één keer" die zegt wat er nog ontbreekt.',
      'Van buitenaf hoort dit bij ⚿ → van buitenaf → acties.',
    ],
    instellen: [
      'NPM: een tweede gebruiker "dashboard-acties" met een echt e-mailadres, geen Administrator, Item Visibility All Items en Proxy Hosts en Certificates op Manage. Vul die in als action_username en action_password bij de NPM-API (README → Nieuwe service in één keer).',
      'Cloudflare: een token met Zone Read en DNS Edit op jbogaert.be (plus Cloudflare Tunnel Edit als je namen via de tunnel gaan), als nieuwe API van soort Cloudflare DNS met zone = jbogaert.be.',
      'Proxmox, voor de back-up: liefst een back-upjob op een pool en Pool.Allocate op die pool voor homepage-acties@pve; of, voor een job met een lijst VMID\'s, Sys.Modify op / en Datastore.Allocate op de opslag van de job (README zegt wat die rechten nog meer toelaten).',
      'Voor "alleen thuis": een toegangslijst in NPM met alleen je LAN en VPN (bv. allow 192.168.0.0/16), satisfy all, die ook het dashboard toelaat.',
    ],
  },
  {
    nr: 37,
    datum: '2026-10-11',
    titel: 'Check van buitenaf',
    items: [
      'Netwerk → check van buitenaf: een gratis Cloudflare Worker bekijkt je publieke tegels om de 5 minuten van buitenaf, zoals een bezoeker. Werkt iets thuis wel en van buitenaf niet (tunnel, NPM, DNS, certificaat), dan staat op de tegel "thuis ok · buiten down" en krijg je een melding; vallen er meer tegels om dezelfde reden uit, dan één melding voor allemaal.',
      'Een klein bolletje op een tegel zegt dat ze ook van buitenaf gecheckt wordt.',
    ],
    instellen: [
      'In Cloudflare een API-token met Account → Workers Scripts → Edit. Zet het in API-beheer bij je Cloudflare-API als geheim workers_token. Dan in Netwerk → check van buitenaf: proef en In Cloudflare zetten, en daarna het token weghalen. Liever zelf plakken kan ook.',
    ],
  },
  {
    nr: 36,
    datum: '2026-10-11',
    titel: 'Wat is publiek',
    items: [
      'Netwerk heeft een tabblad publiek: per naam onder jbogaert.be of iemand op internet erbij kan, en of er een login voor staat (Cloudflare Access, Authentik of een toegangslijst in NPM). Rood = van buitenaf bereikbaar zonder login ervoor. Het tabblad toont het aantal rode namen.',
      'Het dashboard volgt elke weg naar binnen: de tunnel, de oranje en de grijze wolk, en rechtstreeks via je thuis-IP als poort 443 daar voor iedereen naar NPM gaat. Dan is Cloudflare Access te omzeilen, en dat zegt het ook. Een IP-lijst die je LAN toelaat, telt via de tunnel niet: cloudflared komt zelf van je LAN.',
      'Ook records die iemand kan overnemen (naar een vroeger thuis-IP, of naar een naam die niet meer bestaat), records waar NPM niets mee doet en wildcards. Heeft een app zijn eigen login, of gebruik je een record voor je VPN, markeer het dan als bewust (met je 2FA-code en een reden).',
      'Elk uur nagekeken. Een naam die nieuw open staat, geeft een melding, en ! toont de rode namen. Het dashboard leest alleen: het verandert niets in Cloudflare, NPM of OPNsense. Welke calls het doet, zie je met "welke calls?".',
    ],
    instellen: [
      'Cloudflare → My Profile → API Tokens → het token van API-beheer (of van de tegel Cloudflare Tunnel) → Edit: voeg Zone → Zone → Read, Zone → DNS → Read en Account → Access: Apps and Policies → Read toe, met bij Zone Resources je zone jbogaert.be. Optioneel ook Zone → Zone Settings → Read. Krijg je een nieuw token, zet het dan in API-beheer.',
      'NPM → Users → de gebruiker van het dashboard → Permissions: Item visibility All Items, en View op Proxy Hosts, Redirection Hosts, 404 Hosts, Access Lists en SSL Certificates. Bereikt cloudflared NPM met een Docker-naam (bv. http://npm:80), zet die naam dan bij de NPM-API in npm_names.',
      'Zet de nachtelijke kopie van OPNsense aan (Beheer → Configuratiewijzigingen): zo weet het dashboard of poort 443 van je thuis-IP voor iedereen openstaat.',
      'Open Infrastructuur → Netwerk → publiek en klik op vernieuwen. Lees eerst "hoe het binnenkomt", werk dan de rode namen af, ruim records die over te nemen zijn op en beslis over de wildcard.',
    ],
  },
  {
    nr: 35,
    datum: '2026-10-11',
    titel: 'Eenvoudiger',
    items: [
      'De titelbalk heeft nog vijf knoppen: ! Aandacht (alles wat nu mis is, het enige getal dat telt), 🔔 Meldingen (gebeurtenissen) en de menu\'s Infrastructuur, Beheer en Instellingen met leesbare namen. De oude korte namen (hw, df, net, apt, diff, ...) staan er nog naast en werken ook in Ctrl+K. Op de gsm zitten de drie menu\'s samen achter ☰.',
      'De terugknop van je gsm of browser sluit het bovenste venster, menu of vraag, in plaats van het dashboard te verlaten. Vragen als "Verwijderen?" zijn eigen vensters in de stijl van het dashboard, ook in een Android-app.',
      'Haalt het dashboard een tijd niets meer op, dan zegt een rode balk sinds wanneer, met "opnieuw proberen". Bovenaan staat wanneer het laatst bijgewerkt is (oranje als dat langer dan een minuut geleden is).',
      'Een tabblad en een groep met een probleem hebben een rode of oranje stip. Klik op "x down" of op "alleen problemen" om enkel de tegels met een probleem te zien, van alle pagina\'s. Groepen klap je dicht met een klik op hun naam; dat onthoudt elk toestel apart.',
      'Effecten (Instellingen → Effecten) zetten nu echt alles uit: achtergrond, gloed, scanlijnen, glas en animaties. Op een touchscreen staan ze standaard uit.',
      'Het dashboard haalt alles op met twee verzoeken per 30 seconden in plaats van negen aparte: de tegels apart, zodat een integratie die niet antwoordt de status en de meldingen niet ophoudt. Een deel dat mislukt, probeert het de volgende keer opnieuw, en na een gewijzigde tegel rekent het de tegels meteen opnieuw.',
      'Kleine tekst en gelezen meldingen zijn beter leesbaar, en de knop ▤ voor het mini dashboard op een tegel is groter, op de gsm nog wat meer.',
    ],
    instellen: [
      'Niets. Zoek je een oude knop: Ctrl+K met de oude naam (bv. hw of df) opent hetzelfde venster.',
    ],
  },
  {
    nr: 34,
    datum: '2026-10-11',
    titel: 'Betrouwbaarheid',
    items: [
      'De grafiek en de uptime over 7 dagen, 30 dagen en een jaar laden veel sneller: de worker telt de checks per uur op. Losse checks blijven 90 dagen, de uurtotalen 400 dagen, dus de jaargrafiek blijft volledig en de database en elke back-up worden veel kleiner. Het weekrapport rekent ook zo, en het mini dashboard laadt die grafieken niet meer elke 30 seconden opnieuw (de status van nu wel).',
      'Telt de worker de checks een dag lang niet meer per uur op, dan zegt ! dat (met hoelang nog voor er checks voor goed verdwijnen), en staat het in Gezondheid › homepage.',
      'Zoeken in de logs stopt na 20 seconden met een duidelijke melding in plaats van een time-out, en houdt een processorkern vrij voor de checks. Opent de logviewer vanuit de zoekbalk, ! of een melding, dan begint hij bij de laatste 24 uur, en de gevonden regels blijven staan als alleen de grafiek te traag is. Bij een nieuwe filter verdwijnt de grafiek van de vorige meteen, en is de lijst met machines te traag, dan zegt hij dat in plaats van "Nog geen logs ontvangen". Live meekijken toont elke regel één keer en werkt ook als de lijst nog leeg is.',
      'De syslog-ontvanger gooit geen logregels meer weg als de database even weg is: hij houdt er tot 50.000 vast en schrijft ze weg zodra ze terug is, ook bij een herstart of update. Raken er toch regels verloren of draait hij niet, dan staat dat onder ! en in Gezondheid › homepage, ook als hij herstartte terwijl de database weg was. Zit zijn wachtrij vol, dan vallen alleen nieuwe regels via UDP weg; wat machines al via TCP afleverden, blijft. Regels die rsyslog vasthield (de ontvanger herstartte of zijn wachtrij zat vol), staan op hun eigen tijd in plaats van op het moment dat ze eindelijk binnenkwamen; een machine waarvan de klok meer dan een uur achterloopt, krijgt nog altijd de ontvangsttijd.',
      'Zelfherstel stuurt per storing nog maar één bericht naar je gsm (plus één als een herstart eerst lukte en daarna mislukt, en één als de regel pauzeert), ook als je tussendoor de meldingen in 🔔 wist, en volgt "Melden" van de tegel. Elke poging staat op de tijdlijn, en in 🔔 tenzij Melden op "niet" staat. Een regel gaat hoogstens 5 keer per uur af.',
      'Net → apparaten herkent privé-adressen van gsm\'s en laptops: neemt een toestel met een naam een nieuw adres met dezelfde hostnaam op dezelfde interface, dan houdt het zijn naam. Staat het oude adres nog in de ARP-tabel (OPNsense houdt het daar tot 20 minuten na het laatste antwoord), dan wacht het nieuwe een halfuur: verdwijnt het oude in die tijd, dan krijgt het de naam alsnog; staan ze er dan allebei nog, dan is het een ander toestel en krijg je een gewone melding met die naam als hint. Meerdere nieuwe apparaten komen in één melding. Onbekende apparaten en de oude adressen van zo\'n toestel verdwijnen na 30 dagen; wat een naam, notitie of "volgen" heeft, of wat je op "ken ik" zette, blijft staan. Met "vergeten" haal je er zelf een weg.',
      'Een gsm of browser waar 30 dagen geen melding meer aankwam en die blijft mislukken, krijgt geen meldingen meer, met één melding; zet hem opnieuw aan in 🔔 → gsm.',
      'Elke 1e van de maand zet de homepage de nieuwste nachtelijke back-up echt terug in een testdatabase en toont het resultaat met de tabellen onder Gezondheid › homepage. Mislukt het, dan staat het onder ! en krijg je een melding. Blijft de testdatabase staan omdat de container uitviel, dan ruimt de back-up van de nacht erna hem op.',
      'Staat de back-up van het dashboard alleen in de container, dan stelt ! een kopie erbuiten voor. Verandert secret.key nadat je de wachtzin instelde, dan zegt de zelfcontrole dat de sleutel in die kopie verouderd is. LEESMIJ.txt bij de kopie noemt de versies van PostgreSQL en TimescaleDB om terug te zetten.',
      'homepage-terugzetten keurt een terugzetting af als de gegevens van een tabel niet terug konden, en "De laatste back-up is onleesbaar" onder ! zegt nu waarom.',
      'Met TimescaleDB 2.29 of nieuwer liet de nachtelijke back-up de gecomprimeerde logregels niet weg (TimescaleDB noemt die delen sinds 2.29 anders). Nu zoekt hij ze op hun exacte naam op, ook de delen met een oude naam van voor een update van TimescaleDB, dus de back-up wordt weer klein.',
      'Een fout van een proxy zonder uitleg toont nu bv. "Mislukt (fout 504)" in plaats van niets. Alle acties in het auditlog hebben nu een leesbare naam.',
    ],
    instellen: [
      'Niets verplicht. Wil je de test van de back-up meteen zien in plaats van op de 1e: voer in de container één keer systemctl start homepage-backuptest uit.',
      'Optioneel: rol rsyslog opnieuw uit op de machines die je eerder instelde (logs → machines toevoegen, dezelfde SSH-host). Dan houden regels die rsyslog vasthield hun eigen tijd.',
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
      'Onderhoud beginnen of verlengen, gepland onderhoud aanzetten, een cronjob dempen, een webhook of logregel uitzetten en een beveiligingspunt negeren vragen nu je 2FA-code en geven een melding op je gsm, net als een check pauzeren. Dat geldt ook voor een tegel met een lopende check naar een groep slepen met gepland onderhoud, ook als dat pas later begint (de melding zegt wanneer), en voor een tegel zonder check verplaatsen of ergens onder hangen als er een tegel met een lopende check onder hangt. Een herhalend onderhoudsvenster duurt hoogstens 12 uur per keer; een ouder venster dat langer bewaard was, loopt ook maar 12 uur en kun je gewoon uitzetten, bewerken of verwijderen. Een venster uitzetten of verwijderen stopt alleen het onderhoud dat het zelf zette: wat je met de hand verlengde, blijft staan.',
      '"Wis gelezen" laat meldingen staan die nog niet naar je gsm gestuurd zijn. In ! zie je onderhoud dat met de hand gezet is en meer dan een dag loopt, of voor veel services tegelijk. Op de tijdlijn staat elke actie nog maar één keer; onderhoud, verwijderde logregels en wachtwoordwijzigingen van vóór de update blijven er staan.',
      'Rechtstreeks op http://IP laat nginx het dashboard alleen nog open vanuit de container zelf, en van het LAN alleen push-monitors, webhooks en /api/healthz. Na deze update blijft het hele LAN wel open tot je zelf HOMEPAGE_LAN_OPEN=0 zet; ! → instellingen → "Dashboard alleen via NPM" zegt hoe. Een toestel met een publiek IPv6-adres in het netwerk van de container telt als LAN, andere netwerken zet je in HOMEPAGE_LAN_NETS. De 403-pagina zegt van welk adres het verzoek kwam.',
      'SSH-sleutel vastzetten zet alleen nog losse IP-adressen in from=, en een from= met een patroon of netwerk telt als "elk IP". Een link in een notitie kan geen eigen attributen meer krijgen.',
    ],
    instellen: [
      'Open het dashboard na de update via zijn naam in NPM. Werkt dat, zet dan in de container HOMEPAGE_LAN_OPEN=0 in /etc/homepage/homepage.env en voer bash /opt/homepage/deploy/install.sh uit. Krijg je daarna via NPM een 403, dan klopt HOMEPAGE_NPM_IP daar niet: zet het juiste IP en voer het opnieuw uit.',
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
