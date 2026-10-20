// Wat er nieuw is, nieuwste bovenaan. Na een update toont het dashboard één keer wat je nog niet gezien hebt.
// nr loopt op en verandert nooit: het dashboard onthoudt per gebruiker het hoogste nummer dat het al toonde.
// "instellen": wat je zelf moet doen voor het werkt.
export const CHANGELOG = [
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
