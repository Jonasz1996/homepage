// Eén lijst met alle vensters van het dashboard: hun leesbare naam, in welk menu ze staan, en onder welke andere
// namen ze geopend worden (de knoppen in Aandacht, /?open=... van de app en de pushberichten, de bron van een melding).
// Wil je een venster verplaatsen of hernoemen: alleen hier.
//
// big: een groot venster dat geladen blijft als het dicht is (terminalsessies lopen door); de rest is een gewoon venster.
// code: de oude korte naam uit de titelbalk (hw, df, ...), nog klein te zien in het menu.
export const WINDOWS = [
  { id: 'attention', label: 'Aandacht', hint: 'alles wat nu mis is', load: () => import('./Attention.svelte') },
  { id: 'notifications', label: 'Meldingen', hint: 'gebeurtenissen' },

  { id: 'health', menu: 'infra', label: 'Gezondheid', code: 'hw', big: true,
    hint: 'schijven, temperatuur, snapshots, domeinen, cluster, back-ups', load: () => import('./Health.svelte') },
  { id: 'capacity', menu: 'infra', label: 'Capaciteit', code: 'df', hint: 'opslag, cpu, ram, stroom en prognose',
    load: () => import('./Capacity.svelte') },
  { id: 'network', menu: 'infra', label: 'Netwerk', code: 'net', hint: 'internet, publiek, apparaten, kaart, firewall, Wake-on-LAN',
    load: () => import('./Network.svelte') },
  { id: 'cron', menu: 'infra', label: 'Cronjobs', code: 'cron', big: true, hint: 'geplande taken op al je machines',
    load: () => import('./Cron.svelte') },
  { id: 'logs', menu: 'infra', label: 'Logs', code: 'logs', big: true, hint: 'syslog van je machines en containers',
    load: () => import('./Logs.svelte') },
  { id: 'history', menu: 'infra', label: 'Tijdlijn', code: 'history', hint: 'archief: storingen, herstarts, weekrapport',
    load: () => import('./History.svelte') },

  { id: 'terminal', menu: 'beheer', label: 'Terminal', code: '>_', big: true, hint: 'SSH naar je machines',
    load: () => import('./Terminal.svelte') },
  { id: 'updates', menu: 'beheer', label: 'Updates', code: 'apt', hint: 'openstaande pakketten en images',
    load: () => import('./Updates.svelte') },
  { id: 'planned', menu: 'beheer', label: 'Gepland onderhoud', hint: 'vensters plannen, meldingen stil',
    load: () => import('./Planned.svelte') },
  { id: 'configs', menu: 'beheer', label: 'Configuratiewijzigingen', code: 'diff', hint: 'OPNsense, NPM, Proxmox, je bestanden',
    load: () => import('./Configs.svelte') },
  { id: 'restoretest', menu: 'beheer', label: 'Hersteltest', hint: 'back-ups maandelijks echt terugzetten (PBS)',
    load: () => import('./RestoreTestWindow.svelte') },

  { id: 'security', menu: 'instellingen', label: 'Beveiliging', code: '⚿', hint: 'sessies, auditlog, wachtwoord, van buitenaf, Authentik',
    load: () => import('./Security.svelte') },
  { id: 'apis', menu: 'instellingen', label: 'API-beheer', code: 'api', hint: "API's, sleutels en eigen calls",
    load: () => import('./ApiManager.svelte') },
  { id: 'webhooks', menu: 'instellingen', label: 'Webhooks', hint: 'meldingen van Proxmox, PBS, Home Assistant',
    load: () => import('./Webhooks.svelte') },
  { id: 'webpush', menu: 'instellingen', label: 'Meldingen op je gsm', hint: 'web push per toestel',
    load: () => import('./PushDevices.svelte') },
  { id: 'setup', menu: 'instellingen', label: 'Instellingen-checklist', hint: 'wat werkt, half of nog niet ingesteld',
    to: { id: 'attention', tab: 'instellingen' } },
  { id: 'news', menu: 'instellingen', label: 'Wat is er nieuw', hint: 'versie en wijzigingen', load: () => import('./Changelog.svelte') },

  // Zonder menu: geopend vanuit een tegel, de bewerkmodus of de zoekbalk.
  { id: 'detail', label: 'Details', load: () => import('./ServiceDetail.svelte') },
  { id: 'service', label: 'Service bewerken', load: () => import('./ServiceForm.svelte') },
  { id: 'import', label: 'Importeren', load: () => import('./ImportDialog.svelte') },
  { id: 'revisions', label: 'Versies', load: () => import('./Revisions.svelte') },
]

export const MENUS = [
  { id: 'infra', label: 'Infrastructuur', hint: 'wat er draait' },
  { id: 'beheer', label: 'Beheer', hint: 'iets doen of veranderen' },
  { id: 'instellingen', label: 'Instellingen', hint: 'het dashboard zelf' },
]

export const byId = Object.fromEntries(WINDOWS.map((w) => [w.id, w]))

// Andere namen voor een venster: van de knoppen in Aandacht (fix.window, van de server), van /?open=... en van oudere
// versies. Waarde: het venster met eventueel een tabblad of een ander startpunt.
const ALIASES = {
  aandacht: { id: 'attention', tab: 'nu' },
  instellingen: { id: 'attention', tab: 'instellingen' },
  hw: { id: 'health' },
  df: { id: 'capacity' },
  net: { id: 'network' },
  devices: { id: 'network', tab: 'apparaten' },
  apparaten: { id: 'network', tab: 'apparaten' },
  kaart: { id: 'network', tab: 'kaart' },
  firewall: { id: 'network', tab: 'firewall' },
  publiek: { id: 'network', tab: 'publiek' },
  report: { id: 'history', tab: 'report' },
  tijdlijn: { id: 'history' },
  apt: { id: 'updates' },
  diff: { id: 'configs' },
  hersteltest: { id: 'restoretest' },
  api: { id: 'apis' },
  'ssh-keys': { id: 'terminal', sub: 'keys' },
  'ssh-defaults': { id: 'terminal', sub: 'defaults' },
  'ssh-discover': { id: 'terminal', sub: 'discover' },
  'logs-setup': { id: 'logs', setup: true },
  edit: { id: 'service' },
}

/** Alle namen waaronder een venster geopend kan worden. */
export const NAMES = [...WINDOWS.map((w) => w.id), ...Object.keys(ALIASES)]

/** Naam (id, alias of fix.window) → { id, ...startpunt }, of null als het dashboard dat venster niet kent. */
export function resolve(name) {
  if (!name) return null
  const a = ALIASES[name]
  if (a) return { ...a }
  const w = byId[name]
  if (!w) return null
  return w.to ? { ...w.to } : { id: w.id }
}

// De bron van een melding → het venster dat erbij hoort.
const SOURCES = {
  rapport: { id: 'history', tab: 'report' },
  updates: { id: 'updates' },
  cron: { id: 'cron', filter: 'probleem' },
  config: { id: 'configs' },
  apparaat: { id: 'network', tab: 'apparaten' },
  hardware: { id: 'health', tab: 'schijven' },
  snapshots: { id: 'health', tab: 'snapshots' },
  domein: { id: 'health', tab: 'domeinen' },
  homepage: { id: 'health', tab: 'homepage' },
  cluster: { id: 'health', tab: 'cluster' },
  blootstelling: { id: 'network', tab: 'publiek' },
}
export const sourceWindow = (source) => (SOURCES[source] ? { ...SOURCES[source] } : null)
export const NOTIFICATION_SOURCES = Object.keys(SOURCES)
