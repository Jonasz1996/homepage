// Aandacht: welke knop een punt krijgt (fix.window → tekst) en hoe een gebied heet.
import { byId, NAMES, resolve } from './windows.js'

// Waar de naam van het venster niet volstaat: een tegel, of een venster binnen de terminal of de logs.
const SPECIAL = {
  detail: 'tegel', edit: 'bewerken', 'ssh-keys': 'sleutels', 'ssh-defaults': 'standaardlogin', 'ssh-discover': 'uit Proxmox',
  'logs-setup': 'machines toevoegen',
}
export const FIX_LABEL = Object.fromEntries(NAMES.map((w) => [w, SPECIAL[w] || byId[resolve(w)?.id]?.label]))

export const AREA = {
  services: 'down', checks: 'check', 'back-ups': 'back-up', cluster: 'cluster', hardware: 'hardware', opslag: 'opslag', netwerk: 'netwerk',
  homepage: 'dashboard', zabbix: 'zabbix', cron: 'cron', updates: 'updates', certificaten: 'certificaat',
  domeinen: 'domein', integraties: 'API', beveiliging: 'beveiliging', apparaten: 'apparaten', snapshots: 'snapshots',
  onderhoud: 'onderhoud',
}
