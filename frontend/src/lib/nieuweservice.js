// Nieuwe service in één keer: het domein (zonder call naar buiten) en of een tegel daarin valt, voor de knop
// "opruimen…" bij een tegel. Het venster zelf staat in NewService.svelte.
import { api } from './api.js'

// Eén vraag per pagina. Geen domein (nog geen Cloudflare DNS-API) of een fout onthouden we niet: zodra je de API
// toevoegt, ziet de volgende tegel het domein wel.
let cached = null
export function nsDomain() {
  if (!cached) {
    cached = api('/nieuweservice/domein').then(
      (d) => { if (!d?.domain) cached = null; return d },
      (e) => { cached = null; throw e },
    )
  }
  return cached
}

// Eén DNS-label, zoals een wildcardcertificaat dekt (zelfde regel als de server).
export const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/

/** Is de host van deze url precies <label>.<domein>? Nooit het domein zelf, een diepere naam of een IP. */
export function inZone(url, domain) {
  if (!url || !domain) return false
  let host
  try { host = new URL(url).hostname.toLowerCase().replace(/\.$/, '') } catch { return false }
  const i = host.indexOf('.')
  return i > 0 && host.slice(i + 1) === domain.toLowerCase() && LABEL.test(host.slice(0, i))
}
