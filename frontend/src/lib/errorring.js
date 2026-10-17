// De laatste fouten in deze browser, voor de diagnose (! → diagnose ↓): niet opgevangen fouten, verworpen beloftes
// en mislukte API-verzoeken. In het geheugen en in sessionStorage (blijft over een herlaadbeurt, weg met het
// tabblad). Gaat alleen mee met een diagnose die je zelf downloadt; de server maskeert de geheimen erin en bewaart
// niets. Geen querystring (daar staan soms codes of tokens in) en geen blobs.
export const MAX = 50
export const TEXT = 1000
const KEY = 'hp-fouten'

// Kort, zonder een half woord aan het eind (een afgekapt token herkent het maskeren niet meer) en zonder blobs: een
// lange reeks zonder spatie wordt zijn lengte, zoals op de server.
export function short(text, n = TEXT) {
  const t = String(text ?? '').replace(/\S{500,}/g, (m) => `[${m.length} tekens]`)
  if (t.length <= n) return t
  const head = t.slice(0, n)
  const i = head.search(/\s\S*$/)
  return `${i > 0 ? head.slice(0, i) : ''} …`
}

// Een pad of adres zonder querystring, # en (bij een volledig adres) zonder de server ervoor.
export function bare(path) {
  const p = String(path ?? '')
  try {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(p)) return new URL(p).pathname
  } catch { /* geen geldig adres: dan zoals het is */ }
  return p.split(/[?#]/)[0]
}

export function createRing(store = () => globalThis.sessionStorage) {
  let list = null
  function load() {
    if (list) return list
    try {
      const v = JSON.parse(store()?.getItem(KEY) || '[]')
      list = Array.isArray(v) ? v.filter((x) => x && typeof x === 'object').slice(-MAX) : []
    } catch { list = [] }
    return list
  }
  function save() {
    try { store()?.setItem(KEY, JSON.stringify(list)) } catch { /* privévenster, geen opslag of vol */ }
  }
  return {
    add(entry) {
      const l = load()
      l.push({ at: new Date().toISOString(), ...entry })
      if (l.length > MAX) l.splice(0, l.length - MAX)
      save()
    },
    entries: () => load().map((x) => ({ ...x })),
    clear() {
      list = []
      save()
    },
  }
}

const ring = createRing()
export const entries = () => ring.entries()

/** Een API-verzoek dat mislukte (status 0: geen antwoord, bv. geen netwerk). */
export function apiFailed(method, path, status, msg, r = ring) {
  r.add({ kind: 'api', method: String(method || 'GET').toUpperCase(), path: short(bare(path), 300), status, msg: short(msg) })
}

function reason(x) {
  if (x instanceof Error) return `${x.name}: ${x.message}`
  if (typeof x === 'string') return x
  try { return JSON.stringify(x) } catch { return String(x) }
}

/** Luistert naar niet opgevangen fouten en verworpen beloftes. */
export function install(target = globalThis.window, r = ring) {
  if (!target?.addEventListener) return
  target.addEventListener('error', (e) => {
    // Alleen fouten in de code: een afbeelding die niet laadt, komt hier niet (dat event borrelt niet op).
    if (!e.message && !e.error) return
    const at = e.filename ? `${bare(e.filename)}:${e.lineno || 0}:${e.colno || 0}` : undefined
    r.add({ kind: 'fout', msg: short(e.error ? reason(e.error) : e.message), ...(at ? { waar: short(at, 300) } : {}) })
  })
  target.addEventListener('unhandledrejection', (e) => r.add({ kind: 'belofte', msg: short(reason(e.reason)) }))
}
