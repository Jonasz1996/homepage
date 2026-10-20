// Kleine wrapper rond fetch. De X-Requested-With-header is de CSRF-bescherming van de API.
import { apiFailed } from './errorring.js'

export class ApiError extends Error {
  constructor(message, status) {
    super(message)
    this.status = status
  }
}

// Een Blob als body gaat zoals hij is (een stuk van een upload), al de rest als JSON. signal: afbreken.
export async function api(path, { method = 'GET', body, signal } = {}) {
  const headers = { 'X-Requested-With': 'homepage' }
  const raw = typeof Blob !== 'undefined' && body instanceof Blob
  if (body !== undefined) headers['Content-Type'] = raw ? 'application/octet-stream' : 'application/json'
  let r
  try {
    r = await fetch('/api' + path, {
      method,
      headers,
      credentials: 'same-origin',
      signal,
      body: body === undefined ? undefined : raw ? body : JSON.stringify(body),
    })
  } catch (e) {
    // Geen antwoord (geen netwerk, de server herstart): voor de diagnose als status 0. Zelf afgebroken telt niet.
    if (e?.name !== 'AbortError') apiFailed(method, '/api' + path, 0, e?.message)
    throw e
  }
  const text = await r.text()
  let data = null
  try { data = text ? JSON.parse(text) : null } catch { data = text }
  if (!r.ok) {
    const d = data?.detail
    // Zonder uitleg van de API (bv. een 502/504 van een proxy ertussen) en zonder statusText (leeg over HTTP/2,
    // zoals via NPM of Cloudflare): dan toch iets leesbaars, met de code.
    const msg = typeof d === 'string' ? d : Array.isArray(d) ? d.map((x) => String(x.msg).replace(/^Value error, /, '')).join(', ') : r.statusText || `Mislukt (fout ${r.status})`
    apiFailed(method, '/api' + path, r.status, msg)
    if (r.status === 401 && !path.startsWith('/auth/')) window.dispatchEvent(new Event('hp:unauth'))
    if (r.status === 403 && msg.startsWith('buiten:')) {
      signalOutside(msg)
      throw new ApiError(outsideMessage(msg), 403)
    }
    throw new ApiError(msg, r.status)
  }
  return data
}

// Herhaalt fn elke ms milliseconden, maar niet zolang het tabblad verborgen is.
// Komt het tabblad terug in beeld, dan meteen een verse lading. Geeft een stopfunctie terug.
export function poll(fn, ms) {
  const t = setInterval(() => { if (!document.hidden) fn() }, ms)
  const vis = () => { if (!document.hidden) fn() }
  document.addEventListener('visibilitychange', vis)
  return () => { clearInterval(t); document.removeEventListener('visibilitychange', vis) }
}

// Gevoelige acties vragen een recente 2FA-bevestiging. withReauth voert fn uit; antwoordt de
// server "reauth_required", dan vraagt ReauthDialog de code en probeert het één keer opnieuw.
export function requestReauth() {
  return new Promise((resolve, reject) => {
    window.dispatchEvent(new CustomEvent('hp:reauth', { detail: { resolve, reject } }))
  })
}

export async function withReauth(fn) {
  try {
    return await fn()
  } catch (e) {
    if (!(e instanceof ApiError && e.status === 403 && e.message === 'reauth_required')) throw e
    await requestReauth()
    return await fn()
  }
}

// Buitenmodus: van buitenaf (via Cloudflare of een publiek IP) staan sommige functies uit. De server antwoordt dan
// "buiten:<functie>"; het dashboard toont een venster om ze voor één uur aan te zetten.
export const OUTSIDE = { terminal: 'de terminal', updates: 'updates installeren', acties: 'acties', downloads: 'configuraties, diagnose en noodplan downloaden' }
export const outsideMessage = (detail) => `Van buitenaf gaat ${OUTSIDE[detail.slice(7)] || detail.slice(7)} nu niet.`
export function signalOutside(detail) {
  window.dispatchEvent(new CustomEvent('hp:outside', { detail: { feature: detail.slice(7) } }))
}
