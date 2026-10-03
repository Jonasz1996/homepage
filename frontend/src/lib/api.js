// Kleine wrapper rond fetch. De X-Requested-With-header is de CSRF-bescherming van de API.
export class ApiError extends Error {
  constructor(message, status) {
    super(message)
    this.status = status
  }
}

export async function api(path, { method = 'GET', body } = {}) {
  const headers = { 'X-Requested-With': 'homepage' }
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  const r = await fetch('/api' + path, {
    method,
    headers,
    credentials: 'same-origin',
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
  const text = await r.text()
  let data = null
  try { data = text ? JSON.parse(text) : null } catch { data = text }
  if (!r.ok) {
    const d = data?.detail
    const msg = typeof d === 'string' ? d : Array.isArray(d) ? d.map((x) => x.msg).join(', ') : r.statusText
    if (r.status === 401 && !path.startsWith('/auth/')) window.dispatchEvent(new Event('hp:unauth'))
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
