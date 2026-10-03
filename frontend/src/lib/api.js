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
