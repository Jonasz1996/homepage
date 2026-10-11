// homepage-buitencheck: bekijkt adressen van buitenaf voor het dashboard (homepage).
// Het dashboard stuurt elke minuut een lijst (POST /check, met het gedeelde geheim uit de binding HOMEPAGE_TOKEN
// in de kop van het verzoek). De Worker haalt elk adres op vanuit het netwerk van Cloudflare en geeft per adres de
// statuscode terug. Geen planning, geen opslag. Alleen https-adressen onder ALLOWED_SUFFIXES: zo is hij geen open
// proxy, ook niet als het geheim uitlekt.
const SCRIPT_VERSION = 1
const MAX = 45        // gratis plan: 50 subrequests per verzoek
const LANES = 6       // Cloudflare: 6 verbindingen tegelijk; meer wacht en vertekent de tijd
const TIMEOUT = 8000
// Van deze antwoorden ook het begin van de pagina lezen: de foutcode van Cloudflare (1033, 1020) of wie antwoordde.
const SNIFF = (code) => code === 403 || code === 502 || code === 504 || (code >= 520 && code <= 530)

export default {
  async fetch(request, env) {
    const url = new URL(request.url)
    if (request.method !== 'POST' || url.pathname !== '/check') return new Response(null, { status: 404 })
    const want = String(env.HOMEPAGE_TOKEN || '')
    const got = request.headers.get('authorization') || ''
    if (want.length < 32 || !same(got, 'Bearer ' + want)) return new Response(null, { status: 404 })
    let body
    try { body = await request.json() } catch { return json({ error: 'geen JSON' }, 400) }
    const allowed = String(env.ALLOWED_SUFFIXES || '').split(',')
      .map((s) => s.trim().toLowerCase().replace(/^\.+/, '')).filter((s) => s.includes('.'))
    const checks = (Array.isArray(body?.checks) ? body.checks : []).slice(0, MAX)
    const results = new Array(checks.length)
    let next = 0
    const lane = async () => { while (next < checks.length) { const k = next++; results[k] = await one(checks[k], allowed) } }
    await Promise.all(Array.from({ length: Math.min(LANES, checks.length) }, lane))
    return json({ v: 1, script: SCRIPT_VERSION, colo: request.cf?.colo ?? null, results })
  },
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json' } })
}

// Vergelijken zonder dat de tijd verraadt hoeveel tekens kloppen.
function same(a, b) {
  const x = new TextEncoder().encode(a), y = new TextEncoder().encode(b)
  let d = x.length ^ y.length
  for (let i = 0; i < Math.max(x.length, y.length); i++) d |= (x[i] ?? 0) ^ (y[i] ?? 0)
  return d === 0
}

async function one(c, allowed) {
  const out = { i: c?.i ?? null, c: 0, ms: null, e: null, loc: null, cfm: null, cfe: null, srv: null }
  let u
  try { u = new URL(String(c?.u)) } catch { out.e = 'ongeldig adres'; return out }
  const host = u.hostname.toLowerCase()
  if (u.protocol !== 'https:' || !allowed.some((s) => host === s || host.endsWith('.' + s))) { out.e = 'niet toegelaten'; return out }
  const t0 = Date.now()
  try {
    const r = await fetch(u.toString(), { redirect: 'manual', cache: 'no-store', signal: AbortSignal.timeout(TIMEOUT),
                                          headers: { 'user-agent': 'homepage-buitencheck/1' } })
    out.ms = Date.now() - t0
    out.c = r.status
    out.loc = (r.headers.get('location') || '').slice(0, 300) || null
    out.cfm = r.headers.get('cf-mitigated')
    if (SNIFF(r.status)) {
      const page = (await r.text()).slice(0, 8000)
      const m = page.match(/error(?: code)?:?\s*(1\d{3})/i)
      out.cfe = m ? Number(m[1]) : null
      out.srv = /openresty|nginx/i.test(page) ? 'nginx' : /cloudflared/i.test(page) ? 'cloudflared' : null
    } else {
      await r.body?.cancel()
    }
  } catch (err) {
    out.ms = Date.now() - t0
    out.e = err?.name === 'TimeoutError' ? 'time-out' : String(err?.message || err).slice(0, 200)
  }
  return out
}
