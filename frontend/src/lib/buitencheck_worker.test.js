// Tests voor de Cloudflare Worker van de check van buitenaf (backend/app/monitoring/buitencheck_worker.mjs): npm test.
// fetch is nagebootst; de Worker draait hier gewoon onder Node.
import assert from 'node:assert/strict'
import { afterEach, test } from 'node:test'
import worker from '../../../backend/app/monitoring/buitencheck_worker.mjs'

const SECRET = 'a'.repeat(40)
const ENV = { HOMEPAGE_TOKEN: SECRET, ALLOWED_SUFFIXES: 'jbogaert.be' }
const real = globalThis.fetch
let calls = []

// Nagebootst internet: antwoord(url, init) geeft een Response (of gooit).
function stub(antwoord) {
  calls = []
  globalThis.fetch = async (url, init) => {
    calls.push({ url, init })
    return antwoord(url, init)
  }
}
afterEach(() => { globalThis.fetch = real })

function vraag(checks, { auth = `Bearer ${SECRET}`, method = 'POST', path = '/check' } = {}) {
  const headers = { 'content-type': 'application/json' }
  if (auth) headers.authorization = auth
  return new Request(`https://homepage-buitencheck-1a2b3c4d.jonas.workers.dev${path}`, {
    method, headers, body: method === 'POST' ? JSON.stringify({ v: 1, checks }) : undefined,
  })
}
async function run(checks, opts = {}, env = ENV) {
  const r = await worker.fetch(vraag(checks, opts), env)
  return { status: r.status, data: r.status === 200 ? await r.json() : null }
}
const check = (u, i = 1) => ({ i, u })

test('zonder het juiste geheim een kale 404, en niets opgehaald', async () => {
  stub(() => new Response('ok'))
  for (const auth of ['Bearer fout', `Bearer ${SECRET}x`, null, SECRET]) {
    assert.equal((await run([check('https://a.jbogaert.be/')], { auth })).status, 404)
  }
  // Een te kort geheim in Cloudflare telt als geen geheim.
  const kort = 'b'.repeat(31)
  assert.equal((await run([check('https://a.jbogaert.be/')], { auth: `Bearer ${kort}` },
                          { ...ENV, HOMEPAGE_TOKEN: kort })).status, 404)
  assert.equal((await run([], { method: 'GET' })).status, 404)
  assert.equal((await run([], { path: '/' })).status, 404)
  assert.equal(calls.length, 0)
})

test('alleen https onder ALLOWED_SUFFIXES, en nooit een heel topdomein', async () => {
  stub(() => new Response('ok'))
  const { data } = await run([check('http://a.jbogaert.be/', 1), check('https://evil.be/', 2),
                              check('https://jbogaert.be.evil.be/', 3), check('geen adres', 4)])
  assert.deepEqual(data.results.map((r) => r.e), ['niet toegelaten', 'niet toegelaten', 'niet toegelaten', 'ongeldig adres'])
  const be = await run([check('https://evil.be/')], {}, { ...ENV, ALLOWED_SUFFIXES: 'be, .be' })
  assert.equal(be.data.results[0].e, 'niet toegelaten')
  assert.equal(calls.length, 0)
  // De naam zelf en alles eronder mag wel.
  const ok = await run([check('https://jbogaert.be/', 1), check('https://Jelly.JBogaert.be/x', 2)], {},
                       { ...ENV, ALLOWED_SUFFIXES: ' .jbogaert.be ,lan' })
  assert.deepEqual(ok.data.results.map((r) => [r.i, r.c, r.e]), [[1, 200, null], [2, 200, null]])
  assert.equal(ok.data.script, 1)
  assert.equal(ok.data.colo, null)
})

test('hoogstens 45 adressen en 6 tegelijk', async () => {
  let open = 0
  let most = 0
  stub(async () => {
    open++
    most = Math.max(most, open)
    await new Promise((r) => setTimeout(r, 5))
    open--
    return new Response('ok')
  })
  const { data } = await run(Array.from({ length: 50 }, (_, i) => check(`https://t${i}.jbogaert.be/`, i)))
  assert.equal(data.results.length, 45)
  assert.equal(calls.length, 45)
  assert.equal(most, 6)
  assert.deepEqual(data.results.map((r) => r.i), Array.from({ length: 45 }, (_, i) => i))
})

test('foutcodes van Cloudflare en wie antwoordde', async () => {
  stub((url) => {
    if (url.includes('tunnel')) return new Response('<title>Error 1033</title> ... Error code 1033 ...', { status: 530 })
    if (url.includes('waf')) return new Response('error code: 1020', { status: 403 })
    if (url.includes('npm')) return new Response('<center>openresty</center>', { status: 502 })
    if (url.includes('weg')) return new Response(null, { status: 302, headers: { location: 'https://auth.jbogaert.be/login' } })
    if (url.includes('bot')) return new Response('', { status: 403, headers: { 'cf-mitigated': 'challenge' } })
    return new Response('ok')
  })
  const { data } = await run([check('https://tunnel.jbogaert.be/', 1), check('https://waf.jbogaert.be/', 2),
                              check('https://npm.jbogaert.be/', 3), check('https://weg.jbogaert.be/', 4),
                              check('https://bot.jbogaert.be/', 5)])
  const [tunnel, waf, npm, weg, bot] = data.results
  assert.deepEqual([tunnel.c, tunnel.cfe, tunnel.srv], [530, 1033, null])
  assert.deepEqual([waf.c, waf.cfe], [403, 1020])
  assert.deepEqual([npm.c, npm.srv, npm.cfe], [502, 'nginx', null])
  assert.deepEqual([weg.c, weg.loc, weg.cfe], [302, 'https://auth.jbogaert.be/login', null])
  assert.equal(bot.cfm, 'challenge')
  assert.ok(tunnel.ms >= 0)
})

test('time-out en netwerkfout', async () => {
  stub((url) => {
    if (url.includes('traag')) throw new DOMException('The operation was aborted due to timeout', 'TimeoutError')
    throw new TypeError('fetch failed')
  })
  const { data } = await run([check('https://traag.jbogaert.be/', 1), check('https://dood.jbogaert.be/', 2)])
  assert.deepEqual(data.results.map((r) => [r.c, r.e]), [[0, 'time-out'], [0, 'fetch failed']])
})

test('volgt geen doorverwijzingen en vraagt niets uit de cache', async () => {
  stub(() => new Response('ok'))
  await run([check('https://a.jbogaert.be')])
  assert.equal(calls[0].url, 'https://a.jbogaert.be/')
  assert.equal(calls[0].init.redirect, 'manual')
  assert.equal(calls[0].init.cache, 'no-store')
  assert.ok(calls[0].init.signal)
})
