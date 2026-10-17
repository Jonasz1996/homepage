// Tests voor de ring van de laatste fouten in de browser (mee met de diagnose): npm test (node --test).
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { apiFailed, bare, createRing, install, MAX, short } from './errorring.js'

function memory() {
  const data = new Map()
  return { getItem: (k) => data.get(k) ?? null, setItem: (k, v) => data.set(k, String(v)), data }
}

test('kort zonder half woord of blob', () => {
  assert.equal(short('kort'), 'kort')
  assert.equal(short(null), '')
  // Geen half woord aan het eind: een afgekapt token herkent het maskeren niet meer.
  assert.equal(short('een twee drie geheimtoken123', 20), 'een twee drie …')
  assert.equal(short('x'.repeat(600) + ' einde'), '[600 tekens] einde')
  assert.equal(short('abcdefghij', 5), ' …')
  assert.ok(short('woord '.repeat(400)).length <= 1002)
})

test('pad zonder querystring of server', () => {
  assert.equal(bare('/api/auth/oidc/callback?code=GEHEIM#x'), '/api/auth/oidc/callback')
  assert.equal(bare('https://dash.lan/assets/index-abc.js?v=1'), '/assets/index-abc.js')
  assert.equal(bare(undefined), '')
})

test('hoogstens de laatste MAX, ook na herladen', () => {
  const store = memory()
  const r = createRing(() => store)
  for (let i = 0; i < MAX + 10; i++) r.add({ kind: 'fout', msg: `f${i}` })
  const e = r.entries()
  assert.equal(e.length, MAX)
  assert.equal(e[0].msg, 'f10')
  assert.equal(e.at(-1).msg, `f${MAX + 9}`)
  assert.ok(e[0].at)
  // Een nieuwe pagina in hetzelfde tabblad leest ze terug.
  assert.deepEqual(createRing(() => store).entries(), e)
  // Wat de lezer aanpast, verandert de ring niet.
  e[0].msg = 'anders'
  assert.equal(r.entries()[0].msg, 'f10')
  r.clear()
  assert.deepEqual(createRing(() => store).entries(), [])
})

test('zonder opslag of met rommel erin: gewoon in het geheugen', () => {
  const broken = { getItem: () => { throw new Error('geblokkeerd') }, setItem: () => { throw new Error('vol') } }
  const r = createRing(() => broken)
  r.add({ kind: 'fout', msg: 'a' })
  assert.equal(r.entries().length, 1)
  const none = createRing(() => undefined)
  none.add({ kind: 'fout', msg: 'b' })
  assert.equal(none.entries()[0].msg, 'b')
  const store = memory()
  store.setItem('hp-fouten', '{kapot')
  assert.deepEqual(createRing(() => store).entries(), [])
  store.setItem('hp-fouten', JSON.stringify([1, null, 'x', { kind: 'api', msg: 'ok' }]))
  assert.deepEqual(createRing(() => store).entries().map((x) => x.msg), ['ok'])
})

test('mislukt verzoek: methode, pad zonder querystring, status, korte tekst', () => {
  const r = createRing(() => undefined)
  apiFailed('post', '/api/diagnose?x=GEHEIM', 403, 'reauth_required', r)
  apiFailed(undefined, '/api/x', 0, undefined, r)
  const [a, b] = r.entries()
  assert.deepEqual({ ...a, at: undefined }, { at: undefined, kind: 'api', method: 'POST', path: '/api/diagnose',
    status: 403, msg: 'reauth_required' })
  assert.equal(b.method, 'GET')
  assert.equal(b.status, 0)
  assert.equal(b.msg, '')
})

test('niet opgevangen fouten en verworpen beloftes', () => {
  const r = createRing(() => undefined)
  const win = new EventTarget()
  install(win, r)
  const err = Object.assign(new Event('error'), { message: 'Uncaught TypeError: x is undefined', error: new TypeError('x is undefined'),
    filename: 'https://dash.lan/assets/index-abc.js?v=2', lineno: 12, colno: 5 })
  win.dispatchEvent(err)
  win.dispatchEvent(new Event('error'))   // zonder tekst of fout: geen fout in de code
  win.dispatchEvent(Object.assign(new Event('unhandledrejection'), { reason: new Error('weg') }))
  win.dispatchEvent(Object.assign(new Event('unhandledrejection'), { reason: { code: 7 } }))
  const e = r.entries()
  assert.equal(e.length, 3)
  assert.equal(e[0].kind, 'fout')
  assert.equal(e[0].msg, 'TypeError: x is undefined')
  assert.equal(e[0].waar, '/assets/index-abc.js:12:5')
  assert.deepEqual(e.slice(1).map((x) => [x.kind, x.msg]), [['belofte', 'Error: weg'], ['belofte', '{"code":7}']])
  install(undefined, r)   // geen venster (bv. in een test): niets
})
