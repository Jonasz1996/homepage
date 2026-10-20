// Tests voor de hulp van het bestandenvenster: npm test (node --test).
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { ApiError } from './api.js'
import { bits, crumbs, emptyDirs, fileCaller, fromBits, isDir, join, octal, parent, parseOctal, resolve, sortEntries, speed, uploadFile, visible } from './bestanden.js'

test('paden', () => {
  assert.equal(join('/', 'etc'), '/etc')
  assert.equal(join('/etc', 'hosts'), '/etc/hosts')
  assert.equal(parent('/etc/ssh'), '/etc')
  assert.equal(parent('/etc'), '/')
  assert.equal(parent('/'), null)
  assert.deepEqual(crumbs('/'), [{ name: '/', path: '/' }])
  assert.deepEqual(crumbs('/etc/ssh').map((c) => c.path), ['/', '/etc', '/etc/ssh'])
  assert.equal(resolve('/etc', 'ssh'), '/etc/ssh')
  assert.equal(resolve('/etc/ssh', '../hosts'), '/etc/hosts')
  assert.equal(resolve('/etc', '/var//log/'), '/var/log')
  assert.equal(resolve('/etc', '../../..'), '/')
  assert.equal(resolve('/etc', '~', '/root'), '/root')
  assert.equal(resolve('/etc', '~/.ssh', '/root'), '/root/.ssh')
  assert.equal(resolve('/etc', ' ./a '), '/etc/a')
})

const E = (name, type = 'file', extra = {}) => ({ name, type, size: 0, mtime: 0, ...extra })

test('sorteren: mappen eerst, natuurlijke volgorde', () => {
  const list = [E('b10'), E('b9'), E('zmap', 'dir'), E('Amap', 'dir'), E('link', 'link', { to: 'dir' }), E('a')]
  assert.deepEqual(sortEntries(list).map((e) => e.name), ['Amap', 'link', 'zmap', 'a', 'b9', 'b10'])
  assert.deepEqual(sortEntries(list, 'name', false).map((e) => e.name), ['zmap', 'link', 'Amap', 'b10', 'b9', 'a'])
  const sized = [E('groot', 'file', { size: 900 }), E('klein', 'file', { size: 5 }), E('map', 'dir', { size: 4096 })]
  assert.deepEqual(sortEntries(sized, 'size').map((e) => e.name), ['map', 'klein', 'groot'])
  assert.deepEqual(sortEntries(sized, 'size', false).map((e) => e.name), ['map', 'groot', 'klein'])
  assert.ok(isDir(E('l', 'link', { to: 'dir' })) && !isDir(E('l', 'link', { to: 'file' })))
})

test('verborgen en filter', () => {
  const list = [E('.bashrc'), E('Notes.txt'), E('notes-oud.txt'), E('foto.jpg')]
  assert.deepEqual(visible(list).map((e) => e.name), ['Notes.txt', 'notes-oud.txt', 'foto.jpg'])
  assert.deepEqual(visible(list, { hidden: true, filter: 'NOTES' }).map((e) => e.name), ['Notes.txt', 'notes-oud.txt'])
  assert.deepEqual(visible(list, { hidden: true, filter: 'notes oud' }).map((e) => e.name), ['notes-oud.txt'])
})

test('rechten', () => {
  assert.equal(octal(0o644), '644')
  assert.equal(octal(0o4755), '4755')
  assert.deepEqual(bits(0o750), [[true, true, true], [true, false, true], [false, false, false]])
  assert.equal(fromBits(bits(0o640)), 0o640)
  // De speciale bits (setuid, sticky) blijven.
  assert.equal(fromBits(bits(0o755), 0o1777), 0o1755)
  assert.equal(parseOctal(' 0644 '), 0o644)
  assert.equal(parseOctal('888'), null)
  assert.equal(parseOctal('64'), null)
})

test('lege mappen en snelheid', () => {
  const files = [{ rel: 'a/b/x.txt' }, { rel: 'a/y.txt' }]
  assert.deepEqual(emptyDirs(['a', 'a/b', 'a/leeg', 'a/leeg/dieper', 'c'], files), ['a/leeg/dieper', 'c'])
  assert.equal(speed(0), '')
  assert.equal(speed(-5242880), '')
  assert.equal(speed(512), '512 B/s')
  assert.equal(speed(12_500_000), '12.5 MB/s')
})

class FakeFile {
  constructor(text, lastModified = 1_700_000_000_000) {
    this.data = Buffer.from(text)
    this.size = this.data.length
    this.lastModified = lastModified
  }
  slice(a, b) {
    const part = this.data.subarray(a, b)
    return { size: part.length, text: part.toString() }
  }
}

function fakeServer({ exists = null, chunk = 4, fail = {}, limit = Infinity } = {}) {
  const calls = []
  let got = {}
  const call = async (path, opts) => {
    calls.push([opts.method, path, opts.body?.chunk])
    if (path === '/upload') {
      if (exists && !opts.body.overwrite) return { exists }
      got = {}
      chunk = opts.body.chunk || chunk
      return { id: 'u1', chunks: Math.ceil(opts.body.size / chunk), chunk }
    }
    if (opts.method === 'PUT' && opts.body.size > limit) throw Object.assign(new Error('Mislukt (fout 413)'), { status: 413 })
    const m = path.match(/^\/upload\/u1\/(\d+)$/)
    if (m) {
      if (fail[m[1]]) { const e = fail[m[1]].shift(); if (e) throw e }
      got[m[1]] = opts.body.text
      return { got: Object.keys(got).length }
    }
    if (path === '/upload/u1/finish') return { name: 'x', size: Object.values(got).join('').length }
    if (path === '/upload/u1') return { ok: true }
    throw new Error('onbekend ' + path)
  }
  return { call, calls, get got() { return got } }
}

test('uploaden in stukken, met mtime en voortgang', async () => {
  const srv = fakeServer()
  let bytes = 0
  const r = await uploadFile(srv.call, { file: new FakeFile('hallo wereld'), dir: '/tmp', rel: 'x' }, { onbytes: (n) => (bytes += n) })
  assert.equal(r.size, 12)
  assert.equal(bytes, 12)
  assert.deepEqual(Object.keys(srv.got).sort(), ['0', '1', '2'])
  assert.equal([0, 1, 2].map((i) => srv.got[i]).join(''), 'hallo wereld')
  assert.deepEqual(srv.calls[0], ['POST', '/upload', null])
  assert.deepEqual(srv.calls.at(-1), ['POST', '/upload/u1/finish', undefined])
})

test('bestaat al: niets gestuurd', async () => {
  const srv = fakeServer({ exists: { size: 3, mtime: 1 } })
  const r = await uploadFile(srv.call, { file: new FakeFile('abc'), dir: '/', rel: 'x' })
  assert.deepEqual(r, { exists: { size: 3, mtime: 1 } })
  assert.equal(srv.calls.length, 1)
})

test('een stuk dat even mislukt, opnieuw; een echte fout breekt af en ruimt op', async () => {
  const flaky = Object.assign(new Error('weg'), { status: 502 })
  const srv = fakeServer({ fail: { 1: [flaky, flaky] } })
  const waits = []
  const r = await uploadFile(srv.call, { file: new FakeFile('12345678') , dir: '/', rel: 'x' }, { wait: async (ms) => waits.push(ms) })
  assert.equal(r.size, 8)
  assert.deepEqual(waits, [1000, 2000])
  const denied = Object.assign(new Error('Geen toegang'), { status: 403 })
  const srv2 = fakeServer({ fail: { 0: [denied] } })
  await assert.rejects(uploadFile(srv2.call, { file: new FakeFile('12345678'), dir: '/', rel: 'x' }, { parallel: 1, wait: async () => {} }), /Geen toegang/)
  await new Promise((r) => setTimeout(r, 0))
  assert.deepEqual(srv2.calls.at(-1), ['DELETE', '/upload/u1', undefined])
  assert.ok(!srv2.calls.some(([, p]) => p.endsWith('/finish')))
})

test('afbreken stopt zonder opnieuw te proberen', async () => {
  const ctrl = new AbortController()
  const abort = Object.assign(new Error('afgebroken'), { name: 'AbortError' })
  const srv = fakeServer({ fail: { 0: [abort] } })
  ctrl.abort()
  await assert.rejects(uploadFile(srv.call, { file: new FakeFile('1234'), dir: '/', rel: 'x' }, { signal: ctrl.signal, wait: async () => assert.fail('geen nieuwe poging') }), /afgebroken/)
})

test('een proxy die een stuk te groot vindt: opnieuw met kleinere stukken', async () => {
  const big = 'x'.repeat(3 * 1024 * 1024)
  const srv = fakeServer({ chunk: 3 * 1024 * 1024, limit: 1024 * 1024 })
  let bytes = 0
  const r = await uploadFile(srv.call, { file: new FakeFile(big), dir: '/', rel: 'x' }, { onbytes: (n) => (bytes += n) })
  assert.equal(r.size, big.length)
  assert.equal(bytes, big.length)
  assert.deepEqual(srv.calls.filter(([, p]) => p === '/upload').map((c) => c[2]), [null, 1024 * 1024])
  assert.ok(srv.calls.some(([m]) => m === 'DELETE'))
  // Ook 64 KiB te groot: dan geeft het op.
  const srv2 = fakeServer({ chunk: 3 * 1024 * 1024, limit: 1000 })
  await assert.rejects(uploadFile(srv2.call, { file: new FakeFile(big), dir: '/', rel: 'x' }), /413/)
  assert.deepEqual(srv2.calls.filter(([, p]) => p === '/upload').map((c) => c[2]), [null, 1024 * 1024, 256 * 1024, 64 * 1024])
})

// Een venster zoals FileSession.svelte het geeft, met een nep-API: welke verzoeken gingen naar welk venster.
function venster({ answers, reopenAs = 'root' }) {
  const sent = []
  const state = { info: { id: 'w1', user: 'root' }, closed: null, reopens: 0 }
  const api = async (path, opts) => {
    sent.push(path)
    const a = answers.shift()
    if (a instanceof Error) throw a
    return a ?? { ok: true }
  }
  const win = {
    info: () => state.info,
    reopen: async () => { state.reopens++; await null; state.info = { id: `w${state.reopens + 1}`, user: reopenAs } },
    closed: (msg, id) => { state.info = null; state.closed = { msg, id } },
    gone: () => false,
    name: () => 'nas',
  }
  return { call: fileCaller(api, win), sent, state }
}

test('venster: verlopen, dan één keer opnieuw openen en het verzoek nog eens', async () => {
  const v = venster({ answers: [new ApiError('verlopen', 410), new ApiError('verlopen', 410), { a: 1 }, { b: 2 }] })
  const [a, b] = await Promise.all([v.call('/list', {}), v.call('/delete', {})])
  assert.deepEqual([a, b], [{ a: 1 }, { b: 2 }])
  assert.equal(v.state.reopens, 1)
  assert.deepEqual(v.sent, ['/ssh/files/w1/list', '/ssh/files/w1/delete', '/ssh/files/w2/list', '/ssh/files/w2/delete'])
})

test('venster: een stuk van een upload hoort bij het oude venster', async () => {
  const v = venster({ answers: [new ApiError('verlopen', 410)] })
  await assert.rejects(v.call('/upload/u1/0', {}), { status: 410 })
  assert.equal(v.state.reopens, 0)
})

test('venster: de host veranderde (412), dan dicht en niets herhalen', async () => {
  const v = venster({ answers: [new ApiError('De login van nas is intussen gewijzigd', 412), new ApiError('verlopen', 410)] })
  const first = v.call('/delete', {})
  const second = v.call('/list', {})
  await assert.rejects(first, { status: 412 })
  await assert.rejects(second, { status: 410 })
  assert.equal(v.state.closed.msg, 'De login van nas is intussen gewijzigd')
  assert.equal(v.state.reopens, 0)
  await assert.rejects(v.call('/list', {}), { message: 'Niet verbonden' })
  assert.deepEqual(v.sent, ['/ssh/files/w1/delete', '/ssh/files/w1/list'])
})

test('venster: verlopen en opnieuw geopend als een andere gebruiker, dan niets doen', async () => {
  const v = venster({ answers: [new ApiError('verlopen', 410)], reopenAs: 'backup' })
  await assert.rejects(v.call('/delete', {}), { status: 412, message: /opende opnieuw als backup \(was root\)/ })
  assert.deepEqual(v.state.closed, { msg: v.state.closed.msg, id: 'w2' })
  assert.deepEqual(v.sent, ['/ssh/files/w1/delete'])
  // Ook de wachtrij gaat niet als backup verder.
  await assert.rejects(v.call('/upload', {}), { message: 'Niet verbonden' })
})

