// Tests voor live meekijken in de logviewer: npm test (node --test, zonder extra pakketten).
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { advance, append, cursorOf, prepend } from './logtail.js'

const NOW = Date.UTC(2026, 9, 11, 12, 0)
const row = (id, minutesAgo) => ({ id, ts: new Date(NOW - minutesAgo * 60000).toISOString(), msg: `regel ${id}` })
const ids = (rows) => rows.map((i) => i.id)
const unique = (rows) => assert.equal(new Set(ids(rows)).size, rows.length, 'dezelfde id twee keer')

// Zoals de server: de database in volgorde van binnenkomen (id), zoeken op tijd (nieuwste eerst) met last_id, live
// meekijken op id (nieuwste eerst).
function server(db) {
  return {
    search: (limit = 300) => ({
      items: [...db].sort((a, b) => b.ts.localeCompare(a.ts) || b.id - a.id).slice(0, limit),
      last_id: Math.max(0, ...ids(db)),
    }),
    after: (id) => db.filter((i) => i.id > id).reverse(),
  }
}

test('een vastgehouden regel die al in de lijst staat, komt niet nog eens', () => {
  // 80 gewone regels, één per minuut; daarna nog een die rsyslog 55 minuten vasthield: de grootste id, niet bovenaan.
  const db = Array.from({ length: 80 }, (_, i) => row(i + 1, 80 - i))
  db.push(row(81, 55))
  const srv = server(db)
  const r = srv.search()
  let items = r.items
  let cursor = cursorOf(r)
  assert.ok(items.findIndex((i) => i.id === 81) >= 50)
  assert.equal(cursor, 81)

  db.push(row(82, 0))
  const fresh = srv.after(cursor)
  items = prepend(items, fresh)
  cursor = advance(cursor, fresh)
  assert.deepEqual(ids(items.slice(0, 2)), [82, 80])
  assert.equal(items.length, 82)
  unique(items)
  // De volgende keer niets meer.
  assert.deepEqual(srv.after(cursor), [])
  assert.equal(advance(cursor, []), 82)
})

test('wat tussen last_id en het zoeken binnenkwam, komt maar één keer', () => {
  const items = [row(12, 0), row(11, 1), row(10, 2)]
  // last_id was 10: regels 11 en 12 komen ook live terug.
  const merged = prepend(items, [row(13, 0), row(12, 0), row(11, 1)])
  assert.deepEqual(ids(merged), [13, 12, 11, 10])
  assert.equal(prepend(items, [row(12, 0)]), items)
})

test('meer laden na een vastgehouden regel die live bovenaan kwam', () => {
  const items = [row(9, 40), row(8, 0), row(7, 1)]
  const merged = append(items, [row(6, 2), row(9, 40), row(5, 50)])
  assert.deepEqual(ids(merged), [9, 8, 7, 6, 5])
})

test('verder vanaf last_id; zonder last_id de grootste id in de hele lijst', () => {
  const items = [...Array.from({ length: 60 }, (_, i) => row(60 - i, i)), row(99, 70)]
  assert.equal(cursorOf({ items, last_id: 120 }), 120)
  assert.equal(cursorOf({ items, last_id: 0 }), 0)
  assert.equal(cursorOf({ items }), 99)
  assert.equal(cursorOf({ items: [] }), 0)
})

test('hoogstens 3000 regels', () => {
  const items = Array.from({ length: 3000 }, (_, i) => row(3000 - i, i))
  const merged = prepend(items, [row(3002, 0), row(3001, 0)])
  assert.equal(merged.length, 3000)
  assert.deepEqual(ids(merged.slice(0, 3)), [3002, 3001, 3000])
})
