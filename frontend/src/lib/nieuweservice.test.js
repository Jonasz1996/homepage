// Tests voor de knop "opruimen…" bij een tegel: npm test (node --test).
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { inZone } from './nieuweservice.js'

test('alleen <label>.<domein>', () => {
  assert.equal(inZone('https://jellyfin.jbogaert.be', 'jbogaert.be'), true)
  assert.equal(inZone('http://Jellyfin.JBOGAERT.be:8096/web/', 'jbogaert.be'), true)
  assert.equal(inZone('https://jbogaert.be', 'jbogaert.be'), false)
  assert.equal(inZone('https://a.b.jbogaert.be', 'jbogaert.be'), false)
  assert.equal(inZone('https://x.example.com', 'jbogaert.be'), false)
  assert.equal(inZone('https://192.168.0.5:8006', 'jbogaert.be'), false)
  assert.equal(inZone('https://-x.jbogaert.be', 'jbogaert.be'), false)
  assert.equal(inZone('geen url', 'jbogaert.be'), false)
  assert.equal(inZone('https://jellyfin.jbogaert.be', null), false)
})
