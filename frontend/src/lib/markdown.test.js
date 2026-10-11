// Tests voor de Markdown van de notities: npm test (node --test, zonder extra pakketten).
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { markdown } from './markdown.js'

const a = (href, text) => `<a href="${href}" target="_blank" rel="noopener noreferrer">${text}</a>`

// Elke <a> met precies de drie vaste attributen, en nooit een link in een link.
function links(html) {
  const tags = [...html.matchAll(/<a\b([^>]*)>/g)].map((m) => m[1])
  for (const attrs of tags) {
    assert.match(attrs, /^ href="[^"<>]*" target="_blank" rel="noopener noreferrer"$/)
  }
  assert.doesNotMatch(html, /<a\b(?:(?!<\/a>).)*<a\b/s, 'link in een link')
  assert.equal(tags.length, (html.match(/<\/a>/g) || []).length)
  return tags.length
}

test('[tekst](url)', () => {
  assert.equal(markdown('[de wiki](https://wiki.jbogaert.be/a)'), `<p>${a('https://wiki.jbogaert.be/a', 'de wiki')}</p>`)
})

test('los adres', () => {
  assert.equal(markdown('kijk op https://a.be/x?y=1&z=2 nu'),
    `<p>kijk op ${a('https://a.be/x?y=1&amp;z=2', 'https://a.be/x?y=1&amp;z=2')} nu</p>`)
  assert.equal(markdown('https://a.be'), `<p>${a('https://a.be', 'https://a.be')}</p>`)
})

test('adres tussen haakjes', () => {
  assert.equal(markdown('de app (https://a.be/x) en https://c.be'),
    `<p>de app (${a('https://a.be/x', 'https://a.be/x')}) en ${a('https://c.be', 'https://c.be')}</p>`)
})

test('een adres in de linktekst wordt geen tweede link', () => {
  const html = markdown('[zie https://a.be](https://b.be)')
  assert.equal(html, `<p>${a('https://b.be', 'zie https://a.be')}</p>`)
  assert.equal(links(html), 1)
})

test('geen eigen attributen via een adres in het adres', () => {
  // Vroeger maakte de tweede vervanging van het "(https://..." in het href een nieuwe <a>: die sloot het href af,
  // en de rest kwam als attributen op de link.
  const html = markdown('[x](https://a.com/(https://evil.com/style=position:fixed;inset:0)')
  assert.equal(links(html), 1)
  assert.equal(html, `<p>${a('https://a.com/(https://evil.com/style=position:fixed;inset:0', 'x')}</p>`)
  // Een " uit de notitie blijft &quot;: het href loopt nooit vroeger af.
  for (const src of ['[x](https://a.be/"onmouseover=alert(1))', 'https://a.be/"style=x"',
    '[a (https://b.be/"x) c](https://d.be)', 'zie (https://a.be/(https://b.be/"x)']) {
    const out = markdown(src)
    assert.equal(links(out), 1, out)
    assert.match(out, /&quot;/)
  }
})

test('vet en code in de linktekst', () => {
  assert.equal(markdown('[**vet** en `code`](https://a.be)'), `<p>${a('https://a.be', '<b>vet</b> en <code>code</code>')}</p>`)
  // Een adres in code blijft code.
  assert.equal(markdown('`https://a.be`'), '<p><code>https://a.be</code></p>')
})

test('alles wordt eerst geëscaped', () => {
  assert.equal(markdown('<img src=x onerror=alert(1)> "q" & \'s\''),
    '<p>&lt;img src=x onerror=alert(1)&gt; &quot;q&quot; &amp; \'s\'</p>')
  assert.equal(markdown('[x](https://a.be/"><script>)'), `<p>${a('https://a.be/&quot;&gt;&lt;script&gt;', 'x')}</p>`)
  assert.equal(markdown('```\n<b>[x](https://a.be)\n```'), '<pre><code>&lt;b&gt;[x](https://a.be)</code></pre>')
  assert.equal(markdown(''), '')
})
