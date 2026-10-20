// Kleine Markdown-weergave voor notities. Eerst alles escapen, daarna pas opmaak toevoegen:
// zo kan er nooit HTML uit de notitie zelf in de pagina belanden.
const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')

function inline(s) {
  const codes = []
  s = s.replace(/`([^`]+)`/g, (_, c) => `\u0000${codes.push(c) - 1}\u0000`)
  s = s
    .replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>')
    .replace(/(^|[^*])\*([^*\s][^*]*)\*/g, '$1<i>$2</i>')
    .replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>')
    .replace(/(^|[\s(])(https?:\/\/[^\s<)]+)/g, '$1<a href="$2" target="_blank" rel="noopener noreferrer">$2</a>')
  return s.replace(/\u0000(\d+)\u0000/g, (_, i) => `<code>${codes[i]}</code>`)
}

export function markdown(src) {
  const lines = esc(src || '').split('\n')
  const out = []
  let list = null
  let para = []
  const flushPara = () => { if (para.length) out.push(`<p>${inline(para.join(' '))}</p>`); para = [] }
  const flushList = () => { if (list) out.push(`</${list}>`); list = null }
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    if (line.startsWith('```')) {
      flushPara(); flushList()
      const block = []
      while (++i < lines.length && !lines[i].startsWith('```')) block.push(lines[i])
      out.push(`<pre><code>${block.join('\n')}</code></pre>`)
      continue
    }
    const h = line.match(/^(#{1,4})\s+(.*)/)
    const li = line.match(/^\s*([-*]|\d+\.)\s+(.*)/)
    if (h) {
      flushPara(); flushList()
      out.push(`<h${h[1].length + 2}>${inline(h[2])}</h${h[1].length + 2}>`)
    } else if (li) {
      flushPara()
      const kind = /\d/.test(li[1]) ? 'ol' : 'ul'
      if (list !== kind) { flushList(); out.push(`<${kind}>`); list = kind }
      const task = li[2].match(/^\[( |x)\]\s+(.*)/i)
      out.push(task ? `<li class="task${task[1] !== ' ' ? ' done' : ''}">${inline(task[2])}</li>` : `<li>${inline(li[2])}</li>`)
    } else if (!line.trim()) {
      flushPara(); flushList()
    } else {
      flushList()
      para.push(line.trim())
    }
  }
  flushPara(); flushList()
  return out.join('')
}
