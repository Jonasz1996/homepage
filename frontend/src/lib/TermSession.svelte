<script>
  import { FitAddon } from '@xterm/addon-fit'
  import { SearchAddon } from '@xterm/addon-search'
  import { WebLinksAddon } from '@xterm/addon-web-links'
  import { Terminal } from '@xterm/xterm'
  import '@xterm/xterm/css/xterm.css'
  import { onMount } from 'svelte'

  // Eén SSH-sessie: xterm.js in de browser, de shell zelf loopt via de WebSocket van de API.
  // Zoals PuTTY: selecteren = kopiëren, rechtsklik = plakken, middenklik = de laatste selectie plakken.
  let { host, active = true, fontSize = 13, onstate, ontyped } = $props()

  let el = $state()
  let hostkey = $state(null)
  let phase = $state('verbinden')
  let toast = $state('')
  let term, fit, search, ws
  let lastSel = ''
  let toastTimer

  const enc = new TextEncoder()
  const dim = (s) => `\x1b[90m${s}\x1b[0m\r\n`
  const red = (s) => `\x1b[31m${s}\x1b[0m\r\n`

  function setState(s) {
    phase = s
    onstate?.(s)
  }

  function say(text) {
    toast = text
    clearTimeout(toastTimer)
    toastTimer = setTimeout(() => (toast = ''), 1400)
  }

  function connect() {
    hostkey = null
    setState('verbinden')
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
    ws = new WebSocket(`${proto}//${location.host}/api/ssh/ws/${host.id}?cols=${term.cols}&rows=${term.rows}`)
    ws.binaryType = 'arraybuffer'
    ws.onmessage = (e) => {
      if (typeof e.data !== 'string') return term.write(new Uint8Array(e.data))
      const m = JSON.parse(e.data)
      if (m.t === 'status') term.write(dim(m.m))
      else if (m.t === 'hostkey') hostkey = m
      else if (m.t === 'ready') { setState('verbonden'); if (active) term.focus() }
      else if (m.t === 'error') { term.write(red(m.m)); setState('fout') }
      else if (m.t === 'closed') { term.write('\r\n' + dim(m.m)); setState('gesloten') }
    }
    ws.onclose = () => {
      if (phase === 'verbonden' || phase === 'verbinden') { term.write('\r\n' + dim('Verbinding gesloten')); setState('gesloten') }
    }
  }

  function answer(ok) {
    ws.send(JSON.stringify({ t: ok ? 'accept' : 'reject' }))
    term.write(dim(ok ? `Hostsleutel ${hostkey.fp} aanvaard en bewaard.` : 'Hostsleutel geweigerd.'))
    hostkey = null
  }

  // --- Klembord ---------------------------------------------------------------

  async function copyText(text) {
    try {
      if (window.isSecureContext && navigator.clipboard) { await navigator.clipboard.writeText(text); return true }
    } catch { /* val terug op de oude manier */ }
    // Over gewoon http (IP-adres) bestaat navigator.clipboard niet: via een verborgen tekstvak.
    const ta = document.createElement('textarea')
    ta.value = text
    ta.style.cssText = 'position:fixed;left:-9999px;top:0'
    document.body.append(ta)
    ta.select()
    let ok = false
    try { ok = document.execCommand('copy') } catch { /* niet gelukt */ }
    ta.remove()
    term.focus()
    return ok
  }

  async function readClipboard() {
    if (window.isSecureContext && navigator.clipboard?.readText) {
      try { return await navigator.clipboard.readText() } catch { /* geweigerd */ }
    }
    return null
  }

  function pasteText(text) {
    if (!text) return
    const lines = text.replace(/\r?\n$/, '').split(/\r?\n/).length
    // Meerdere regels plakken voert ze allemaal uit: eerst vragen (zoals Windows Terminal).
    if (lines > 1 && !confirm(`${lines} regels plakken in ${host.name}? Elke regel wordt uitgevoerd.`)) return
    term.paste(text)
    term.focus()
  }

  export async function paste() {
    const text = await readClipboard()
    if (text !== null) return pasteText(text)
    if (lastSel) { pasteText(lastSel); say('laatste selectie geplakt'); return }
    say('klembord plakken: Ctrl+V (over http mag rechtsklik het klembord niet lezen)')
  }

  export async function copy() {
    const sel = term.getSelection()
    if (sel && (await copyText(sel))) say('gekopieerd')
  }

  // --- Voor het venster eromheen ------------------------------------------------

  export function focus() { term?.focus() }

  export function send(text) {
    if (ws?.readyState === 1) ws.send(enc.encode(text))
  }

  export function reconnect() {
    try { ws?.close() } catch { /* al dicht */ }
    term.write('\r\n')
    connect()
  }

  export function find(q, back = false) {
    if (!q) { search.clearDecorations(); return }
    const opts = { caseSensitive: false, decorations: { matchOverviewRuler: '#e6b56b', activeMatchColorOverviewRuler: '#8fd6a4',
                                                          matchBackground: '#e6b56b55', activeMatchBackground: '#8fd6a4aa' } }
    return back ? search.findPrevious(q, opts) : search.findNext(q, opts)
  }

  export function clear() { term.clear() }

  /** De hele uitvoer (ook wat weggescrold is) als tekstbestand, zoals de log van PuTTY. */
  export function saveLog() {
    const b = term.buffer.active
    const lines = []
    for (let i = 0; i < b.length; i++) lines.push(b.getLine(i)?.translateToString(true) ?? '')
    while (lines.length && !lines[lines.length - 1]) lines.pop()
    const stamp = new Date().toISOString().slice(0, 16).replace(/[:T]/g, '-')
    const a = document.createElement('a')
    a.href = URL.createObjectURL(new Blob([lines.join('\n') + '\n'], { type: 'text/plain' }))
    a.download = `${host.name}-${stamp}.log`
    a.click()
    setTimeout(() => URL.revokeObjectURL(a.href), 1000)
  }

  onMount(() => {
    term = new Terminal({
      fontFamily: 'ui-monospace, "Cascadia Code", "SF Mono", Consolas, "Liberation Mono", monospace',
      fontSize, cursorBlink: true, scrollback: 10000, allowProposedApi: true, rightClickSelectsWord: false,
      theme: { background: '#0c0c0c', foreground: '#dddddd', cursor: '#8fd6a4', selectionBackground: '#5a7a9a88' },
    })
    fit = new FitAddon()
    search = new SearchAddon()
    term.loadAddon(fit)
    term.loadAddon(search)
    term.loadAddon(new WebLinksAddon((e, uri) => { if (/^https?:\/\//i.test(uri)) window.open(uri, '_blank', 'noopener') }))
    term.open(el)
    fit.fit()
    term.onData((d) => { send(d); ontyped?.(d) })
    term.onResize(({ cols, rows }) => ws?.readyState === 1 && ws.send(JSON.stringify({ t: 'r', c: cols, r: rows })))

    // Selecteren = kopiëren.
    term.onSelectionChange(() => {
      const sel = term.getSelection()
      if (sel) lastSel = sel
    })
    const up = () => setTimeout(async () => {
      const sel = term.getSelection()
      if (sel && (await copyText(sel))) say('gekopieerd')
    }, 0)
    el.addEventListener('mouseup', (e) => { if (e.button === 0) up() })
    // Rechtsklik = plakken, middenklik = laatste selectie plakken.
    el.addEventListener('contextmenu', (e) => { e.preventDefault(); paste() })
    el.addEventListener('auxclick', (e) => { if (e.button === 1) { e.preventDefault(); pasteText(lastSel) } })
    el.addEventListener('mousedown', (e) => { if (e.button === 1) e.preventDefault() })
    // Ctrl+Shift+C / Ctrl+Shift+V zoals in een Linux-terminal; Ctrl+C blijft "afbreken".
    term.attachCustomKeyEventHandler((e) => {
      if (!e.ctrlKey || !e.shiftKey) return true
      // Sneltoetsen van het venster (zoeken, dupliceren, tabs): niet naar de shell sturen.
      if (['KeyF', 'KeyD', 'ArrowLeft', 'ArrowRight'].includes(e.code)) return false
      if (e.type !== 'keydown') return true
      if (e.code === 'KeyC') { copy(); return false }
      if (e.code === 'KeyV') {
        // Over http kan de pagina het klembord niet lezen: dan plakt de browser zelf (gewone paste).
        if (!(window.isSecureContext && navigator.clipboard?.readText)) return true
        e.preventDefault(); paste(); return false
      }
      return true
    })

    const ro = new ResizeObserver(() => { if (el.offsetParent) fit.fit() })
    ro.observe(el)
    connect()
    return () => { ro.disconnect(); clearTimeout(toastTimer); try { ws?.close() } catch { /* */ } term.dispose() }
  })

  $effect(() => {
    if (active && term) queueMicrotask(() => { fit.fit(); term.focus() })
  })

  $effect(() => {
    const size = fontSize
    if (term && term.options.fontSize !== size) {
      term.options.fontSize = size
      queueMicrotask(() => fit.fit())
    }
  })
</script>

<div class="sess" class:hidden={!active}>
  <div class="term" bind:this={el}></div>
  {#if toast}<div class="toast">{toast}</div>{/if}
  {#if hostkey}
    <div class="hk card">
      <p>Eerste verbinding met <b>{host.name}</b> ({host.host}). Klopt deze hostsleutel?</p>
      <code class="fp">{hostkey.alg} {hostkey.fp}</code>
      <p class="hint">Controleer op de server met <code>ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</code>.</p>
      <div class="row">
        <button class="btn" onclick={() => answer(true)}>Aanvaarden</button>
        <button class="btn alt" onclick={() => answer(false)}>Weigeren</button>
      </div>
    </div>
  {/if}
</div>

<style>
  .sess { position: absolute; inset: 0; padding: 8px 4px 4px 10px; background: #0c0c0c }
  .sess.hidden { visibility: hidden; pointer-events: none }
  .term { width: 100%; height: 100% }
  .toast { position: absolute; right: 18px; bottom: 14px; padding: 5px 10px; border-radius: 7px; font-size: 12px;
           background: rgba(143, 214, 164, .15); border: 1px solid rgba(143, 214, 164, .4); color: var(--ok); pointer-events: none; z-index: 3 }
  .hk { position: absolute; left: 50%; top: 40px; transform: translateX(-50%); width: min(560px, 92%); padding: 16px 18px; z-index: 2 }
  .hk code.fp { display: block; word-break: break-all; color: var(--ok); margin: 8px 0 }
  .hk p { margin: 0 0 6px; font-size: 13px }
</style>
