<script>
  import { FitAddon } from '@xterm/addon-fit'
  import { Terminal } from '@xterm/xterm'
  import '@xterm/xterm/css/xterm.css'
  import { onMount } from 'svelte'

  // Eén SSH-sessie: xterm.js in de browser, de shell zelf loopt via de WebSocket van de API.
  let { host, active = true, onstate } = $props()

  let el = $state()
  let hostkey = $state(null)
  let phase = $state('verbinden')
  let term, fit, ws

  const enc = new TextEncoder()
  const dim = (s) => `\x1b[90m${s}\x1b[0m\r\n`
  const red = (s) => `\x1b[31m${s}\x1b[0m\r\n`

  function setState(s) {
    phase = s
    onstate?.(s)
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
      else if (m.t === 'ready') { setState('verbonden'); term.focus() }
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

  export function focus() {
    term?.focus()
  }

  export function reconnect() {
    try { ws?.close() } catch { /* al dicht */ }
    term.write('\r\n')
    connect()
  }

  onMount(() => {
    term = new Terminal({
      fontFamily: 'ui-monospace, "Cascadia Code", "SF Mono", Consolas, "Liberation Mono", monospace',
      fontSize: 13, cursorBlink: true, scrollback: 5000, allowProposedApi: false,
      theme: { background: '#0c0c0c', foreground: '#dddddd', cursor: '#8fd6a4', selectionBackground: '#44444488' },
    })
    fit = new FitAddon()
    term.loadAddon(fit)
    term.open(el)
    fit.fit()
    term.onData((d) => ws?.readyState === 1 && ws.send(enc.encode(d)))
    term.onResize(({ cols, rows }) => ws?.readyState === 1 && ws.send(JSON.stringify({ t: 'r', c: cols, r: rows })))
    const ro = new ResizeObserver(() => { if (el.offsetParent) fit.fit() })
    ro.observe(el)
    connect()
    return () => { ro.disconnect(); try { ws?.close() } catch { /* */ } term.dispose() }
  })

  $effect(() => {
    if (active && term) queueMicrotask(() => { fit.fit(); term.focus() })
  })
</script>

<div class="sess" class:hidden={!active}>
  <div class="term" bind:this={el}></div>
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
  .hk { position: absolute; left: 50%; top: 40px; transform: translateX(-50%); width: min(560px, 92%); padding: 16px 18px; z-index: 2 }
  .hk code.fp { display: block; word-break: break-all; color: var(--ok); margin: 8px 0 }
  .hk p { margin: 0 0 6px; font-size: 13px }
</style>
