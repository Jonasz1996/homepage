<script>
  import { onMount, tick, untrack } from 'svelte'
  import { requestReauth } from './api.js'
  import { wsUrl } from './cronfmt.js'

  // Live meekijken in de cronlog van één machine: wanneer cron iets start, de uitvoer van bewaakte jobs
  // (hp-cron) en de diensten achter je eigen systemd-timers.
  let { targets = [], jobs = [] } = $props()

  let target = $state(untrack(() => targets[0]?.key || ''))
  let lines = $state([])
  let state = $state('')
  let paused = $state(false)
  let filter = $state('')
  let el = $state()
  let ws
  let rest = ''

  let names = $derived(Object.fromEntries(jobs.filter((j) => j.monitored).map((j) => [j.wid, j.name])))
  const dec = new TextDecoder()

  function pretty(line) {
    const m = line.match(/@@RUN (\{.*\})/)
    if (m) {
      try {
        const r = JSON.parse(m[1])
        const s = r.end - r.start
        return { cls: r.rc === 0 ? 'ok' : 'bad', text: `${line.slice(0, line.indexOf('@@RUN'))}${r.rc === 0 ? '✓' : '✕'} run klaar: exitcode ${r.rc}, ${s} s` }
      } catch { /* gewone regel */ }
    }
    if (/@@START/.test(line)) return { cls: 'dim', text: line.replace(/@@START \{.*\}/, '▶ job gestart (bewaakt)') }
    if (/ CMD \(/.test(line)) return { cls: 'cmd', text: line }
    if (/\bhp-cron\[\d+\]: \[[0-9a-f]+\]/.test(line)) return { cls: 'out', text: line }
    return { cls: /error|fail|fout/i.test(line) ? 'bad' : '', text: line }
  }

  function connect() {
    ws?.close()
    lines = []
    rest = ''
    if (!target) return
    state = 'verbinden…'
    ws = new WebSocket(wsUrl(`/cron/ws/tail/${encodeURIComponent(target)}`))
    ws.binaryType = 'arraybuffer'
    ws.onmessage = async (e) => {
      if (typeof e.data === 'string') {
        const m = JSON.parse(e.data)
        if (m.t === 'ready') state = 'live'
        else if (m.t === 'error') {
          state = m.m
          if (m.m === 'reauth_required') { try { await requestReauth(); connect() } catch { /* */ } }
        }
        return
      }
      const text = rest + dec.decode(new Uint8Array(e.data), { stream: true })
      const parts = text.split('\n')
      rest = parts.pop()
      if (paused) return
      lines = [...lines, ...parts.filter(Boolean).map(pretty)].slice(-3000)
      await tick()
      if (el && !paused) el.scrollTop = el.scrollHeight
    }
    ws.onclose = () => { if (state === 'live' || state === 'verbinden…') state = 'verbinding gesloten' }
  }

  $effect(() => {
    target
    untrack(connect)
  })
  onMount(() => () => ws?.close())

  let shown = $derived(filter ? lines.filter((l) => l.text.toLowerCase().includes(filter.toLowerCase())) : lines)
  const withName = (t) => t.replace(/\[([0-9a-f]{10})\]/, (m, id) => (names[id] ? `[${names[id]}]` : m))
</script>

<div class="wrap">
  <div class="filters">
    <select bind:value={target} aria-label="Machine">
      {#each targets as t (t.key)}<option value={t.key}>{t.name}</option>{/each}
    </select>
    <input class="q" bind:value={filter} placeholder="filter…" />
    <label class="chk"><input type="checkbox" bind:checked={paused} /> pauze</label>
    <button class="mini" onclick={() => (lines = [])}>⌫ leegmaken</button>
    <button class="mini" onclick={connect}>⟳ opnieuw</button>
    <span class="st" class:on={state === 'live'}>{state}</span>
  </div>
  <div class="log" bind:this={el}>
    {#each shown as l, i (i)}<div class="l {l.cls}">{withName(l.text)}</div>{:else}
      <p class="hint">{targets.length ? 'Wachten op cronregels… (de laatste 150 staan er meteen)' : 'Nog geen machines gescand.'}</p>
    {/each}
  </div>
  <p class="hint small">Uitvoer van een job zie je hier live als hij bewaakt wordt. Zelf iets starten kan bij een job met ▶ nu uitvoeren.</p>
</div>

<style>
  .wrap { flex: 1; display: flex; flex-direction: column; min-height: 0; padding: 10px 14px 12px; border-top: 1px solid var(--line); margin-top: 8px }
  .filters { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; margin-bottom: 8px }
  .filters select { width: auto; min-width: 180px }
  .q { flex: 1; min-width: 160px }
  .st { font-size: 12px; color: var(--muted) }
  .st.on { color: var(--ok) }
  .st.on::before { content: '● '; animation: blink 1.4s infinite }
  @keyframes blink { 50% { opacity: .3 } }
  .log { flex: 1; overflow: auto; background: #0c0c0c; border: 1px solid var(--line); border-radius: 8px; padding: 8px 10px; font-size: 12px }
  .l { white-space: pre-wrap; word-break: break-all; color: var(--text); line-height: 1.5 }
  .l.cmd { color: #9fb7d6 }
  .l.out { color: #ccc }
  .l.ok { color: var(--ok) }
  .l.bad { color: var(--err) }
  .l.dim { color: var(--dim) }
  .small { font-size: 11.5px; margin: 8px 0 0 }
</style>
