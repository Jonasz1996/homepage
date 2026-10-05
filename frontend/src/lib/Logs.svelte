<script>
  import { onMount, untrack } from 'svelte'
  import { api, poll } from './api.js'
  import LogRules from './LogRules.svelte'
  import LogSetup from './LogSetup.svelte'

  // Logviewer: alle syslog-regels van je machines, met zoeken, filters en live meekijken.
  let { open = false, initial = null, onclose } = $props()

  const SEV = ['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug']
  const RANGES = ['1h', '24h', '7d', '30d']

  let hosts = $state([])
  let host = $state(untrack(() => initial?.host || null))
  let q = $state('')
  let qLive = $state('')
  let sev = $state('')
  let range = $state('24h')
  let live = $state(true)
  let items = $state([])
  let more = $state(false)
  let hist = $state(null)
  let error = $state('')
  let modal = $state(null)
  let busy = $state(false)

  function params(extra = {}) {
    const p = new URLSearchParams({ range, ...extra })
    if (host) p.append('host', host)
    if (qLive.trim()) p.set('q', qLive.trim())
    if (sev !== '') p.set('sev', sev)
    return p
  }

  // Elke nieuwe lading krijgt een nummer: antwoorden voor een oude filter worden genegeerd.
  let gen = 0
  async function load() {
    const my = ++gen
    busy = true
    try {
      const [r, h, hs] = await Promise.all([
        api('/logs?' + params({ limit: 300 })), api('/logs/histogram?' + params()), api('/logs/hosts'),
      ])
      if (my !== gen) return
      items = r.items
      more = r.more
      hist = h
      hosts = hs
      error = ''
    } catch (e) {
      error = e.message
    } finally {
      busy = false
    }
  }

  async function loadMore() {
    const my = gen
    const last = items[items.length - 1]
    try {
      const r = await api('/logs?' + params({ limit: 300, before_ts: last.ts, before_id: last.id }))
      if (my !== gen) return
      items = [...items, ...r.items]
      more = r.more
    } catch (e) { error = e.message }
  }

  async function tail() {
    if (!open || !live || !items.length) return
    const my = gen
    try {
      const r = await api('/logs?' + params({ after_id: Math.max(...items.slice(0, 50).map((i) => i.id)) }))
      if (my === gen && r.items.length) items = [...r.items, ...items].slice(0, 3000)
    } catch { /* volgende poging */ }
  }

  // Zoekterm pas na een korte pauze in het typen toepassen.
  let timer
  $effect(() => {
    const v = q
    clearTimeout(timer)
    timer = setTimeout(() => (qLive = v), 300)
  })

  $effect(() => {
    host; qLive; sev; range
    if (open) untrack(load)
  })

  // Geopend vanuit een tegel of de zoekbalk: meteen op die machine en/of die zoekterm.
  $effect(() => {
    if (initial?.host || initial?.q) untrack(() => {
      if (initial.host) host = initial.host
      if (initial.q) q = qLive = initial.q
    })
  })

  onMount(() => {
    const stopTail = poll(tail, 3000)
    const stopHosts = poll(() => open && api('/logs/hosts').then((h) => (hosts = h)).catch(() => {}), 30000)
    return () => { stopTail(); stopHosts() }
  })

  const fmt = (ts) => {
    const d = new Date(ts)
    const time = d.toLocaleTimeString('nl-BE', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    return range === '1h' || range === '24h' ? time : `${d.toLocaleDateString('nl-BE', { day: '2-digit', month: '2-digit' })} ${time}`
  }
  const sevClass = (s) => (s <= 3 ? 'e' : s === 4 ? 'w' : s >= 7 ? 'd' : '')

  let maxBar = $derived(Math.max(1, ...(hist?.points || []).map((p) => p.total)))
</script>

<div class="ov" class:hidden={!open}>
  <div class="win card glow">
    <div class="bar">
      <div class="dots"><i></i><i></i><i></i></div>
      <span class="title">root@jbogaert:~# tail -f /var/log/{host || '*'}</span>
      <div class="right">
        <button class="mini" onclick={() => (modal = 'rules')}>meldingsregels</button>
        <button class="mini" onclick={() => (modal = 'setup')}>machines toevoegen</button>
        <button class="mini x" onclick={onclose} aria-label="Logs sluiten">✕</button>
      </div>
    </div>
    <div class="cols">
      <aside>
        <button class="hb" class:on={!host} onclick={() => (host = null)}>
          <b>alle machines</b><small>{hosts.reduce((a, h) => a + h.count, 0).toLocaleString('nl-BE')} regels / 24 u</small>
        </button>
        {#each hosts as h (h.host)}
          <button class="hb" class:on={host === h.host} onclick={() => (host = host === h.host ? null : h.host)}>
            <b>{#if h.docker}<span class="dk" title="Docker-container (Portainer)">▣</span> {/if}{h.host}</b>
            <small>{h.count.toLocaleString('nl-BE')}{#if h.errors}&nbsp;·&nbsp;<span class="e">{h.errors} fouten</span>{/if}</small>
          </button>
        {:else}
          <p class="hint">Nog geen logs ontvangen. Kies <b>machines toevoegen</b>.</p>
        {/each}
      </aside>
      <section>
        <div class="filters">
          <input class="q" bind:value={q} placeholder="zoeken in berichten…" />
          <select bind:value={sev} aria-label="Ernst">
            <option value="">alle niveaus</option>
            <option value="4">warning en erger</option>
            <option value="3">err en erger</option>
            <option value="2">crit en erger</option>
          </select>
          {#each RANGES as r}
            <button class="mini" class:on={range === r} onclick={() => (range = r)}>{r}</button>
          {/each}
          <label class="chk"><input type="checkbox" bind:checked={live} /> live</label>
        </div>
        {#if hist}
          <svg class="hist" viewBox="0 0 {hist.points.length} 40" preserveAspectRatio="none" aria-hidden="true">
            {#each hist.points as p, i}
              {@const h = (p.total / maxBar) * 38}
              {@const he = (p.err / maxBar) * 38}
              {@const hw = (p.warn / maxBar) * 38}
              <rect x={i + 0.1} width="0.8" y={40 - h} height={h} class="t" />
              <rect x={i + 0.1} width="0.8" y={40 - he - hw} height={hw} class="w" />
              <rect x={i + 0.1} width="0.8" y={40 - he} height={he} class="e" />
            {/each}
          </svg>
        {/if}
        {#if error}<p class="err">{error}</p>{/if}
        <div class="list">
          {#each items as l (l.id)}
            <div class="ln {sevClass(l.severity)}">
              <span class="ts">{fmt(l.ts)}</span>
              <button class="host" onclick={() => (host = l.host)}>{l.host}</button>
              <span class="app">{l.app || '-'}</span>
              <span class="sev">{SEV[l.severity]}</span>
              <span class="msg">{l.msg}</span>
            </div>
          {:else}
            <p class="hint pad">{busy ? 'laden…' : 'Geen regels gevonden.'}</p>
          {/each}
          {#if more}<button class="mini more" onclick={loadMore}>meer laden</button>{/if}
        </div>
      </section>
    </div>
  </div>
</div>

{#if modal === 'rules'}
  <LogRules hosts={hosts.map((h) => h.host)} onclose={() => (modal = null)} />
{:else if modal === 'setup'}
  <LogSetup onclose={() => { modal = null; load() }} />
{/if}

<style>
  .dk { color: var(--mid); font-size: 11px; margin-right: 4px }
  .ov { position: fixed; inset: 0; z-index: 60; background: rgba(0, 0, 0, .65); padding: 2vh 1vw; display: flex }
  .ov.hidden { display: none }
  .win { flex: 1; display: flex; flex-direction: column; min-height: 0; overflow: hidden }
  .cols { flex: 1; display: flex; min-height: 0 }
  aside { width: 210px; flex: none; border-right: 1px solid var(--line); padding: 10px; overflow: auto; display: flex; flex-direction: column; gap: 3px }
  .hb { text-align: left; background: none; border: 1px solid transparent; border-radius: 8px; padding: 5px 8px; color: var(--text); cursor: pointer; font: inherit }
  .hb:hover { background: var(--fill) }
  .hb.on { background: var(--fill-h); border-color: var(--line-2) }
  .hb b { display: block; font-weight: 500; font-size: 12.5px; color: var(--text-h); overflow: hidden; text-overflow: ellipsis; white-space: nowrap }
  .hb small { color: var(--muted); font-size: 11px }
  section { flex: 1; min-width: 0; display: flex; flex-direction: column }
  .filters { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; padding: 10px 12px }
  .filters .q { flex: 1; min-width: 180px }
  .filters select { width: auto }
  .hist { height: 42px; width: calc(100% - 24px); margin: 0 12px 6px }
  .hist .t { fill: rgba(255, 255, 255, .18) }
  .hist .w { fill: var(--mid) }
  .hist .e { fill: var(--err) }
  .list { flex: 1; overflow: auto; font-size: 12px; border-top: 1px solid var(--line) }
  .ln { display: grid; grid-template-columns: auto 120px 110px 58px 1fr; gap: 10px; padding: 2px 12px; border-bottom: 1px solid rgba(255, 255, 255, .03); align-items: baseline }
  .ln:hover { background: rgba(255, 255, 255, .04) }
  .ts { color: var(--dim); white-space: nowrap }
  .host { background: none; border: 0; padding: 0; font: inherit; color: #a9c7ff; cursor: pointer; text-align: left; overflow: hidden; text-overflow: ellipsis; white-space: nowrap }
  .app { color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap }
  .sev { color: var(--dim); font-size: 11px }
  .msg { white-space: pre-wrap; word-break: break-word; color: var(--text) }
  .ln.e .sev, .ln.e .msg { color: var(--err) }
  .ln.w .sev { color: var(--mid) }
  .ln.d .msg { color: var(--dim) }
  .e { color: var(--err) }
  .pad { padding: 20px }
  .more { margin: 10px 12px }
  @media (max-width: 760px) {
    .cols { flex-direction: column }
    aside { width: auto; max-height: 22vh; border-right: 0; border-bottom: 1px solid var(--line) }
    .ln { grid-template-columns: auto 1fr; }
    .ln .app, .ln .sev { display: none }
    .ln .msg { grid-column: 1 / -1 }
  }
</style>
