<script>
  import { onMount, untrack } from 'svelte'
  import { api, poll } from './api.js'
  import { advance, append, cursorOf, prepend } from './logtail.js'
  import LogRules from './LogRules.svelte'
  import LogSetup from './LogSetup.svelte'

  // Logviewer: alle syslog-regels van je machines, met zoeken, filters en live meekijken.
  let { open = false, initial = null, onclose } = $props()

  const SEV = ['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug']
  const RANGES = ['1h', '24h', '7d', '30d']

  let hosts = $state([])
  let hostsError = $state('')
  let host = $state(null)
  let q = $state('')
  let qLive = $state('')
  let sev = $state('')
  let range = $state('24h')
  let live = $state(true)
  let items = $state([])
  let more = $state(false)
  let hist = $state(null)
  let histError = $state('')
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

  // Elke nieuwe lading krijgt een nummer: antwoorden voor een oude filter worden genegeerd. Er loopt er één tegelijk:
  // verandert de filter terwijl er een bezig is, dan daarna nog één keer met de nieuwste. Een verlaten zoekopdracht
  // loopt op de server toch door (tot 20 s), dus niet stapelen.
  let gen = 0
  let running = false
  // Live meekijken gaat verder na deze id (zie logtail.js). Null zolang er gezocht wordt: dan geen nieuwe regels van de
  // nieuwe filter boven de lijst van de vorige.
  let cursor = null
  async function load() {
    gen++
    if (running) return
    running = true
    busy = true
    try {
      let my
      do {
        my = gen
        await search(my)
      } while (my !== gen && open)
    } finally {
      running = false
      busy = false
    }
  }

  // Eerst de regels, dan de grafiek: die is het duurst. Mislukt de grafiek, dan blijven de regels staan; mislukt het
  // zoeken, dan geen regels van de vorige filter onder de nieuwe. Zo ook de grafiek: die van de vorige filter gaat weg
  // zodra de nieuwe regels er zijn, niet pas als de nieuwe grafiek er is (tot 20 s later).
  async function search(my) {
    const p = params()
    cursor = null
    let r
    try {
      r = await api('/logs?' + params({ limit: 300 }))
    } catch (e) {
      if (my === gen) { items = []; more = false; hist = null; histError = ''; error = e.message }
      return
    }
    if (my !== gen) return
    items = r.items
    cursor = cursorOf(r)
    more = r.more
    error = ''
    hist = null
    histError = ''
    try {
      const h = await api('/logs/histogram?' + p)
      if (my === gen) { hist = h; histError = '' }
    } catch (e) {
      if (my === gen) { hist = null; histError = e.status === 503 ? 'grafiek te traag voor deze periode' : `geen grafiek: ${e.message}` }
    }
  }

  // De lijst met machines links: bij het openen en elke 30 s (onMount), niet bij elke filter. Mislukt het (de server
  // stopt na 5 s), dan blijft de vorige lijst staan, maar niet stil: zonder lijst stond er anders "nog geen logs".
  const loadHosts = () => api('/logs/hosts')
    .then((h) => { hosts = h; hostsError = '' })
    .catch((e) => { hostsError = e.status === 503 ? 'te traag' : `niet geladen: ${e.message}` })

  async function loadMore() {
    const my = gen
    const last = items[items.length - 1]
    try {
      const r = await api('/logs?' + params({ limit: 300, before_ts: last.ts, before_id: last.id }))
      if (my !== gen) return
      items = append(items, r.items)
      more = r.more
    } catch (e) { error = e.message }
  }

  async function tail() {
    if (!open || !live || cursor === null) return
    const my = gen
    const from = cursor
    try {
      const r = await api('/logs?' + params({ after_id: from }))
      // Intussen opnieuw gezocht, of een andere poging was al verder: die geldt.
      if (my !== gen || from !== cursor) return
      items = prepend(items, r.items)
      cursor = advance(from, r.items)
    } catch { /* volgende poging */ }
  }

  // Zoekterm pas na een korte pauze in het typen toepassen.
  let timer
  $effect(() => {
    const v = q
    clearTimeout(timer)
    timer = setTimeout(() => (qLive = v), 300)
  })

  // Hoe het venster geopend werd. $effect.pre loopt vóór het laden hieronder: zo vertrekt er geen zoekopdracht met
  // de filters van de vorige keer (die liep op de server toch door, desnoods over 30 dagen).
  $effect.pre(() => {
    const init = initial
    if (!init) return
    untrack(() => {
      // Met de knop bovenaan: zoals je het venster achterliet. Van elders (zoekbalk, aandacht, checklist, een
      // melding) opnieuw de laatste 24 uur: 7 of 30 dagen over alle machines is traag.
      if (!init.keep) range = '24h'
      // Een logregel uit de zoekbalk: die machine en die zoekterm, alle niveaus, zodat de regel er zeker bij staat.
      if (init.host || init.q) {
        host = init.host || null
        q = qLive = init.q || ''
        sev = ''
      }
      // Vanuit de instellingen-checklist: meteen rsyslog uitrollen.
      if (init.setup) modal = 'setup'
    })
  })

  $effect(() => {
    host; qLive; sev; range
    if (open) untrack(load)
  })

  $effect(() => {
    if (open) untrack(loadHosts)
  })

  onMount(() => {
    const stopTail = poll(tail, 3000)
    const stopHosts = poll(() => open && loadHosts(), 30000)
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
          <b>alle machines</b><small>{hostsError && !hosts.length ? 'aantal onbekend' : `${hosts.reduce((a, h) => a + h.count, 0).toLocaleString('nl-BE')} regels / 24 u`}</small>
        </button>
        {#each hosts as h (h.host)}
          <button class="hb" class:on={host === h.host} onclick={() => (host = host === h.host ? null : h.host)}>
            <b>{#if h.docker}<span class="dk" title="Docker-container (Portainer)">▣</span> {/if}{h.host}</b>
            <small>{h.count.toLocaleString('nl-BE')}{#if h.errors}&nbsp;·&nbsp;<span class="e">{h.errors} fouten</span>{/if}</small>
          </button>
        {:else}
          {#if !hostsError}<p class="hint">Nog geen logs ontvangen. Kies <b>machines toevoegen</b>.</p>{/if}
        {/each}
        {#if hostsError}<p class="hint">Lijst met machines {hostsError}{hosts.length ? '; de aantallen zijn van daarnet' : ''}. Nieuwe poging over 30 s.</p>{/if}
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
        {:else if histError}
          <p class="hnote">{histError}</p>
        {:else if busy}
          <p class="hnote">grafiek laden…</p>
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
  <LogSetup onclose={() => { modal = null; load(); loadHosts() }} />
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
  .hnote { margin: 0 12px 6px; color: var(--dim); font-size: 11.5px }
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
