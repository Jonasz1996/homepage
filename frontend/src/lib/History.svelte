<script>
  import { untrack } from 'svelte'
  import { api } from './api.js'
  import Modal from './Modal.svelte'

  // Tijdlijn (storingen, herstarts, back-ups, updates, wijzigingen) en het weekrapport.
  let { onclose, tab: startTab = 'timeline' } = $props()

  let tab = $state(untrack(() => startTab))
  let error = $state('')

  const ONE = {
    storing: 'storing', herstart: 'herstart', backup: 'back-up', updates: 'updates', wijziging: 'wijziging', actie: 'actie',
    capaciteit: 'capaciteit', netwerk: 'netwerk', toegang: 'toegang', log: 'log', melding: 'melding',
  }
  const KINDS = {
    storing: 'storingen', herstart: 'herstarts', backup: "back-ups", updates: 'updates', wijziging: 'wijzigingen',
    actie: 'acties', capaciteit: 'capaciteit', netwerk: 'netwerk', toegang: 'toegang', log: 'logs', melding: 'overig',
  }

  // --- Tijdlijn ---
  let items = $state([])
  let more = $state(false)
  let kind = $state('')
  let busy = $state(false)

  async function loadTimeline(append = false) {
    busy = true
    const p = new URLSearchParams({ limit: 100 })
    if (kind) p.set('kind', kind)
    if (append && items.length) p.set('before', items[items.length - 1].ts)
    try {
      const r = await api('/timeline?' + p)
      items = append ? [...items, ...r.items] : r.items
      more = r.more
      error = ''
    } catch (e) {
      error = e.message
    } finally {
      busy = false
    }
  }

  const day = (ts) => new Date(ts).toLocaleDateString('nl-BE', { weekday: 'long', day: 'numeric', month: 'long' })
  const time = (ts) => new Date(ts).toLocaleTimeString('nl-BE', { hour: '2-digit', minute: '2-digit' })
  let days = $derived.by(() => {
    const out = []
    for (const it of items) {
      const d = day(it.ts)
      if (!out.length || out[out.length - 1].day !== d) out.push({ day: d, items: [] })
      out[out.length - 1].items.push(it)
    }
    return out
  })

  // --- Rapport ---
  let period = $state('7')
  let report = $state(null)

  async function loadReport() {
    report = null
    try {
      report = await api(period === 'week' ? '/report?week=true' : `/report?days=${period}`)
      error = ''
    } catch (e) {
      error = e.message
    }
  }

  $effect(() => {
    if (tab === 'timeline') { kind; untrack(() => loadTimeline()) }
    else { period; untrack(() => loadReport()) }
  })

  function dur(s) {
    if (s == null) return '—'
    const m = Math.round(s / 60)
    if (m < 60) return `${Math.max(m, 1)} min`
    if (m < 48 * 60) return `${Math.floor(m / 60)} u ${m % 60} min`
    return `${Math.floor(m / 1440)} dagen`
  }
  const pct = (v) => (v == null ? '—' : v >= 99.995 ? '100%' : `${v.toFixed(2)}%`)
  const lvl = (v) => (v == null ? '' : v < 99 ? 'e' : v < 99.9 ? 'w' : 'g')
  const range = (r) => {
    const f = (d) => new Date(d).toLocaleDateString('nl-BE', { day: 'numeric', month: 'short' })
    return `${f(r.start)} – ${f(r.end)}`
  }
</script>

<Modal title="history | less" {onclose} wide>
  <div class="tabs">
    <button class="mini" class:on={tab === 'timeline'} onclick={() => (tab = 'timeline')}>tijdlijn</button>
    <button class="mini" class:on={tab === 'report'} onclick={() => (tab = 'report')}>weekrapport</button>
    <span class="sp"></span>
    {#if tab === 'timeline'}
      <select bind:value={kind} aria-label="Soort">
        <option value="">alles</option>
        {#each Object.entries(KINDS) as [k, label]}<option value={k}>{label}</option>{/each}
      </select>
    {:else}
      <select bind:value={period} aria-label="Periode">
        <option value="7">laatste 7 dagen</option>
        <option value="week">vorige week (ma–zo)</option>
        <option value="30">laatste 30 dagen</option>
      </select>
    {/if}
  </div>
  {#if error}<p class="err">{error}</p>{/if}

  {#if tab === 'timeline'}
    {#each days as d (d.day)}
      <div class="day">{d.day}</div>
      <ol class="tl">
        {#each d.items as it (it.id)}
          <li class="lv-{it.level} k-{it.kind}">
            <span class="t">{time(it.ts)}</span>
            <span class="dot" aria-hidden="true"></span>
            <div class="what">
              <span class="kind">{ONE[it.kind] || it.kind}</span>
              <b>{it.title}</b>
              {#if it.body}<p>{it.body}</p>{/if}
            </div>
          </li>
        {/each}
      </ol>
    {:else}
      {#if !busy}<p class="hint">Nog niets op de tijdlijn. Storingen, herstarts, back-ups, updates en wijzigingen komen hier vanzelf.</p>{/if}
    {/each}
    {#if more}<button class="mini" disabled={busy} onclick={() => loadTimeline(true)}>meer laden</button>{/if}
  {:else if report}
    <p class="hint per">{range(report)}</p>
    <div class="stats">
      <div class="stat {lvl(report.uptime)}"><b>{pct(report.uptime)}</b><small>uptime</small></div>
      <div class="stat" class:e={report.outages.count}><b>{report.outages.count}</b><small>storingen</small></div>
      <div class="stat"><b>{dur(report.outages.longest?.seconds)}</b>
        <small>langste{report.outages.longest ? `: ${report.outages.longest.name}` : ''}{report.outages.longest?.ongoing ? ' (nog bezig)' : ''}</small></div>
      <div class="stat" class:e={report.backups.open.length}><b>{report.backups.made}</b>
        <small>back-ups{report.backups.open.length ? `, ${report.backups.open.length} met probleem` : ''}</small></div>
      <div class="stat"><b>{report.restarts.length}</b><small>herstarts</small></div>
      <div class="stat" class:w={report.updates.security}><b>{report.updates.pending}</b>
        <small>updates open{report.updates.security ? `, ${report.updates.security} beveiliging` : ''}</small></div>
    </div>

    <div class="cols">
      <section>
        <span class="lbl">Minst bereikbaar</span>
        {#each report.services.filter((s) => s.uptime < 100).slice(0, 12) as s (s.service_id)}
          <div class="ln"><span>{s.name}</span><b class={lvl(s.uptime)}>{pct(s.uptime)}</b></div>
        {:else}
          <p class="hint">Alles was de hele periode bereikbaar.</p>
        {/each}
      </section>
      <section>
        <span class="lbl">Traagst (gemiddeld)</span>
        {#each report.slowest as s (s.service_id)}
          <div class="ln"><span>{s.name}</span><b>{Math.round(s.avg_ms)} ms <small>max {Math.round(s.max_ms)}</small></b></div>
        {:else}
          <p class="hint">Nog geen metingen.</p>
        {/each}
      </section>
      {#if report.outages.per_service.length}
        <section>
          <span class="lbl">Storingen per service</span>
          {#each report.outages.per_service as s (s.service_id)}
            <div class="ln"><span>{s.name}</span><b>{s.count}×</b></div>
          {/each}
        </section>
      {/if}
      <section>
        <span class="lbl">Back-ups met een probleem</span>
        {#each report.backups.open as b}
          <div class="ln"><span>{b.group} <small>{b.service} · {b.store}</small></span><b class="e">{b.problem}</b></div>
        {:else}
          <p class="hint">Geen gemiste of mislukte back-ups.</p>
        {/each}
      </section>
      {#if report.updates.machines.length}
        <section>
          <span class="lbl">Meeste updates open</span>
          {#each report.updates.machines as m}
            <div class="ln"><span>{m.name}</span><b class:w={m.security}>{m.count}{m.security ? ` (${m.security} beveiliging)` : ''}</b></div>
          {/each}
        </section>
      {/if}
      {#if report.disks.length}
        <section>
          <span class="lbl">Opslag die vol loopt</span>
          {#each report.disks as d}
            <div class="ln"><span>{d.name}</span><b class:e={d.days_left <= 3} class:w={d.days_left > 3}>over {Math.max(0, Math.round(d.days_left))} dagen</b></div>
          {/each}
        </section>
      {/if}
    </div>
    <p class="hint small">Uptime zonder onderhoudsvensters. Elke maandagochtend komt de samenvatting van de vorige week in je meldingen.</p>
  {:else}
    <p class="hint">rapport berekenen…</p>
  {/if}
</Modal>

<style>
  .tabs { display: flex; gap: 6px; align-items: center; margin-bottom: 8px }
  .tabs .sp { flex: 1 }
  .tabs select { width: auto; padding: 5px 8px }
  .day { color: var(--muted); font-size: 11.5px; text-transform: lowercase; margin: 14px 0 4px; letter-spacing: .04em }
  .tl { list-style: none; margin: 0; padding: 0 }
  .tl li { display: grid; grid-template-columns: 44px 14px 1fr; gap: 8px; align-items: start; padding: 4px 0; position: relative }
  .tl li::before { content: ''; position: absolute; left: 58px; top: 0; bottom: 0; width: 1px; background: rgba(255, 255, 255, .08) }
  .t { color: var(--dim); font-size: 11.5px; text-align: right; padding-top: 2px }
  .dot { width: 9px; height: 9px; border-radius: 50%; background: #777; margin: 5px 0 0 1px; position: relative; z-index: 1 }
  .lv-ok .dot { background: var(--ok) }
  .lv-warn .dot { background: var(--mid) }
  .lv-err .dot { background: var(--err) }
  .k-wijziging .dot, .k-actie .dot { background: #a9c7ff }
  .what { min-width: 0; font-size: 12.5px }
  .what b { font-weight: 500; color: var(--text-h) }
  .what p { margin: 2px 0 0; color: var(--muted); white-space: pre-line; overflow-wrap: anywhere; font-size: 12px }
  .kind { font-size: 10.5px; color: var(--dim); margin-right: 6px; text-transform: uppercase; letter-spacing: .05em }
  .per { margin: 0 0 8px }
  .stats { display: grid; grid-template-columns: repeat(auto-fill, minmax(120px, 1fr)); gap: 8px }
  .stat { padding: 10px 12px; border-radius: 10px; background: var(--fill); border: 1px solid rgba(255, 255, 255, .08) }
  .stat b { display: block; font-size: 18px; color: var(--text-h); font-weight: 500 }
  .stat small { color: var(--muted); font-size: 11px }
  .stat.g b { color: var(--ok) }
  .stat.w b { color: var(--mid) }
  .stat.e b { color: var(--err) }
  .cols { display: grid; grid-template-columns: repeat(auto-fill, minmax(min(100%, 300px), 1fr)); gap: 4px 22px; margin-top: 12px }
  .ln { display: flex; justify-content: space-between; gap: 10px; font-size: 12.5px; padding: 4px 0; border-bottom: 1px solid rgba(255, 255, 255, .05) }
  .ln span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap }
  .ln small { color: var(--dim) }
  .ln b { font-weight: 500; white-space: nowrap }
  b.g { color: var(--ok) }
  b.w { color: var(--mid) }
  b.e { color: var(--err) }
  .small { font-size: 11.5px; margin-top: 12px }
</style>
