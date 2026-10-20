<script>
  import { storm } from './fx.js'
  import { onMount, untrack } from 'svelte'
  import { api, poll, withReauth } from './api.js'
  import IntegrationPanel from './IntegrationPanel.svelte'
  import LatencyChart from './LatencyChart.svelte'
  import Modal from './Modal.svelte'
  import Notes from './Notes.svelte'
  import RestoreTest from './RestoreTest.svelte'
  import HealRules from './HealRules.svelte'
  import Incidents from './Incidents.svelte'
  import Maintenance from './Maintenance.svelte'

  // Mini dashboard van één service: gegevens van de integratie en de monitoring-historiek.
  let { service, groups = [], onclose, onedit, onchanged, onterminal } = $props()

  // SSH-hosts die aan deze service gekoppeld zijn: knop om meteen een terminal te openen.
  let sshHosts = $state([])
  api('/ssh/hosts').then((hs) => (sshHosts = hs.filter((h) => h.service_id === service.id))).catch(() => {})

  // Laatste gebeurtenissen van deze service op de tijdlijn (storingen, herstarts, updates, acties).
  let events = $state([])
  api(`/timeline?service_id=${untrack(() => service.id)}&limit=8`).then((r) => (events = r.items)).catch(() => {})

  let wolMsg = $state('')
  async function wake() {
    if (!confirm(`${service.name} wekken met Wake-on-LAN?`)) return
    try {
      wolMsg = '✓ ' + (await withReauth(() => api(`/services/${service.id}/wol`, { method: 'POST' }))).message
      storm()
    } catch (e) { wolMsg = '✕ ' + e.message }
  }

  const RANGES = ['1h', '24h', '7d', '30d', '1y']
  let range = $state('24h')
  let data = $state(null)
  let error = $state('')

  async function load() {
    const r = range
    try {
      const d = await api(`/services/${service.id}/history?range=${r}`)
      if (r !== range) return // intussen een andere periode gekozen
      data = d
      error = ''
    } catch (e) {
      error = e.message
    }
  }

  $effect(() => {
    range
    load()
  })

  onMount(() => {
    return poll(load, 30000)
  })

  const pct = (v) => (v == null ? '—' : `${(Math.floor(v * 1000) / 10).toFixed(1)}%`)
  const ms = (v) => (v == null ? '—' : v < 10 ? `${v.toFixed(1)} ms` : `${Math.round(v)} ms`)
  const when = (ts) => new Date(ts).toLocaleString('nl-BE', { dateStyle: 'short', timeStyle: 'short' })
  function ago(ts) {
    const m = Math.round((Date.now() - new Date(ts).getTime()) / 60000)
    if (m < 60) return `${m} min`
    if (m < 48 * 60) return `${Math.floor(m / 60)} u ${m % 60} min`
    return `${Math.floor(m / 1440)} dagen`
  }
  const dur = (a, b) => {
    const m = Math.round((new Date(b) - new Date(a)) / 60000)
    return m < 60 ? `${m} min` : `${Math.floor(m / 60)} u ${m % 60} min`
  }
  const statusText = { up: 'bereikbaar', down: 'down', unknown: 'onbekend' }

  let maintUntil = $state(untrack(() => service.maintenance_until))
  let maintActive = $derived(maintUntil && new Date(maintUntil) > new Date())
  async function maintenance(minutes) {
    const r = await api(`/services/${service.id}/maintenance`, { method: 'POST', body: { minutes } })
    maintUntil = r.maintenance_until
    onchanged?.()
  }
  let certDays = $derived(data?.state?.cert_expires_at ? Math.floor((new Date(data.state.cert_expires_at) - Date.now()) / 86400000) : null)
</script>

<Modal title={`stat ${service.name.toLowerCase()}`} {onclose} wide>
  <div class="top">
    <div>
      <h3>{service.name}</h3>
      {#if service.url}<a class="url" href={service.url} target="_blank" rel="noopener noreferrer">{service.url}</a>{/if}
    </div>
    <div class="row">
      {#each sshHosts as h (h.id)}
        <button class="mini" onclick={() => onterminal?.(h.id)} title="{h.username}@{h.host}">&gt;_ {h.name}</button>
      {/each}
      {#if service.config?.mac}<button class="mini" onclick={wake} title="Wake-on-LAN naar {service.config.mac}">⏻ wekken</button>{/if}
      <button class="mini" onclick={() => onedit(service)}>✎ bewerken</button>
    </div>
  </div>
  {#if wolMsg}<p class="wol" class:e={wolMsg.startsWith('✕')}>{wolMsg}</p>{/if}

  <div class="maint">
    {#if maintActive}
      <span class="on">onderhoud tot {when(maintUntil)}</span>
      <button class="mini" onclick={() => maintenance(0)}>onderhoud stoppen</button>
    {:else}
      <span class="lbl">onderhoud</span>
      {#each [[30, '30 min'], [60, '1 u'], [240, '4 u'], [1440, '1 dag']] as [m, l]}
        <button class="mini" onclick={() => maintenance(m)}>{l}</button>
      {/each}
    {/if}
  </div>

  <Maintenance {service} />
  {#if service.check?.type}<Incidents {service} down={data?.state?.status === 'down'} />{/if}

  {#if service.type === 'pbs'}<RestoreTest />{/if}
  <Notes {service} {onchanged} />

  {#if service.type && service.type !== 'link'}
    <IntegrationPanel {service} {groups} {onchanged} />
  {/if}

  {#if !service.check?.type}
    <p class="hint">Voor deze service staat nog geen monitoring aan. Kies onder <b>bewerken → Monitoring</b> een check.</p>
  {:else}
    <p class="err">{error}</p>
    {#if data}
      <div class="kgrid">
        <div class="kpi {data.state?.status || 'unknown'}">
          <small>status</small>
          <b>{statusText[data.state?.status || 'unknown']}</b>
          {#if data.state}<small>sinds {ago(data.state.since)}</small>{/if}
        </div>
        <div class="kpi">
          <small>latency nu</small>
          <b>{ms(data.state?.latency_ms)}</b>
          <small>{service.check.type} {service.check.target || ''}</small>
        </div>
        <div class="kpi" class:bad={data.uptime != null && data.uptime < 0.99}>
          <small>uptime {range}</small>
          <b>{pct(data.uptime)}</b>
          <small>{data.checks} checks</small>
        </div>
        {#if certDays !== null}
          <div class="kpi" class:bad={certDays <= 14}>
            <small>certificaat</small>
            <b>{certDays} dagen</b>
            <small>tot {when(data.state.cert_expires_at)}</small>
          </div>
        {/if}
        <div class="kpi" class:bad={data.outages.length > 0}>
          <small>verstoringen {range}</small>
          <b>{data.outages.length}</b>
          <small>{data.state?.last_error || 'geen fout bij laatste check'}</small>
        </div>
      </div>

      <div class="tabs" role="tablist">
        {#each RANGES as r}
          <button class="mini" class:on={range === r} role="tab" aria-selected={range === r} onclick={() => (range = r)}>{r}</button>
        {/each}
      </div>
      <span class="lbl">Latency (ms) en uptime</span>
      <LatencyChart points={data.points} bucketSeconds={data.bucket_seconds} />

      {#if data.outages.length}
        <span class="lbl">Verstoringen</span>
        <table class="tbl">
          <thead><tr><th>begin</th><th>duur (ongeveer)</th><th>gelukt</th></tr></thead>
          <tbody>
            {#each data.outages as o}
              <tr><td>{when(o.start)}</td><td>{dur(o.start, o.end)}</td><td class="e">{pct(o.worst)}</td></tr>
            {/each}
          </tbody>
        </table>
      {/if}

      {#if events.length}
        <span class="lbl">Gebeurtenissen</span>
        <table class="tbl ev">
          <tbody>
            {#each events as ev (ev.id)}
              <tr><td>{when(ev.ts)}</td><td class={ev.level === 'err' ? 'e' : ev.level === 'ok' ? 'o' : ''}>{ev.title}</td></tr>
            {/each}
          </tbody>
        </table>
      {/if}

      {#if service.check?.type}<HealRules {service} />{/if}

      <span class="lbl">Laatste checks</span>
      <table class="tbl">
        <thead><tr><th>tijd</th><th>resultaat</th><th>latency</th><th>details</th></tr></thead>
        <tbody>
          {#each data.recent as r}
            <tr>
              <td>{when(r.ts)}</td>
              <td class={r.ok ? 'o' : 'e'}>{r.ok ? 'ok' : 'fout'}{r.maintenance ? ' (onderhoud)' : ''}</td>
              <td>{ms(r.latency_ms)}</td>
              <td>{r.status_code ?? ''} {r.error ?? ''}</td>
            </tr>
          {:else}
            <tr><td colspan="4" class="m">Nog geen checks uitgevoerd. De worker start ze binnen een minuut.</td></tr>
          {/each}
        </tbody>
      </table>
    {/if}
  {/if}
</Modal>

<style>
  .maint { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; margin: 0 0 12px }
  .wol { font-size: 12px; color: var(--ok); margin: 0 0 8px }
  .wol.e { color: var(--err) }
  .ev td:first-child { width: 150px; white-space: nowrap }
  .maint .lbl { margin: 0 4px 0 0 }
  .maint .on { color: var(--mid); font-size: 12.5px }
  .top { display: flex; justify-content: space-between; align-items: flex-start; gap: 10px; margin-bottom: 10px }
  .url { color: var(--muted); font-size: 12.5px; word-break: break-all }
  .kgrid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 8px; margin-top: 8px }
  .kpi { padding: 10px 12px; border-radius: 10px; background: var(--fill); border: 1px solid rgba(255, 255, 255, .08) }
  .kpi b { display: block; font-size: 18px; color: var(--text-h); margin: 2px 0 }
  .kpi small { display: block; color: var(--muted); font-size: 11.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap }
  .kpi.up { border-color: rgba(143, 214, 164, .5) }
  .kpi.up b { color: var(--ok) }
  .kpi.down, .kpi.bad { border-color: var(--err) }
  .kpi.down b, .kpi.bad b { color: var(--err) }
  .tabs { display: flex; gap: 6px; margin: 16px 0 0 }
  .tbl { width: 100%; border-collapse: collapse; font-size: 12.5px; margin-top: 6px }
  .tbl th { text-align: left; color: var(--muted); font-weight: 400; font-size: 11.5px; padding: 5px 6px; border-bottom: 1px solid rgba(255, 255, 255, .1) }
  .tbl td { padding: 5px 6px; border-bottom: 1px solid rgba(255, 255, 255, .05); vertical-align: top; word-break: break-word }
  .tbl tr:hover td { background: rgba(255, 255, 255, .04) }
  .o { color: var(--ok) }
  .e { color: var(--err) }
  .m { color: var(--muted) }
</style>
