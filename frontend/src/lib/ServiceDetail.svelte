<script>
  import { onMount } from 'svelte'
  import { api, poll } from './api.js'
  import LatencyChart from './LatencyChart.svelte'
  import Modal from './Modal.svelte'

  // Mini dashboard van één service. Later komen hier ook de API-gegevens van de integratie.
  let { service, onclose, onedit } = $props()

  const RANGES = ['1h', '24h', '7d', '30d', '1y']
  let range = $state('24h')
  let data = $state(null)
  let error = $state('')

  async function load() {
    try {
      data = await api(`/services/${service.id}/history?range=${range}`)
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
</script>

<Modal title={`stat ${service.name.toLowerCase()}`} {onclose} wide>
  <div class="top">
    <div>
      <h3>{service.name}</h3>
      {#if service.url}<a class="url" href={service.url} target="_blank" rel="noopener noreferrer">{service.url}</a>{/if}
    </div>
    <button class="mini" onclick={() => onedit(service)}>✎ bewerken</button>
  </div>

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

      <span class="lbl">Laatste checks</span>
      <table class="tbl">
        <thead><tr><th>tijd</th><th>resultaat</th><th>latency</th><th>details</th></tr></thead>
        <tbody>
          {#each data.recent as r}
            <tr>
              <td>{when(r.ts)}</td>
              <td class={r.ok ? 'o' : 'e'}>{r.ok ? 'ok' : 'fout'}</td>
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
