<script>
  import { onMount } from 'svelte'
  import { api } from './api.js'
  import { duration } from './format.js'

  // Zabbix in het mini dashboard: de hosts van deze service (en de node waarop ze draait), met CPU, RAM, schijf,
  // uptime en ping, een grafiek van 24 u en de open problemen.
  let { service } = $props()
  let data = $state.raw(null)
  let error = $state('')

  onMount(async () => {
    try { data = await api(`/services/${service.id}/zabbix`) } catch (e) { error = e.message }
  })

  const SEV = ['niet ingedeeld', 'info', 'waarschuwing', 'gemiddeld', 'hoog', 'ramp']
  const show = (m) => (m.format === 'percent' ? `${Math.round(m.value)}%` : m.format === 'uptime' ? duration(m.value)
    : m.format === 'ms' ? `${(m.value * 1000).toFixed(1)} ms` : m.format === 'bool' ? (m.value ? 'ja' : 'nee') : m.value)
  const mlevel = (m) => (m.format === 'percent' ? (m.value >= 90 ? 'err' : m.value >= 80 ? 'warn' : '') : m.format === 'bool' && !m.value ? 'err' : '')
  function line(points) {
    if (!points?.length || points.length < 2) return ''
    const t0 = points[0][0], t1 = points.at(-1)[0] || t0 + 1
    return points.map(([t, v], i) => `${i ? 'L' : 'M'}${(((t - t0) / (t1 - t0 || 1)) * 100).toFixed(1)},${(22 - (Math.min(100, v) / 100) * 20).toFixed(1)}`).join('')
  }
  const since = (ts) => (ts ? duration(Date.now() / 1000 - ts) : '')
  const link = (h) => `${data.url}/zabbix.php?action=problem.view&filter_set=1&hostids%5B%5D=${h.id}`
</script>

{#if data?.hosts?.length || error}
  <section class="zbx">
    <div class="hd"><span class="lbl">zabbix</span>{#if data?.error}<span class="e">{data.error} (laatste stand)</span>{/if}</div>
    {#if error}<p class="e">{error}</p>{/if}
    {#each data?.hosts || [] as h (h.id)}
      <div class="host" class:bad={h.level === 'err'}>
        <div class="hh">
          <i class="dot" class:bad={h.level === 'err'}></i>
          <b>{h.name}</b>
          {#if h.role === 'node'}<small class="tag">node</small>{/if}
          <small>{h.down ? 'onbereikbaar' : h.ips.join(', ')}</small>
          {#if data.url}<a class="mini" href={link(h)} target="_blank" rel="noopener">open in Zabbix</a>{/if}
        </div>
        {#if h.metrics.length}
          <div class="ms">
            {#each h.metrics as m (m.label)}
              <div class="m lv-{mlevel(m)}">
                <small>{m.label}</small><b>{show(m)}</b>
                {#if m.points?.length > 1}
                  <svg viewBox="0 0 100 24" preserveAspectRatio="none" aria-label="{m.label} over 24 uur"><path d={line(m.points)} /></svg>
                {/if}
              </div>
            {/each}
          </div>
        {/if}
        {#each h.problems as p}
          <div class="p sev{p.severity}"><span class="sv">{SEV[p.severity] || '?'}</span>{p.name}<small>{since(p.since)}</small></div>
        {:else}
          {#if !h.down}<p class="okp">Geen open problemen.</p>{/if}
        {/each}
      </div>
    {/each}
  </section>
{:else if data?.configured}
  <p class="hint">Zabbix: geen host gevonden voor deze service. Kies er zelf een via <b>✎ bewerken</b> → Monitoring → Zabbix-hosts,
    of zet daar <code>-</code> om Zabbix bij deze tegel uit te zetten.</p>
{/if}

<style>
  .zbx { margin: 14px 0 }
  .hd { display: flex; gap: 10px; align-items: baseline }
  .e { color: var(--err); font-size: 12px }
  .host { border: 1px solid var(--line); border-left: 3px solid var(--ok); border-radius: 10px; padding: 8px 10px; margin: 6px 0; background: var(--fill) }
  .host.bad { border-left-color: var(--err) }
  .hh { display: flex; gap: 8px; align-items: baseline; flex-wrap: wrap }
  .hh b { color: var(--text-h); font-weight: 500 }
  .hh small { color: var(--dim); font-size: 11.5px }
  .hh a { margin-left: auto; text-decoration: none }
  .tag { border: 1px solid var(--line-2); border-radius: 6px; padding: 0 5px }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--ok); align-self: center }
  .dot.bad { background: var(--err); box-shadow: 0 0 6px var(--err) }
  .ms { display: grid; grid-template-columns: repeat(auto-fill, minmax(120px, 1fr)); gap: 6px; margin: 8px 0 4px }
  .m { border: 1px solid var(--line); border-radius: 8px; padding: 4px 8px; display: flex; flex-direction: column }
  .m small { color: var(--muted); font-size: 11px }
  .m b { color: var(--text-h); font-weight: 500; font-size: 15px }
  .m.lv-warn b { color: var(--mid) }
  .m.lv-err b { color: var(--err) }
  .m svg { width: 100%; height: 22px; margin-top: 2px }
  .m path { fill: none; stroke: var(--ok); stroke-width: 1.4; vector-effect: non-scaling-stroke }
  .m.lv-err path { stroke: var(--err) }
  .p { display: flex; gap: 8px; align-items: baseline; font-size: 12.5px; padding: 2px 0 }
  .p small { margin-left: auto; color: var(--dim); white-space: nowrap }
  .sv { font-size: 10.5px; padding: 0 5px; border-radius: 5px; border: 1px solid var(--line-2); color: var(--muted); white-space: nowrap }
  .sev2 .sv { color: var(--mid) }
  .sev3 .sv, .sev4 .sv, .sev5 .sv { color: var(--err); border-color: rgba(255, 110, 110, .5) }
  .okp { color: var(--muted); font-size: 12px; margin: 2px 0 }
  .hint { color: var(--muted); font-size: 12px }
</style>
