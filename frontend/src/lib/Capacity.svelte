<script>
  import { onMount } from 'svelte'
  import { api, poll } from './api.js'
  import { bytes } from './format.js'
  import Modal from './Modal.svelte'
  import Nightly from './Nightly.svelte'

  // Capaciteit: opslag met voorspelling, en CPU/RAM/schijf van alle nodes en VM's/CT's.
  let { onclose } = $props()

  let data = $state(null)
  let error = $state('')
  let filter = $state('')
  let sort = $state('mem')

  // Stroom uit Home Assistant (alleen als er een homeassistant-tegel is).
  let power = $state([])
  async function load() {
    try { data = await api('/capacity'); error = '' } catch (e) { error = e.message }
    try { power = await api('/power') } catch { power = [] }
  }
  onMount(() => { load(); return poll(load, 60000) })
  const eur = (v) => (v == null ? '—' : `€ ${v.toFixed(2)}`)
  const kwh = (v) => (v == null ? '—' : `${v.toFixed(v < 10 ? 2 : 1)} kWh`)
  function bars(days) {
    const vals = Object.values(days || {})
    const max = Math.max(0.001, ...vals)
    return vals.map((v, i) => ({ x: i * 4, h: Math.max(v > 0 ? 1 : 0, (v / max) * 20) }))
  }

  const pct = (a, b) => (a != null && b ? (a / b) * 100 : null)
  const lvl = (p) => (p == null ? '' : p >= 92 ? 'e' : p >= 80 ? 'w' : '')
  const fmtPct = (p) => (p == null ? '—' : `${p.toFixed(0)}%`)
  function left(d) {
    if (d == null) return 'stabiel'
    if (d < 1) return 'vol binnen een dag'
    if (d > 365) return 'meer dan een jaar'
    return `vol over ${Math.round(d)} dagen`
  }
  const leftLvl = (d) => (d == null ? '' : d <= 3 ? 'e' : d <= 14 ? 'w' : '')
  const rate = (r) => (r == null ? '' : `${r >= 0 ? '+' : '−'}${bytes(Math.abs(r))}/dag`)

  function spark(series) {
    const pts = series.filter((p) => p[1] != null)
    if (pts.length < 2) return ''
    const t0 = pts[0][0], t1 = pts[pts.length - 1][0] || t0 + 1
    const lo = Math.min(...pts.map((p) => p[1])), hi = Math.max(...pts.map((p) => p[1]))
    const span = Math.max(hi - lo, 1)
    return pts.map((p) => `${(((p[0] - t0) / (t1 - t0 || 1)) * 120).toFixed(1)},${(22 - ((p[1] - lo) / span) * 20).toFixed(1)}`).join(' ')
  }

  const SORTS = { mem: (g) => pct(g.mem, g.mem_total) ?? -1, cpu: (g) => g.cpu ?? -1, disk: (g) => pct(g.disk, g.disk_total) ?? -1, name: null }
  let guests = $derived.by(() => {
    const q = filter.trim().toLowerCase()
    const list = (data?.guests || []).filter((g) => !q || `${g.label} ${g.node}`.toLowerCase().includes(q))
    const f = SORTS[sort]
    return f ? [...list].sort((a, b) => f(b) - f(a)) : list
  })
</script>

<Modal title="df -h && top" {onclose} wide>
  {#if error}<p class="err">{error}</p>{/if}
  {#if data && !data.storage.length && !data.nodes.length && !power.length}
    <p class="hint">Nog geen metingen. Voeg een service van type <b>proxmox</b> toe; de worker meet elke 10 minuten.</p>
  {:else if data}
    {#if data.storage.length}
    <span class="lbl">Opslag</span>
    {#each data.storage as s (s.service_id + s.name)}
      {@const p = pct(s.used, s.total)}
      <div class="st">
        <div class="sn"><b>{s.name}</b><small>{s.type || ''}{data.storage.some((x) => x.service !== s.service) ? ` · ${s.service}` : ''}</small></div>
        <div class="sm">
          <div class="meter"><i class={lvl(p)} style="width:{Math.min(100, p || 0)}%"></i></div>
          <small>{bytes(s.used)} van {bytes(s.total)} · {fmtPct(p)}</small>
        </div>
        <svg viewBox="0 0 120 24" class="sp" aria-hidden="true"><polyline points={spark(s.series)} /></svg>
        <div class="fc {leftLvl(s.days_left)}"><b>{left(s.days_left)}</b><small>{rate(s.rate_per_day)}</small></div>
      </div>
    {/each}
    <p class="hint small">Voorspelling op basis van de laatste 7 dagen. Melding als iets binnen 14 en binnen 3 dagen vol loopt.</p>
    {/if}

    {#each power as pw (pw.service_id)}
      <span class="lbl">Stroom · {pw.service}</span>
      {#if pw.error}<p class="err">{pw.error}</p>{/if}
      <table class="tbl">
        <thead><tr><th>node</th><th>nu</th><th>gem. 24u</th><th>deze maand</th><th>kost</th><th>prognose maand</th><th>30 dagen</th></tr></thead>
        <tbody>
          {#each pw.nodes as n (n.name)}
            <tr>
              <td>{n.name}</td>
              <td>{n.watts != null ? `${Math.round(n.watts)} W` : '—'}</td>
              <td class="m">{n.avg_24h != null ? `${Math.round(n.avg_24h)} W` : '—'}</td>
              <td>{kwh(n.month_kwh)}{#if n.measured}<small title="Uit de eigen metingen om de 10 minuten (geen energy-sensor)"> ≈</small>{/if}</td>
              <td>{eur(n.month_cost)}</td>
              <td class="m">{kwh(n.forecast_kwh)} <small>{eur(n.forecast_cost)}</small></td>
              <td><svg viewBox="0 0 124 22" class="pb" aria-hidden="true">{#each bars(n.days) as b}<rect x={b.x} y={22 - b.h} width="3" height={b.h} />{/each}</svg></td>
            </tr>
          {/each}
          {#if pw.nodes.length > 1}
            {@const t = (k) => pw.nodes.reduce((a, n) => (n[k] == null ? a : (a ?? 0) + n[k]), null)}
            <tr class="sum">
              <td>totaal</td><td>{t('watts') != null ? `${Math.round(t('watts'))} W` : '—'}</td><td></td>
              <td>{kwh(t('month_kwh'))}</td><td>{eur(t('month_cost'))}</td><td class="m">{kwh(t('forecast_kwh'))} <small>{eur(t('forecast_cost'))}</small></td><td></td>
            </tr>
          {/if}
        </tbody>
      </table>
    {/each}

    {#if data.nodes.length || data.guests.length}
    <span class="lbl">Nodes</span>
    <table class="tbl">
      <thead><tr><th>node</th><th>cpu</th><th>cpu piek 24u</th><th>ram</th><th>ram piek 24u</th><th>rootfs</th></tr></thead>
      <tbody>
        {#each data.nodes as n (n.service_id + n.name)}
          {@const m = pct(n.mem, n.mem_total)}
          {@const d = pct(n.disk, n.disk_total)}
          <tr>
            <td>{n.name}</td>
            <td class={lvl(n.cpu * 100)}>{fmtPct(n.cpu * 100)}</td>
            <td class="m">{n.cpu_max_24h != null ? fmtPct(n.cpu_max_24h * 100) : '—'}</td>
            <td class={lvl(m)}>{fmtPct(m)} <small>{bytes(n.mem)} / {bytes(n.mem_total)}</small></td>
            <td class="m">{fmtPct(pct(n.mem_max_24h, n.mem_total))}</td>
            <td class={lvl(d)}>{fmtPct(d)}</td>
          </tr>
        {/each}
      </tbody>
    </table>

    <div class="gh">
      <span class="lbl">VM's en containers</span>
      <input class="q" bind:value={filter} placeholder="filter…" />
      <select bind:value={sort} aria-label="Sorteren">
        <option value="mem">meeste ram</option>
        <option value="cpu">meeste cpu</option>
        <option value="disk">volste schijf</option>
        <option value="name">op id</option>
      </select>
    </div>
    <table class="tbl">
      <thead><tr><th>naam</th><th>node</th><th>cpu</th><th>ram</th><th>ram piek 24u</th><th>schijf</th></tr></thead>
      <tbody>
        {#each guests as g (g.service_id + g.name)}
          {@const m = pct(g.mem, g.mem_total)}
          {@const d = pct(g.disk, g.disk_total)}
          <tr class:off={g.cpu == null}>
            <td>{g.label}</td>
            <td class="m">{g.node}</td>
            <td>{g.cpu == null ? 'uit' : fmtPct(g.cpu * 100)}</td>
            <td class={lvl(m)}>{fmtPct(m)} <small>{g.mem != null ? bytes(g.mem) : ''} / {bytes(g.mem_total)}</small></td>
            <td class="m">{fmtPct(pct(g.mem_max_24h, g.mem_total))}</td>
            <td class={lvl(d)}>{d == null ? '—' : fmtPct(d)} <small>{d == null ? '' : `${bytes(g.disk)} / ${bytes(g.disk_total)}`}</small></td>
          </tr>
        {/each}
      </tbody>
    </table>
    <p class="hint small">Bij VM's meldt Proxmox geen schijfgebruik, alleen bij containers.
      {#if data.sampled_at}Laatste meting {new Date(data.sampled_at).toLocaleTimeString('nl-BE', { hour: '2-digit', minute: '2-digit' })}.{/if}</p>
    {/if}
  {:else}
    <p class="hint">laden…</p>
  {/if}
  {#if data}<Nightly />{/if}
</Modal>

<style>
  .st { display: grid; grid-template-columns: minmax(120px, 1.2fr) 2fr 120px minmax(120px, 1fr); gap: 14px; align-items: center;
        padding: 9px 12px; border-radius: 10px; background: var(--fill); border: 1px solid rgba(255, 255, 255, .08); margin-bottom: 6px }
  .sn b, .fc b { display: block; font-weight: 500; color: var(--text-h); font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap }
  .sn small, .sm small, .fc small { color: var(--muted); font-size: 11.5px }
  .meter { height: 7px; border-radius: 4px; background: rgba(255, 255, 255, .08); overflow: hidden; margin-bottom: 4px }
  .meter i { display: block; height: 100%; background: var(--ok); border-radius: 4px }
  .meter i.w { background: var(--mid) }
  .meter i.e { background: var(--err) }
  .sp { width: 120px; height: 24px }
  .sp polyline { fill: none; stroke: rgba(255, 255, 255, .55); stroke-width: 1.3; vector-effect: non-scaling-stroke }
  .fc { text-align: right }
  .fc.w b { color: var(--mid) }
  .fc.e b { color: var(--err) }
  .small { font-size: 11.5px; margin-top: 4px }
  .tbl { width: 100%; border-collapse: collapse; font-size: 12.5px; margin-top: 6px }
  .tbl th { text-align: left; color: var(--muted); font-weight: 400; font-size: 11.5px; padding: 5px 6px; border-bottom: 1px solid rgba(255, 255, 255, .1) }
  .tbl td { padding: 5px 6px; border-bottom: 1px solid rgba(255, 255, 255, .05); white-space: nowrap }
  .tbl td small { color: var(--dim); font-size: 11px }
  .tbl tr.off td { color: var(--dim) }
  .m { color: var(--muted) }
  .pb { width: 124px; height: 22px; display: block }
  .pb rect { fill: rgba(255, 255, 255, .45) }
  tr.sum td { color: var(--text-h); border-top: 1px solid rgba(255, 255, 255, .15) }
  td.w { color: var(--mid) }
  td.e { color: var(--err) }
  .gh { display: flex; gap: 8px; align-items: flex-end; margin-top: 14px }
  .gh .lbl { flex: 1; margin-bottom: 4px }
  .gh .q { width: 160px; padding: 5px 8px }
  .gh select { width: auto; padding: 5px 8px }
  @media (max-width: 700px) {
    .st { grid-template-columns: 1fr 1fr }
    .sp { display: none }
    .tbl { display: block; overflow-x: auto }
  }
</style>
