<script>
  import { onMount } from 'svelte'
  import { api } from './api.js'

  // Apparaten op het netwerk (ARP en DHCP van OPNsense). Onbekende staan bovenaan; geef ze een naam.
  let data = $state(null)
  let error = $state('')
  let q = $state('')
  let edit = $state(null)
  let busy = $state('')

  async function load() {
    try { data = await api('/devices'); error = '' } catch (e) { error = e.message }
  }
  onMount(load)

  async function refresh() {
    busy = 'refresh'
    try { await api('/devices/refresh', { method: 'POST' }); await load() } catch (e) { error = e.message } finally { busy = '' }
  }
  async function save(d, body) {
    try { await api(`/devices/${d.mac}`, { method: 'PATCH', body }); edit = null; await load() } catch (e) { error = e.message }
  }
  async function scan(d) {
    busy = d.mac
    try { await api(`/devices/${d.mac}/scan`, { method: 'POST' }); await load() } catch (e) { error = e.message } finally { busy = '' }
  }

  const ago = (ts) => {
    const m = Math.round((Date.now() - new Date(ts).getTime()) / 60000)
    return m < 60 ? `${Math.max(m, 0)} min` : m < 2880 ? `${Math.floor(m / 60)} u` : `${Math.floor(m / 1440)} d`
  }
  let rows = $derived((data?.items || []).filter((d) => {
    const t = `${d.name || ''} ${d.hostname || ''} ${d.vendor || ''} ${d.ip || ''} ${d.mac} ${d.intf || ''}`.toLowerCase()
    return q.toLowerCase().split(/\s+/).filter(Boolean).every((w) => t.includes(w))
  }))
</script>

{#if error}<p class="err">{error}</p>{/if}
<div class="top">
  {#if data}<span class="sum"><b>{data.summary.online}</b> online van {data.summary.total}
    {#if data.summary.unknown}<span class="w">· {data.summary.unknown} zonder naam</span>{/if}</span>{/if}
  <input class="q" bind:value={q} placeholder="zoeken: naam, IP, MAC, fabrikant…" />
  <button class="mini" disabled={busy === 'refresh'} onclick={refresh}>{busy === 'refresh' ? 'bezig…' : 'nu ophalen'}</button>
</div>
{#if data?.last?.errors?.length}{#each data.last.errors as e}<p class="e small">{e.source}: {e.error}</p>{/each}{/if}
<table class="tbl">
  <thead><tr><th></th><th>apparaat</th><th>IP</th><th>MAC · fabrikant</th><th>poorten</th><th></th></tr></thead>
  <tbody>
    {#each rows as d (d.mac)}
      <tr class:new={!d.known}>
        <td><i class="dot" class:on={d.online} title={d.online ? 'online' : `laatst gezien ${ago(d.last_seen)} geleden`}></i></td>
        <td>
          {#if edit?.mac === d.mac}
            <input class="nm" bind:value={edit.name} placeholder="naam" onkeydown={(e) => e.key === 'Enter' && save(d, { name: edit.name, known: true })} />
          {:else}
            <b>{d.name || d.hostname || '—'}</b>{#if !d.known}<span class="tag">nieuw</span>{/if}
            {#if d.name && d.hostname && d.hostname !== d.name}<small class="m"> {d.hostname}</small>{/if}
          {/if}
          <small class="m block"><span class="mip">{d.ip || ''} ·{' '}</span>{d.intf || ''} · sinds {new Date(d.first_seen).toLocaleDateString('nl-BE')}</small>
        </td>
        <td class="mono">{d.ip || '—'}</td>
        <td><span class="mono">{d.mac}</span><small class="m block">{d.vendor || 'onbekende fabrikant'}</small></td>
        <td>
          {#if d.ports?.length}<span class="ports">{#each d.ports as p}<span title={d.port_names[p]}>{p}</span>{/each}</span>
          {:else if d.ports}<small class="m">geen open</small>{/if}
          <label class="chk" title="Elke 6 uur scannen en melden als er een nieuwe poort openstaat"><input type="checkbox" checked={d.scan}
                 onchange={(e) => save(d, { scan: e.currentTarget.checked })} /> volgen</label>
        </td>
        <td class="act">
          {#if edit?.mac === d.mac}
            <button class="mini" onclick={() => save(d, { name: edit.name, known: true })}>bewaren</button>
          {:else}
            <button class="mini" onclick={() => (edit = { mac: d.mac, name: d.name || d.hostname || '' })}>naam</button>
            {#if !d.known}<button class="mini" onclick={() => save(d, { known: true })}>ken ik</button>{/if}
            <button class="mini" disabled={busy === d.mac || !d.ip} onclick={() => scan(d)}>{busy === d.mac ? 'scannen…' : 'scan'}</button>
          {/if}
        </td>
      </tr>
    {:else}
      <tr><td colspan="6" class="m">{data ? 'Nog geen apparaten. Ze komen uit de ARP- en DHCP-tabel van een OPNsense-tegel (API-key met de rechten "Diagnostics: ARP Table" en "Services: DHCP: Leases").' : 'laden…'}</td></tr>
    {/each}
  </tbody>
</table>

<style>
  .top { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-bottom: 8px }
  .sum { font-size: 13px }
  .sum b { font-size: 17px; color: var(--text-h); font-weight: 500 }
  .q { flex: 1; min-width: 180px }
  .w { color: var(--mid) }
  .e { color: var(--err) }
  .small { font-size: 12px; margin: 2px 0 }
  .tbl { width: 100%; border-collapse: collapse; font-size: 12.5px }
  .tbl th { text-align: left; font-weight: 400; color: var(--muted); font-size: 11.5px; padding: 5px 6px; border-bottom: 1px solid var(--line) }
  .tbl td { padding: 6px; border-bottom: 1px solid var(--line); vertical-align: top }
  .tbl b { font-weight: 500; color: var(--text-h) }
  tr.new td { background: rgba(240, 180, 107, .06) }
  .tag { margin-left: 6px; font-size: 10.5px; padding: 0 6px; border-radius: 6px; background: rgba(240, 180, 107, .16); color: var(--mid) }
  .dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: var(--dim); margin-top: 5px }
  .dot.on { background: var(--ok) }
  .m { color: var(--muted); font-size: 11.5px }
  .block { display: block }
  .mono { font-size: 12px }
  .ports { display: flex; flex-wrap: wrap; gap: 3px; margin-bottom: 3px }
  .ports span { font-size: 11px; padding: 0 5px; border-radius: 5px; border: 1px solid var(--line-2); color: #a9c7ff }
  .chk { display: flex; gap: 4px; align-items: center; font-size: 11.5px; color: var(--muted) }
  .chk input { width: auto }
  .act { white-space: nowrap; text-align: right }
  .nm { width: 160px }
  .mip { display: none }
  @media (max-width: 700px) {
    .tbl th:nth-child(3), .tbl td:nth-child(3), .tbl th:nth-child(4), .tbl td:nth-child(4) { display: none }
    .mip { display: inline }
    .act { white-space: normal; width: 1% }
    .act button { display: block; width: 100%; margin-bottom: 3px }
  }
</style>
