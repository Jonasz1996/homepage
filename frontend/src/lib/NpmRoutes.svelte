<script>
  import { onMount } from 'svelte'
  import { api, poll } from './api.js'

  // Checks rechtstreeks naar de server achter NPM (zonder DNS): per tegel hoe de check loopt, aan/uit, firewall.
  let data = $state(null)
  let error = $state('')
  let busy = $state(false)
  let filter = $state('')

  async function load() {
    try {
      data = await api('/npm/routes')
      error = ''
    } catch (e) {
      error = e.message
    }
  }

  onMount(() => {
    load()
    return poll(load, 30000)
  })

  async function toggle(e) {
    const box = e.currentTarget
    busy = true
    try {
      data = await api('/npm/routes', { method: 'PUT', body: { enabled: box.checked } })
      error = ''
    } catch (err) {
      error = err.message
      await load()
      // Svelte schrijft dezelfde waarde niet opnieuw: zet het vakje zelf terug op wat de server heeft.
      box.checked = !!data?.enabled
    } finally {
      busy = false
    }
  }

  async function refresh() {
    busy = true
    try {
      data = await api('/npm/routes/refresh', { method: 'POST' })
      error = ''
    } catch (e) {
      error = e.message
    } finally {
      busy = false
    }
  }

  const when = (iso) => (iso ? new Date(iso).toLocaleTimeString('nl-BE', { hour: '2-digit', minute: '2-digit' }) : '')
  let walled = $derived((data?.blocked || []).filter((b) => !b.refused))
  let refused = $derived((data?.blocked || []).filter((b) => b.refused))
  let rows = $derived((data?.rows || []).filter((r) => !filter || `${r.name} ${r.host} ${r.to || r.why || ''}`.toLowerCase().includes(filter.toLowerCase())))
</script>

<p class="hint">
  Een check op een naam die NPM kent, gaat rechtstreeks naar de server erachter: zonder DNS en zonder NPM, met dezelfde
  headers als NPM. Bereikt het dashboard die server niet, dan gaat de check naar het IP van NPM, ook zonder DNS. Klik
  je op een tegel, dan opent nog altijd de naam.
</p>
{#if data}
  <div class="row">
    <label class="chk"><input type="checkbox" checked={data.enabled} disabled={busy} onchange={toggle} /> rechtstreeks checken</label>
    <button class="mini" disabled={busy} onclick={refresh}>{busy ? 'bezig…' : 'nu vernieuwen'}</button>
    {#if data.at}<span class="dim">opgehaald {when(data.at)}</span>{/if}
  </div>
  {#each data.errors as e}<p class="err">NPM: {e}</p>{/each}
  {#if data.enabled}
    <p class="sum">
      <b class="okc">{data.counts.direct}</b> rechtstreeks, <b class:warnc={data.counts.npm}>{data.counts.npm}</b> via NPM zonder DNS,
      <b class:warnc={data.counts.naam}>{data.counts.naam}</b> via de naam
      {#if !data.at}(de proxy hosts worden zo opgehaald){/if}
    </p>
    {#if walled.length}
      <div class="fw">
        Het dashboard bereikt deze servers niet, dus die checks gaan nog door NPM. Laat in OPNsense het dashboard naar
        die poorten toe (net → firewall geeft de regel), en klik dan op nu vernieuwen:
        <ul>
          {#each walled as b (b.endpoint)}<li><code>{b.endpoint}</code> <span class="dim">{b.tiles.join(', ')}</span></li>{/each}
        </ul>
      </div>
    {/if}
    {#if refused.length}
      <div class="fw">
        Deze servers weigeren de verbinding: ze antwoorden, maar niets luistert op die poort. Staat de service uit, of
        luistert ze op een andere poort dan in NPM? Tot dan gaan die checks door NPM:
        <ul>
          {#each refused as b (b.endpoint)}<li><code>{b.endpoint}</code> <span class="dim">{b.tiles.join(', ')}</span></li>{/each}
        </ul>
      </div>
    {/if}
    {#if data.rows.length > 8}<input class="filter" placeholder="filter" bind:value={filter} />{/if}
    {#if data.rows.length}
      <div class="tw">
        <table>
          <thead><tr><th>tegel</th><th>naam</th><th>check gaat</th></tr></thead>
          <tbody>
            {#each rows as r (r.service_id)}
              <tr>
                <td>{r.name}</td>
                <td class="dim">{r.host}</td>
                {#if r.direct}<td class="okc">→ {r.to}</td>
                {:else if r.npm}<td class:warnc={r.blocked}>via NPM ({r.npm}): {r.why}</td>
                {:else}<td class="dim">via de naam: {r.why}</td>{/if}
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  {:else}
    <p class="sum">Uit: elke check vraagt DNS en gaat door NPM.</p>
  {/if}
{/if}
<p class="err">{error}</p>

<style>
  .row { display: flex; align-items: center; gap: 10px; flex-wrap: wrap }
  .chk { display: flex; gap: 6px; align-items: center; font-size: 12.5px }
  .dim { color: var(--dim); font-size: 12px }
  .sum { font-size: 12.5px; color: var(--text); margin: 8px 0 }
  .okc { color: var(--ok) }
  .warnc { color: var(--mid) }
  .fw { font-size: 12.5px; color: var(--text); border: 1px solid var(--mid); border-radius: 8px; padding: 8px 10px; margin: 8px 0 }
  .fw ul { margin: 6px 0 0; padding-left: 18px }
  .fw code { color: var(--text-h) }
  .filter { max-width: 180px; padding: 4px 8px; font-size: 12px; margin-bottom: 6px }
  .tw { max-height: 320px; overflow: auto }
  table { width: 100%; border-collapse: collapse; font-size: 12.5px }
  th { text-align: left; color: var(--muted); font-weight: normal; padding: 3px 6px }
  td { padding: 3px 6px; border-top: 1px solid rgba(255, 255, 255, .06); overflow-wrap: anywhere }
  td:first-child { overflow-wrap: normal }
</style>
