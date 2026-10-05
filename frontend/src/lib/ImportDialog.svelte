<script>
  import { untrack } from 'svelte'
  import { api } from './api.js'
  import Modal from './Modal.svelte'

  let { pages, groups = [], tab: startTab = 'yaml', onclose, ondone } = $props()
  let tab = $state(untrack(() => startTab))

  let text = $state('')
  let target = $state('new')
  let pageName = $state('Homelab')
  let error = $state('')
  let result = $state(null)
  let busy = $state(false)

  async function pick(e) {
    const f = e.currentTarget.files?.[0]
    if (f) text = await f.text()
  }

  async function go(e) {
    e.preventDefault()
    busy = true
    error = ''
    try {
      result = await api('/import', {
        method: 'POST',
        body: { yaml: text, page_id: target === 'new' ? null : Number(target), page_name: pageName },
      })
      ondone()
    } catch (err) {
      error = err.message
    } finally {
      busy = false
    }
  }

  // --- Uptime Kuma vervangen ----------------------------------------------------------------------
  let kuma = $state({ url: '', api_key: '', insecure: false })
  let cmp = $state.raw(null)
  let picked = $state({})
  let group = $state(untrack(() => groups[0]?.id ?? null))
  let done = $state(null)
  async function compare(e) {
    if (e) { e.preventDefault(); done = null }
    busy = true
    error = ''
    try {
      cmp = await api('/kuma/compare', { method: 'POST', body: $state.snapshot(kuma) })
      picked = Object.fromEntries(cmp.monitors.filter((m) => m.state === 'ontbreekt' || m.state === 'zonder-check').map((m) => [m.name, true]))
    } catch (err) { error = err.message } finally { busy = false }
  }
  let chosen = $derived((cmp?.monitors || []).filter((m) => picked[m.name]))
  async function take() {
    busy = true
    error = ''
    try {
      done = await api('/kuma/apply', { method: 'POST', body: {
        group_id: group,
        add: chosen.filter((m) => m.state === 'ontbreekt').map((m) => m.proposal),
        checks: chosen.filter((m) => m.state === 'zonder-check').map((m) => ({ service_id: m.service.id, check: m.proposal.check })),
      } })
      ondone()
      await compare()
    } catch (err) { error = err.message } finally { busy = false }
  }
  const STATE = { gedekt: 'gedekt', 'zonder-check': 'tegel zonder check', ontbreekt: 'ontbreekt', 'niet-overnemen': 'niet over te nemen' }
  const where = (m) => (m.proposal ? (m.proposal.check.target || m.proposal.url) : m.url || m.host || '')
</script>

<Modal title={tab === 'kuma' ? 'import uptime kuma' : 'import services.yaml'} {onclose} wide>
  <div class="tabs">
    <button class="mini" class:on={tab === 'yaml'} onclick={() => (tab = 'yaml')}>services.yaml</button>
    <button class="mini" class:on={tab === 'kuma'} onclick={() => (tab = 'kuma')}>Uptime Kuma vervangen</button>
  </div>
  {#if tab === 'kuma'}
  <p class="hint">
    Het dashboard haalt je monitors uit Uptime Kuma en vergelijkt ze met je tegels. Wat ontbreekt, wordt een tegel met
    een check; een tegel zonder check krijgt er een. Daarna volgt het dashboard alles wat Kuma volgde en mag Kuma uit.
    De API-sleutel wordt niet bewaard.
  </p>
  <form onsubmit={compare}>
    <div class="row two">
      <div>
        <label class="lbl" for="k-url">Adres van Uptime Kuma</label>
        <input id="k-url" bind:value={kuma.url} placeholder="http://192.168.0.20:3001" required />
      </div>
      <div>
        <label class="lbl" for="k-key">API-sleutel (Kuma: Instellingen → API-sleutels)</label>
        <input id="k-key" type="password" bind:value={kuma.api_key} autocomplete="off" required />
      </div>
    </div>
    <label class="chk"><input type="checkbox" bind:checked={kuma.insecure} /> zelfondertekend certificaat</label>
    <div class="row"><button class="btn" disabled={busy || !kuma.url || !kuma.api_key}>{busy && !cmp ? 'ophalen…' : 'vergelijken'}</button></div>
  </form>
  <p class="err">{error}</p>
  {#if cmp}
    {@const c = cmp.counts}
    <p class="sum"><span class="g">{c.gedekt} gedekt</span> · <span class="w">{c['zonder-check']} tegel zonder check</span> ·
      <span class="e">{c.ontbreekt} ontbreken</span> · <span class="m">{c['niet-overnemen']} niet over te nemen</span></p>
    {#if !c.ontbreekt && !c['zonder-check']}
      <p class="hint good">Alles wat Kuma volgt, volgt het dashboard ook. Zet in Kuma de meldingen uit (en verwijder de webhook
        naar het dashboard onder meldingen → webhooks), laat het een week meelopen en zet Kuma dan uit.</p>
    {/if}
    <div class="wrap">
      <table class="tbl">
        <thead><tr><th></th><th>monitor</th><th>type</th><th>in Kuma</th><th>dashboard</th><th>check</th></tr></thead>
        <tbody>
          {#each cmp.monitors as m (m.name)}
            <tr class="s-{m.state}">
              <td>{#if m.state === 'ontbreekt' || m.state === 'zonder-check'}<input type="checkbox" bind:checked={picked[m.name]} aria-label={`${m.name} overnemen`} />{/if}</td>
              <td><b>{m.name}</b></td>
              <td class="m">{m.type}</td>
              <td class:g={m.status === 'up'} class:e={m.status === 'down'} class="st">{m.status}</td>
              <td><span class="chip">{STATE[m.state]}</span>{#if m.service} <small>{m.service.name}</small>{/if}</td>
              <td class="m">{#if m.proposal}{m.proposal.check.type} {where(m)}{/if}{#if m.why}<div class="why">{m.why}</div>{/if}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    {#if chosen.length}
      <div class="row two">
        {#if chosen.some((m) => m.state === 'ontbreekt')}
          <div>
            <label class="lbl" for="k-group">Nieuwe tegels in</label>
            <select id="k-group" bind:value={group}>{#each groups as g (g.id)}<option value={g.id}>{g.label}</option>{/each}</select>
          </div>
        {/if}
      </div>
      <div class="row">
        <button class="btn" disabled={busy || (chosen.some((m) => m.state === 'ontbreekt') && group == null)} onclick={take}>
          {chosen.length} overnemen</button>
      </div>
    {/if}
    {#if done}<p class="hint good">Overgenomen: {done.added} nieuwe tegels, {done.checks} checks aangezet.</p>{/if}
  {/if}
  <div class="row"><button type="button" class="btn alt" onclick={onclose}>Sluiten</button></div>
  {:else}
  <p class="hint">
    Plak je <code>services.yaml</code> van homepage.dev, of een export van dit dashboard.
    Widget-wachtwoorden en API-sleutels worden versleuteld bewaard.
  </p>
  <form onsubmit={go}>
    <input type="file" accept=".yaml,.yml,text/yaml" onchange={pick} />
    <label class="lbl" for="imp-text">YAML</label>
    <textarea id="imp-text" bind:value={text} rows="14" required></textarea>
    <div class="row two">
      <div>
        <label class="lbl" for="imp-target">Toevoegen aan</label>
        <select id="imp-target" bind:value={target}>
          <option value="new">nieuwe pagina</option>
          {#each pages as p (p.id)}<option value={String(p.id)}>{p.name}</option>{/each}
        </select>
      </div>
      {#if target === 'new'}
        <div>
          <label class="lbl" for="imp-name">Naam nieuwe pagina</label>
          <input id="imp-name" bind:value={pageName} maxlength="80" />
        </div>
      {/if}
    </div>
    <p class="err">{error}</p>
    {#if result}<p class="ok">Geïmporteerd: {result.groups} groepen, {result.services} services.</p>{/if}
    <div class="row">
      <button class="btn" disabled={busy || !text.trim()}>Importeren</button>
      <button type="button" class="btn alt" onclick={onclose}>Sluiten</button>
    </div>
  </form>
  {/if}
</Modal>

<style>
  .two > div { flex: 1; min-width: 200px }
  .tabs { display: flex; gap: 6px; margin-bottom: 10px }
  .chk { font-size: 12px; color: var(--muted); display: flex; gap: 6px; align-items: center; margin: 6px 0 }
  .sum { font-size: 12.5px; margin: 8px 0 }
  .wrap { overflow-x: auto; margin: 6px 0 }
  .tbl { width: 100%; border-collapse: collapse; font-size: 12.5px; min-width: 560px }
  .tbl th { text-align: left; font-weight: 400; color: var(--muted); font-size: 11.5px; padding: 5px 8px; border-bottom: 1px solid var(--line) }
  .tbl td { padding: 5px 8px; border-bottom: 1px solid var(--line); vertical-align: top }
  .tbl td b { font-weight: 500; color: var(--text-h) }
  .tbl small, .m { color: var(--muted) }
  .why { font-size: 11.5px; color: var(--muted) }
  .chip { font-size: 11px; padding: 0 6px; border-radius: 6px; border: 1px solid var(--line-2) }
  .s-gedekt .chip { color: var(--ok) }
  .s-zonder-check .chip { color: var(--mid) }
  .s-ontbreekt .chip { color: var(--err) }
  .s-niet-overnemen { opacity: .65 }
  .g, .good { color: var(--ok) }
  .w { color: var(--mid) }
  .e { color: var(--err) }
</style>
