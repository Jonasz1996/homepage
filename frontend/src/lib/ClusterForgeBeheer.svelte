<script>
  import { onMount } from 'svelte'
  import { api } from './api.js'
  import { ask } from './dialog.svelte.js'

  // ClusterForge beheert een deel van het dashboard: een groep per cluster, een tegel per cluster en per node.
  let { service, onchanged } = $props()

  let st = $state(null)
  let pageId = $state('')
  let nodes = $state(true)
  let error = $state('')
  let busy = $state(false)

  async function load() {
    try {
      st = await api('/clusterforge/beheer')
      pageId = st.page_id ?? ''
      nodes = st.nodes
    } catch (e) {
      error = e.message
    }
  }
  onMount(load)

  let on = $derived(st?.service_id === service.id)
  let other = $derived(st?.service_id && st.service_id !== service.id ? st.sources.find((s) => s.id === st.service_id) : null)

  async function save(enable) {
    if (!enable && !(await ask('Beheer door ClusterForge uitzetten? De tegels en groepen blijven staan, maar worden niet meer bijgewerkt.', { ok: 'Uitzetten' }))) return
    busy = true
    error = ''
    try {
      await api('/clusterforge/beheer', { method: 'PUT', body: { service_id: enable ? service.id : null, page_id: pageId === '' ? null : Number(pageId), nodes } })
      await load()
      onchanged?.()
    } catch (e) {
      error = e.message
    } finally {
      busy = false
    }
  }

  async function syncNow() {
    busy = true
    error = ''
    try {
      await api('/clusterforge/beheer/sync', { method: 'POST', body: { force: true } })
      await load()
      onchanged?.()
    } catch (e) {
      error = e.message
    } finally {
      busy = false
    }
  }
  const when = (iso) => (iso ? new Date(iso).toLocaleString('nl-BE', { dateStyle: 'short', timeStyle: 'short' }) : '')
</script>

{#if st}
  <p class="hint">Laat ClusterForge dit deel van het dashboard bijhouden: per cluster een groep met een tegel voor het
    cluster en een tegel per node, nieuwe nodes en clusters komen er vanzelf bij, wat uit ClusterForge verdwijnt gaat
    weg. Elke {Math.round(st.every / 60)} minuten. Tegels die je zelf maakt blijven altijd staan; van een beheerde tegel
    neemt ClusterForge alleen naam, link, omschrijving en groep, je icoon, plaats en check blijven.</p>
  {#if other}<p class="hint">Nu is <b>{other.name}</b> de bron. Aanzetten hier neemt het over.</p>{/if}
  <div class="row">
    <label class="lbl" for="cfb-page">pagina</label>
    <select id="cfb-page" bind:value={pageId} disabled={busy}>
      <option value="">eigen pagina "ClusterForge"</option>
      {#each st.pages as p (p.id)}<option value={p.id}>{p.name}</option>{/each}
    </select>
    <label class="chk"><input type="checkbox" bind:checked={nodes} disabled={busy} /> ook een tegel per node</label>
  </div>
  <div class="row">
    {#if on}
      <span class="on">● aan</span>
      <button class="mini" disabled={busy} onclick={() => save(true)}>opslaan</button>
      <button class="mini" disabled={busy} onclick={syncNow}>nu synchroniseren</button>
      <button class="mini x" disabled={busy} onclick={() => save(false)}>uitzetten</button>
    {:else}
      <button class="mini" disabled={busy} onclick={() => save(true)}>aanzetten met deze tegel</button>
    {/if}
    <span class="cnt">{st.managed} beheerde tegels</span>
  </div>
  {#if on && st.last}
    {#if st.last.error}
      <p class="err">{when(st.last.at)}: {st.last.error}</p>
    {:else}
      <p class="last">{when(st.last.at)}: {st.last.clusters} clusters{st.last.nodes == null ? '' : `, ${st.last.nodes} nodes`} ·
        {st.last.added} nieuw, {st.last.changed} bijgewerkt, {st.last.removed} weg</p>
      {#if st.last.nodes == null && nodes}<p class="warn">Deze ClusterForge geeft nog geen nodes (/api/dashboard/v1/nodes): werk ClusterForge bij, dan komen de nodetegels er vanzelf bij.</p>{/if}
      {#if st.last.held}<p class="warn">{st.last.held} tegels zouden in één keer weggaan; de worker liet ze staan. Klopt het, kies dan "nu synchroniseren".</p>{/if}
    {/if}
  {/if}
{/if}
<p class="err">{error}</p>

<style>
  .row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin: 6px 0 }
  .row select { max-width: 240px }
  .chk { display: flex; gap: 6px; align-items: center; font-size: 12.5px }
  .on { color: var(--ok); font-size: 12.5px }
  .cnt { margin-left: auto; color: var(--dim); font-size: 11.5px }
  .last { color: var(--muted); font-size: 12px }
  .warn { color: var(--mid); font-size: 12px }
</style>
