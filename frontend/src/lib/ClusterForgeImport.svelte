<script>
  import { untrack } from 'svelte'
  import { api } from './api.js'

  // Een tegel per ClusterForge-cluster: zelfde API en sleutels, check rood zolang het cluster niet in orde is.
  let { service, groups = [], onchanged } = $props()

  let clusters = $state(null)
  let picked = $state({})
  let groupId = $state(untrack(() => service.group_id ?? groups[0]?.id))
  let monitor = $state(true)
  let error = $state('')
  let result = $state('')

  async function open() {
    error = ''
    try {
      clusters = await api(`/services/${service.id}/clusterforge/clusters`)
      picked = Object.fromEntries(clusters.filter((c) => !c.exists).map((c) => [c.slug, true]))
    } catch (e) {
      error = e.message
    }
  }

  async function run() {
    const chosen = clusters.filter((c) => picked[c.slug] && !c.exists).map((c) => c.slug)
    try {
      const r = await api(`/services/${service.id}/clusterforge/import`, { method: 'POST', body: { group_id: groupId, clusters: chosen, monitor } })
      result = `${r.added} tegels toegevoegd.`
      await open()
      onchanged?.()
    } catch (e) {
      error = e.message
    }
  }
  let count = $derived(Object.entries(picked).filter(([k, v]) => v && !clusters?.find((c) => c.slug === k)?.exists).length)
</script>

{#if !clusters}
  <p class="hint">Maak een eigen tegel per cluster, met status, nodes, VIP, database, incidenten en updates. Zijn check
    wordt rood zolang het cluster niet in orde is. Clusters die al een tegel hebben worden overgeslagen.</p>
  <button class="mini" onclick={open}>clusters ophalen</button>
{:else}
  <div class="list">
    {#each clusters as c (c.slug)}
      <label class="chk" class:dim={c.exists}>
        <input type="checkbox" bind:checked={picked[c.slug]} disabled={c.exists} />
        <span class="n">{c.name}</span><span class="u" class:bad={!c.ok}>{c.status_label}</span>
        {#if c.exists}<span class="tag">heeft al een tegel</span>{/if}
      </label>
    {:else}
      <p class="hint">Het token mag geen enkel cluster zien.</p>
    {/each}
  </div>
  <div class="row">
    <select bind:value={groupId}>
      {#each groups as g (g.id)}<option value={g.id}>{g.label}</option>{/each}
    </select>
    <label class="chk"><input type="checkbox" bind:checked={monitor} /> check aanzetten</label>
    <button class="mini" disabled={!count || !groupId} onclick={run}>{count} toevoegen</button>
  </div>
{/if}
{#if result}<p class="ok">{result}</p>{/if}
<p class="err">{error}</p>

<style>
  .list { max-height: 260px; overflow: auto; border: 1px solid var(--line); border-radius: 8px; padding: 6px 8px; margin-bottom: 8px }
  .chk { display: flex; gap: 8px; align-items: center; font-size: 12.5px; padding: 2px 0 }
  .chk.dim { opacity: .5 }
  .n { color: var(--text-h); min-width: 140px }
  .u { color: var(--muted) }
  .u.bad { color: var(--mid) }
  .tag { margin-left: auto; font-size: 10.5px; color: var(--dim) }
  .row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap }
  .row select { max-width: 240px }
  .ok { color: var(--ok); font-size: 12.5px }
</style>
