<script>
  import { untrack } from 'svelte'
  import { api } from './api.js'

  // Proxy hosts uit NPM in één keer als tegels toevoegen.
  let { service, groups = [], onchanged } = $props()

  let hosts = $state(null)
  let picked = $state({})
  let groupId = $state(untrack(() => groups[0]?.id))
  let monitor = $state(true)
  let error = $state('')
  let result = $state('')

  async function open() {
    error = ''
    try {
      hosts = await api(`/services/${service.id}/npm/hosts`)
      picked = Object.fromEntries(hosts.filter((h) => !h.exists && h.enabled).map((h) => [h.url, true]))
    } catch (e) {
      error = e.message
    }
  }

  async function run() {
    const chosen = hosts.filter((h) => picked[h.url])
    try {
      const r = await api(`/services/${service.id}/npm/import`, { method: 'POST', body: { group_id: groupId, hosts: chosen, monitor } })
      result = `${r.added} services toegevoegd.`
      await open()
      onchanged?.()
    } catch (e) {
      error = e.message
    }
  }
  let count = $derived(Object.values(picked).filter(Boolean).length)
</script>

{#if !hosts}
  <p class="hint">Maak in één keer tegels van je proxy hosts. Hosts die al een tegel hebben worden overgeslagen.</p>
  <button class="mini" onclick={open}>proxy hosts ophalen</button>
{:else}
  <div class="list">
    {#each hosts as h (h.url)}
      <label class="chk" class:dim={h.exists}>
        <input type="checkbox" bind:checked={picked[h.url]} disabled={h.exists} />
        <span class="n">{h.name}</span><span class="u">{h.url}</span>
        {#if h.exists}<span class="tag">bestaat al</span>{:else if !h.enabled}<span class="tag">uit in NPM</span>{/if}
      </label>
    {/each}
  </div>
  <div class="row">
    <select bind:value={groupId}>
      {#each groups as g (g.id)}<option value={g.id}>{g.label}</option>{/each}
    </select>
    <label class="chk"><input type="checkbox" bind:checked={monitor} /> HTTP-check aanzetten</label>
    <button class="mini" disabled={!count || !groupId} onclick={run}>{count} toevoegen</button>
  </div>
{/if}
{#if result}<p class="ok">{result}</p>{/if}
<p class="err">{error}</p>

<style>
  .list { max-height: 260px; overflow: auto; border: 1px solid var(--line); border-radius: 8px; padding: 6px 8px; margin-bottom: 8px }
  .chk { display: flex; gap: 8px; align-items: center; font-size: 12.5px; padding: 2px 0 }
  .chk.dim { opacity: .5 }
  .n { color: var(--text-h); min-width: 120px }
  .u { color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap }
  .tag { margin-left: auto; font-size: 10.5px; color: var(--dim) }
  .row select { max-width: 240px }
  .ok { color: var(--ok); font-size: 12.5px }
</style>
