<script>
  import { onMount } from 'svelte'
  import { api, withReauth } from './api.js'
  import Modal from './Modal.svelte'

  let { onclose, ondone } = $props()
  let items = $state([])
  let error = $state('')

  const fmt = (ts) => new Date(ts).toLocaleString('nl-BE', { dateStyle: 'short', timeStyle: 'short' })

  async function load() {
    items = await api('/revisions')
  }

  async function restore(r) {
    if (!confirm(`Layout terugzetten naar "${r.summary}" (${fmt(r.created_at)})?`)) return
    try {
      // Zet de oude versie checks stil (gepauzeerd, verwijderd, meldingen uit), dan vraagt dat een recente 2FA.
      await withReauth(() => api(`/revisions/${r.id}/restore`, { method: 'POST' }))
      ondone()
      await load()
    } catch (e) {
      error = e.message
    }
  }

  onMount(load)
</script>

<Modal title="git log --layout" {onclose}>
  <p class="hint">Elke wijziging bewaart een versie van de volledige layout. Terugzetten is zelf ook een nieuwe versie.</p>
  <p class="err">{error}</p>
  <div class="list">
    {#each items as r, i (r.id)}
      <div class="item">
        <span class="ts">{fmt(r.created_at)}</span>
        <span class="sum">{r.summary}</span>
        {#if i > 0}<button class="mini" onclick={() => restore(r)}>Terugzetten</button>{:else}<span class="now">huidig</span>{/if}
      </div>
    {:else}
      <p class="hint">Nog geen versies.</p>
    {/each}
  </div>
</Modal>

<style>
  .list { max-height: 56vh; overflow: auto }
  .item {
    display: flex; gap: 10px; align-items: center; padding: 8px 12px; margin-bottom: 6px; border-radius: 8px;
    background: var(--fill); border: 1px solid rgba(255, 255, 255, .06); border-left: 3px solid #666; font-size: 12.5px
  }
  .ts { color: var(--muted); flex: none }
  .sum { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap }
  .now { color: var(--ok); font-size: 11.5px }
</style>
