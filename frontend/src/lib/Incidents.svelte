<script>
  import { onMount } from 'svelte'
  import { api } from './api.js'

  // Vorige storingen van een service met hun notities: bij een nieuwe storing zie je meteen wat toen hielp.
  let { service, down = false } = $props()

  let data = $state(null)
  let edit = $state(null)
  let error = $state('')

  async function load() {
    try { data = await api(`/services/${service.id}/incidents`); error = '' } catch (e) { error = e.message }
  }
  onMount(load)

  async function save() {
    try {
      await api(`/timeline/events/${edit.id}/note`, { method: 'PUT', body: { note: edit.note } })
      edit = null
      await load()
    } catch (e) { error = e.message }
  }

  const when = (ts) => new Date(ts).toLocaleString('nl-BE', { dateStyle: 'short', timeStyle: 'short' })
  let downs = $derived((data?.items || []).filter((i) => i.level === 'err'))
  let noted = $derived(downs.filter((i) => i.note))
</script>

{#if downs.length}
  <div class="inc" class:alert={down && noted.length}>
    <span class="lbl">vorige storingen{data.count_year > downs.length ? ` (${data.count_year} dit jaar)` : ''}</span>
    {#if down && noted.length}<p class="tip">Dit hielp de vorige keer:</p>{/if}
    {#if error}<p class="err">{error}</p>{/if}
    {#each downs as i (i.event_id)}
      <div class="it">
        <div class="h"><span class="m">{when(i.ts)}</span> {i.body || i.title}
          {#if edit?.id !== i.event_id}
            <button class="mini" onclick={() => (edit = { id: i.event_id, note: i.note || '' })}>{i.note ? '✎' : '+ notitie'}</button>
          {/if}
        </div>
        {#if edit?.id === i.event_id}
          <textarea bind:value={edit.note} rows="3" maxlength="4000" placeholder="Oorzaak en hoe je het oploste"></textarea>
          <div class="line">
            <button class="mini" onclick={save}>bewaren</button>
            <button class="mini" onclick={() => (edit = null)}>annuleren</button>
          </div>
        {:else if i.note}
          <p class="note">{i.note}</p>
        {/if}
      </div>
    {/each}
  </div>
{/if}

<style>
  .inc { margin: 8px 0 }
  .inc.alert { border: 1px solid rgba(240, 180, 107, .4); border-radius: 10px; padding: 8px 10px; background: rgba(240, 180, 107, .05) }
  .tip { margin: 2px 0 6px; color: var(--mid); font-size: 12.5px }
  .it { padding: 5px 0; border-top: 1px solid var(--line); font-size: 12.5px }
  .h { display: flex; gap: 8px; align-items: baseline; flex-wrap: wrap }
  .m { color: var(--muted); font-size: 11.5px }
  .note { margin: 4px 0 0; white-space: pre-wrap; color: var(--text-h); padding-left: 10px; border-left: 2px solid var(--mid) }
  textarea { width: 100%; margin-top: 4px; font: inherit; font-size: 12.5px }
  .line { display: flex; gap: 6px; margin-top: 4px }
</style>
