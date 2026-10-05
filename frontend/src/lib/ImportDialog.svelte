<script>
  import { api } from './api.js'
  import Modal from './Modal.svelte'

  let { pages, onclose, ondone } = $props()

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
</script>

<Modal title="import services.yaml" {onclose} wide>
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
    {#if result}<p class="ok">Geïmporteerd: {result.groups} groepen, {result.services} services.</p>
      {#if result.checks_skipped?.length}<p class="hint">{result.checks_skipped.length} checks overgeslagen (ongeldig): {result.checks_skipped.slice(0, 8).join(', ')}{result.checks_skipped.length > 8 ? ' …' : ''}. Zet ze opnieuw via bewerken.</p>{/if}
    {/if}
    <div class="row">
      <button class="btn" disabled={busy || !text.trim()}>Importeren</button>
      <button type="button" class="btn alt" onclick={onclose}>Sluiten</button>
    </div>
  </form>
</Modal>

<style>
  .two > div { flex: 1; min-width: 200px }
</style>
