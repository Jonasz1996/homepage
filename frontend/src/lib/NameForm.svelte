<script>
  import { untrack } from 'svelte'
  import { ask } from './dialog.svelte.js'
  import Modal from './Modal.svelte'

  // Formulier voor pagina's en groepen: naam + optioneel icoon.
  let { title, initial = {}, onsave, ondelete = null, onclose } = $props()

  const start = untrack(() => initial) || {}
  let name = $state(start.name || '')
  let icon = $state(start.icon || '')
  let error = $state('')
  let busy = $state(false)

  async function save(e) {
    e.preventDefault()
    busy = true
    try {
      await onsave({ name, icon: icon || null })
      onclose()
    } catch (err) {
      error = err.message
    } finally {
      busy = false
    }
  }

  async function del() {
    if (!(await ask(`'${initial.name}' en alles erin verwijderen? Je kunt dit terugzetten via Versies.`, { ok: 'Verwijderen', danger: true }))) return
    try {
      await ondelete()
      onclose()
    } catch (err) {
      error = err.message
    }
  }
</script>

<Modal {title} {onclose}>
  <form onsubmit={save}>
    <label class="lbl" for="nf-name">Naam</label>
    <!-- svelte-ignore a11y_autofocus -->
    <input id="nf-name" bind:value={name} maxlength="80" required autofocus />
    <label class="lbl" for="nf-icon">Icoon (optioneel)</label>
    <input id="nf-icon" bind:value={icon} placeholder="bv. proxmox.png of mdi-server" />
    <p class="err">{error}</p>
    <div class="row">
      <button class="btn" disabled={busy}>Opslaan</button>
      {#if ondelete}<button type="button" class="btn alt danger" onclick={del}>Verwijderen</button>{/if}
    </div>
  </form>
</Modal>
