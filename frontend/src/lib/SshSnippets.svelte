<script>
  import { untrack } from 'svelte'
  import { api } from './api.js'
  import Modal from './Modal.svelte'

  // Opgeslagen commando's (zoals macro's in RDM): één klik stuurt ze naar de terminal.
  let { snippets = [], onclose, onsaved } = $props()

  let list = $state(untrack(() => snippets).map((s) => ({ ...s })))
  let error = $state('')

  const add = () => list.push({ name: '', command: '', run: true })
  async function save() {
    error = ''
    try {
      const body = list.filter((s) => s.name.trim() && s.command.trim())
      onsaved(await api('/ssh/snippets', { method: 'PUT', body }))
      onclose()
    } catch (e) { error = e.message }
  }
</script>

<Modal title="snippets" {onclose} wide>
  <p class="hint">Klik in de terminal op ⌘ snippets om er één te sturen. "Uitvoeren" stuurt er een Enter achter;
    anders staat het commando klaar om aan te passen.</p>
  {#each list as s, i}
    <div class="sn">
      <input bind:value={s.name} placeholder="naam, bv. updates" maxlength="60" />
      <textarea bind:value={s.command} rows="1" placeholder="apt update && apt list --upgradable" maxlength="4000"></textarea>
      <label class="chk"><input type="checkbox" bind:checked={s.run} /> uitvoeren</label>
      <button class="mini x" onclick={() => list.splice(i, 1)} aria-label="Verwijderen">✕</button>
    </div>
  {/each}
  <button class="mini" onclick={add}>+ snippet</button>
  <p class="err">{error}</p>
  <div class="row">
    <button class="btn" onclick={save}>Opslaan</button>
    <button class="btn alt" onclick={onclose}>Annuleren</button>
  </div>
</Modal>

<style>
  .sn { display: grid; grid-template-columns: 160px 1fr auto auto; gap: 8px; align-items: center; margin-bottom: 6px }
  .sn textarea { resize: vertical; min-height: 38px; font: inherit; font-size: 12.5px }
  @media (max-width: 600px) { .sn { grid-template-columns: 1fr auto; } .sn textarea { grid-column: 1 / -1 } }
</style>
