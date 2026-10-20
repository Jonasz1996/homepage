<script>
  import { untrack } from 'svelte'
  import { api, withReauth } from './api.js'
  import Modal from './Modal.svelte'

  // Standaard login voor elke host zonder eigen sleutel of wachtwoord (zoals de hosts uit Proxmox).
  let { defaults, keys = [], onclose, onsaved } = $props()

  const d = untrack(() => defaults) || {}
  let username = $state(d.username || 'root')
  let password = $state('')
  let clearPassword = $state(false)
  let key_id = $state(d.key_id ?? null)
  let auto_sync = $state(!!d.auto_sync)
  let error = $state('')

  async function save(e) {
    e.preventDefault()
    error = ''
    try {
      const body = { username, key_id: key_id || null, auto_sync, password: clearPassword ? '' : password || null }
      onsaved(await withReauth(() => api('/ssh/defaults', { method: 'PUT', body })))
      onclose()
    } catch (err) { error = err.message }
  }
</script>

<Modal title="ssh --defaults" {onclose}>
  <form onsubmit={save}>
    <p class="help">Geldt voor elke host zonder eigen sleutel of wachtwoord. Per host kan je dat altijd overschrijven
      onder ✎.</p>
    <label class="lbl" for="sd-user">Gebruiker</label>
    <!-- svelte-ignore a11y_autofocus -->
    <input id="sd-user" bind:value={username} maxlength="64" required autofocus />
    <label class="lbl" for="sd-pw">Wachtwoord {d.has_password ? '(ingesteld, leeg laten = behouden)' : ''}</label>
    <input id="sd-pw" type="password" bind:value={password} autocomplete="new-password" disabled={clearPassword} />
    {#if d.has_password}<label class="chk"><input type="checkbox" bind:checked={clearPassword} /> wachtwoord wissen</label>{/if}
    <label class="lbl" for="sd-key">Sleutel (wordt eerst geprobeerd, daarna het wachtwoord)</label>
    <select id="sd-key" bind:value={key_id}>
      <option value={null}>geen</option>
      {#each keys as k (k.id)}<option value={k.id}>{k.name}</option>{/each}
    </select>
    <label class="chk sync"><input type="checkbox" bind:checked={auto_sync} />
      hosts uit Proxmox automatisch bijhouden (elk half uur: nieuwe containers en VM's erbij, gewijzigde IP's bijgewerkt)</label>
    <p class="err">{error}</p>
    <div class="row">
      <button class="btn">Opslaan</button>
      <button type="button" class="btn alt" onclick={onclose}>Annuleren</button>
    </div>
  </form>
</Modal>

<style>
  .help { font-size: 12.5px; color: var(--muted); margin: 0 0 6px; line-height: 1.5 }
  .sync { margin-top: 14px; line-height: 1.5 }
</style>
